"""LNA0 Agent runtime loop."""

from __future__ import annotations

import json
import os
import random
import time
from typing import Any

from lna0_shared.constants import AGENT_VERSION
from lna0_shared.security import redact
from lna0_shared.validation import validate_heartbeat

from .config import AgentConfig, load_config
from .http_client import HttpJsonError, post_json, signed_request
from .operations import OperationAdapter
from .state import load_state, save_state
from .supervisor import SupervisorClient, collect_heartbeat

_supervisor_environment_logged = False
_supervisor_runtime_logged = False


def log(level: str, message: str, **fields: Any) -> None:
    print(json.dumps(redact({"level": level, "message": message, **fields}), separators=(",", ":")), flush=True)


def log_supervisor_environment_diagnostic() -> None:
    global _supervisor_environment_logged
    if _supervisor_environment_logged:
        return
    log(
        "info",
        "supervisor environment diagnostic",
        supervisor_token_available=bool(os.environ.get("SUPERVISOR_TOKEN")),
        supervisor_env_available=bool(os.environ.get("SUPERVISOR")),
        environment_keys=sorted(key for key in os.environ if key.startswith("SUPERVISOR")),
    )
    _supervisor_environment_logged = True


def ensure_enrolled(config: AgentConfig) -> str:
    state = load_state(config.state_path)
    credential = state.get("credential")
    if isinstance(credential, str) and credential:
        return credential
    if not config.enrollment_token:
        raise RuntimeError("Agent is not enrolled and no enrollment_token is configured")
    response = post_json(
        f"{config.control_plane_url}/api/v1/nodes/enroll",
        {
            "node_id": config.node_id,
            "house_id": config.house_id,
            "hostname": config.hostname,
            "agent_version": AGENT_VERSION,
            "enrollment_token": config.enrollment_token,
        },
        ca_pem=config.control_plane_ca_pem,
        allow_insecure_dev_http=config.allow_insecure_dev_http,
    )
    credential = response.get("credential")
    if not isinstance(credential, str) or not credential:
        raise RuntimeError("Enrollment response did not include a credential")
    save_state(config.state_path, {"credential": credential, "node_id": config.node_id, "house_id": config.house_id})
    log("info", "node enrolled", node_id=config.node_id)
    return credential


def send_heartbeat(config: AgentConfig, supervisor: SupervisorClient, credential: str) -> None:
    heartbeat = collect_heartbeat(
        supervisor=supervisor,
        node_id=config.node_id,
        house_id=config.house_id,
        hostname=config.hostname,
        agent_version=AGENT_VERSION,
        fallback_haos_version="18.3",
        fallback_core_version="2026.9.4",
    )
    validate_heartbeat(heartbeat)
    signed_request(
        method="POST",
        url=f"{config.control_plane_url}/api/v1/nodes/{config.node_id}/heartbeat",
        credential=credential,
        data=heartbeat,
        ca_pem=config.control_plane_ca_pem,
        allow_insecure_dev_http=config.allow_insecure_dev_http,
    )
    log("info", "heartbeat sent", node_id=config.node_id)


def poll_operation(config: AgentConfig, supervisor: SupervisorClient, credential: str) -> None:
    response = signed_request(
        method="GET",
        url=f"{config.control_plane_url}/api/v1/nodes/{config.node_id}/operations/next",
        credential=credential,
        ca_pem=config.control_plane_ca_pem,
        allow_insecure_dev_http=config.allow_insecure_dev_http,
    )
    operation = response.get("operation")
    if operation is None:
        return
    adapter = OperationAdapter(supervisor)
    operation_id = operation.get("operation_id", "unknown")
    try:
        result = adapter.dispatch(operation, config.node_id)
        status = "completed"
        summary = json.dumps(redact(result), separators=(",", ":"))[:512]
        error_code = None
    except Exception as exc:
        status = "rejected"
        error_code = type(exc).__name__
        detail = str(redact(str(exc)))
        if config.supervisor_token:
            detail = detail.replace(config.supervisor_token, "[REDACTED]")
        summary = f"{error_code}: {detail}"[:512]
        log("warning", "operation failed", operation_id=operation_id, error=error_code, detail=detail)
    signed_request(
        method="POST",
        url=f"{config.control_plane_url}/api/v1/nodes/{config.node_id}/operations/{operation_id}/result",
        credential=credential,
        data={"status": status, "result_summary": summary, "error_code": error_code},
        ca_pem=config.control_plane_ca_pem,
        allow_insecure_dev_http=config.allow_insecure_dev_http,
    )


def run_once(config: AgentConfig) -> None:
    global _supervisor_runtime_logged
    if not _supervisor_runtime_logged:
        log(
            "info",
            "supervisor runtime configured",
            supervisor_base_url=config.supervisor_base_url,
            supervisor_token_available=bool(config.supervisor_token),
        )
        _supervisor_runtime_logged = True
    credential = ensure_enrolled(config)
    supervisor = SupervisorClient(config.supervisor_base_url, config.supervisor_token)
    if config.enrollment_token:
        if supervisor.clear_own_enrollment_token():
            log("info", "enrollment token cleared from add-on options", node_id=config.node_id)
        else:
            log("warning", "unable to clear enrollment token from add-on options", node_id=config.node_id)
    send_heartbeat(config, supervisor, credential)
    poll_operation(config, supervisor, credential)


def main() -> None:
    log_supervisor_environment_diagnostic()
    config = load_config()
    backoff = 5
    while True:
        try:
            run_once(config)
            backoff = 5
            sleep_for = config.heartbeat_interval_seconds
        except HttpJsonError as exc:
            log("warning", "control plane request failed", status=exc.status)
            sleep_for = min(300, backoff) + random.uniform(0, 2)
            backoff = min(300, backoff * 2)
        except Exception as exc:
            log("error", "agent loop failed", error=type(exc).__name__)
            sleep_for = min(300, backoff) + random.uniform(0, 2)
            backoff = min(300, backoff * 2)
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
