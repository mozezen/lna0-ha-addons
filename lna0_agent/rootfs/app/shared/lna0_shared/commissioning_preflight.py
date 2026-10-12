"""Pure preflight evaluation for the v0.1 commissioning slice."""

from __future__ import annotations

import re
from typing import Any

from .validation import ValidationError, validate_hostname

MIN_FREE_DISK_GB = 4.0

PREFLIGHT_FACT_FIELDS = {
    "golden_base_version",
    "agent_version",
    "haos_version",
    "core_version",
    "hostname",
    "network_ready",
    "control_plane_reachable",
    "disk_free_gb",
    "tailscale_required",
    "tailscale_connected",
    "ssh_required",
    "ssh_available",
}

SECRET_KEY_RE = re.compile(r"(authorization|auth|credential|password|private[_-]?key|secret|token)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]+|\b(?:enr_|node_)[A-Za-z0-9_-]{20,}\b|password\s*[:=]|token\s*[:=])")


def evaluate_preflight(facts: dict[str, Any]) -> dict[str, Any]:
    """Evaluate injected runtime facts without doing OS or network I/O."""

    if not isinstance(facts, dict):
        return _result("failed", [_check("contract", "failed", "Preflight facts must be an object.")])

    checks: list[dict[str, Any]] = []
    missing = sorted(PREFLIGHT_FACT_FIELDS - set(facts))
    extra = sorted(set(facts) - PREFLIGHT_FACT_FIELDS)
    if missing:
        checks.append(_check("contract.required_fields", "failed", f"Missing preflight facts: {', '.join(missing)}."))
    if extra:
        checks.append(_check("contract.known_fields", "failed", f"Unknown preflight facts: {', '.join(extra)}."))
    if _contains_secret_material(facts):
        checks.append(_check("contract.no_secrets", "failed", "Preflight facts must not include secret material."))

    checks.extend(
        [
            _non_empty_string_check(facts, "golden_base_version", "golden_base_version.present", "Golden Base version is present."),
            _non_empty_string_check(facts, "agent_version", "agent_version.present", "Agent version is present."),
            _hostname_check(facts),
            _boolean_ready_check(facts, "network_ready", "network.ready", "Network is ready.", "Network is not ready."),
            _boolean_ready_check(
                facts,
                "control_plane_reachable",
                "control_plane.reachable",
                "Control Plane is reachable.",
                "Control Plane is not reachable.",
            ),
            _disk_check(facts),
            _conditional_component_check(
                facts,
                required_key="tailscale_required",
                ready_key="tailscale_connected",
                check_id="tailscale.state",
                passed_message="Tailscale requirement is satisfied.",
                blocked_message="Tailscale is required but not connected.",
            ),
            _conditional_component_check(
                facts,
                required_key="ssh_required",
                ready_key="ssh_available",
                check_id="ssh.state",
                passed_message="SSH requirement is satisfied.",
                blocked_message="SSH is required but unavailable.",
            ),
        ]
    )

    if any(check["status"] == "failed" for check in checks):
        status = "failed"
    elif any(check["status"] == "blocked" for check in checks):
        status = "blocked"
    else:
        status = "passed"
    return _result(status, checks)


def _result(status: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    if status == "passed":
        summary = "Preflight passed."
    elif status == "blocked":
        summary = "Preflight is blocked by a recoverable runtime condition."
    else:
        summary = "Preflight failed because the supplied facts are invalid."
    return {"status": status, "checks": checks, "summary": summary}


def _check(check_id: str, status: str, message: str, evidence_refs: list[str] | None = None) -> dict[str, Any]:
    return {"id": check_id, "status": status, "message": message, "evidence_refs": list(evidence_refs or [])}


def _non_empty_string_check(facts: dict[str, Any], key: str, check_id: str, passed_message: str) -> dict[str, Any]:
    value = facts.get(key)
    if isinstance(value, str) and value.strip():
        return _check(check_id, "passed", passed_message, [f"fact:{key}"])
    return _check(check_id, "failed", f"{key} must be a non-empty string.")


def _hostname_check(facts: dict[str, Any]) -> dict[str, Any]:
    value = facts.get("hostname")
    if not isinstance(value, str) or not value.strip():
        return _check("hostname.present", "failed", "hostname must be a non-empty string.")
    try:
        validate_hostname(value.strip().lower())
    except ValidationError:
        return _check("hostname.valid", "failed", "hostname must be a DNS-safe label.")
    return _check("hostname.present", "passed", "Hostname is present.", ["fact:hostname"])


def _boolean_ready_check(
    facts: dict[str, Any],
    key: str,
    check_id: str,
    passed_message: str,
    blocked_message: str,
) -> dict[str, Any]:
    value = facts.get(key)
    if not isinstance(value, bool):
        return _check(check_id, "failed", f"{key} must be a boolean.")
    if value:
        return _check(check_id, "passed", passed_message, [f"fact:{key}"])
    return _check(check_id, "blocked", blocked_message, [f"fact:{key}"])


def _disk_check(facts: dict[str, Any]) -> dict[str, Any]:
    value = facts.get("disk_free_gb")
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        return _check("disk.free_gb", "failed", "disk_free_gb must be a non-negative number.")
    if float(value) < MIN_FREE_DISK_GB:
        return _check(
            "disk.free_gb",
            "blocked",
            f"At least {MIN_FREE_DISK_GB:g} GB free disk is required.",
            ["fact:disk_free_gb"],
        )
    return _check("disk.free_gb", "passed", "Free disk threshold is satisfied.", ["fact:disk_free_gb"])


def _conditional_component_check(
    facts: dict[str, Any],
    *,
    required_key: str,
    ready_key: str,
    check_id: str,
    passed_message: str,
    blocked_message: str,
) -> dict[str, Any]:
    required = facts.get(required_key)
    ready = facts.get(ready_key)
    if not isinstance(required, bool):
        return _check(check_id, "failed", f"{required_key} must be a boolean.")
    if not isinstance(ready, bool):
        return _check(check_id, "failed", f"{ready_key} must be a boolean.")
    if required and not ready:
        return _check(check_id, "blocked", blocked_message, [f"fact:{ready_key}"])
    return _check(check_id, "passed", passed_message, [f"fact:{required_key}", f"fact:{ready_key}"])


def _contains_secret_material(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)) or _contains_secret_material(item):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_secret_material(item) for item in value)
    return isinstance(value, str) and bool(SECRET_VALUE_RE.search(value))
