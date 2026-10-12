"""Completed commissioning artifact reader and reporter."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from lna0_shared.security import canonical_json, utc_iso
from lna0_shared.validation import ValidationError, validate_commissioning_report
from lna0_shared.commissioning import validate_commissioning_state

from .http_client import HttpJsonError, signed_request
from .state import load_state, save_state

MAX_STATE_BYTES = 64 * 1024
MAX_HANDOVER_BYTES = 256 * 1024


class CommissioningArtifactsUnavailable(RuntimeError):
    """Raised when local commissioning artifacts are incomplete or invalid."""


def load_completed_commissioning_payload(
    *,
    state_path: Path,
    handover_path: Path,
    node_id: str,
    house_id: str,
    private_state: dict[str, Any],
) -> dict[str, Any] | None:
    if not state_path.exists():
        return None
    state = _read_json_file(state_path, MAX_STATE_BYTES)
    state = validate_commissioning_state(state)
    if state.get("state") != "completed":
        return None
    if state.get("node_id") != node_id or state.get("house_id") != house_id:
        raise CommissioningArtifactsUnavailable("commissioning state identity conflicts with agent identity")
    if private_state.get("node_id") not in {None, node_id} or private_state.get("house_id") not in {None, house_id}:
        raise CommissioningArtifactsUnavailable("private agent identity conflicts with runtime identity")
    if not _checkpoint_passed(state, "validation") or not _checkpoint_passed(state, "backup") or not _checkpoint_passed(state, "handover"):
        return None
    if not state.get("commissioning_id") or not state.get("completed_at"):
        return None

    report_bytes = _read_bounded_bytes(handover_path, MAX_HANDOVER_BYTES)
    report = _parse_json_object(report_bytes, handover_path)
    _validate_handover_report(report, state, node_id, house_id)
    payload = {
        "schema_version": 1,
        "commissioning_id": state["commissioning_id"],
        "node_id": node_id,
        "house_id": house_id,
        "status": "completed",
        "validation_status": "passed",
        "backup_status": "passed",
        "backup_ref": state["artifacts"]["backup_ref"],
        "handover_status": "passed",
        "handover_report_ref": _safe_ref(state["artifacts"]["handover_report_ref"], handover_path),
        "handover_report_hash": "sha256:" + hashlib.sha256(report_bytes).hexdigest(),
        "completed_at": state["completed_at"],
        "golden_base_version": report["golden_base_version"],
        "agent_version": report["agent_version"],
        "house_config_hash": report["house_config_hash"],
        "feature_manifest_hash": report["feature_manifest_hash"],
    }
    return validate_commissioning_report(payload)


def payload_hash(payload: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(validate_commissioning_report(payload))).hexdigest()


def report_completed_commissioning(config: Any, credential: str) -> str | None:
    private_state = load_state(config.state_path)
    payload = load_completed_commissioning_payload(
        state_path=config.commissioning_state_path,
        handover_path=config.commissioning_handover_path,
        node_id=config.node_id,
        house_id=config.house_id,
        private_state=private_state,
    )
    if payload is None:
        return None
    digest = payload_hash(payload)
    ack = private_state.get("commissioning_reporting")
    if (
        isinstance(ack, dict)
        and ack.get("commissioning_id") == payload["commissioning_id"]
        and ack.get("payload_hash") == digest
        and ack.get("status") in {"accepted", "already_recorded", "conflict"}
    ):
        return str(ack["status"])
    try:
        response = signed_request(
            method="POST",
            url=f"{config.control_plane_url}/api/v1/nodes/{config.node_id}/commissioning",
            credential=credential,
            data=payload,
            ca_pem=config.control_plane_ca_pem,
            allow_insecure_dev_http=config.allow_insecure_dev_http,
        )
    except HttpJsonError as exc:
        if exc.status == 409:
            _store_ack(config.state_path, private_state, payload["commissioning_id"], digest, "conflict")
            return "conflict"
        raise
    status = response.get("status")
    if status in {"accepted", "already_recorded"}:
        _store_ack(config.state_path, private_state, payload["commissioning_id"], digest, str(status))
        return str(status)
    raise RuntimeError("commissioning response did not include an accepted status")


def _store_ack(path: Path, state: dict[str, Any], commissioning_id: str, digest: str, status: str) -> None:
    updated = dict(state)
    updated["commissioning_reporting"] = {
        "commissioning_id": commissioning_id,
        "payload_hash": digest,
        "status": status,
        "reported_at": utc_iso(),
    }
    save_state(path, updated)


def _read_json_file(path: Path, max_bytes: int) -> dict[str, Any]:
    return _parse_json_object(_read_bounded_bytes(path, max_bytes), path)


def _read_bounded_bytes(path: Path, max_bytes: int) -> bytes:
    size = path.stat().st_size
    if size > max_bytes:
        raise CommissioningArtifactsUnavailable(f"commissioning artifact too large: {path}")
    return path.read_bytes()


def _parse_json_object(raw: bytes, path: Path) -> dict[str, Any]:
    try:
        data = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise CommissioningArtifactsUnavailable(f"commissioning artifact is not valid JSON: {path}") from exc
    if not isinstance(data, dict):
        raise CommissioningArtifactsUnavailable(f"commissioning artifact must be a JSON object: {path}")
    return data


def _validate_handover_report(report: dict[str, Any], state: dict[str, Any], node_id: str, house_id: str) -> None:
    required = {
        "schema_version",
        "commissioning_id",
        "node_id",
        "house_id",
        "completed_at",
        "golden_base_version",
        "agent_version",
        "house_config_hash",
        "feature_manifest_hash",
        "backup_ref",
        "status",
    }
    if not required.issubset(report):
        raise CommissioningArtifactsUnavailable("handover report is missing required fields")
    if report["schema_version"] != 1 or report["status"] not in {"ready_for_handover", "completed"}:
        raise CommissioningArtifactsUnavailable("handover report status is invalid")
    for key, expected in (
        ("commissioning_id", state["commissioning_id"]),
        ("node_id", node_id),
        ("house_id", house_id),
        ("backup_ref", state["artifacts"]["backup_ref"]),
    ):
        if report.get(key) != expected:
            raise CommissioningArtifactsUnavailable(f"handover report {key} conflicts with commissioning state")
    trial = {
        "schema_version": 1,
        "commissioning_id": state["commissioning_id"],
        "node_id": node_id,
        "house_id": house_id,
        "status": "completed",
        "validation_status": "passed",
        "backup_status": "passed",
        "backup_ref": state["artifacts"]["backup_ref"],
        "handover_status": "passed",
        "handover_report_ref": _path_ref(Path(state["artifacts"]["handover_report_ref"])),
        "handover_report_hash": "sha256:" + "0" * 64,
        "completed_at": state["completed_at"],
        "golden_base_version": report["golden_base_version"],
        "agent_version": report["agent_version"],
        "house_config_hash": report["house_config_hash"],
        "feature_manifest_hash": report["feature_manifest_hash"],
    }
    try:
        validate_commissioning_report(trial)
    except ValidationError as exc:
        raise CommissioningArtifactsUnavailable(str(exc)) from exc


def _checkpoint_passed(state: dict[str, Any], step: str) -> bool:
    return state.get("checkpoints", {}).get(step, {}).get("status") == "passed"


def _safe_ref(value: Any, fallback_path: Path) -> str:
    if isinstance(value, str) and value and not value.startswith(("/", "\\")) and "\\" not in value:
        return value
    return _path_ref(fallback_path)


def _path_ref(path: Path) -> str:
    return "path:" + quote(path.as_posix(), safe="/:._@#=-")
