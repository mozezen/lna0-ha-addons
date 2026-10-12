"""Pure commissioning state helpers for the v0.1 Installer flow."""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

from .security import parse_utc_iso
from .validation import HOUSE_ID_RE, NODE_ID_RE, ValidationError

SCHEMA_VERSION = 1

STEPS = (
    "preflight",
    "identity",
    "network",
    "enrollment",
    "house_config",
    "features",
    "branding",
    "validation",
    "backup",
    "handover",
)

NORMAL_STATES = (
    "not_started",
    "preflight",
    "identity",
    "network",
    "enrollment",
    "house_config",
    "features",
    "branding",
    "validation",
    "backup",
    "ready_for_handover",
    "completed",
)

SPECIAL_STATES = ("blocked", "failed")
STATES = NORMAL_STATES + SPECIAL_STATES
CHECKPOINT_STATUSES = ("pending", "running", "passed", "blocked", "failed", "skipped")

STATE_TO_STEP = {
    "not_started": None,
    "preflight": "preflight",
    "identity": "identity",
    "network": "network",
    "enrollment": "enrollment",
    "house_config": "house_config",
    "features": "features",
    "branding": "branding",
    "validation": "validation",
    "backup": "backup",
    "ready_for_handover": "handover",
    "completed": None,
    "blocked": None,
    "failed": None,
}

STEP_TO_STATE = {
    "preflight": "preflight",
    "identity": "identity",
    "network": "network",
    "enrollment": "enrollment",
    "house_config": "house_config",
    "features": "features",
    "branding": "branding",
    "validation": "validation",
    "backup": "backup",
    "handover": "ready_for_handover",
}

ARTIFACT_KEYS = (
    "house_config_ref",
    "feature_manifest_ref",
    "overrides_ref",
    "validation_report_ref",
    "backup_ref",
    "handover_report_ref",
)

SECRET_KEY_RE = re.compile(r"(authorization|auth|credential|password|private[_-]?key|secret|token)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]+|\b(?:enr_|node_)[A-Za-z0-9_-]{20,}\b|password\s*[:=]|token\s*[:=])")


def valid_states() -> tuple[str, ...]:
    return STATES


def valid_steps() -> tuple[str, ...]:
    return STEPS


def can_transition(current_state: str | dict[str, Any], next_state: str) -> bool:
    current_value = _state_value(current_state)
    if current_value not in STATES or next_state not in STATES:
        return False
    if current_value == "completed":
        return False
    if current_value in SPECIAL_STATES:
        if not isinstance(current_state, dict):
            return False
        current_step = current_state.get("current_step")
        if current_step not in STEPS:
            return False
        return next_state in {STEP_TO_STATE[current_step], _state_after_step(current_step)}
    if next_state in SPECIAL_STATES:
        return True
    current_index = NORMAL_STATES.index(current_value)
    next_index = NORMAL_STATES.index(next_state)
    return next_index == current_index + 1


def assert_transition(current_state: str | dict[str, Any], next_state: str) -> None:
    if not can_transition(current_state, next_state):
        raise ValidationError(f"illegal commissioning transition: {_state_value(current_state)} -> {next_state}")


def next_expected_step(state: str) -> str | None:
    if state not in STATES:
        raise ValidationError("unknown commissioning state")
    if state in {"completed", "blocked", "failed"}:
        return None
    if state == "not_started":
        return "preflight"
    return STATE_TO_STEP[state]


def mark_checkpoint(
    state: dict[str, Any],
    step: str,
    status: str,
    timestamp: str,
    *,
    summary: str | None = None,
    evidence_refs: list[str] | None = None,
    retry_count: int | None = None,
) -> dict[str, Any]:
    _require_step(step)
    _require_checkpoint_status(status)
    _require_timestamp(timestamp)
    _reject_secret_material({"summary": summary, "evidence_refs": evidence_refs or []})
    if retry_count is not None and (not isinstance(retry_count, int) or isinstance(retry_count, bool) or retry_count < 0):
        raise ValidationError("retry_count must be a non-negative integer")
    updated = deepcopy(state)
    previous = updated.setdefault("checkpoints", {}).get(step, {})
    checkpoint = {
        "status": status,
        "started_at": previous.get("started_at"),
        "completed_at": previous.get("completed_at"),
        "summary": summary,
        "evidence_refs": list(evidence_refs or []),
        "retry_count": retry_count if retry_count is not None else int(previous.get("retry_count", 0)),
    }
    if status == "running" and checkpoint["started_at"] is None:
        checkpoint["started_at"] = timestamp
    if status in {"passed", "blocked", "failed", "skipped"}:
        checkpoint["completed_at"] = timestamp
        if checkpoint["started_at"] is None:
            checkpoint["started_at"] = previous.get("started_at") or timestamp
    updated["checkpoints"][step] = checkpoint
    updated["updated_at"] = timestamp
    return updated


def fail_step(
    state: dict[str, Any],
    step: str,
    timestamp: str,
    *,
    code: str,
    message: str,
    recoverable: bool = True,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    updated = mark_checkpoint(state, step, "failed", timestamp, summary=message, evidence_refs=evidence_refs)
    _reject_secret_material({"code": code, "message": message})
    updated["state"] = "failed"
    updated["current_step"] = step
    updated["last_error"] = {
        "code": _require_string(code, "code"),
        "message": _require_string(message, "message", max_len=512),
        "step": step,
        "recoverable": bool(recoverable),
        "occurred_at": timestamp,
    }
    return updated


def block_step(
    state: dict[str, Any],
    step: str,
    timestamp: str,
    *,
    code: str,
    message: str,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    updated = mark_checkpoint(state, step, "blocked", timestamp, summary=message, evidence_refs=evidence_refs)
    _reject_secret_material({"code": code, "message": message})
    updated["state"] = "blocked"
    updated["current_step"] = step
    updated["last_error"] = {
        "code": _require_string(code, "code"),
        "message": _require_string(message, "message", max_len=512),
        "step": step,
        "recoverable": True,
        "occurred_at": timestamp,
    }
    return updated


def complete_step(
    state: dict[str, Any],
    step: str,
    timestamp: str,
    *,
    summary: str | None = None,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    _require_step(step)
    current_step = state.get("current_step")
    if state.get("state") in SPECIAL_STATES:
        if current_step != step:
            raise ValidationError("blocked or failed commissioning can only resume at the same logical step")
    elif current_step != step and STATE_TO_STEP.get(state.get("state")) != step:
        raise ValidationError("cannot complete a step that is not current")
    updated = mark_checkpoint(state, step, "passed", timestamp, summary=summary, evidence_refs=evidence_refs)
    next_state = _state_after_step(step)
    assert_transition(state, next_state)
    updated["state"] = next_state
    updated["current_step"] = next_expected_step(next_state)
    updated["last_error"] = None
    if next_state == "completed":
        updated["completed_at"] = timestamp
        updated["current_step"] = None
    return updated


def validate_commissioning_state(state: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise ValidationError("commissioning state must be an object")
    _require_exact_keys(
        state,
        {
            "schema_version",
            "commissioning_id",
            "node_id",
            "house_id",
            "state",
            "current_step",
            "started_at",
            "updated_at",
            "completed_at",
            "checkpoints",
            "last_error",
            "acknowledgements",
            "artifacts",
        },
    )
    if state["schema_version"] != SCHEMA_VERSION:
        raise ValidationError("unsupported commissioning schema_version")
    if not isinstance(state["commissioning_id"], str) or not re.match(r"^LNA0-COM-\d{6}$", state["commissioning_id"]):
        raise ValidationError("commissioning_id must look like LNA0-COM-000001")
    if not isinstance(state["node_id"], str) or not NODE_ID_RE.match(state["node_id"]):
        raise ValidationError("node_id must look like LNA0-N-000001")
    if not isinstance(state["house_id"], str) or not HOUSE_ID_RE.match(state["house_id"]):
        raise ValidationError("house_id must look like LNA0-H-000001")
    if state["state"] not in STATES:
        raise ValidationError("unknown commissioning state")
    if state["current_step"] is not None and state["current_step"] not in STEPS:
        raise ValidationError("unknown commissioning current_step")
    _require_timestamp(state["started_at"])
    _require_timestamp(state["updated_at"])
    if state["completed_at"] is not None:
        _require_timestamp(state["completed_at"])
    _validate_checkpoints(state["checkpoints"])
    if state["last_error"] is not None:
        _validate_last_error(state["last_error"])
    _validate_acknowledgements(state["acknowledgements"])
    _validate_artifacts(state["artifacts"])
    _reject_secret_material(state)
    return deepcopy(state)


def _state_value(state: str | dict[str, Any]) -> str:
    return state.get("state") if isinstance(state, dict) else state


def _state_after_step(step: str) -> str:
    index = STEPS.index(step)
    if index == len(STEPS) - 1:
        return "completed"
    return STEP_TO_STATE[STEPS[index + 1]]


def _require_step(step: str) -> None:
    if step not in STEPS:
        raise ValidationError("unknown commissioning step")


def _require_checkpoint_status(status: str) -> None:
    if status not in CHECKPOINT_STATUSES:
        raise ValidationError("unknown checkpoint status")


def _require_timestamp(value: Any) -> str:
    if not isinstance(value, str):
        raise ValidationError("timestamp must be a string")
    try:
        parse_utc_iso(value)
    except Exception as exc:
        raise ValidationError("timestamp must be ISO-8601 with timezone") from exc
    return value


def _require_string(value: Any, field: str, *, max_len: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ValidationError(f"{field} must be a non-empty string")
    return value


def _require_exact_keys(data: dict[str, Any], required: set[str], optional: set[str] | None = None) -> None:
    optional = optional or set()
    keys = set(data)
    missing = required - keys
    extra = keys - required - optional
    if missing:
        raise ValidationError(f"missing fields: {', '.join(sorted(missing))}")
    if extra:
        raise ValidationError(f"unknown fields: {', '.join(sorted(extra))}")


def _validate_checkpoints(checkpoints: Any) -> None:
    if not isinstance(checkpoints, dict):
        raise ValidationError("checkpoints must be an object")
    extra = set(checkpoints) - set(STEPS)
    if extra:
        raise ValidationError(f"unknown checkpoint fields: {', '.join(sorted(extra))}")
    for step, checkpoint in checkpoints.items():
        _require_step(step)
        if not isinstance(checkpoint, dict):
            raise ValidationError("checkpoint must be an object")
        _require_exact_keys(checkpoint, {"status", "started_at", "completed_at", "summary", "evidence_refs", "retry_count"})
        _require_checkpoint_status(checkpoint["status"])
        if checkpoint["started_at"] is not None:
            _require_timestamp(checkpoint["started_at"])
        if checkpoint["completed_at"] is not None:
            _require_timestamp(checkpoint["completed_at"])
        if checkpoint["summary"] is not None:
            _require_string(checkpoint["summary"], "checkpoint.summary", max_len=512)
        if not isinstance(checkpoint["evidence_refs"], list) or not all(isinstance(item, str) and item for item in checkpoint["evidence_refs"]):
            raise ValidationError("checkpoint.evidence_refs must be an array of strings")
        if not isinstance(checkpoint["retry_count"], int) or isinstance(checkpoint["retry_count"], bool) or checkpoint["retry_count"] < 0:
            raise ValidationError("checkpoint.retry_count must be a non-negative integer")


def _validate_last_error(last_error: Any) -> None:
    if not isinstance(last_error, dict):
        raise ValidationError("last_error must be an object or null")
    _require_exact_keys(last_error, {"code", "message", "step", "recoverable", "occurred_at"})
    _require_string(last_error["code"], "last_error.code")
    _require_string(last_error["message"], "last_error.message", max_len=512)
    _require_step(last_error["step"])
    if not isinstance(last_error["recoverable"], bool):
        raise ValidationError("last_error.recoverable must be boolean")
    _require_timestamp(last_error["occurred_at"])


def _validate_acknowledgements(acknowledgements: Any) -> None:
    if not isinstance(acknowledgements, list):
        raise ValidationError("acknowledgements must be an array")
    for item in acknowledgements:
        if not isinstance(item, dict):
            raise ValidationError("acknowledgement must be an object")
        _require_exact_keys(item, {"id", "step", "acknowledged", "acknowledged_at"}, {"note"})
        if not isinstance(item["id"], str) or not re.match(r"^[a-z][a-z0-9_-]*$", item["id"]):
            raise ValidationError("acknowledgement.id is invalid")
        _require_step(item["step"])
        if not isinstance(item["acknowledged"], bool):
            raise ValidationError("acknowledgement.acknowledged must be boolean")
        if item["acknowledged_at"] is not None:
            _require_timestamp(item["acknowledged_at"])
        if "note" in item:
            _require_string(item["note"], "acknowledgement.note", max_len=512)


def _validate_artifacts(artifacts: Any) -> None:
    if not isinstance(artifacts, dict):
        raise ValidationError("artifacts must be an object")
    _require_exact_keys(artifacts, set(ARTIFACT_KEYS))
    for key, value in artifacts.items():
        if value is not None and (not isinstance(value, str) or not value or len(value) > 512):
            raise ValidationError(f"{key} must be a string or null")


def _reject_secret_material(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if SECRET_KEY_RE.search(key_text):
                if key_text in {"secrets_ref", "secret_ref"}:
                    continue
                raise ValidationError("commissioning state must not contain secret-looking keys")
            _reject_secret_material(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_material(item)
    elif isinstance(value, str) and SECRET_VALUE_RE.search(value):
        raise ValidationError("commissioning state must not contain secret-looking values")
