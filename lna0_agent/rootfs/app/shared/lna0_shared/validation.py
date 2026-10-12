"""Strict schema validation without runtime third-party dependencies."""

from __future__ import annotations

import re
from typing import Any

from .constants import ALLOWED_OPERATIONS, HOUSE_ID_PREFIX, NODE_ID_PREFIX, SCHEMA_VERSION
from .security import parse_utc_iso

NODE_ID_RE = re.compile(r"^LNA0-N-\d{6}$")
HOUSE_ID_RE = re.compile(r"^LNA0-H-\d{6}$")
COMMISSIONING_ID_RE = re.compile(r"^LNA0-COM-\d{6}$")
SHA256_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:#=%-]{0,511}$")
SECRET_KEY_RE = re.compile(r"(authorization|auth|credential|password|private[_-]?key|api[_-]?key|secret|token)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]+|\b(?:enr_|node_)[A-Za-z0-9_-]{20,}\b|password\s*[:=]|token\s*[:=]|api[_-]?key\s*[:=]|private[_-]?key\s*[:=]|credential\s*[:=])")


class ValidationError(ValueError):
    """Raised when a request fails strict contract validation."""


def _require_exact_keys(data: dict[str, Any], required: set[str], optional: set[str] | None = None) -> None:
    optional = optional or set()
    keys = set(data)
    missing = required - keys
    extra = keys - required - optional
    if missing:
        raise ValidationError(f"missing fields: {', '.join(sorted(missing))}")
    if extra:
        raise ValidationError(f"unknown fields: {', '.join(sorted(extra))}")


def _require_string(data: dict[str, Any], key: str, *, min_len: int = 1, max_len: int = 256) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not (min_len <= len(value) <= max_len):
        raise ValidationError(f"{key} must be a string")
    return value


def _require_number(data: dict[str, Any], key: str) -> float:
    value = data.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
        raise ValidationError(f"{key} must be a non-negative number")
    return float(value)


def validate_node_id(node_id: str) -> str:
    if not isinstance(node_id, str) or not NODE_ID_RE.match(node_id):
        raise ValidationError(f"node_id must look like {NODE_ID_PREFIX}000001")
    return node_id


def validate_house_id(house_id: str) -> str:
    if not isinstance(house_id, str) or not HOUSE_ID_RE.match(house_id):
        raise ValidationError(f"house_id must look like {HOUSE_ID_PREFIX}000001")
    return house_id


def validate_commissioning_id(commissioning_id: str) -> str:
    if not isinstance(commissioning_id, str) or not COMMISSIONING_ID_RE.match(commissioning_id):
        raise ValidationError("commissioning_id must look like LNA0-COM-000001")
    return commissioning_id


def validate_hostname(hostname: str) -> str:
    if not isinstance(hostname, str) or not re.match(r"^[a-z0-9][a-z0-9-]{0,62}$", hostname):
        raise ValidationError("hostname must be a DNS-safe label")
    return hostname


def validate_enrollment_request(data: dict[str, Any]) -> dict[str, Any]:
    _require_exact_keys(data, {"node_id", "house_id", "hostname", "agent_version", "enrollment_token"})
    return {
        "node_id": validate_node_id(_require_string(data, "node_id")),
        "house_id": validate_house_id(_require_string(data, "house_id")),
        "hostname": validate_hostname(_require_string(data, "hostname")),
        "agent_version": _require_string(data, "agent_version", max_len=32),
        "enrollment_token": _require_string(data, "enrollment_token", min_len=20, max_len=256),
    }


def validate_enrollment_token_create(data: dict[str, Any]) -> dict[str, Any]:
    _require_exact_keys(data, {"node_id", "house_id"}, {"hostname", "ttl_seconds", "display_name"})
    ttl = data.get("ttl_seconds", 900)
    if not isinstance(ttl, int) or ttl < 60 or ttl > 3600:
        raise ValidationError("ttl_seconds must be an integer between 60 and 3600")
    hostname = data.get("hostname")
    if hostname is not None:
        hostname = validate_hostname(hostname)
    return {
        "node_id": validate_node_id(_require_string(data, "node_id")),
        "house_id": validate_house_id(_require_string(data, "house_id")),
        "hostname": hostname,
        "ttl_seconds": ttl,
        "display_name": data.get("display_name") if isinstance(data.get("display_name"), str) else None,
    }


def validate_disk(data: Any) -> dict[str, float]:
    if not isinstance(data, dict):
        raise ValidationError("disk must be an object")
    _require_exact_keys(data, {"total_gb", "used_gb", "free_gb"})
    disk = {
        "total_gb": _require_number(data, "total_gb"),
        "used_gb": _require_number(data, "used_gb"),
        "free_gb": _require_number(data, "free_gb"),
    }
    if disk["used_gb"] > disk["total_gb"]:
        raise ValidationError("disk.used_gb cannot exceed total_gb")
    return disk


def validate_heartbeat(data: dict[str, Any]) -> dict[str, Any]:
    _require_exact_keys(
        data,
        {
            "schema_version",
            "node_id",
            "house_id",
            "hostname",
            "agent_version",
            "golden_base_version",
            "house_config_schema_version",
            "feature_manifest_schema_version",
            "status",
            "haos_version",
            "core_version",
            "disk",
            "timestamp",
        },
    )
    if data["schema_version"] != SCHEMA_VERSION:
        raise ValidationError("unsupported schema_version")
    if data["status"] != "online":
        raise ValidationError("heartbeat status must be online")
    parse_utc_iso(_require_string(data, "timestamp"))
    return {
        "schema_version": SCHEMA_VERSION,
        "node_id": validate_node_id(_require_string(data, "node_id")),
        "house_id": validate_house_id(_require_string(data, "house_id")),
        "hostname": validate_hostname(_require_string(data, "hostname")),
        "agent_version": _require_string(data, "agent_version", max_len=32),
        "golden_base_version": _require_string(data, "golden_base_version", max_len=32),
        "house_config_schema_version": _require_string(data, "house_config_schema_version", max_len=16),
        "feature_manifest_schema_version": _require_string(data, "feature_manifest_schema_version", max_len=16),
        "status": "online",
        "haos_version": _require_string(data, "haos_version", max_len=64),
        "core_version": _require_string(data, "core_version", max_len=64),
        "disk": validate_disk(data["disk"]),
        "timestamp": data["timestamp"],
    }


def validate_operation_create(data: dict[str, Any], node_id: str) -> dict[str, Any]:
    _require_exact_keys(data, {"operation"}, {"params", "expires_in_seconds", "requested_by", "confirm_node_id"})
    operation = _require_string(data, "operation", max_len=64)
    if operation not in ALLOWED_OPERATIONS:
        raise ValidationError("operation is not allowlisted")
    params = data.get("params", {})
    if not isinstance(params, dict):
        raise ValidationError("params must be an object")
    if params:
        raise ValidationError("v0.1 operations do not accept arbitrary parameters")
    expires = data.get("expires_in_seconds", 300)
    if not isinstance(expires, int) or expires < 30 or expires > 900:
        raise ValidationError("expires_in_seconds must be between 30 and 900")
    if operation in {"home_assistant.restart", "node.restart"} and data.get("confirm_node_id") != node_id:
        raise ValidationError("disruptive operation requires confirm_node_id")
    requested_by = data.get("requested_by", "admin@lna0.local")
    if not isinstance(requested_by, str) or len(requested_by) > 256:
        raise ValidationError("requested_by must be a string")
    return {
        "operation": operation,
        "params": {},
        "expires_in_seconds": expires,
        "requested_by": requested_by,
    }


def validate_commissioning_report(data: dict[str, Any]) -> dict[str, Any]:
    _reject_secret_like_material(data)
    _require_exact_keys(
        data,
        {
            "schema_version",
            "commissioning_id",
            "node_id",
            "house_id",
            "status",
            "validation_status",
            "backup_status",
            "backup_ref",
            "handover_status",
            "handover_report_ref",
            "handover_report_hash",
            "completed_at",
            "golden_base_version",
            "agent_version",
            "house_config_hash",
            "feature_manifest_hash",
        },
    )
    if data["schema_version"] != 1:
        raise ValidationError("unsupported schema_version")
    if data["status"] != "completed":
        raise ValidationError("commissioning status must be completed")
    for key in ("validation_status", "backup_status", "handover_status"):
        if data[key] != "passed":
            raise ValidationError(f"{key} must be passed")
    completed_at = _require_string(data, "completed_at", max_len=64)
    try:
        parse_utc_iso(completed_at)
    except Exception as exc:
        raise ValidationError("completed_at must be ISO-8601 with timezone") from exc
    return {
        "schema_version": 1,
        "commissioning_id": validate_commissioning_id(_require_string(data, "commissioning_id")),
        "node_id": validate_node_id(_require_string(data, "node_id")),
        "house_id": validate_house_id(_require_string(data, "house_id")),
        "status": "completed",
        "validation_status": "passed",
        "backup_status": "passed",
        "backup_ref": _require_safe_ref(data, "backup_ref"),
        "handover_status": "passed",
        "handover_report_ref": _require_safe_ref(data, "handover_report_ref"),
        "handover_report_hash": _require_sha256_ref(data, "handover_report_hash"),
        "completed_at": completed_at,
        "golden_base_version": _require_string(data, "golden_base_version", max_len=32),
        "agent_version": _require_string(data, "agent_version", max_len=32),
        "house_config_hash": _require_sha256_ref(data, "house_config_hash"),
        "feature_manifest_hash": _require_sha256_ref(data, "feature_manifest_hash"),
    }


def _require_sha256_ref(data: dict[str, Any], key: str) -> str:
    value = _require_string(data, key, min_len=71, max_len=71)
    if not SHA256_REF_RE.match(value):
        raise ValidationError(f"{key} must be a sha256 content hash")
    return value


def _require_safe_ref(data: dict[str, Any], key: str) -> str:
    value = _require_string(data, key, max_len=512)
    if not SAFE_REF_RE.match(value) or SECRET_VALUE_RE.search(value):
        raise ValidationError(f"{key} must be a safe reference")
    return value


def _reject_secret_like_material(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)) and str(key) not in {"handover_report_hash"}:
                raise ValidationError("request must not contain secret-looking keys")
            _reject_secret_like_material(item)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_like_material(item)
    elif isinstance(value, str) and SECRET_VALUE_RE.search(value):
        raise ValidationError("request must not contain secret-looking values")

