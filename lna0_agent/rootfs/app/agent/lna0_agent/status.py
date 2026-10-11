"""Sanitized Agent status projection for Home Assistant commissioning."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from lna0_shared.constants import AGENT_VERSION, GOLDEN_BASE_VERSION
from lna0_shared.security import utc_iso
from lna0_shared.validation import validate_house_id, validate_node_id

STATUS_SCHEMA_VERSION = 1
DEFAULT_STATUS_PATH = Path("/config/lna0/agent-status.json")
ALLOWED_STATUS_KEYS = {
    "schema_version",
    "status",
    "node_id",
    "house_id",
    "credential_status",
    "agent_version",
    "golden_base_version",
    "updated_at",
}
ALLOWED_STATUSES = {"enrolled", "not_enrolled", "unavailable"}
ALLOWED_CREDENTIAL_STATUSES = {"active", "missing", "unknown"}


def build_status(
    *,
    status: str,
    node_id: str,
    house_id: str,
    credential_status: str,
    updated_at: str | None = None,
    agent_version: str = AGENT_VERSION,
    golden_base_version: str = GOLDEN_BASE_VERSION,
) -> dict[str, Any]:
    """Build and validate the non-secret status document."""

    document = {
        "schema_version": STATUS_SCHEMA_VERSION,
        "status": status,
        "node_id": validate_node_id(node_id),
        "house_id": validate_house_id(house_id),
        "credential_status": credential_status,
        "agent_version": _non_empty_string(agent_version, "agent_version"),
        "golden_base_version": _non_empty_string(golden_base_version, "golden_base_version"),
        "updated_at": updated_at or utc_iso(),
    }
    validate_status(document)
    return document


def validate_status(document: dict[str, Any]) -> dict[str, Any]:
    """Reject malformed or secret-looking status documents."""

    if not isinstance(document, dict):
        raise ValueError("status document must be an object")
    if set(document) != ALLOWED_STATUS_KEYS:
        raise ValueError("status document schema mismatch")
    for key in document:
        if key not in ALLOWED_STATUS_KEYS:
            raise ValueError("status document contains secret-looking keys")
    if document["schema_version"] != STATUS_SCHEMA_VERSION:
        raise ValueError("unsupported status schema_version")
    if document["status"] not in ALLOWED_STATUSES:
        raise ValueError("unsupported status")
    if document["credential_status"] not in ALLOWED_CREDENTIAL_STATUSES:
        raise ValueError("unsupported credential_status")
    validate_node_id(document["node_id"])
    validate_house_id(document["house_id"])
    _non_empty_string(document["agent_version"], "agent_version")
    _non_empty_string(document["golden_base_version"], "golden_base_version")
    _non_empty_string(document["updated_at"], "updated_at")
    for value in document.values():
        if isinstance(value, str):
            for part in ("enr_", "node_", "Bearer ", "SUPERVISOR_TOKEN"):
                if part in value:
                    raise ValueError("status document contains secret-looking values")
    return dict(document)


def write_status(path: str | Path, document: dict[str, Any]) -> None:
    """Atomically write sanitized status JSON for HA to consume."""

    path = Path(path)
    validated = validate_status(document)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    payload = json.dumps(validated, sort_keys=True, separators=(",", ":")) + "\n"
    with temp.open("w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temp, 0o644)
    temp.replace(path)
    os.chmod(path, 0o644)


def publish_status(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    """Build, write, and return the sanitized Agent status."""

    document = build_status(**kwargs)
    write_status(path, document)
    return document


def _non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()
