"""Deterministic handover report generation for commissioning."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .validation import ValidationError, validate_house_id, validate_node_id

HANDOVER_SCHEMA_VERSION = 1
SECRET_KEY_RE = re.compile(r"(authorization|auth|credential|password|private[_-]?key|api[_-]?key|secret|token)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]+|\b(?:enr_|node_)[A-Za-z0-9_-]{20,}\b|password\s*[:=]|token\s*[:=]|api[_-]?key\s*[:=])")


def build_handover_report(
    *,
    commissioning_id: str,
    node_id: str,
    house_id: str,
    completed_at: str,
    golden_base_version: str,
    agent_version: str,
    house_config_schema_version: str,
    feature_manifest_schema_version: str,
    house_config_hash: str,
    feature_manifest_hash: str,
    backup_ref: str,
    validation_summary: str,
    completed_steps: list[str],
    acknowledgements: list[dict[str, Any]],
    technical_debt: list[dict[str, Any]],
    status: str,
) -> dict[str, Any]:
    if not re.match(r"^LNA0-COM-\d{6}$", commissioning_id):
        raise ValidationError("commissioning_id must look like LNA0-COM-000001")
    validate_node_id(node_id)
    validate_house_id(house_id)
    if status not in {"ready_for_handover", "completed"}:
        raise ValidationError("handover status is invalid")
    for value, field in (
        (golden_base_version, "golden_base_version"),
        (agent_version, "agent_version"),
        (house_config_schema_version, "house_config_schema_version"),
        (feature_manifest_schema_version, "feature_manifest_schema_version"),
        (backup_ref, "backup_ref"),
        (validation_summary, "validation_summary"),
    ):
        if not isinstance(value, str) or not value:
            raise ValidationError(f"{field} must be a non-empty string")
    for value, field in ((house_config_hash, "house_config_hash"), (feature_manifest_hash, "feature_manifest_hash")):
        if not isinstance(value, str) or not re.match(r"^sha256:[0-9a-f]{64}$", value):
            raise ValidationError(f"{field} must be a sha256 content hash")
    report = {
        "schema_version": HANDOVER_SCHEMA_VERSION,
        "commissioning_id": commissioning_id,
        "node_id": node_id,
        "house_id": house_id,
        "completed_at": completed_at,
        "golden_base_version": golden_base_version,
        "agent_version": agent_version,
        "house_config_schema_version": house_config_schema_version,
        "feature_manifest_schema_version": feature_manifest_schema_version,
        "house_config_hash": house_config_hash,
        "feature_manifest_hash": feature_manifest_hash,
        "backup_ref": backup_ref,
        "validation_summary": validation_summary,
        "completed_steps": list(completed_steps),
        "acknowledgements": deepcopy(acknowledgements),
        "technical_debt": deepcopy(technical_debt),
        "status": status,
    }
    if _contains_secret_material(report):
        raise ValidationError("handover report must not contain secret material")
    return report


def serialize_handover_report(report: dict[str, Any]) -> str:
    payload = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2)
    return payload if payload.endswith("\n") else payload + "\n"


def handover_report_hash(report: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(serialize_handover_report(report).encode("utf-8")).hexdigest()


def write_handover_report(path: str | Path, report: dict[str, Any]) -> str:
    target = Path(path)
    payload = serialize_handover_report(report)
    tmp_name: str | None = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent, delete=False) as tmp:
            tmp_name = tmp.name
            tmp.write(payload)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_name, target)
    except OSError as exc:
        if tmp_name:
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except OSError:
                pass
        raise ValidationError(f"failed to write handover report: {target}") from exc
    return handover_report_hash(report)


def _contains_secret_material(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)) or _contains_secret_material(item):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_secret_material(item) for item in value)
    return isinstance(value, str) and bool(SECRET_VALUE_RE.search(value))
