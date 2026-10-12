"""Pure commissioning validation evaluation for v0.1 handover readiness."""

from __future__ import annotations

import re
from typing import Any

from .validation import ValidationError, validate_house_id, validate_node_id

VALIDATION_STATUSES = {"passed", "blocked", "failed"}
REQUIRED_FIELDS = {
    "identity",
    "preflight_passed",
    "enrollment_passed",
    "house_config_applied",
    "feature_manifest_applied",
    "house_config_hash",
    "feature_manifest_hash",
    "heartbeat_healthy",
    "control_plane_visible",
    "required_manual_checks",
    "technical_debt_checks",
}
SECRET_KEY_RE = re.compile(r"(authorization|auth|credential|password|private[_-]?key|api[_-]?key|secret|token)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]+|\b(?:enr_|node_)[A-Za-z0-9_-]{20,}\b|password\s*[:=]|token\s*[:=]|api[_-]?key\s*[:=])")
SAFE_DEBT_GATE = "first-production-field-release"


def evaluate_commissioning_validation(facts: dict[str, Any]) -> dict[str, Any]:
    """Evaluate injected validation facts without OS, network, or Control Plane I/O."""

    if not isinstance(facts, dict):
        return _result("failed", [_check("contract", "failed", "Validation facts must be an object.")], [])

    checks: list[dict[str, Any]] = []
    missing = sorted(REQUIRED_FIELDS - set(facts))
    extra = sorted(set(facts) - REQUIRED_FIELDS)
    if missing:
        checks.append(_check("contract.required_fields", "failed", f"Missing validation facts: {', '.join(missing)}."))
    if extra:
        checks.append(_check("contract.known_fields", "failed", f"Unknown validation facts: {', '.join(extra)}."))
    if _contains_secret_material(facts):
        checks.append(_check("contract.no_secrets", "failed", "Validation facts must not include secret material."))

    checks.extend(
        [
            _identity_check(facts.get("identity")),
            _bool_check(facts, "preflight_passed", "preflight.passed", "Preflight passed."),
            _bool_check(facts, "enrollment_passed", "enrollment.passed", "Enrollment passed."),
            _bool_check(facts, "house_config_applied", "house_config.applied", "House Config applied."),
            _bool_check(facts, "feature_manifest_applied", "features.applied", "Feature Manifest applied."),
            _hash_check(facts, "house_config_hash", "house_config.hash"),
            _hash_check(facts, "feature_manifest_hash", "features.hash"),
            _bool_check(facts, "heartbeat_healthy", "heartbeat.healthy", "Heartbeat is healthy."),
            _bool_check(facts, "control_plane_visible", "control_plane.visible", "Node is visible in Control Plane."),
        ]
    )

    manual_checks, required_acknowledgements = _manual_checks(facts.get("required_manual_checks"))
    checks.extend(manual_checks)
    checks.extend(_technical_debt_checks(facts.get("technical_debt_checks")))

    if any(check["status"] == "failed" for check in checks):
        status = "failed"
    elif any(check["status"] == "blocked" for check in checks):
        status = "blocked"
    else:
        status = "passed"
    return _result(status, checks, required_acknowledgements)


def _result(status: str, checks: list[dict[str, Any]], required_acknowledgements: list[str]) -> dict[str, Any]:
    if status == "passed":
        summary = "Commissioning validation passed."
    elif status == "blocked":
        summary = "Commissioning validation is blocked by missing evidence or acknowledgements."
    else:
        summary = "Commissioning validation failed because supplied facts are invalid."
    return {"status": status, "checks": checks, "summary": summary, "required_acknowledgements": required_acknowledgements}


def _check(check_id: str, status: str, message: str, evidence_refs: list[str] | None = None) -> dict[str, Any]:
    return {"id": check_id, "status": status, "message": message, "evidence_refs": list(evidence_refs or [])}


def _identity_check(identity: Any) -> dict[str, Any]:
    if not isinstance(identity, dict):
        return _check("identity.valid", "failed", "identity must be an object.")
    try:
        validate_node_id(identity.get("node_id"))
        validate_house_id(identity.get("house_id"))
    except ValidationError:
        return _check("identity.valid", "failed", "identity node_id and house_id must match canonical patterns.")
    hostname = identity.get("hostname")
    if not isinstance(hostname, str) or not hostname:
        return _check("identity.valid", "failed", "identity hostname must be present.")
    return _check("identity.valid", "passed", "Identity is valid.", ["identity"])


def _bool_check(facts: dict[str, Any], field: str, check_id: str, passed_message: str) -> dict[str, Any]:
    value = facts.get(field)
    if not isinstance(value, bool):
        return _check(check_id, "failed", f"{field} must be a boolean.")
    if not value:
        return _check(check_id, "blocked", f"{field} evidence is missing or not passing.", [f"fact:{field}"])
    return _check(check_id, "passed", passed_message, [f"fact:{field}"])


def _hash_check(facts: dict[str, Any], field: str, check_id: str) -> dict[str, Any]:
    value = facts.get(field)
    if value is None or value == "":
        return _check(check_id, "blocked", f"{field} evidence is missing.", [f"fact:{field}"])
    if not isinstance(value, str) or not re.match(r"^sha256:[0-9a-f]{64}$", value):
        return _check(check_id, "failed", f"{field} must be a sha256 content hash.")
    return _check(check_id, "passed", f"{field} is present.", [value])


def _manual_checks(value: Any) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(value, list):
        return [_check("manual.contract", "failed", "required_manual_checks must be an array.")], []
    checks: list[dict[str, Any]] = []
    required_acknowledgements: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            checks.append(_check("manual.contract", "failed", "manual check must be an object."))
            continue
        check_id = item.get("id")
        acknowledged = item.get("acknowledged")
        if not isinstance(check_id, str) or not re.match(r"^[a-z][a-z0-9_-]*$", check_id):
            checks.append(_check("manual.contract", "failed", "manual check id is invalid."))
            continue
        if check_id in seen:
            checks.append(_check(f"manual.{check_id}", "failed", "manual check id is duplicated."))
            continue
        seen.add(check_id)
        if not isinstance(acknowledged, bool):
            checks.append(_check(f"manual.{check_id}", "failed", "manual check acknowledged must be boolean."))
        elif acknowledged:
            checks.append(_check(f"manual.{check_id}", "passed", "Manual check acknowledged.", [f"ack:{check_id}"]))
        else:
            required_acknowledgements.append(check_id)
            checks.append(_check(f"manual.{check_id}", "blocked", "Manual check must be acknowledged.", [f"ack:{check_id}"]))
    return checks, required_acknowledgements


def _technical_debt_checks(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return [_check("technical_debt.contract", "failed", "technical_debt_checks must be an array.")]
    checks: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            checks.append(_check("technical_debt.contract", "failed", "technical debt check must be an object."))
            continue
        check_id = item.get("id")
        required_before = item.get("required_before")
        status = item.get("status", "open")
        if not isinstance(check_id, str) or not re.match(r"^[a-z][a-z0-9_-]*$", check_id):
            checks.append(_check("technical_debt.contract", "failed", "technical debt id is invalid."))
        elif status == "passed":
            checks.append(_check(f"technical_debt.{check_id}", "passed", "Technical debt check is closed.", [f"debt:{check_id}"]))
        elif required_before == SAFE_DEBT_GATE:
            checks.append(_check(f"technical_debt.{check_id}", "passed", "Technical debt may remain open until first production field release.", [f"debt:{check_id}"]))
        else:
            checks.append(_check(f"technical_debt.{check_id}", "blocked", "Technical debt gate must be resolved before handover.", [f"debt:{check_id}"]))
    return checks


def _contains_secret_material(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)) or _contains_secret_material(item):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_secret_material(item) for item in value)
    return isinstance(value, str) and bool(SECRET_VALUE_RE.search(value))
