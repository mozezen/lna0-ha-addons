"""Safe House Config and Feature Manifest application helpers."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

try:
    import yaml
    from jsonschema import Draft202012Validator
except ImportError as exc:  # pragma: no cover - exercised only in missing dev environments.
    yaml = None
    Draft202012Validator = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None

from .constants import FEATURE_MANIFEST_SCHEMA_VERSION, HOUSE_CONFIG_SCHEMA_VERSION
from .validation import ValidationError, validate_house_id, validate_node_id

ROOT = Path(__file__).resolve().parents[2]
HOUSE_CONFIG_SCHEMA_PATH = ROOT / "shared" / "schemas" / "house-config.schema.json"
FEATURE_MANIFEST_SCHEMA_PATH = ROOT / "shared" / "schemas" / "feature-manifest.schema.json"

APPLY_STATUSES = {"applied", "unchanged", "blocked", "failed"}
SECRET_KEY_RE = re.compile(r"(authorization|credential|password|private[_-]?key|api[_-]?key|secret|token)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(
    r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]+|\b(?:enr_|node_)[A-Za-z0-9_-]{20,}\b|password\s*[:=]|token\s*[:=]|api[_-]?key\s*[:=])"
)


@dataclass(frozen=True)
class ConfigApplyResult:
    success: bool
    status: str
    path_ref: str | None = None
    content_hash: str | None = None
    message: str = ""
    recoverable: bool = False

    def __post_init__(self) -> None:
        if self.status not in APPLY_STATUSES:
            raise ValidationError("unknown config apply status")
        if self.success and self.status not in {"applied", "unchanged"}:
            raise ValidationError("successful apply result must be applied or unchanged")
        if not self.success and self.status in {"applied", "unchanged"}:
            raise ValidationError("unsuccessful apply result cannot be applied or unchanged")
        if self.path_ref is not None and not self.path_ref:
            raise ValidationError("path_ref must be a non-empty string or null")
        if self.content_hash is not None and not re.match(r"^sha256:[0-9a-f]{64}$", self.content_hash):
            raise ValidationError("content_hash must be sha256:<hex> or null")


def validate_house_config(data: dict[str, Any], *, house_id: str, node_id: str) -> dict[str, Any]:
    """Validate House Config against the canonical schema and commissioning identity."""

    valid = _validate_with_schema(data, HOUSE_CONFIG_SCHEMA_PATH)
    if str(valid.get("schema_version")) != HOUSE_CONFIG_SCHEMA_VERSION:
        raise ValidationError("unsupported House Config schema_version")
    house = valid.get("house", {})
    if house.get("house_id") != validate_house_id(house_id):
        raise ValidationError("House Config house_id does not match commissioning session")
    if house.get("node_id") != validate_node_id(node_id):
        raise ValidationError("House Config node_id does not match commissioning session")
    _reject_secret_material(valid, allowed_ref_paths={("secrets",), ("secrets", "refs")})
    return valid


def validate_feature_manifest(data: dict[str, Any]) -> dict[str, Any]:
    """Validate Feature Manifest against the canonical schema."""

    valid = _validate_with_schema(data, FEATURE_MANIFEST_SCHEMA_PATH)
    if str(valid.get("schema_version")) != FEATURE_MANIFEST_SCHEMA_VERSION:
        raise ValidationError("unsupported Feature Manifest schema_version")
    _reject_secret_material(valid, allowed_ref_paths=set())
    return valid


def apply_house_config(
    data: dict[str, Any],
    *,
    target_path: str | Path,
    house_id: str,
    node_id: str,
    replace_existing: bool = False,
) -> ConfigApplyResult:
    try:
        valid = validate_house_config(data, house_id=house_id, node_id=node_id)
        return _apply_config(valid, target_path=target_path, label="House Config", replace_existing=replace_existing)
    except ValidationError as exc:
        return ConfigApplyResult(False, "failed", message=str(exc), recoverable=False)


def apply_feature_manifest(
    data: dict[str, Any],
    *,
    target_path: str | Path,
    replace_existing: bool = False,
) -> ConfigApplyResult:
    try:
        valid = validate_feature_manifest(data)
        return _apply_config(valid, target_path=target_path, label="Feature Manifest", replace_existing=replace_existing)
    except ValidationError as exc:
        return ConfigApplyResult(False, "failed", message=str(exc), recoverable=False)


def inspect_applied_config(target_path: str | Path) -> ConfigApplyResult:
    target = Path(target_path)
    if not target.exists():
        return ConfigApplyResult(False, "blocked", path_ref=str(target), message="Config file is not applied.", recoverable=True)
    try:
        data = _load_existing_data(target)
        content_hash = stable_content_hash(data)
    except ValidationError as exc:
        return ConfigApplyResult(False, "failed", path_ref=str(target), message=str(exc), recoverable=False)
    return ConfigApplyResult(True, "unchanged", path_ref=str(target), content_hash=content_hash, message="Config file is present.")


def stable_content_hash(data: dict[str, Any]) -> str:
    payload = _deterministic_payload(data)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _apply_config(data: dict[str, Any], *, target_path: str | Path, label: str, replace_existing: bool) -> ConfigApplyResult:
    target = Path(target_path)
    payload = _deterministic_payload(data)
    content_hash = stable_content_hash(data)
    existed = target.exists()
    if existed:
        existing = _load_existing_data(target)
        existing_hash = stable_content_hash(existing)
        if existing_hash == content_hash:
            return ConfigApplyResult(True, "unchanged", str(target), content_hash, f"{label} already applied.")
        if not replace_existing:
            return ConfigApplyResult(
                False,
                "blocked",
                str(target),
                existing_hash,
                f"Existing {label} differs; explicit replacement is required.",
                True,
            )
    _atomic_write(target, payload)
    action = "replaced" if replace_existing and existed else "applied"
    return ConfigApplyResult(True, "applied", str(target), content_hash, f"{label} {action}.")


def _validate_with_schema(data: dict[str, Any], schema_path: Path) -> dict[str, Any]:
    if _IMPORT_ERROR is not None or Draft202012Validator is None:
        raise ValidationError(f"missing schema validation dependency: {_IMPORT_ERROR}")
    if not isinstance(data, dict):
        raise ValidationError("config payload must be an object")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "<root>"
        raise ValidationError(f"schema validation failed at {location}: {first.message}")
    return deepcopy(data)


def _deterministic_payload(data: dict[str, Any]) -> str:
    payload = json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2)
    return payload if payload.endswith("\n") else payload + "\n"


def _load_existing_data(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        if yaml is None:
            raise ValidationError("existing config is not deterministic JSON and PyYAML is unavailable")
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValidationError("existing config payload must be an object")
    return data


def _atomic_write(target: Path, payload: str) -> None:
    parent = target.parent
    tmp_name: str | None = None
    try:
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=parent, delete=False) as tmp:
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
        raise ValidationError(f"failed to write config file: {target}") from exc


def _reject_secret_material(value: Any, *, allowed_ref_paths: set[tuple[str, ...]], path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            child_path = path + (key_text,)
            if SECRET_KEY_RE.search(key_text) and child_path not in allowed_ref_paths:
                raise ValidationError("config payload must not contain secret-looking keys")
            _reject_secret_material(item, allowed_ref_paths=allowed_ref_paths, path=child_path)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_material(item, allowed_ref_paths=allowed_ref_paths, path=path)
    elif isinstance(value, str):
        if path in allowed_ref_paths:
            return
        if SECRET_VALUE_RE.search(value):
            raise ValidationError("config payload must not contain secret-looking values")
