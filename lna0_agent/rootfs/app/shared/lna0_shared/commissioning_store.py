"""File-backed persistence for commissioning runtime state."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .commissioning import validate_commissioning_state
from .validation import ValidationError


class CommissioningStoreError(RuntimeError):
    """Raised when commissioning state cannot be persisted or loaded."""


class CommissioningStateStore:
    @staticmethod
    def exists(path: str | Path) -> bool:
        return Path(path).exists()

    @staticmethod
    def load(path: str | Path) -> dict[str, Any]:
        target = Path(path)
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise CommissioningStoreError(f"commissioning state not found: {target}") from exc
        except json.JSONDecodeError as exc:
            raise CommissioningStoreError(f"commissioning state is not valid JSON/YAML-safe data: {target}") from exc
        try:
            return validate_commissioning_state(data)
        except ValidationError as exc:
            raise CommissioningStoreError(f"invalid commissioning state: {exc}") from exc

    @staticmethod
    def save(path: str | Path, state: dict[str, Any]) -> None:
        target = Path(path)
        try:
            valid = validate_commissioning_state(state)
        except ValidationError as exc:
            raise CommissioningStoreError(f"invalid commissioning state: {exc}") from exc
        parent = target.parent
        payload = json.dumps(valid, ensure_ascii=False, sort_keys=True, indent=2)
        if not payload.endswith("\n"):
            payload += "\n"
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
            raise CommissioningStoreError(f"failed to save commissioning state: {target}") from exc
