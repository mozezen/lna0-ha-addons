"""Hardcoded allowlisted Supervisor operation adapter."""

from __future__ import annotations

from typing import Any, Callable

from lna0_shared.constants import ALLOWED_OPERATIONS
from lna0_shared.security import now_utc, parse_utc_iso
from lna0_shared.validation import ValidationError, validate_node_id

from .supervisor import SupervisorClient


class OperationAdapter:
    def __init__(self, supervisor: SupervisorClient):
        self.supervisor = supervisor
        self._handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "diagnostic.snapshot": self.diagnostic_snapshot,
            "backup.create": self.backup_create,
            "home_assistant.restart": self.home_assistant_restart,
            "node.restart": self.node_restart,
            "inventory.refresh": self.inventory_refresh,
            "health.refresh": self.health_refresh,
        }

    def dispatch(self, operation: dict[str, Any], local_node_id: str) -> dict[str, Any]:
        required = {"operation_id", "node_id", "name", "params", "issued_at", "expires_at", "nonce"}
        extra = set(operation) - required
        missing = required - set(operation)
        if extra or missing:
            raise ValidationError("operation schema mismatch")
        if operation["name"] not in ALLOWED_OPERATIONS:
            raise ValidationError("unknown operation rejected")
        if validate_node_id(operation["node_id"]) != local_node_id:
            raise ValidationError("node ID mismatch")
        if parse_utc_iso(operation["expires_at"]) <= now_utc():
            raise ValidationError("expired operation rejected")
        if operation["params"] != {}:
            raise ValidationError("v0.1 operation params must be empty")
        return self._handlers[operation["name"]](operation)

    def diagnostic_snapshot(self, _: dict[str, Any]) -> dict[str, Any]:
        return {
            "supervisor": self._safe_get("/supervisor/info"),
            "core": self._safe_get("/core/info"),
            "host": self._safe_get("/host/info"),
            "resolution": self._safe_get("/resolution/info"),
        }

    def backup_create(self, _: dict[str, Any]) -> dict[str, Any]:
        return self.supervisor.post("/backups/new/full", {"name": "LNA0 controlled backup"})

    def home_assistant_restart(self, _: dict[str, Any]) -> dict[str, Any]:
        return self.supervisor.post("/core/restart")

    def node_restart(self, _: dict[str, Any]) -> dict[str, Any]:
        return self.supervisor.post("/host/reboot")

    def inventory_refresh(self, _: dict[str, Any]) -> dict[str, Any]:
        return {
            "supervisor": self._safe_get("/supervisor/info"),
            "core": self._safe_get("/core/info"),
            "host": self._safe_get("/host/info"),
            "network": self._safe_get("/network/info"),
        }

    def health_refresh(self, _: dict[str, Any]) -> dict[str, Any]:
        return {
            "supervisor": self._safe_get("/supervisor/info"),
            "core": self._safe_get("/core/info"),
            "host": self._safe_get("/host/info"),
            "resolution": self._safe_get("/resolution/info"),
        }

    def _safe_get(self, path: str) -> dict[str, Any]:
        try:
            return self.supervisor.get(path)
        except Exception as exc:
            return {"error": type(exc).__name__}

