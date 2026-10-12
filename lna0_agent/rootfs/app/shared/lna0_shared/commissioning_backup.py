"""Backup client boundary for commissioning handover."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Protocol

from .validation import ValidationError, validate_house_id, validate_node_id


@dataclass(frozen=True)
class BackupRequest:
    commissioning_id: str
    node_id: str
    house_id: str
    reason: str = "commissioning-handover"
    metadata_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not re.match(r"^LNA0-COM-\d{6}$", self.commissioning_id):
            raise ValidationError("commissioning_id must look like LNA0-COM-000001")
        validate_node_id(self.node_id)
        validate_house_id(self.house_id)
        if self.reason != "commissioning-handover":
            raise ValidationError("backup reason must be commissioning-handover")
        if not all(isinstance(item, str) and item for item in self.metadata_refs):
            raise ValidationError("metadata_refs must be strings")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class BackupResult:
    success: bool
    status: str
    backup_ref: str | None = None
    message: str = ""
    recoverable: bool = False

    def __post_init__(self) -> None:
        if self.status not in {"created", "already_exists", "blocked", "failed"}:
            raise ValidationError("unknown backup status")
        if self.success and self.status not in {"created", "already_exists"}:
            raise ValidationError("successful backup result must be created or already_exists")
        if not self.success and self.status in {"created", "already_exists"}:
            raise ValidationError("unsuccessful backup result cannot be created")
        if self.backup_ref is not None and not self.backup_ref:
            raise ValidationError("backup_ref must be a non-empty string or null")


class BackupClient(Protocol):
    def create_backup(self, request: BackupRequest) -> BackupResult:
        """Create or find a commissioning handover backup."""
