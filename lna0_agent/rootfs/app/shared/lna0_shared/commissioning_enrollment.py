"""Control Plane enrollment boundary for commissioning."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Protocol

from .validation import ValidationError, validate_hostname, validate_house_id, validate_node_id


@dataclass(frozen=True)
class EnrollmentRequest:
    commissioning_id: str
    node_id: str
    house_id: str
    hostname: str
    agent_version: str
    golden_base_version: str
    house_config_schema_version: str | None = None
    feature_manifest_schema_version: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)


@dataclass(frozen=True)
class EnrollmentResult:
    success: bool
    status: str
    node_ref: str | None = None
    credential_ref: str | None = None
    message: str = ""
    recoverable: bool = False

    def __post_init__(self) -> None:
        if self.status not in {"enrolled", "already_enrolled", "blocked", "failed"}:
            raise ValidationError("unknown enrollment status")
        if self.success and self.status not in {"enrolled", "already_enrolled"}:
            raise ValidationError("successful enrollment result must be enrolled or already_enrolled")
        if not self.success and self.status in {"enrolled", "already_enrolled"}:
            raise ValidationError("unsuccessful enrollment result cannot be enrolled")
        if self.credential_ref is not None and not self.credential_ref.strip():
            raise ValidationError("credential_ref must be a non-empty string or null")
        if self.node_ref is not None and not self.node_ref.strip():
            raise ValidationError("node_ref must be a non-empty string or null")


class EnrollmentClient(Protocol):
    def enroll(self, request: EnrollmentRequest) -> EnrollmentResult:
        """Enroll a node with the Control Plane."""


def build_enrollment_request(
    *,
    commissioning_id: str,
    node_id: str,
    house_id: str,
    hostname: str,
    agent_version: str,
    golden_base_version: str,
    house_config_schema_version: str | None = None,
    feature_manifest_schema_version: str | None = None,
) -> EnrollmentRequest:
    if not isinstance(commissioning_id, str) or not re.match(r"^LNA0-COM-\d{6}$", commissioning_id):
        raise ValidationError("commissioning_id must look like LNA0-COM-000001")
    if not isinstance(hostname, str):
        raise ValidationError("hostname must be a DNS-safe label")
    hostname = validate_hostname(hostname.strip().lower())
    if not isinstance(agent_version, str) or not agent_version.strip():
        raise ValidationError("agent_version must be a non-empty string")
    if not isinstance(golden_base_version, str) or not golden_base_version.strip():
        raise ValidationError("golden_base_version must be a non-empty string")
    if house_config_schema_version is not None and not str(house_config_schema_version).strip():
        raise ValidationError("house_config_schema_version must be a non-empty string or null")
    if feature_manifest_schema_version is not None and not str(feature_manifest_schema_version).strip():
        raise ValidationError("feature_manifest_schema_version must be a non-empty string or null")
    return EnrollmentRequest(
        commissioning_id=commissioning_id,
        node_id=validate_node_id(node_id),
        house_id=validate_house_id(house_id),
        hostname=hostname,
        agent_version=agent_version.strip(),
        golden_base_version=golden_base_version.strip(),
        house_config_schema_version=house_config_schema_version,
        feature_manifest_schema_version=feature_manifest_schema_version,
    )
