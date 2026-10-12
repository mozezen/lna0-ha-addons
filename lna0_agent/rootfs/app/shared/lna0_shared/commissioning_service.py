"""Application service for the v0.1 commissioning backend slices."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from .commissioning import SCHEMA_VERSION, block_step, complete_step, fail_step, mark_checkpoint, validate_commissioning_state
from .commissioning_backup import BackupClient, BackupRequest, BackupResult
from .commissioning_config_apply import (
    ConfigApplyResult,
    apply_feature_manifest as apply_feature_manifest_file,
    apply_house_config as apply_house_config_file,
)
from .commissioning_enrollment import EnrollmentClient, EnrollmentResult, build_enrollment_request
from .commissioning_handover import build_handover_report, write_handover_report
from .commissioning_preflight import evaluate_preflight
from .commissioning_store import CommissioningStateStore
from .commissioning_validation import evaluate_commissioning_validation
from .validation import ValidationError, validate_hostname, validate_house_id, validate_node_id

COMMISSIONING_STEPS = (
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
IDENTITY_HOSTNAME_PREFIX = "commissioning-identity:hostname="
SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,511}$")
SECRET_REF_RE = re.compile(r"(?i)(bearer\s+|password\s*[:=]|token\s*[:=]|api[_-]?key\s*[:=]|private[_-]?key|credential)")


class CommissioningServiceError(RuntimeError):
    """Raised when commissioning orchestration cannot proceed."""


class CommissioningSessionService:
    def __init__(self, state_path: str | Path, store: type[CommissioningStateStore] = CommissioningStateStore) -> None:
        self.state_path = Path(state_path)
        self.store = store

    def start_commissioning(
        self,
        *,
        commissioning_id: str,
        node_id: str,
        house_id: str,
        timestamp: str,
    ) -> dict[str, Any]:
        node_id = validate_node_id(node_id)
        house_id = validate_house_id(house_id)
        if not isinstance(commissioning_id, str) or not re.match(r"^LNA0-COM-\d{6}$", commissioning_id):
            raise CommissioningServiceError("commissioning_id must look like LNA0-COM-000001")
        if self.store.exists(self.state_path):
            state = self.resume_commissioning()
            if (
                state["commissioning_id"] != commissioning_id
                or state["node_id"] != node_id
                or state["house_id"] != house_id
            ):
                raise CommissioningServiceError("existing commissioning state identity conflicts with start request")
            return state

        state = validate_commissioning_state(
            {
                "schema_version": SCHEMA_VERSION,
                "commissioning_id": commissioning_id,
                "node_id": node_id,
                "house_id": house_id,
                "state": "preflight",
                "current_step": "preflight",
                "started_at": timestamp,
                "updated_at": timestamp,
                "completed_at": None,
                "checkpoints": {},
                "last_error": None,
                "acknowledgements": [],
                "artifacts": {
                    "house_config_ref": None,
                    "feature_manifest_ref": None,
                    "overrides_ref": None,
                    "validation_report_ref": None,
                    "backup_ref": None,
                    "handover_report_ref": None,
                },
            }
        )
        self.store.save(self.state_path, state)
        return state

    def resume_commissioning(self) -> dict[str, Any]:
        return self.store.load(self.state_path)

    def run_preflight(self, facts: dict[str, Any], *, timestamp: str) -> dict[str, Any]:
        state = self.resume_commissioning()
        self._require_step_available(state, "preflight")
        result = evaluate_preflight(facts)
        evidence_refs = [f"preflight:{check['id']}" for check in result["checks"] if check["status"] != "passed"]
        if result["status"] == "passed":
            updated = complete_step(state, "preflight", timestamp, summary=result["summary"], evidence_refs=["preflight:passed"])
        elif result["status"] == "blocked":
            updated = block_step(
                state,
                "preflight",
                timestamp,
                code="preflight_blocked",
                message=result["summary"],
                evidence_refs=evidence_refs,
            )
        else:
            updated = fail_step(
                state,
                "preflight",
                timestamp,
                code="preflight_failed",
                message=result["summary"],
                recoverable=False,
                evidence_refs=evidence_refs,
            )
        self.store.save(self.state_path, updated)
        return {"state": updated, "preflight": result, "progress": get_progress(updated)}

    def establish_identity(self, *, hostname: str, timestamp: str) -> dict[str, Any]:
        state = self.resume_commissioning()
        if not isinstance(hostname, str):
            raise CommissioningServiceError("hostname must be a DNS-safe label")
        hostname = validate_hostname(hostname.strip().lower())
        existing_hostname = _hostname_from_identity_checkpoint(state)
        if existing_hostname is not None and existing_hostname != hostname:
            raise CommissioningServiceError("persisted commissioning identity cannot change hostname")
        if state.get("node_id") != validate_node_id(state.get("node_id")) or state.get("house_id") != validate_house_id(state.get("house_id")):
            raise CommissioningServiceError("persisted commissioning identity is invalid")
        if state.get("current_step") == "identity" or state.get("state") in {"blocked", "failed"} and state.get("current_step") == "identity":
            identity_evidence = [f"{IDENTITY_HOSTNAME_PREFIX}{hostname}"]
            updated = complete_step(
                state,
                "identity",
                timestamp,
                summary=f"Identity verified for hostname {hostname}.",
                evidence_refs=identity_evidence,
            )
            updated = complete_step(
                updated,
                "network",
                timestamp,
                summary="Network readiness satisfied by passed preflight checks for this vertical slice.",
                evidence_refs=["preflight:network_ready", "preflight:control_plane_reachable"],
            )
            self.store.save(self.state_path, updated)
            return {"state": updated, "progress": get_progress(updated)}
        if existing_hostname == hostname:
            return {"state": state, "progress": get_progress(state)}
        raise CommissioningServiceError("identity cannot be established before preflight passes")

    def run_enrollment(
        self,
        client: EnrollmentClient,
        *,
        timestamp: str,
        agent_version: str,
        golden_base_version: str,
        house_config_schema_version: str | None = None,
        feature_manifest_schema_version: str | None = None,
    ) -> dict[str, Any]:
        state = self.resume_commissioning()
        self._require_enrollment_prerequisites(state)
        hostname = _hostname_from_identity_checkpoint(state)
        if hostname is None:
            raise CommissioningServiceError("identity checkpoint does not include hostname evidence")
        request = build_enrollment_request(
            commissioning_id=state["commissioning_id"],
            node_id=state["node_id"],
            house_id=state["house_id"],
            hostname=hostname,
            agent_version=agent_version,
            golden_base_version=golden_base_version,
            house_config_schema_version=house_config_schema_version,
            feature_manifest_schema_version=feature_manifest_schema_version,
        )
        result = client.enroll(request)
        if not isinstance(result, EnrollmentResult):
            raise CommissioningServiceError("enrollment client returned an invalid result")
        if result.success:
            updated = self.mark_enrollment_success(result, timestamp=timestamp)
        elif result.recoverable:
            updated = self.mark_enrollment_blocked(result, timestamp=timestamp)
        else:
            updated = self.mark_enrollment_failed(result, timestamp=timestamp)
        return {"state": updated, "enrollment": result, "progress": get_progress(updated)}

    def mark_enrollment_success(self, result: EnrollmentResult, *, timestamp: str) -> dict[str, Any]:
        state = self.resume_commissioning()
        self._require_enrollment_prerequisites(state)
        evidence_refs = [item for item in (result.node_ref, result.credential_ref) if item]
        summary = result.message or f"Control Plane enrollment {result.status}."
        updated = complete_step(state, "enrollment", timestamp, summary=summary, evidence_refs=evidence_refs)
        self.store.save(self.state_path, updated)
        return updated

    def mark_enrollment_blocked(self, result: EnrollmentResult, *, timestamp: str) -> dict[str, Any]:
        state = self.resume_commissioning()
        self._require_enrollment_prerequisites(state)
        updated = block_step(
            state,
            "enrollment",
            timestamp,
            code="enrollment_blocked",
            message=result.message or "Control Plane enrollment is temporarily blocked.",
            evidence_refs=[result.node_ref] if result.node_ref else [],
        )
        self.store.save(self.state_path, updated)
        return updated

    def mark_enrollment_failed(self, result: EnrollmentResult, *, timestamp: str) -> dict[str, Any]:
        state = self.resume_commissioning()
        self._require_enrollment_prerequisites(state)
        updated = fail_step(
            state,
            "enrollment",
            timestamp,
            code="enrollment_failed",
            message=result.message or "Control Plane enrollment failed.",
            recoverable=False,
            evidence_refs=[result.node_ref] if result.node_ref else [],
        )
        self.store.save(self.state_path, updated)
        return updated

    def apply_house_config(
        self,
        config: dict[str, Any],
        *,
        target_path: str | Path,
        timestamp: str,
        replace_existing: bool = False,
    ) -> dict[str, Any]:
        state = self.resume_commissioning()
        self._require_house_config_prerequisites(state)
        result = apply_house_config_file(
            config,
            target_path=target_path,
            house_id=state["house_id"],
            node_id=state["node_id"],
            replace_existing=replace_existing,
        )
        updated = self._persist_config_apply_result(state, "house_config", result, timestamp=timestamp)
        return {"state": updated, "house_config": result, "progress": get_progress(updated)}

    def apply_feature_manifest(
        self,
        manifest: dict[str, Any],
        *,
        target_path: str | Path,
        timestamp: str,
        replace_existing: bool = False,
    ) -> dict[str, Any]:
        state = self.resume_commissioning()
        self._require_feature_manifest_prerequisites(state)
        result = apply_feature_manifest_file(manifest, target_path=target_path, replace_existing=replace_existing)
        updated = self._persist_config_apply_result(state, "features", result, timestamp=timestamp)
        return {"state": updated, "feature_manifest": result, "progress": get_progress(updated)}

    def apply_branding_refs(self, refs: dict[str, str] | None = None, *, timestamp: str) -> dict[str, Any]:
        state = self.resume_commissioning()
        self._require_branding_prerequisites(state)
        refs = refs or {}
        allowed = {"contractor_logo_ref", "project_brand_ref", "dashboard_theme_ref"}
        unknown = set(refs) - allowed
        if unknown:
            result = _service_result(False, "failed", f"Unknown branding refs: {', '.join(sorted(unknown))}.", False)
        else:
            try:
                evidence_refs = _branding_evidence_refs(refs)
                summary = "Branding refs applied." if refs else "Branding is optional for v0.1 and no refs were supplied."
                updated = complete_step(state, "branding", timestamp, summary=summary, evidence_refs=evidence_refs)
                self.store.save(self.state_path, updated)
                return {"state": updated, "branding": _service_result(True, "passed", summary, False), "progress": get_progress(updated)}
            except ValidationError as exc:
                result = _service_result(False, "failed", str(exc), False)
        updated = fail_step(state, "branding", timestamp, code="branding_failed", message=result["message"], recoverable=False)
        self.store.save(self.state_path, updated)
        return {"state": updated, "branding": result, "progress": get_progress(updated)}

    def acknowledge_manual_check(self, check_id: str, *, timestamp: str, note: str | None = None) -> dict[str, Any]:
        state = self.resume_commissioning()
        if not isinstance(check_id, str) or not re.match(r"^[a-z][a-z0-9_-]*$", check_id):
            raise CommissioningServiceError("manual check id is invalid")
        if note is not None and (not isinstance(note, str) or SECRET_REF_RE.search(note)):
            raise CommissioningServiceError("acknowledgement note is invalid")
        acknowledgements = list(state["acknowledgements"])
        for acknowledgement in acknowledgements:
            if acknowledgement["id"] == check_id:
                if acknowledgement["step"] != "validation":
                    raise CommissioningServiceError("duplicate acknowledgement id belongs to another step")
                if acknowledgement["acknowledged"]:
                    return {"state": state, "progress": get_progress(state)}
                acknowledgement["acknowledged"] = True
                acknowledgement["acknowledged_at"] = timestamp
                if note is not None:
                    acknowledgement["note"] = note
                break
        else:
            item = {"id": check_id, "step": "validation", "acknowledged": True, "acknowledged_at": timestamp}
            if note is not None:
                item["note"] = note
            acknowledgements.append(item)
        updated = dict(state)
        updated["acknowledgements"] = acknowledgements
        updated["updated_at"] = timestamp
        updated = validate_commissioning_state(updated)
        self.store.save(self.state_path, updated)
        return {"state": updated, "progress": get_progress(updated)}

    def run_validation(self, facts: dict[str, Any], *, timestamp: str) -> dict[str, Any]:
        state = self.resume_commissioning()
        self._require_validation_prerequisites(state)
        merged = _merge_acknowledgements(facts, state["acknowledgements"])
        result = evaluate_commissioning_validation(merged)
        evidence_refs = _validation_evidence_refs(result)
        if result["status"] == "passed":
            updated = complete_step(state, "validation", timestamp, summary=result["summary"], evidence_refs=evidence_refs)
            updated["artifacts"]["validation_report_ref"] = "commissioning-validation:passed"
        elif result["status"] == "blocked":
            updated = block_step(
                state,
                "validation",
                timestamp,
                code="validation_blocked",
                message=result["summary"],
                evidence_refs=evidence_refs,
            )
        else:
            updated = fail_step(
                state,
                "validation",
                timestamp,
                code="validation_failed",
                message=result["summary"],
                recoverable=False,
                evidence_refs=evidence_refs,
            )
        self.store.save(self.state_path, updated)
        return {"state": updated, "validation": result, "progress": get_progress(updated)}

    def create_handover_backup(self, client: BackupClient, *, timestamp: str) -> dict[str, Any]:
        state = self.resume_commissioning()
        self._require_backup_prerequisites(state)
        request = BackupRequest(
            commissioning_id=state["commissioning_id"],
            node_id=state["node_id"],
            house_id=state["house_id"],
            metadata_refs=tuple(_passed_checkpoint_refs(state, ("house_config", "features", "validation"))),
        )
        result = client.create_backup(request)
        if not isinstance(result, BackupResult):
            raise CommissioningServiceError("backup client returned an invalid result")
        evidence_refs = [result.backup_ref] if result.backup_ref else []
        if result.success:
            summary = result.message or f"Backup {result.status}."
            updated = complete_step(state, "backup", timestamp, summary=summary, evidence_refs=evidence_refs)
            updated["artifacts"]["backup_ref"] = result.backup_ref
        elif result.recoverable:
            updated = block_step(
                state,
                "backup",
                timestamp,
                code="backup_blocked",
                message=result.message or "Backup is temporarily blocked.",
                evidence_refs=evidence_refs,
            )
        else:
            updated = fail_step(
                state,
                "backup",
                timestamp,
                code="backup_failed",
                message=result.message or "Backup failed.",
                recoverable=False,
                evidence_refs=evidence_refs,
            )
        self.store.save(self.state_path, updated)
        return {"state": updated, "backup": result, "progress": get_progress(updated)}

    def prepare_handover(
        self,
        *,
        report_path: str | Path,
        timestamp: str,
        golden_base_version: str,
        agent_version: str,
        house_config_schema_version: str,
        feature_manifest_schema_version: str,
        validation_summary: str,
        technical_debt: list[dict[str, Any]],
    ) -> dict[str, Any]:
        state = self.resume_commissioning()
        self._require_handover_prerequisites(state)
        report = build_handover_report(
            commissioning_id=state["commissioning_id"],
            node_id=state["node_id"],
            house_id=state["house_id"],
            completed_at=timestamp,
            golden_base_version=golden_base_version,
            agent_version=agent_version,
            house_config_schema_version=house_config_schema_version,
            feature_manifest_schema_version=feature_manifest_schema_version,
            house_config_hash=_checkpoint_hash(state, "house_config"),
            feature_manifest_hash=_checkpoint_hash(state, "features"),
            backup_ref=state["artifacts"]["backup_ref"],
            validation_summary=validation_summary,
            completed_steps=[step for step in COMMISSIONING_STEPS if state["checkpoints"].get(step, {}).get("status") == "passed"],
            acknowledgements=state["acknowledgements"],
            technical_debt=technical_debt,
            status="ready_for_handover",
        )
        report_hash = write_handover_report(report_path, report)
        updated = mark_checkpoint(
            state,
            "handover",
            "running",
            timestamp,
            summary="Handover report prepared.",
            evidence_refs=[f"path:{report_path}", f"hash:{report_hash}"],
        )
        updated["artifacts"]["handover_report_ref"] = str(report_path)
        self.store.save(self.state_path, updated)
        return {"state": updated, "handover_report": report, "handover_report_hash": report_hash, "progress": get_progress(updated)}

    def complete_commissioning(self, *, timestamp: str) -> dict[str, Any]:
        state = self.resume_commissioning()
        if state["state"] == "completed":
            return {"state": state, "progress": get_progress(state)}
        self._require_completion_prerequisites(state)
        updated = complete_step(
            state,
            "handover",
            timestamp,
            summary="Commissioning completed and ready for handover.",
            evidence_refs=[f"path:{state['artifacts']['handover_report_ref']}"],
        )
        self.store.save(self.state_path, updated)
        return {"state": updated, "progress": get_progress(updated)}

    def get_progress(self) -> dict[str, Any]:
        return get_progress(self.resume_commissioning())

    def _require_step_available(self, state: dict[str, Any], step: str) -> None:
        if state.get("current_step") == step:
            return
        if state.get("state") in {"blocked", "failed"} and state.get("current_step") == step:
            return
        raise CommissioningServiceError(f"{step} cannot run before required previous steps pass")

    def _require_enrollment_prerequisites(self, state: dict[str, Any]) -> None:
        for step in ("preflight", "identity", "network"):
            if state.get("checkpoints", {}).get(step, {}).get("status") != "passed":
                raise CommissioningServiceError("enrollment cannot run before prerequisite checkpoints pass")
        self._require_step_available(state, "enrollment")

    def _require_house_config_prerequisites(self, state: dict[str, Any]) -> None:
        if state.get("checkpoints", {}).get("enrollment", {}).get("status") != "passed":
            raise CommissioningServiceError("House Config cannot run before enrollment passes")
        self._require_step_available(state, "house_config")

    def _require_feature_manifest_prerequisites(self, state: dict[str, Any]) -> None:
        if state.get("checkpoints", {}).get("house_config", {}).get("status") != "passed":
            raise CommissioningServiceError("Feature Manifest cannot run before House Config passes")
        self._require_step_available(state, "features")

    def _require_branding_prerequisites(self, state: dict[str, Any]) -> None:
        if state.get("checkpoints", {}).get("features", {}).get("status") != "passed":
            raise CommissioningServiceError("Branding cannot run before Feature Manifest passes")
        self._require_step_available(state, "branding")

    def _require_validation_prerequisites(self, state: dict[str, Any]) -> None:
        if state.get("checkpoints", {}).get("branding", {}).get("status") != "passed":
            raise CommissioningServiceError("Validation cannot run before branding passes")
        self._require_step_available(state, "validation")

    def _require_backup_prerequisites(self, state: dict[str, Any]) -> None:
        if state.get("checkpoints", {}).get("validation", {}).get("status") != "passed":
            raise CommissioningServiceError("Backup cannot run before validation passes")
        self._require_step_available(state, "backup")

    def _require_handover_prerequisites(self, state: dict[str, Any]) -> None:
        if state.get("checkpoints", {}).get("backup", {}).get("status") != "passed":
            raise CommissioningServiceError("Handover cannot prepare before backup passes")
        if state.get("state") != "ready_for_handover" or state.get("current_step") != "handover":
            raise CommissioningServiceError("Handover can only prepare from ready_for_handover")

    def _require_completion_prerequisites(self, state: dict[str, Any]) -> None:
        self._require_handover_prerequisites(state)
        if not state["artifacts"].get("handover_report_ref"):
            raise CommissioningServiceError("handover report must be prepared before completion")

    def _persist_config_apply_result(
        self,
        state: dict[str, Any],
        step: str,
        result: ConfigApplyResult,
        *,
        timestamp: str,
    ) -> dict[str, Any]:
        evidence_refs = _config_evidence_refs(result)
        if result.success:
            updated = complete_step(state, step, timestamp, summary=result.message, evidence_refs=evidence_refs)
            if step == "house_config":
                updated["artifacts"]["house_config_ref"] = result.path_ref
            if step == "features":
                updated["artifacts"]["feature_manifest_ref"] = result.path_ref
        elif result.recoverable:
            updated = block_step(
                state,
                step,
                timestamp,
                code=f"{step}_blocked",
                message=result.message,
                evidence_refs=evidence_refs,
            )
        else:
            updated = fail_step(
                state,
                step,
                timestamp,
                code=f"{step}_failed",
                message=result.message,
                recoverable=False,
                evidence_refs=evidence_refs,
            )
        self.store.save(self.state_path, updated)
        return updated


def get_progress(state: dict[str, Any]) -> dict[str, Any]:
    state = validate_commissioning_state(state)
    checkpoints = state.get("checkpoints", {})
    completed_steps = [step for step in COMMISSIONING_STEPS if checkpoints.get(step, {}).get("status") == "passed"]
    percent = 100 if state["state"] == "completed" else int((len(completed_steps) / len(COMMISSIONING_STEPS)) * 100)
    if len(completed_steps) == len(COMMISSIONING_STEPS):
        percent = 100
    blocked_step = state["current_step"] if state["state"] == "blocked" else None
    failed_step = state["current_step"] if state["state"] == "failed" else None
    return {
        "commissioning_id": state["commissioning_id"],
        "state": state["state"],
        "current_step": state["current_step"],
        "percent_complete": percent,
        "completed_steps": completed_steps,
        "blocked_step": blocked_step,
        "failed_step": failed_step,
        "can_resume": state["state"] != "completed"
        and not (state["state"] == "failed" and not (state.get("last_error") or {}).get("recoverable", False)),
    }


def _hostname_from_identity_checkpoint(state: dict[str, Any]) -> str | None:
    checkpoint = state.get("checkpoints", {}).get("identity", {})
    for ref in checkpoint.get("evidence_refs", []):
        if isinstance(ref, str) and ref.startswith(IDENTITY_HOSTNAME_PREFIX):
            return ref.removeprefix(IDENTITY_HOSTNAME_PREFIX)
    return None


def _config_evidence_refs(result: ConfigApplyResult) -> list[str]:
    refs: list[str] = []
    if result.path_ref:
        refs.append(f"path:{result.path_ref}")
    if result.content_hash:
        refs.append(f"hash:{result.content_hash}")
    if result.status == "unchanged":
        refs.append("apply:unchanged")
    if result.status == "applied":
        refs.append("apply:applied")
    return refs


def _branding_evidence_refs(refs: dict[str, str]) -> list[str]:
    if not refs:
        return ["branding:optional"]
    evidence_refs: list[str] = []
    for key, value in sorted(refs.items()):
        if not isinstance(value, str) or not SAFE_REF_RE.match(value) or SECRET_REF_RE.search(value):
            raise ValidationError("branding refs must be safe references")
        evidence_refs.append(f"branding:{key}={value}")
    return evidence_refs


def _service_result(success: bool, status: str, message: str, recoverable: bool) -> dict[str, Any]:
    return {"success": success, "status": status, "message": message, "recoverable": recoverable}


def _merge_acknowledgements(facts: dict[str, Any], acknowledgements: list[dict[str, Any]]) -> dict[str, Any]:
    merged = dict(facts)
    acknowledged = {item["id"] for item in acknowledgements if item.get("step") == "validation" and item.get("acknowledged")}
    manual_checks = []
    for item in facts.get("required_manual_checks", []):
        if isinstance(item, dict):
            updated = dict(item)
            if updated.get("id") in acknowledged:
                updated["acknowledged"] = True
            manual_checks.append(updated)
        else:
            manual_checks.append(item)
    merged["required_manual_checks"] = manual_checks
    return merged


def _validation_evidence_refs(result: dict[str, Any]) -> list[str]:
    refs = [f"validation:{check['id']}" for check in result["checks"] if check["status"] != "passed"]
    refs.extend(f"ack:{item}" for item in result.get("required_acknowledgements", []))
    if result["status"] == "passed":
        refs.append("validation:passed")
    return refs


def _passed_checkpoint_refs(state: dict[str, Any], steps: tuple[str, ...]) -> list[str]:
    refs: list[str] = []
    for step in steps:
        checkpoint = state.get("checkpoints", {}).get(step, {})
        if checkpoint.get("status") == "passed":
            refs.extend(checkpoint.get("evidence_refs", []))
    return refs


def _checkpoint_hash(state: dict[str, Any], step: str) -> str:
    for ref in state.get("checkpoints", {}).get(step, {}).get("evidence_refs", []):
        if isinstance(ref, str) and ref.startswith("hash:sha256:"):
            return ref.removeprefix("hash:")
    raise CommissioningServiceError(f"{step} checkpoint does not include a content hash")
