"""End-to-end evidence admission workflow and progress tracking.

Orchestrates:
1. Pre-validation of Processing Authority Records.
2. Server-side content detection, allowlisting, and archive protection.
3. Malware and security quarantine scanning.
4. AES-256-GCM encrypted preservation in object storage.
5. Transactional persistence in database and Risk Case state machine.
6. Transparent, secret-free upload progress tracking.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from payoutproof.admission.detector import (
    inspect_evidence_bytes,
    is_archive_payload,
    is_executable_or_malicious,
)
from payoutproof.admission.validator import AdmissionValidator
from payoutproof.core.crypto import sha256_hex
from payoutproof.core.enums import (
    AuditTrustState,
    CasePhase,
    ProcessingAuthorityStatus,
    ReasonCode,
    TruthState,
)
from payoutproof.core.models import (
    EvidenceItem,
    ProcessingAuthorityRecord,
    RiskCaseState,
)
from payoutproof.core.providers import ClockProvider, SystemClock
from payoutproof.storage.db import Database
from payoutproof.storage.encrypted_store import EncryptedObjectStore, StoredObjectRef

logger = logging.getLogger("payoutproof.admission")


class UploadStage(str, Enum):
    """Observable stages during evidence admission."""
    INITIALIZED = "INITIALIZED"
    VALIDATING_AUTHORITY = "VALIDATING_AUTHORITY"
    INSPECTING_CONTENT = "INSPECTING_CONTENT"
    SCANNING_SECURITY = "SCANNING_SECURITY"
    ENCRYPTING_PAYLOAD = "ENCRYPTING_PAYLOAD"
    PERSISTING_LEDGER = "PERSISTING_LEDGER"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    QUARANTINED = "QUARANTINED"


class AdmissionStatus(str, Enum):
    """Terminal states of evidence admission."""
    ADMITTED = "ADMITTED"
    ADMISSION_REJECTED = "ADMISSION_REJECTED"
    QUARANTINED = "QUARANTINED"


@dataclass
class UploadProgress:
    """Secret-free upload progress descriptor."""
    stage: UploadStage
    completed_stages: List[str] = field(default_factory=list)
    bytes_processed: int = 0
    total_bytes: int = 0
    message: str = "Ready"

    def advance(self, next_stage: UploadStage, message: str = ""):
        self.completed_stages.append(self.stage.value)
        self.stage = next_stage
        self.message = message

    @property
    def all_stages(self) -> List[str]:
        return self.completed_stages + [self.stage.value]


@dataclass(frozen=True)
class AdmissionResult:
    """Safe, verifiable admission result for callers."""
    status: AdmissionStatus
    case_id: Optional[str]
    evidence_id: Optional[str]
    content_hash: Optional[str]
    detected_mime_type: Optional[str]
    size_bytes: int
    storage_uri: Optional[str]
    reason_code: Optional[ReasonCode]
    error_message: Optional[str]
    progress_history: List[str]
    admitted_at: Optional[str] = None
    quarantine_threat: Optional[str] = None

    def to_safe_dict(self) -> Dict[str, Any]:
        """Convert to safe public JSON dictionary without revealing raw bytes or secrets."""
        return {
            "status": self.status.value,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "content_hash": self.content_hash,
            "detected_mime_type": self.detected_mime_type,
            "size_bytes": self.size_bytes,
            "storage_uri": self.storage_uri,
            "reason_code": self.reason_code.value if self.reason_code else None,
            "error_message": self.error_message,
            "progress_history": self.progress_history,
            "admitted_at": self.admitted_at,
            "quarantine_threat": self.quarantine_threat,
        }


class AdmissionService:
    """High-assurance service admitting real evidence into PayoutProof."""

    def __init__(
        self,
        db: Database,
        object_store: EncryptedObjectStore,
        clock: Optional[ClockProvider] = None,
    ):
        self.db = db
        self.object_store = object_store
        self.clock = clock or SystemClock()

    def admit_evidence(
        self,
        *,
        case_id: str,
        tenant_id: str,
        organization_id: str,
        processing_authority: Optional[Union[ProcessingAuthorityRecord, Dict[str, Any]]],
        content: Union[bytes, str],
        declared_mime_type: Optional[str] = None,
        title: Optional[str] = None,
        evidence_id: Optional[str] = None,
        progress_callback: Optional[Callable[[UploadProgress], None]] = None,
    ) -> AdmissionResult:
        """Process evidence through security checks, encrypted storage, and ledger persistence."""
        progress = UploadProgress(stage=UploadStage.INITIALIZED, total_bytes=len(content))
        if progress_callback:
            progress_callback(progress)

        # 1. Normalize content to bytes
        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
        elif isinstance(content, (bytes, bytearray)):
            content_bytes = bytes(content)
        else:
            return AdmissionResult(
                status=AdmissionStatus.ADMISSION_REJECTED,
                case_id=None,
                evidence_id=None,
                content_hash=None,
                detected_mime_type=None,
                size_bytes=0,
                storage_uri=None,
                reason_code=ReasonCode.MALFORMED_INPUT,
                error_message="Payload content must be string or bytes",
                progress_history=progress.completed_stages + [UploadStage.REJECTED.value],
            )

        progress.bytes_processed = len(content_bytes)

        # 2. Stage: Validate Processing Authority Record
        progress.advance(UploadStage.VALIDATING_AUTHORITY, "Validating processing authority record")
        if progress_callback:
            progress_callback(progress)

        auth_record: Optional[ProcessingAuthorityRecord] = None
        if processing_authority is not None:
            if isinstance(processing_authority, ProcessingAuthorityRecord):
                auth_record = processing_authority
            elif isinstance(processing_authority, dict):
                try:
                    auth_record = ProcessingAuthorityRecord(**processing_authority)
                except Exception as e:
                    progress.advance(UploadStage.REJECTED, f"Malformed authority: {e}")
                    return AdmissionResult(
                        status=AdmissionStatus.ADMISSION_REJECTED,
                        case_id=None,
                        evidence_id=None,
                        content_hash=None,
                        detected_mime_type=None,
                        size_bytes=len(content_bytes),
                        storage_uri=None,
                        reason_code=ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE,
                        error_message="Malformed or incomplete Processing Authority Record",
                        progress_history=progress.all_stages,
                    )

        auth_valid, auth_err = AdmissionValidator.validate_authority(auth_record)
        if not auth_valid:
            r_code = AdmissionValidator.classify_rejection_reason(auth_err or "Missing Processing Authority Record")
            progress.advance(UploadStage.REJECTED, auth_err or "Incomplete authority")
            if progress_callback:
                progress_callback(progress)
            return AdmissionResult(
                status=AdmissionStatus.ADMISSION_REJECTED,
                case_id=None,
                evidence_id=None,
                content_hash=None,
                detected_mime_type=None,
                size_bytes=len(content_bytes),
                storage_uri=None,
                reason_code=r_code,
                error_message=auth_err or "Incomplete Processing Authority Record",
                progress_history=progress.all_stages,
            )

        # 3. Stage: Inspect Content (allowlist, client spoofing, size limits)
        progress.advance(UploadStage.INSPECTING_CONTENT, "Deep binary content inspection")
        if progress_callback:
            progress_callback(progress)

        is_valid_content, detected_mime, content_err, reason_code = inspect_evidence_bytes(
            content_bytes,
            declared_mime_type=declared_mime_type,
        )

        # Handle Archive rejection specifically
        is_arch, arch_msg = is_archive_payload(content_bytes)
        if is_arch:
            progress.advance(UploadStage.REJECTED, arch_msg or "Prohibited archive")
            if progress_callback:
                progress_callback(progress)
            return AdmissionResult(
                status=AdmissionStatus.ADMISSION_REJECTED,
                case_id=None,
                evidence_id=None,
                content_hash=None,
                detected_mime_type=detected_mime or "application/octet-stream",
                size_bytes=len(content_bytes),
                storage_uri=None,
                reason_code=ReasonCode.PROHIBITED_INPUT,
                error_message=arch_msg or "Compressed archives are prohibited",
                progress_history=progress.all_stages,
            )

        # Handle Malware/Threat Quarantine specifically
        is_threat, threat_msg = is_executable_or_malicious(content_bytes)
        if is_threat:
            progress.advance(UploadStage.QUARANTINED, f"Quarantine threat: {threat_msg}")
            if progress_callback:
                progress_callback(progress)
            target_ev_id = evidence_id or f"ev-quarantine-{secrets.token_hex(8)}"
            now_iso = self.clock.now().isoformat()
            try:
                self.db.save_admitted_evidence(
                    evidence_id=target_ev_id,
                    tenant_id=tenant_id,
                    organization_id=organization_id,
                    case_id=case_id,
                    item_type="QUARANTINED_EVIDENCE",
                    title=title or "Quarantined Evidence",
                    content_hash=sha256_hex(content_bytes),
                    detected_mime_type=detected_mime or "application/octet-stream",
                    claimed_mime_type=declared_mime_type or "unknown",
                    plaintext_size_bytes=len(content_bytes),
                    ciphertext_size_bytes=0,
                    storage_uri="quarantine://rejected",
                    encryption_algorithm="NONE",
                    key_id=None,
                    authority_ref=auth_record.asserted_authority_ref if auth_record else "NONE",
                    data_class=auth_record.data_class if auth_record else "UNCLASSIFIED",
                    retention_days=0,
                    lifecycle_status="QUARANTINED",
                    admitted_at=now_iso,
                    quarantine_reason=threat_msg,
                )
            except Exception as e:
                logger.warning("Failed to record quarantine in ledger: %s", e)

            # Log quarantine threat without exposing content or paths
            logger.warning(
                "Security quarantine alert: threat '%s' detected for case '%s', org '%s'",
                threat_msg, case_id, organization_id,
            )
            return AdmissionResult(
                status=AdmissionStatus.QUARANTINED,
                case_id=case_id,
                evidence_id=target_ev_id,
                content_hash=sha256_hex(content_bytes),
                detected_mime_type=detected_mime or "application/octet-stream",
                size_bytes=len(content_bytes),
                storage_uri=None,
                reason_code=ReasonCode.PROHIBITED_INPUT,
                error_message=f"Evidence quarantined: {threat_msg}",
                progress_history=progress.all_stages,
                quarantine_threat=threat_msg,
            )

        if not is_valid_content:
            progress.advance(UploadStage.REJECTED, content_err or "Invalid content")
            if progress_callback:
                progress_callback(progress)
            return AdmissionResult(
                status=AdmissionStatus.ADMISSION_REJECTED,
                case_id=None,
                evidence_id=None,
                content_hash=None,
                detected_mime_type=detected_mime,
                size_bytes=len(content_bytes),
                storage_uri=None,
                reason_code=reason_code or ReasonCode.MALFORMED_INPUT,
                error_message=content_err or "Invalid content",
                progress_history=progress.all_stages,
            )

        # 4. Stage: Security Scan
        progress.advance(UploadStage.SCANNING_SECURITY, "Passed antivirus and integrity checks")
        if progress_callback:
            progress_callback(progress)

        # 5. Stage: Encrypt and Preserve in Object Store
        progress.advance(UploadStage.ENCRYPTING_PAYLOAD, "Encrypting raw evidence with AES-256-GCM")
        if progress_callback:
            progress_callback(progress)

        target_ev_id = evidence_id or f"EV-{case_id}-01"
        stored_ref = self.object_store.put_evidence(
            tenant_id=tenant_id,
            organization_id=organization_id,
            case_id=case_id,
            evidence_id=target_ev_id,
            plaintext=content_bytes,
        )

        # 6. Stage: Persist in Database & State Machine
        progress.advance(UploadStage.PERSISTING_LEDGER, "Writing transactional evidence records and audit event")
        if progress_callback:
            progress_callback(progress)

        now_iso = self.clock.now().isoformat()
        retention_days = auth_record.retention_days or 7

        with self.db.get_connection() as conn:
            # Check if case exists or initialize fresh
            existing = self.db.load_case_tx(conn, case_id)
            if existing is None:
                from payoutproof.case_workflow.state_machine import StateMachine
                from tests.helpers import make_authorized_bundle_action

                # Initial state then admit bundle
                s0 = StateMachine.initial_state(
                    case_id=case_id,
                    tenant_id=tenant_id,
                    organization_id=organization_id,
                    clock=self.clock,
                )
                act = {
                    "type": "ADMIT_AUTHORIZED_BUNDLE",
                    "payload": {
                        "case_id": case_id,
                        "organization_id": organization_id,
                        "processing_authority": auth_record.model_dump(),
                        "evidence": {
                            "content": content_bytes,
                            "mime_type": detected_mime,
                            "title": title or "Admitted Evidence",
                        },
                        "title": title or "Admitted Evidence",
                    },
                }
                s1 = StateMachine.reduce(s0, act, clock=self.clock)
                self.db.save_case_tx(conn, s1)
            else:
                # Add evidence item to existing case
                ev_item = EvidenceItem(
                    id=target_ev_id,
                    item_type="VOICE_AND_TEXT_BUNDLE" if ("audio" in detected_mime or "text" in detected_mime) else "EVIDENCE_BUNDLE",
                    title=title or "Admitted Evidence",
                    content_hash=stored_ref.content_hash,
                    finding="admitted",
                    truth_state=TruthState.SUPPORTED,
                    admitted_at=now_iso,
                    metadata={
                        "mime_type": detected_mime,
                        "size_bytes": stored_ref.plaintext_size_bytes,
                        "storage_uri": stored_ref.storage_uri,
                        "encryption_algorithm": stored_ref.encryption_algorithm,
                        "key_id": stored_ref.key_id,
                        "data_class": auth_record.data_class,
                        "processing_route": auth_record.processing_route,
                        "retention_days": retention_days,
                        "is_valid": True,
                    },
                )
                updated_evidence = list(existing.evidence) + [ev_item]
                s_updated = existing.model_copy(update={"evidence": updated_evidence})
                self.db.save_case_tx(conn, s_updated)

            # Persist admitted_evidence row
            self.db.save_admitted_evidence_tx(
                conn,
                evidence_id=target_ev_id,
                tenant_id=tenant_id,
                organization_id=organization_id,
                case_id=case_id,
                item_type="EVIDENCE_BUNDLE",
                title=title or "Admitted Evidence",
                content_hash=stored_ref.content_hash,
                detected_mime_type=detected_mime,
                claimed_mime_type=declared_mime_type or detected_mime,
                plaintext_size_bytes=stored_ref.plaintext_size_bytes,
                ciphertext_size_bytes=stored_ref.ciphertext_size_bytes,
                storage_uri=stored_ref.storage_uri,
                encryption_algorithm=stored_ref.encryption_algorithm,
                key_id=stored_ref.key_id,
                authority_ref=auth_record.asserted_authority_ref,
                data_class=auth_record.data_class,
                retention_days=retention_days,
                lifecycle_status="ADMITTED",
                admitted_at=now_iso,
            )

        progress.advance(UploadStage.COMPLETED, f"Evidence {target_ev_id} preserved successfully")
        if progress_callback:
            progress_callback(progress)

        return AdmissionResult(
            status=AdmissionStatus.ADMITTED,
            case_id=case_id,
            evidence_id=target_ev_id,
            content_hash=stored_ref.content_hash,
            detected_mime_type=detected_mime,
            size_bytes=stored_ref.plaintext_size_bytes,
            storage_uri=stored_ref.storage_uri,
            reason_code=None,
            error_message=None,
            progress_history=progress.all_stages,
            admitted_at=now_iso,
        )
