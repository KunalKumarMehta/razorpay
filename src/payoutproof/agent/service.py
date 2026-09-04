"""Trust Agent extraction orchestration service (Issue #14).

Coordinates extraction jobs across the provider boundary, guarantees explicit
failure states, preserves cryptographic provenance, and prevents false confirmation.
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Any, Dict, List, Optional

from payoutproof.agent.models import (
    ExtractionFailureReason,
    ExtractionJobRecord,
    JobStatus,
    ProviderProvenance,
    ProviderResult,
)
from payoutproof.agent.provider import (
    DeterministicFakeProvider,
    ExtractionProvider,
    SimulationMode,
)
from payoutproof.audit.chain import AuditChain
from payoutproof.core.crypto import sha256_hex
from payoutproof.core.enums import (
    DestinationStatus,
    FindingName,
    IntentStatus,
    TruthState,
)
from payoutproof.core.models import Finding, PaymentIntent, RiskCaseState
from payoutproof.core.providers import ClockProvider, SystemClock
from payoutproof.storage.db import Database
from payoutproof.storage.encrypted_store import EncryptedObjectStore

logger = logging.getLogger("payoutproof.agent")


class TrustAgentService:
    """Asynchronous orchestration service for Trust Agent extraction jobs."""

    def __init__(
        self,
        db: Database,
        object_store: EncryptedObjectStore,
        provider: Optional[ExtractionProvider] = None,
        clock: Optional[ClockProvider] = None,
    ) -> None:
        self.db = db
        self.object_store = object_store
        self.provider = provider or DeterministicFakeProvider()
        self.clock = clock or SystemClock()

    def enqueue_job(
        self,
        *,
        case_id: str,
        evidence_id: str,
        organization_id: str,
        tenant_id: str,
        simulation_mode: Optional[SimulationMode] = None,
    ) -> ExtractionJobRecord:
        """Enqueue an extraction job for an admitted evidence item."""
        evidence_record = self.db.load_admitted_evidence(evidence_id)
        if not evidence_record or evidence_record.get("organization_id") != organization_id:
            raise ValueError(f"Evidence '{evidence_id}' not found in organization '{organization_id}'")

        job_id = f"JOB-{case_id}-{secrets.token_hex(6)}"
        now_iso = self.clock.now().isoformat()

        # Check if evidence was quarantined during admission
        is_quarantined = evidence_record.get("lifecycle_status") == "QUARANTINED"
        initial_status = JobStatus.QUARANTINED if is_quarantined else JobStatus.QUEUED
        err_code = ExtractionFailureReason.SECURITY_QUARANTINE.value if is_quarantined else None
        err_msg = (
            f"Evidence was quarantined: {evidence_record.get('quarantine_reason', 'Security quarantine')}"
            if is_quarantined
            else None
        )

        provenance = {
            "source_channel": evidence_record.get("data_class", "FINANCIAL_DOCUMENT"),
            "evidence_hash": evidence_record["content_hash"],
            "authority_ref": evidence_record.get("authority_ref", "NONE"),
            "tenant_id": tenant_id,
            "organization_id": organization_id,
            "simulation_mode": simulation_mode.value if simulation_mode else None,
        }

        self.db.save_extraction_job(
            job_id=job_id,
            case_id=case_id,
            evidence_id=evidence_id,
            organization_id=organization_id,
            tenant_id=tenant_id,
            status=initial_status.value,
            provider_id=getattr(self.provider, "provider_id", "fake-trust-agent-v1"),
            model_version=getattr(self.provider, "model_version", "pilot-extract-v1.0.0"),
            confidence=0.0 if is_quarantined else None,
            timing_ms=0.0 if is_quarantined else None,
            raw_output_ref=None,
            source_provenance_json=json.dumps(provenance),
            result_json=None,
            error_code=err_code,
            error_message=err_msg,
            created_at=now_iso,
            updated_at=now_iso,
        )

        return ExtractionJobRecord(
            job_id=job_id,
            case_id=case_id,
            evidence_id=evidence_id,
            organization_id=organization_id,
            tenant_id=tenant_id,
            status=initial_status,
            provider_id=getattr(self.provider, "provider_id", "fake-trust-agent-v1"),
            model_version=getattr(self.provider, "model_version", "pilot-extract-v1.0.0"),
            confidence=0.0 if is_quarantined else None,
            timing_ms=0.0 if is_quarantined else None,
            raw_output_ref=None,
            source_provenance=provenance,
            result=None,
            error_code=err_code,
            error_message=err_msg,
            created_at=now_iso,
            updated_at=now_iso,
        )

    def run_extraction_job(
        self,
        *,
        case_id: str,
        evidence_id: str,
        organization_id: str,
        tenant_id: str,
        simulation_mode: Optional[SimulationMode] = None,
    ) -> ExtractionJobRecord:
        """Enqueue and synchronously process an extraction job."""
        job = self.enqueue_job(
            case_id=case_id,
            evidence_id=evidence_id,
            organization_id=organization_id,
            tenant_id=tenant_id,
            simulation_mode=simulation_mode,
        )
        if job.status == JobStatus.QUARANTINED:
            return job
        return self.process_job(job.job_id, simulation_mode=simulation_mode)

    def process_job(
        self,
        job_id: str,
        *,
        simulation_mode: Optional[SimulationMode] = None,
    ) -> ExtractionJobRecord:
        """Process an extraction job through the provider boundary and update case state.

        Guarantees:
        1. Terminal jobs are not reprocessed.
        2. Progresses through PROCESSING to SUCCEEDED, FAILED, TIMED_OUT, or QUARANTINED.
        3. Never converts failures, timeouts, missing signals, or low-confidence
           results into affirmative evidence or confirmed intents.
        """
        row = self.db.load_extraction_job(job_id)
        if not row:
            raise ValueError(f"Job '{job_id}' not found")

        current_status = row["status"]
        if current_status in (
            JobStatus.SUCCEEDED.value,
            JobStatus.FAILED.value,
            JobStatus.TIMED_OUT.value,
            JobStatus.QUARANTINED.value,
        ):
            return ExtractionJobRecord(
                job_id=row["job_id"],
                case_id=row["case_id"],
                evidence_id=row["evidence_id"],
                organization_id=row["organization_id"],
                tenant_id=row["tenant_id"],
                status=JobStatus(row["status"]),
                provider_id=row["provider_id"],
                model_version=row["model_version"],
                confidence=row.get("confidence"),
                timing_ms=row.get("timing_ms"),
                raw_output_ref=row.get("raw_output_ref"),
                source_provenance=json.loads(row["source_provenance_json"]),
                result=json.loads(row["result_json"]) if row.get("result_json") else None,
                error_code=row.get("error_code"),
                error_message=row.get("error_message"),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

        # 1. Transition to PROCESSING
        now_iso = self.clock.now().isoformat()
        self.db.save_extraction_job(
            job_id=job_id,
            case_id=row["case_id"],
            evidence_id=row["evidence_id"],
            organization_id=row["organization_id"],
            tenant_id=row["tenant_id"],
            status=JobStatus.PROCESSING.value,
            provider_id=row["provider_id"],
            model_version=row["model_version"],
            confidence=row.get("confidence"),
            timing_ms=row.get("timing_ms"),
            raw_output_ref=row.get("raw_output_ref"),
            source_provenance_json=row["source_provenance_json"],
            result_json=row.get("result_json"),
            error_code=None,
            error_message=None,
            created_at=row["created_at"],
            updated_at=now_iso,
        )

        evidence_row = self.db.load_admitted_evidence(row["evidence_id"])
        if not evidence_row:
            raise ValueError(f"Evidence '{row['evidence_id']}' vanished from database")

        # Check for quarantine
        if evidence_row.get("lifecycle_status") == "QUARANTINED":
            term_status = JobStatus.QUARANTINED
            err_code = ExtractionFailureReason.SECURITY_QUARANTINE.value
            err_msg = f"Evidence was quarantined: {evidence_row.get('quarantine_reason')}"
            self.db.save_extraction_job(
                job_id=job_id,
                case_id=row["case_id"],
                evidence_id=row["evidence_id"],
                organization_id=row["organization_id"],
                tenant_id=row["tenant_id"],
                status=term_status.value,
                provider_id=row["provider_id"],
                model_version=row["model_version"],
                confidence=0.0,
                timing_ms=0.0,
                raw_output_ref=None,
                source_provenance_json=row["source_provenance_json"],
                result_json=None,
                error_code=err_code,
                error_message=err_msg,
                created_at=row["created_at"],
                updated_at=now_iso,
            )
            return self.get_job(job_id)  # type: ignore

        # 2. Retrieve decrypted content from object store
        storage_uri = evidence_row["storage_uri"]
        try:
            raw_content, _ = self.object_store.get(storage_uri)
        except Exception as e:
            term_status = JobStatus.FAILED
            err_code = ExtractionFailureReason.INTERNAL_ERROR.value
            err_msg = f"Failed to retrieve evidence from storage: {e}"
            self.db.save_extraction_job(
                job_id=job_id,
                case_id=row["case_id"],
                evidence_id=row["evidence_id"],
                organization_id=row["organization_id"],
                tenant_id=row["tenant_id"],
                status=term_status.value,
                provider_id=row["provider_id"],
                model_version=row["model_version"],
                confidence=0.0,
                timing_ms=0.0,
                raw_output_ref=None,
                source_provenance_json=row["source_provenance_json"],
                result_json=None,
                error_code=err_code,
                error_message=err_msg,
                created_at=row["created_at"],
                updated_at=now_iso,
            )
            return self.get_job(job_id)  # type: ignore

        # 3. Call Provider Boundary
        prov_provenance = json.loads(row["source_provenance_json"])
        mode_override = simulation_mode
        if mode_override is None and prov_provenance.get("simulation_mode"):
            try:
                mode_override = SimulationMode(prov_provenance["simulation_mode"])
            except Exception:
                pass

        provider_result: ProviderResult = self.provider.extract(
            raw_content,
            evidence_row,
            simulation_mode=mode_override,
        )

        # 4. Process and update Risk Case state transactionally
        raw_out = provider_result.raw_output or {}
        result_dict = {
            "confidence": provider_result.confidence,
            "timing_ms": provider_result.timing_ms,
            "raw_output_ref": provider_result.raw_output_ref,
            "failure_reason": provider_result.failure_reason.value if provider_result.failure_reason else None,
            "findings": [f.model_dump() for f in provider_result.findings],
            "extracted_intent": (
                provider_result.extracted_intent.model_dump()
                if provider_result.extracted_intent
                else None
            ),
        }
        if "audio_diagnostics" in raw_out:
            result_dict["audio_diagnostics"] = raw_out["audio_diagnostics"]

        with self.db.get_connection() as conn:
            case_state = self.db.load_case_tx(conn, row["case_id"])
            if case_state is not None:
                # Merge new findings: replace any existing finding with same name
                existing_names = {f.name for f in provider_result.findings}
                kept_findings = [f for f in case_state.findings if f.name not in existing_names]
                updated_findings = kept_findings + provider_result.findings

                # Only update intent if job strictly succeeded with high confidence (>= 0.80)
                # and had no failure reason
                updated_intent = case_state.intent
                if (
                    provider_result.status == JobStatus.SUCCEEDED
                    and provider_result.failure_reason is None
                    and provider_result.confidence >= 0.80
                    and provider_result.extracted_intent is not None
                ):
                    updated_intent = provider_result.extracted_intent

                # Update CaseInvestigation diagnostics if audio evidence was processed
                updated_investigation = case_state.investigation
                raw_out = provider_result.raw_output or {}
                audio_diag = raw_out.get("audio_diagnostics")
                if audio_diag:
                    if provider_result.status == JobStatus.SUCCEEDED:
                        model_status = "COMPLETED"
                    elif provider_result.failure_reason == ExtractionFailureReason.MATERIAL_AMBIGUITY:
                        model_status = "AMBIGUOUS"
                    elif provider_result.failure_reason == ExtractionFailureReason.SPOOF_DETECTED:
                        model_status = "SPOOF_DETECTED"
                    elif provider_result.status == JobStatus.TIMED_OUT:
                        model_status = "TIMED_OUT"
                    else:
                        model_status = "FAILED"

                    updated_investigation = case_state.investigation.model_copy(
                        update={
                            "model_status": model_status,
                            "attempt": case_state.investigation.attempt + 1,
                            "asr_confidence": audio_diag.get("asr_confidence"),
                            "extraction_latency_ms": provider_result.timing_ms,
                            "language_stratum": audio_diag.get("language_stratum"),
                        }
                    )

                # Append audit event to case
                audit_type = (
                    "TRUST_AGENT_EXTRACTION_COMPLETED"
                    if provider_result.status == JobStatus.SUCCEEDED
                    else "TRUST_AGENT_EXTRACTION_FAILED"
                )
                audit_summary = (
                    f"Trust Agent extraction {job_id} succeeded with confidence {provider_result.confidence:.2f}"
                    if provider_result.status == JobStatus.SUCCEEDED
                    else f"Trust Agent extraction {job_id} status {provider_result.status.value}: {provider_result.error_message or 'Unresolved extraction'}"
                )

                audit_details = {
                    "job_id": job_id,
                    "evidence_id": row["evidence_id"],
                    "provider_id": provider_result.provider_id,
                    "model_version": provider_result.model_version,
                    "status": provider_result.status.value,
                    "confidence": provider_result.confidence,
                    "timing_ms": provider_result.timing_ms,
                    "raw_output_ref": provider_result.raw_output_ref,
                    "failure_reason": (
                        provider_result.failure_reason.value
                        if provider_result.failure_reason
                        else None
                    ),
                    "error_message": provider_result.error_message,
                }
                if audio_diag:
                    audit_details["audio_duration_ms"] = audio_diag.get("metadata", {}).get("duration_ms")
                    audit_details["language_stratum"] = audio_diag.get("language_stratum")
                    audit_details["anti_spoof_status"] = audio_diag.get("anti_spoof", {}).get("status")
                    audit_details["anti_spoof_score"] = audio_diag.get("anti_spoof", {}).get("score")
                    audit_details["has_material_ambiguity"] = audio_diag.get("has_material_ambiguity", False)

                new_event = AuditChain.create_event(
                    events=case_state.audit,
                    event_type=audit_type,
                    summary=audit_summary,
                    actor=f"agent:{provider_result.provider_id}",
                    case_id=case_state.case_id,
                    details=audit_details,
                    clock=self.clock,
                )

                updated_case = case_state.model_copy(
                    update={
                        "findings": updated_findings,
                        "intent": updated_intent,
                        "investigation": updated_investigation,
                        "audit": list(case_state.audit) + [new_event],
                        "case_version": case_state.case_version + 1,
                    }
                )
                self.db.save_case_tx(conn, updated_case)

            # 5. Persist final job status in extraction_jobs
            now_iso_term = self.clock.now().isoformat()
            self.db.save_extraction_job_tx(
                conn,
                job_id=job_id,
                case_id=row["case_id"],
                evidence_id=row["evidence_id"],
                organization_id=row["organization_id"],
                tenant_id=row["tenant_id"],
                status=provider_result.status.value,
                provider_id=provider_result.provider_id,
                model_version=provider_result.model_version,
                confidence=provider_result.confidence,
                timing_ms=provider_result.timing_ms,
                raw_output_ref=provider_result.raw_output_ref,
                source_provenance_json=row["source_provenance_json"],
                result_json=json.dumps(result_dict),
                error_code=(
                    provider_result.failure_reason.value
                    if provider_result.failure_reason
                    else None
                ),
                error_message=provider_result.error_message,
                created_at=row["created_at"],
                updated_at=now_iso_term,
            )

        return self.get_job(job_id)  # type: ignore

    def get_job(
        self,
        job_id: str,
        organization_id: Optional[str] = None,
    ) -> Optional[ExtractionJobRecord]:
        """Retrieve extraction job record by ID."""
        row = self.db.load_extraction_job(job_id)
        if not row:
            return None
        if organization_id is not None and row.get("organization_id") != organization_id:
            return None

        return ExtractionJobRecord(
            job_id=row["job_id"],
            case_id=row["case_id"],
            evidence_id=row["evidence_id"],
            organization_id=row["organization_id"],
            tenant_id=row["tenant_id"],
            status=JobStatus(row["status"]),
            provider_id=row["provider_id"],
            model_version=row["model_version"],
            confidence=row.get("confidence"),
            timing_ms=row.get("timing_ms"),
            raw_output_ref=row.get("raw_output_ref"),
            source_provenance=json.loads(row["source_provenance_json"]),
            result=json.loads(row["result_json"]) if row.get("result_json") else None,
            error_code=row.get("error_code"),
            error_message=row.get("error_message"),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def list_case_jobs(
        self,
        case_id: str,
        organization_id: Optional[str] = None,
    ) -> List[ExtractionJobRecord]:
        """List all extraction jobs for a case."""
        rows = self.db.list_case_extraction_jobs(case_id, organization_id=organization_id)
        return [
            ExtractionJobRecord(
                job_id=r["job_id"],
                case_id=r["case_id"],
                evidence_id=r["evidence_id"],
                organization_id=r["organization_id"],
                tenant_id=r["tenant_id"],
                status=JobStatus(r["status"]),
                provider_id=r["provider_id"],
                model_version=r["model_version"],
                confidence=r.get("confidence"),
                timing_ms=r.get("timing_ms"),
                raw_output_ref=r.get("raw_output_ref"),
                source_provenance=json.loads(r["source_provenance_json"]),
                result=json.loads(r["result_json"]) if r.get("result_json") else None,
                error_code=r.get("error_code"),
                error_message=r.get("error_message"),
                created_at=r["created_at"],
                updated_at=r["updated_at"],
            )
            for r in rows
        ]
