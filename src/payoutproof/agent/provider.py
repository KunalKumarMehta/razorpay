"""Trust Agent extraction provider boundary and deterministic test doubles (Issue #14)."""

from __future__ import annotations

import json
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from payoutproof.agent.models import (
    ExtractionFailureReason,
    JobStatus,
    ProviderProvenance,
    ProviderResult,
)
from payoutproof.core.crypto import sha256_hex
from payoutproof.core.enums import DestinationStatus, FindingName, IntentStatus, TruthState
from payoutproof.core.models import Finding, PaymentIntent
from payoutproof.intent.extractor import extract_intent_from_structured_data


class SimulationMode(str, Enum):
    """Deterministic simulation modes for provider testing and fault injection."""
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    MALFORMED_SCHEMA = "MALFORMED_SCHEMA"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    MISSING_SIGNAL = "MISSING_SIGNAL"
    PROVIDER_OUTAGE = "PROVIDER_OUTAGE"
    SECURITY_QUARANTINE = "SECURITY_QUARANTINE"


@runtime_checkable
class ExtractionProvider(Protocol):
    """Protocol for Trust Agent extraction backends."""

    def extract(
        self,
        evidence_bytes: bytes,
        evidence_meta: Dict[str, Any],
        simulation_mode: Optional[SimulationMode] = None,
    ) -> ProviderResult:
        """Execute extraction against raw evidence and return structured ProviderResult."""
        ...


class DeterministicFakeProvider:
    """Deterministic, reproducible test double for Trust Agent extraction.

    Covers success, timeout, malformed schema, low confidence, missing signal,
    provider outage, and security quarantine without network dependencies or flakiness.
    """

    DEFAULT_PROVIDER_ID = "fake-trust-agent-v1"
    DEFAULT_MODEL_VERSION = "pilot-extract-v1.0.0"

    def __init__(
        self,
        default_mode: SimulationMode = SimulationMode.SUCCESS,
        provider_id: Optional[str] = None,
        model_version: Optional[str] = None,
    ) -> None:
        self.default_mode = default_mode
        self.provider_id = provider_id or self.DEFAULT_PROVIDER_ID
        self.model_version = model_version or self.DEFAULT_MODEL_VERSION

    def extract(
        self,
        evidence_bytes: bytes,
        evidence_meta: Dict[str, Any],
        simulation_mode: Optional[SimulationMode] = None,
    ) -> ProviderResult:
        mode = simulation_mode or self.default_mode

        # Construct provenance from evidence metadata
        provenance = ProviderProvenance(
            source_channel=evidence_meta.get("data_class", "FINANCIAL_DOCUMENT"),
            evidence_hash=evidence_meta.get("content_hash") or sha256_hex(evidence_bytes),
            authority_ref=evidence_meta.get("authority_ref", "REF-AUTH-UNKNOWN"),
            tenant_id=evidence_meta.get("tenant_id", "unknown-tenant"),
            organization_id=evidence_meta.get("organization_id", "unknown-org"),
        )

        if mode == SimulationMode.TIMEOUT:
            return ProviderResult(
                provider_id=self.provider_id,
                model_version=self.model_version,
                confidence=0.0,
                timing_ms=30000.0,
                raw_output_ref=None,
                source_provenance=provenance,
                status=JobStatus.TIMED_OUT,
                failure_reason=ExtractionFailureReason.TIMEOUT,
                error_message="Provider extraction timed out after 30000ms deadline",
                raw_output=None,
                extracted_intent=None,
                findings=[
                    Finding(
                        name=FindingName.INSTRUCTION_CONSISTENCY.value,
                        truth_state=TruthState.NOT_EVALUATED,
                        detail="Extraction timed out; no signals evaluated",
                        organization_id=provenance.organization_id,
                    )
                ],
            )

        elif mode == SimulationMode.MALFORMED_SCHEMA:
            return ProviderResult(
                provider_id=self.provider_id,
                model_version=self.model_version,
                confidence=0.0,
                timing_ms=85.0,
                raw_output_ref=None,
                source_provenance=provenance,
                status=JobStatus.FAILED,
                failure_reason=ExtractionFailureReason.MALFORMED_SCHEMA,
                error_message="Provider emitted unparseable schema: JSONDecodeError at char 0",
                raw_output={"raw_text": "INVALID_NON_JSON_RESPONSE<<<!>>>"},
                extracted_intent=None,
                findings=[
                    Finding(
                        name=FindingName.INSTRUCTION_CONSISTENCY.value,
                        truth_state=TruthState.NOT_EVALUATED,
                        detail="Provider schema malformed; extraction failed",
                        organization_id=provenance.organization_id,
                    )
                ],
            )

        elif mode == SimulationMode.PROVIDER_OUTAGE:
            return ProviderResult(
                provider_id=self.provider_id,
                model_version=self.model_version,
                confidence=0.0,
                timing_ms=45.0,
                raw_output_ref=None,
                source_provenance=provenance,
                status=JobStatus.FAILED,
                failure_reason=ExtractionFailureReason.PROVIDER_OUTAGE,
                error_message="Upstream HTTP 503 Service Unavailable: connection refused",
                raw_output=None,
                extracted_intent=None,
                findings=[
                    Finding(
                        name=FindingName.INSTRUCTION_CONSISTENCY.value,
                        truth_state=TruthState.NOT_EVALUATED,
                        detail="Provider outage; extraction could not proceed",
                        organization_id=provenance.organization_id,
                    )
                ],
            )

        elif mode == SimulationMode.LOW_CONFIDENCE:
            # Low confidence MUST NOT be converted to affirmative evidence or confirmed intent
            raw_out = {
                "detected_counterparty": "Unknown Entity",
                "detected_amount": "50000",
                "quality_score": 0.34,
            }
            raw_bytes = json.dumps(raw_out, sort_keys=True).encode("utf-8")
            return ProviderResult(
                provider_id=self.provider_id,
                model_version=self.model_version,
                confidence=0.34,
                timing_ms=175.0,
                raw_output_ref=f"raw-ref://{sha256_hex(raw_bytes)[:16]}",
                source_provenance=provenance,
                status=JobStatus.FAILED,
                failure_reason=ExtractionFailureReason.LOW_CONFIDENCE,
                error_message="Model confidence 0.34 falls below minimum threshold 0.80",
                raw_output=raw_out,
                extracted_intent=None,
                findings=[
                    Finding(
                        name=FindingName.INSTRUCTION_CONSISTENCY.value,
                        truth_state=TruthState.INSUFFICIENT_QUALITY,
                        detail="Evidence quality insufficient for conclusive extraction (confidence=0.34 < 0.80)",
                        organization_id=provenance.organization_id,
                    )
                ],
            )

        elif mode == SimulationMode.MISSING_SIGNAL:
            # Missing signal MUST NOT be converted to affirmative evidence
            raw_out = {"message": "No actionable payout instruction found in payload"}
            raw_bytes = json.dumps(raw_out, sort_keys=True).encode("utf-8")
            return ProviderResult(
                provider_id=self.provider_id,
                model_version=self.model_version,
                confidence=0.10,
                timing_ms=120.0,
                raw_output_ref=f"raw-ref://{sha256_hex(raw_bytes)[:16]}",
                source_provenance=provenance,
                status=JobStatus.FAILED,
                failure_reason=ExtractionFailureReason.MISSING_SIGNAL,
                error_message="No instruction or counterparty signal observed in evidence",
                raw_output=raw_out,
                extracted_intent=None,
                findings=[
                    Finding(
                        name=FindingName.INSTRUCTION_CONSISTENCY.value,
                        truth_state=TruthState.NOT_OBSERVED,
                        detail="No payout instruction or counterparty signals observed in evidence payload",
                        organization_id=provenance.organization_id,
                    )
                ],
            )

        elif mode == SimulationMode.SECURITY_QUARANTINE:
            return ProviderResult(
                provider_id=self.provider_id,
                model_version=self.model_version,
                confidence=0.0,
                timing_ms=10.0,
                raw_output_ref=None,
                source_provenance=provenance,
                status=JobStatus.QUARANTINED,
                failure_reason=ExtractionFailureReason.SECURITY_QUARANTINE,
                error_message="Evidence was quarantined due to security threat; extraction refused",
                raw_output=None,
                extracted_intent=None,
                findings=[
                    Finding(
                        name=FindingName.INSTRUCTION_CONSISTENCY.value,
                        truth_state=TruthState.NOT_EVALUATED,
                        detail="Quarantined payload; processing halted",
                        organization_id=provenance.organization_id,
                    )
                ],
            )

        # Mode SUCCESS
        # Attempt to parse payload if JSON, or generate deterministic structured output
        extracted_data: Dict[str, Any] = {}
        try:
            parsed = json.loads(evidence_bytes.decode("utf-8"))
            if isinstance(parsed, dict):
                extracted_data = parsed
        except Exception:
            pass

        counterparty = str(extracted_data.get("counterparty") or "Acme Tech Solutions Ltd")
        destination = str(extracted_data.get("destination") or "HDFC0001234:9876543210")
        amount = str(extracted_data.get("amount") or "425000")
        currency = str(extracted_data.get("currency") or "INR")
        purpose = str(extracted_data.get("purpose") or "Vendor payment for Q3 software licenses")
        ref_id = str(extracted_data.get("instruction_ref") or "INV-2026-8819")

        intent = PaymentIntent(
            counterparty=counterparty,
            destination=destination,
            destination_status=DestinationStatus.UNAPPROVED,
            amount=amount,
            currency=currency,
            purpose=purpose,
            instruction_reference=ref_id,
            provenance=[f"evidence:{provenance.evidence_hash[:12]}"],
            status=IntentStatus.EXTRACTED,
            intent_hash=None,
        )

        raw_out = {
            "counterparty": counterparty,
            "destination": destination,
            "amount": amount,
            "currency": currency,
            "purpose": purpose,
            "instruction_reference": ref_id,
            "confidence": 0.96,
        }
        raw_bytes = json.dumps(raw_out, sort_keys=True).encode("utf-8")
        raw_ref = f"raw-ref://{sha256_hex(raw_bytes)[:16]}"

        return ProviderResult(
            provider_id=self.provider_id,
            model_version=self.model_version,
            confidence=0.96,
            timing_ms=145.0,
            raw_output_ref=raw_ref,
            source_provenance=provenance,
            status=JobStatus.SUCCEEDED,
            failure_reason=None,
            error_message=None,
            raw_output=raw_out,
            extracted_intent=intent,
            findings=[
                Finding(
                    name=FindingName.INSTRUCTION_CONSISTENCY.value,
                    truth_state=TruthState.SUPPORTED,
                    detail="Intent extracted with high confidence from authorized evidence",
                    evidence_ref=provenance.evidence_hash,
                    organization_id=provenance.organization_id,
                )
            ],
        )
