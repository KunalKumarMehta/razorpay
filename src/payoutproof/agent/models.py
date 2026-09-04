"""Data models and lifecycle states for Trust Agent extraction jobs (Issue #14)."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from payoutproof.core.enums import TruthState
from payoutproof.core.models import Finding, PaymentIntent


class JobStatus(str, Enum):
    """Authoritative lifecycle states for Trust Agent extraction jobs."""
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    QUARANTINED = "QUARANTINED"


class ExtractionFailureReason(str, Enum):
    """Explicit, non-silent failure and uncertainty classifications."""
    TIMEOUT = "TIMEOUT"
    MALFORMED_SCHEMA = "MALFORMED_SCHEMA"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    MISSING_SIGNAL = "MISSING_SIGNAL"
    PROVIDER_OUTAGE = "PROVIDER_OUTAGE"
    SECURITY_QUARANTINE = "SECURITY_QUARANTINE"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    # Audio-specific failure and uncertainty states (Issue #15)
    UNSUPPORTED_AUDIO_FORMAT = "UNSUPPORTED_AUDIO_FORMAT"
    AUDIO_CORRUPTED = "AUDIO_CORRUPTED"
    MATERIAL_AMBIGUITY = "MATERIAL_AMBIGUITY"
    SPOOF_DETECTED = "SPOOF_DETECTED"
    ACOUSTIC_QUALITY_UNCERTAIN = "ACOUSTIC_QUALITY_UNCERTAIN"


class ProviderProvenance(BaseModel):
    """Source provenance tracing evidence origin through the provider boundary."""
    model_config = ConfigDict(frozen=True)

    source_channel: str
    evidence_hash: str
    authority_ref: str
    tenant_id: str
    organization_id: str


class ProviderResult(BaseModel):
    """Canonical result emitted at the extraction provider boundary.

    Records provider identity, model or configuration version, confidence,
    timing, raw-output reference, and source provenance.
    """
    model_config = ConfigDict(frozen=True)

    provider_id: str
    model_version: str
    confidence: float = Field(ge=0.0, le=1.0)
    timing_ms: float = Field(ge=0.0)
    raw_output_ref: Optional[str] = None
    source_provenance: ProviderProvenance
    status: JobStatus
    failure_reason: Optional[ExtractionFailureReason] = None
    error_message: Optional[str] = None
    raw_output: Optional[Dict[str, Any]] = None
    extracted_intent: Optional[PaymentIntent] = None
    findings: List[Finding] = Field(default_factory=list)


class ExtractionJobRecord(BaseModel):
    """Durable database record representing one extraction job."""
    model_config = ConfigDict(frozen=True)

    job_id: str
    case_id: str
    evidence_id: str
    organization_id: str
    tenant_id: str
    status: JobStatus
    provider_id: str
    model_version: str
    confidence: Optional[float] = None
    timing_ms: Optional[float] = None
    raw_output_ref: Optional[str] = None
    source_provenance: Dict[str, Any]
    result: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    created_at: str
    updated_at: str

    def to_public_dict(self) -> Dict[str, Any]:
        """Expose safe public view without credentials or raw unredacted bytes."""
        return {
            "job_id": self.job_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "organization_id": self.organization_id,
            "status": self.status.value,
            "provider_id": self.provider_id,
            "model_version": self.model_version,
            "confidence": self.confidence,
            "timing_ms": self.timing_ms,
            "raw_output_ref": self.raw_output_ref,
            "source_provenance": self.source_provenance,
            "result": self.result,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
