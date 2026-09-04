"""Comprehensive test suite for representative audio Payment Intent extraction (Issue #15)."""

from __future__ import annotations

import base64
import io
import shutil
import tempfile
import wave
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from payoutproof.admission.service import AdmissionService
from payoutproof.agent.audio import (
    AntiSpoofStatus,
    AudioCorruptedError,
    AudioFormatError,
    parse_audio_metadata,
)
from payoutproof.agent.models import (
    ExtractionFailureReason,
    JobStatus,
)
from payoutproof.agent.provider import (
    DeterministicFakeProvider,
    SimulationMode,
)
from payoutproof.agent.service import TrustAgentService
from payoutproof.api.app import create_app
from payoutproof.auth.roles import Role
from payoutproof.core.config import AppConfig
from payoutproof.core.enums import FindingName, IntentStatus, TruthState
from payoutproof.storage.db import Database
from payoutproof.storage.encrypted_store import EncryptedObjectStore


def make_valid_wav(duration_s: float = 2.0, sample_rate: int = 16000) -> bytes:
    """Generate valid 16-bit mono PCM WAV bytes."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(sample_rate)
        n_frames = int(duration_s * sample_rate)
        w.writeframes(b"\x00\x00" * n_frames)
    return buf.getvalue()


@pytest.fixture
def temp_store_dir():
    temp_dir = tempfile.mkdtemp(prefix="payoutproof_audio_store_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_key():
    return "0123456789abcdef0123456789abcdef"


@pytest.fixture
def object_store(temp_store_dir, test_key):
    return EncryptedObjectStore(base_dir=temp_store_dir, encryption_key=test_key)


@pytest.fixture
def db(tmp_path):
    return Database(
        db_path=str(tmp_path / "audio_test.db"),
        audit_checkpoint_secret="test-audit-secret-32-chars-long-minimum",
    )


@pytest.fixture
def valid_authority() -> Dict[str, Any]:
    return {
        "data_class": "VOICE_RECORDING",
        "source": "RECORDED_CALL_SYSTEM",
        "subject_category": "AUTHORIZED_SIGNER",
        "submitter": "call-ops@example.com",
        "purpose": "Verbal corroboration of high-value payout instruction",
        "asserted_authority_ref": "REF-VOICE-AUTH-9901",
        "permitted_uses": ["PAYOUT_VERIFICATION"],
        "processing_route": "LOCAL_ONLY",
        "redaction_declaration": "PII masked according to standard policy",
        "retention_days": 180,
        "legal_hold": False,
        "restrictions": [],
        "is_valid": True,
    }


# ─── 1. AUDIO CONTAINER & PARSING TESTS ──────────────────────────────────────

def test_parse_valid_wav_metadata():
    """WAV parser extracts valid duration, sample rate, channels, and bit depth."""
    wav_bytes = make_valid_wav(duration_s=2.5, sample_rate=16000)
    meta = parse_audio_metadata(wav_bytes)
    assert meta.format == "audio/wav"
    assert meta.duration_ms == 2500
    assert meta.sample_rate_hz == 16000
    assert meta.channels == 1
    assert meta.bits_per_sample == 16
    assert meta.size_bytes == len(wav_bytes)


def test_corrupted_wav_header_raises_error():
    """Corrupted/truncated WAV header raises AudioCorruptedError."""
    truncated = b"RIFF\x20\x00\x00\x00WAVEfmt "
    with pytest.raises(AudioCorruptedError):
        parse_audio_metadata(truncated)


def test_unsupported_audio_format_raises_error():
    """Unknown or unsupported audio formats raise AudioFormatError."""
    random_bytes = b"FLAC\x00\x00\x00\x22\x10\x00\x10\x00"
    with pytest.raises(AudioFormatError):
        parse_audio_metadata(random_bytes)


# ─── 2. REPRESENTATIVE LANGUAGE STRATA & FIELD PROVENANCE ───────────────────

def test_audio_extraction_en_in_with_field_provenance(db, object_store, valid_authority):
    """en-IN audio extracts PaymentIntent with exact field-level audio timestamps and hash."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    wav_bytes = make_valid_wav(duration_s=10.0, sample_rate=16000)
    adm_res = adm_service.admit_evidence(
        case_id="case-voice-en-in",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_authority,
        content=wav_bytes,
        declared_mime_type="audio/wav",
        title="Voice Verification Call en-IN",
    )
    assert adm_res.status.value == "ADMITTED"

    job = agent_service.run_extraction_job(
        case_id="case-voice-en-in",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.AUDIO_SUCCESS_EN_IN,
    )

    assert job.status == JobStatus.SUCCEEDED
    assert job.confidence >= 0.80
    assert job.error_code is None

    # Verify RiskCase state
    case_row = db.load_case("case-voice-en-in")
    assert case_row is not None
    assert case_row.intent.status == IntentStatus.EXTRACTED
    assert case_row.intent.counterparty == "Acme Tech Solutions Ltd"
    assert case_row.intent.amount == "425000"
    assert case_row.intent.destination == "HDFC0001234:9876543210"

    # Verify field-level audio provenance
    provs = case_row.intent.provenance
    assert len(provs) >= 4
    # Check that provenance contains audio timestamps and content hash
    assert any("audio:field=counterparty" in p and adm_res.content_hash[:12] in p for p in provs)
    assert any("audio:field=amount" in p and "t=" in p for p in provs)
    assert any("audio:field=destination" in p for p in provs)

    # Verify CaseInvestigation diagnostics
    inv = case_row.investigation
    assert inv.model_status == "COMPLETED"
    assert inv.asr_confidence >= 0.80
    assert inv.language_stratum == "en-IN"
    assert inv.attempt >= 1


def test_audio_extraction_hi_in(db, object_store, valid_authority):
    """hi-IN audio extracts Hindi-spoken PaymentIntent and updates case state."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    wav_bytes = make_valid_wav(duration_s=9.0, sample_rate=16000)
    adm_res = adm_service.admit_evidence(
        case_id="case-voice-hi-in",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_authority,
        content=wav_bytes,
        declared_mime_type="audio/wav",
        title="Voice Verification Call hi-IN",
    )

    job = agent_service.run_extraction_job(
        case_id="case-voice-hi-in",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.AUDIO_SUCCESS_HI_IN,
    )

    assert job.status == JobStatus.SUCCEEDED

    case_row = db.load_case("case-voice-hi-in")
    assert case_row.intent.status == IntentStatus.EXTRACTED
    assert case_row.intent.counterparty == "भारत ट्रेडर्स"
    assert case_row.intent.amount == "150000"
    assert case_row.intent.destination == "SBIN0004321:1122334455"

    assert case_row.investigation.language_stratum == "hi-IN"
    assert case_row.investigation.model_status == "COMPLETED"


# ─── 3. ANTI-SPOOF & ASR DIAGNOSTICS ────────────────────────────────────────

def test_anti_spoof_genuine_records_supported_finding(db, object_store, valid_authority):
    """Genuine human speech records FindingName.AASIST_SYNTHETIC_SCORE as SUPPORTED."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    wav_bytes = make_valid_wav(duration_s=3.0)
    adm_res = adm_service.admit_evidence(
        case_id="case-genuine",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_authority,
        content=wav_bytes,
    )

    job = agent_service.run_extraction_job(
        case_id="case-genuine",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.AUDIO_SUCCESS_EN_IN,
    )

    case_row = db.load_case("case-genuine")
    aasist_findings = [f for f in case_row.findings if f.name == FindingName.AASIST_SYNTHETIC_SCORE.value]
    assert len(aasist_findings) == 1
    assert aasist_findings[0].truth_state == TruthState.SUPPORTED
    assert "genuine" in aasist_findings[0].detail.lower()


def test_synthetic_speech_detection_fails_closed(db, object_store, valid_authority):
    """Synthetic speech detection triggers fail-closed behavior, refuting authenticity."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    wav_bytes = make_valid_wav(duration_s=3.0)
    adm_res = adm_service.admit_evidence(
        case_id="case-spoof",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_authority,
        content=wav_bytes,
    )

    job = agent_service.run_extraction_job(
        case_id="case-spoof",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.AUDIO_SPOOF_DETECTED,
    )

    assert job.status == JobStatus.FAILED
    assert job.error_code == ExtractionFailureReason.SPOOF_DETECTED.value

    case_row = db.load_case("case-spoof")
    # Intent MUST NOT be extracted or confirmed
    assert case_row.intent.status == IntentStatus.NOT_EXTRACTED

    # AASIST finding must be CONTRADICTED
    aasist_findings = [f for f in case_row.findings if f.name == FindingName.AASIST_SYNTHETIC_SCORE.value]
    assert len(aasist_findings) == 1
    assert aasist_findings[0].truth_state == TruthState.CONTRADICTED

    # Investigation status must report spoof detection
    assert case_row.investigation.model_status == "SPOOF_DETECTED"


def test_uncertain_acoustic_quality(db, object_store, valid_authority):
    """Uncertain acoustic quality maps to INSUFFICIENT_QUALITY finding."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    wav_bytes = make_valid_wav(duration_s=3.0)
    adm_res = adm_service.admit_evidence(
        case_id="case-uncertain",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_authority,
        content=wav_bytes,
    )

    job = agent_service.run_extraction_job(
        case_id="case-uncertain",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.AUDIO_UNCERTAIN_SPOOF,
    )

    case_row = db.load_case("case-uncertain")
    aasist_findings = [f for f in case_row.findings if f.name == FindingName.AASIST_SYNTHETIC_SCORE.value]
    assert len(aasist_findings) == 1
    assert aasist_findings[0].truth_state == TruthState.INSUFFICIENT_QUALITY


# ─── 4. MATERIAL AMBIGUITY & PROTECTIVE WORKFLOW BEHAVIOR ───────────────────

def test_material_ambiguity_fails_closed(db, object_store, valid_authority):
    """Unresolved material ambiguity in audio halts pipeline and prevents intent confirmation."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    wav_bytes = make_valid_wav(duration_s=8.0)
    adm_res = adm_service.admit_evidence(
        case_id="case-ambiguity",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_authority,
        content=wav_bytes,
    )

    job = agent_service.run_extraction_job(
        case_id="case-ambiguity",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.AUDIO_MATERIAL_AMBIGUITY,
    )

    assert job.status == JobStatus.FAILED
    assert job.error_code == ExtractionFailureReason.MATERIAL_AMBIGUITY.value

    case_row = db.load_case("case-ambiguity")
    # Crucial safety invariant: intent is NOT extracted!
    assert case_row.intent.status == IntentStatus.NOT_EXTRACTED
    assert case_row.investigation.model_status == "AMBIGUOUS"

    inst_findings = [f for f in case_row.findings if f.name == FindingName.INSTRUCTION_CONSISTENCY.value]
    assert len(inst_findings) == 1
    assert inst_findings[0].truth_state == TruthState.INSUFFICIENT_QUALITY
    assert "ambiguity" in inst_findings[0].detail.lower()


def test_corrupted_audio_fails_closed(db, object_store, valid_authority):
    """Corrupted audio payload fails closed with AUDIO_CORRUPTED."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    corrupted_bytes = b"RIFF\x00\x00\x00\x00WAVEtruncated"
    adm_res = adm_service.admit_evidence(
        case_id="case-corrupted-audio",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_authority,
        content=corrupted_bytes,
        declared_mime_type="audio/wav",
    )

    job = agent_service.run_extraction_job(
        case_id="case-corrupted-audio",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.AUDIO_CORRUPTED,
    )

    assert job.status == JobStatus.FAILED
    assert job.error_code == ExtractionFailureReason.AUDIO_CORRUPTED.value

    case_row = db.load_case("case-corrupted-audio")
    assert case_row.intent.status == IntentStatus.NOT_EXTRACTED


# ─── 5. API INTEGRATION TEST ─────────────────────────────────────────────────

def test_api_audio_extraction_flow(temp_store_dir, valid_authority):
    """End-to-end API test: upload audio evidence, run extraction, verify diagnostics."""
    config = AppConfig.for_tests(
        grant_secret="test-grant-secret-32-chars-long-minimum",
        audit_checkpoint_secret="test-audit-secret-32-chars-long-minimum",
        object_store_path=str(temp_store_dir),
        db_path=str(temp_store_dir / "api_audio_test.db"),
    )
    app = create_app(config=config)
    client = TestClient(app)

    session_token = app.state.session_store.mint(
        subject="operator-audio-1",
        display_name="Audio Operator",
        role=Role.PAYMENT_OPERATOR,
        tenant_id="tenant-voice",
        organization_id="org-voice",
        idp_issuer="https://idp.local",
    )
    client.cookies.set("payoutproof_session", session_token)

    # 1. Admit WAV audio
    wav_bytes = make_valid_wav(duration_s=3.0)
    adm_payload = {
        "case_id": "case-api-audio",
        "item_type": "VOICE_RECORDING",
        "title": "Verbal Authorization",
        "content_base64": base64.b64encode(wav_bytes).decode("ascii"),
        "declared_mime_type": "audio/wav",
        "processing_authority": valid_authority,
    }
    adm_res = client.post("/api/evidence/admit", json=adm_payload)
    assert adm_res.status_code == 200
    evidence_id = adm_res.json()["evidence_id"]

    # 2. Run extraction job via API with AUDIO_SUCCESS_EN_IN
    extract_payload = {
        "evidence_id": evidence_id,
        "simulation_mode": "AUDIO_SUCCESS_EN_IN",
    }
    job_res = client.post("/api/cases/case-api-audio/jobs/extract", json=extract_payload)
    assert job_res.status_code == 200, job_res.text
    job_data = job_res.json()
    assert job_data["status"] == "SUCCEEDED"
    assert job_data["result"] is not None
    assert "audio_diagnostics" in job_data["result"]
    diag = job_data["result"]["audio_diagnostics"]
    assert diag["language_stratum"] == "en-IN"
    assert diag["metadata"]["duration_ms"] == 3000
    assert diag["anti_spoof"]["status"] == "GENUINE"
