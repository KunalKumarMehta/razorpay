"""Comprehensive test suite for Trust Agent extraction jobs with explicit failure states (Issue #14)."""

from __future__ import annotations

import base64
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from payoutproof.admission.service import AdmissionService
from payoutproof.agent.models import (
    ExtractionFailureReason,
    ExtractionJobRecord,
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
from payoutproof.core.enums import CasePhase, FindingName, IntentStatus, TruthState
from payoutproof.core.models import RiskCaseState
from payoutproof.storage.db import Database
from payoutproof.storage.encrypted_store import EncryptedObjectStore


@pytest.fixture
def temp_store_dir():
    temp_dir = tempfile.mkdtemp(prefix="payoutproof_agent_store_")
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
        db_path=str(tmp_path / "agent_test.db"),
        audit_checkpoint_secret="test-audit-secret-32-chars-long-minimum",
    )


@pytest.fixture
def valid_authority() -> Dict[str, Any]:
    return {
        "data_class": "FINANCIAL_DOCUMENT",
        "source": "VENDOR_PORTAL",
        "subject_category": "VENDOR",
        "submitter": "operator@example.com",
        "purpose": "Evidence corroboration for pilot payout",
        "asserted_authority_ref": "REF-AUTH-2026-001",
        "permitted_uses": ["PAYOUT_VERIFICATION"],
        "processing_route": "LOCAL_ONLY",
        "redaction_declaration": "PII masked according to standard policy",
        "retention_days": 180,
        "legal_hold": False,
        "restrictions": [],
        "is_valid": True,
    }


def admit_sample_evidence(
    service: AdmissionService,
    *,
    case_id: str,
    tenant_id: str = "tenant-1",
    organization_id: str = "org-1",
    authority: Dict[str, Any],
    content: bytes = b"%PDF-1.4 sample invoice text for payment payout",
    declared_mime: str = "application/pdf",
):
    """Helper to admit evidence into storage and database."""
    return service.admit_evidence(
        case_id=case_id,
        tenant_id=tenant_id,
        organization_id=organization_id,
        processing_authority=authority,
        content=content,
        declared_mime_type=declared_mime,
        title="Sample Test Document",
    )


# ─── 1. DETERMINISTIC PROVIDER SIMULATION TESTS ─────────────────────────────

def test_deterministic_provider_success():
    """DeterministicFakeProvider returns valid extraction on SUCCESS mode."""
    provider = DeterministicFakeProvider()
    content = b"%PDF-1.4 Payout to Acme Corp of USD 5000.00"
    res = provider.extract(
        evidence_bytes=content,
        evidence_meta={"data_class": "FINANCIAL_DOCUMENT", "tenant_id": "t1", "organization_id": "o1"},
        simulation_mode=SimulationMode.SUCCESS,
    )
    assert res.status == JobStatus.SUCCEEDED
    assert res.confidence >= 0.80
    assert res.extracted_intent is not None
    assert res.extracted_intent.counterparty == "Acme Tech Solutions Ltd"
    assert res.extracted_intent.amount == "425000"
    assert res.raw_output_ref.startswith("raw-ref://")
    assert res.failure_reason is None


def test_deterministic_provider_all_failure_modes():
    """DeterministicFakeProvider simulates all explicit failure modes accurately."""
    provider = DeterministicFakeProvider()
    content = b"sample content"

    modes_expected = [
        (SimulationMode.TIMEOUT, ExtractionFailureReason.TIMEOUT, JobStatus.TIMED_OUT),
        (SimulationMode.MALFORMED_SCHEMA, ExtractionFailureReason.MALFORMED_SCHEMA, JobStatus.FAILED),
        (SimulationMode.LOW_CONFIDENCE, ExtractionFailureReason.LOW_CONFIDENCE, JobStatus.FAILED),
        (SimulationMode.MISSING_SIGNAL, ExtractionFailureReason.MISSING_SIGNAL, JobStatus.FAILED),
        (SimulationMode.PROVIDER_OUTAGE, ExtractionFailureReason.PROVIDER_OUTAGE, JobStatus.FAILED),
        (SimulationMode.SECURITY_QUARANTINE, ExtractionFailureReason.SECURITY_QUARANTINE, JobStatus.QUARANTINED),
    ]

    for mode, expected_reason, expected_status in modes_expected:
        res = provider.extract(
            evidence_bytes=content,
            evidence_meta={"data_class": "FINANCIAL_DOCUMENT", "tenant_id": "t1", "organization_id": "o1"},
            simulation_mode=mode,
        )
        assert res.status == expected_status
        assert res.failure_reason == expected_reason
        if mode == SimulationMode.LOW_CONFIDENCE:
            assert res.confidence < 0.80
        elif mode == SimulationMode.MISSING_SIGNAL:
            assert res.extracted_intent is None
        elif mode == SimulationMode.TIMEOUT:
            assert res.confidence == 0.0


# ─── 2. TRUST AGENT SERVICE LIFECYCLE TESTS ─────────────────────────────────

def test_trust_agent_service_success_lifecycle(db, object_store, valid_authority):
    """Job progresses QUEUED -> PROCESSING -> SUCCEEDED and binds confirmed intent."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    adm_res = admit_sample_evidence(adm_service, case_id="case-100", authority=valid_authority)
    assert adm_res.status.value == "ADMITTED"

    job = agent_service.run_extraction_job(
        case_id="case-100",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.SUCCESS,
    )

    assert job.status == JobStatus.SUCCEEDED
    assert job.confidence >= 0.80
    assert job.error_code is None
    assert job.raw_output_ref is not None
    assert job.raw_output_ref.startswith("raw-ref://")
    assert job.source_provenance["evidence_hash"] == adm_res.content_hash

    # Verify Risk Case state update: PaymentIntent is extracted
    case_row = db.load_case("case-100")
    assert case_row is not None
    assert case_row.intent.status == IntentStatus.EXTRACTED
    assert case_row.intent.amount == "425000"
    assert case_row.intent.counterparty == "Acme Tech Solutions Ltd"

    # Verify findings are recorded as SUPPORTED
    supported_findings = [f for f in case_row.findings if f.truth_state == TruthState.SUPPORTED]
    assert len(supported_findings) > 0


# ─── 3. NON-CONVERSION GUARANTEES ───────────────────────────────────────────

def test_low_confidence_never_confirms_intent(db, object_store, valid_authority):
    """Low confidence (< 0.80) maps to INSUFFICIENT_QUALITY and NEVER confirms intent."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    adm_res = admit_sample_evidence(adm_service, case_id="case-low-conf", authority=valid_authority)

    job = agent_service.run_extraction_job(
        case_id="case-low-conf",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.LOW_CONFIDENCE,
    )

    assert job.status == JobStatus.FAILED
    assert job.confidence < 0.80
    assert job.error_code == ExtractionFailureReason.LOW_CONFIDENCE.value

    case_row = db.load_case("case-low-conf")
    # Crucial safety invariant: intent is NOT extracted/confirmed!
    assert case_row.intent.status == IntentStatus.NOT_EXTRACTED

    # Finding must be INSUFFICIENT_QUALITY, not SUPPORTED
    low_findings = [f for f in case_row.findings if f.truth_state == TruthState.INSUFFICIENT_QUALITY]
    assert len(low_findings) > 0
    assert not any(f.truth_state == TruthState.SUPPORTED for f in case_row.findings)


def test_missing_signal_maps_to_not_observed(db, object_store, valid_authority):
    """Missing signals in evidence map to NOT_OBSERVED and NEVER confirm intent."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    adm_res = admit_sample_evidence(adm_service, case_id="case-missing-sig", authority=valid_authority)

    job = agent_service.run_extraction_job(
        case_id="case-missing-sig",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.MISSING_SIGNAL,
    )

    assert job.status == JobStatus.FAILED
    assert job.error_code == ExtractionFailureReason.MISSING_SIGNAL.value

    case_row = db.load_case("case-missing-sig")
    assert case_row.intent.status == IntentStatus.NOT_EXTRACTED

    # Finding must be NOT_OBSERVED
    obs_findings = [f for f in case_row.findings if f.truth_state == TruthState.NOT_OBSERVED]
    assert len(obs_findings) > 0
    assert not any(f.truth_state == TruthState.SUPPORTED for f in case_row.findings)


def test_timeout_and_outage_never_confirm_intent(db, object_store, valid_authority):
    """Timeouts and outages map to NOT_EVALUATED and leave intent unconfirmed."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    for case_id, mode, expected_status in [
        ("case-timeout", SimulationMode.TIMEOUT, JobStatus.TIMED_OUT),
        ("case-outage", SimulationMode.PROVIDER_OUTAGE, JobStatus.FAILED),
    ]:
        adm_res = admit_sample_evidence(adm_service, case_id=case_id, authority=valid_authority)

        job = agent_service.run_extraction_job(
            case_id=case_id,
            evidence_id=adm_res.evidence_id,
            organization_id="org-1",
            tenant_id="tenant-1",
            simulation_mode=mode,
        )

        assert job.status == expected_status

        case_row = db.load_case(case_id)
        assert case_row.intent.status == IntentStatus.NOT_EXTRACTED

        uneval_findings = [f for f in case_row.findings if f.truth_state == TruthState.NOT_EVALUATED]
        assert len(uneval_findings) > 0
        assert not any(f.truth_state == TruthState.SUPPORTED for f in case_row.findings)


def test_quarantined_evidence_aborts_job(db, object_store, valid_authority):
    """Evidence marked QUARANTINED aborts extraction job immediately."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    # Malicious executable payload triggers quarantine during admission
    malware_bytes = b"MZ\x90\x00\x03\x00\x00\x00"
    adm_res = adm_service.admit_evidence(
        case_id="case-quarantine",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_authority,
        content=malware_bytes,
        title="Infected Document",
    )
    assert adm_res.status.value == "QUARANTINED"

    job = agent_service.run_extraction_job(
        case_id="case-quarantine",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.SUCCESS,
    )

    assert job.status == JobStatus.QUARANTINED
    assert job.error_code == ExtractionFailureReason.SECURITY_QUARANTINE.value
    assert "quarantined" in job.error_message.lower()


# ─── 4. IDEMPOTENCY AND TERMINAL REPROCESS TESTS ─────────────────────────────

def test_terminal_job_is_not_reprocessed(db, object_store, valid_authority):
    """Completed job is returned without re-invoking provider."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    adm_res = admit_sample_evidence(adm_service, case_id="case-idempotent", authority=valid_authority)
    job1 = agent_service.run_extraction_job(
        case_id="case-idempotent",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.SUCCESS,
    )
    assert job1.status == JobStatus.SUCCEEDED

    # Reprocessing returns identical terminal job
    job2 = agent_service.process_job(job1.job_id)
    assert job2.job_id == job1.job_id
    assert job2.status == JobStatus.SUCCEEDED
    assert job2.created_at == job1.created_at


# ─── 5. API ENDPOINT TESTS ───────────────────────────────────────────────────

def test_api_extraction_endpoints(temp_store_dir, valid_authority):
    """Verify POST /api/cases/{case_id}/jobs/extract, GET /api/jobs/{id}, GET /api/cases/{case_id}/jobs."""
    config = AppConfig.for_tests(
        grant_secret="test-grant-secret-32-chars-long-minimum",
        audit_checkpoint_secret="test-audit-secret-32-chars-long-minimum",
        object_store_path=str(temp_store_dir),
        db_path=str(temp_store_dir / "api_test.db"),
    )
    app = create_app(config=config)
    client = TestClient(app)

    session_token = app.state.session_store.mint(
        subject="operator-99",
        display_name="Operator 99",
        role=Role.PAYMENT_OPERATOR,
        tenant_id="tenant-alpha",
        organization_id="org-beta",
        idp_issuer="https://idp.local",
    )
    client.cookies.set("payoutproof_session", session_token)

    # 1. Admit evidence
    pdf_bytes = b"%PDF-1.4 Payment invoice of USD 7500.00 to Global Supplies"
    adm_payload = {
        "case_id": "case-api-extract",
        "item_type": "DOCUMENT",
        "title": "Supplies Invoice",
        "content_base64": base64.b64encode(pdf_bytes).decode("ascii"),
        "declared_mime_type": "application/pdf",
        "processing_authority": valid_authority,
    }
    adm_res = client.post("/api/evidence/admit", json=adm_payload)
    assert adm_res.status_code == 200
    evidence_id = adm_res.json()["evidence_id"]

    # 2. Run extraction job via API
    extract_payload = {
        "evidence_id": evidence_id,
        "simulation_mode": "success",
    }
    job_res = client.post("/api/cases/case-api-extract/jobs/extract", json=extract_payload)
    assert job_res.status_code == 200, job_res.text
    job_data = job_res.json()
    assert job_data["status"] == "SUCCEEDED"
    assert job_data["confidence"] >= 0.80
    assert job_data["raw_output_ref"].startswith("raw-ref://")
    job_id = job_data["job_id"]

    # 3. Get job details
    get_res = client.get(f"/api/jobs/{job_id}")
    assert get_res.status_code == 200
    get_data = get_res.json()
    assert get_data["job_id"] == job_id
    assert get_data["status"] == "SUCCEEDED"

    # 4. List case jobs
    list_res = client.get("/api/cases/case-api-extract/jobs")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert len(list_data["jobs"]) == 1
    assert list_data["jobs"][0]["job_id"] == job_id


def test_api_extraction_tenant_isolation(temp_store_dir, valid_authority):
    """Verify tenant isolation: operator cannot extract or view jobs from another organization."""
    config = AppConfig.for_tests(
        grant_secret="test-grant-secret-32-chars-long-minimum",
        audit_checkpoint_secret="test-audit-secret-32-chars-long-minimum",
        object_store_path=str(temp_store_dir),
        db_path=str(temp_store_dir / "isolation_test.db"),
    )
    app = create_app(config=config)
    client = TestClient(app)

    # Session for Org A
    token_a = app.state.session_store.mint(
        subject="user-a",
        display_name="User A",
        role=Role.PAYMENT_OPERATOR,
        tenant_id="tenant-A",
        organization_id="org-A",
        idp_issuer="https://idp.local",
    )
    client.cookies.set("payoutproof_session", token_a)

    # Admit evidence in Org A
    pdf_bytes = b"%PDF-1.4 Org A confidential statement"
    adm_payload = {
        "case_id": "case-org-a",
        "title": "Org A Invoice",
        "content_base64": base64.b64encode(pdf_bytes).decode("ascii"),
        "processing_authority": valid_authority,
    }
    adm_res = client.post("/api/evidence/admit", json=adm_payload)
    assert adm_res.status_code == 200
    evidence_id = adm_res.json()["evidence_id"]

    # Run extraction in Org A
    job_res = client.post(
        "/api/cases/case-org-a/jobs/extract",
        json={"evidence_id": evidence_id, "simulation_mode": "success"},
    )
    assert job_res.status_code == 200
    job_id = job_res.json()["job_id"]

    # Switch session to Org B
    token_b = app.state.session_store.mint(
        subject="user-b",
        display_name="User B",
        role=Role.PAYMENT_OPERATOR,
        tenant_id="tenant-B",
        organization_id="org-B",
        idp_issuer="https://idp.local",
    )
    client.cookies.set("payoutproof_session", token_b)

    # Org B trying to view Org A's job -> 404
    forbidden_get = client.get(f"/api/jobs/{job_id}")
    assert forbidden_get.status_code == 404

    # Org B trying to list Org A's case jobs -> 404
    forbidden_list = client.get("/api/cases/case-org-a/jobs")
    assert forbidden_list.status_code == 404

    # Org B trying to extract Org A's evidence -> 404
    forbidden_extract = client.post(
        "/api/cases/case-org-a/jobs/extract",
        json={"evidence_id": evidence_id, "simulation_mode": "success"},
    )
    assert forbidden_extract.status_code == 404
