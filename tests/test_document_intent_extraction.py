"""Comprehensive test suite for representative document and image Payment Intent extraction (Issue #16)."""

from __future__ import annotations

import base64
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from payoutproof.admission.service import AdmissionService
from payoutproof.agent.document import (
    BoundingBox,
    DocumentCorruptedError,
    DocumentFormatError,
    parse_document_metadata,
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


MINIMAL_PDF_BYTES = (
    b"%PDF-1.4\n"
    b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"
    b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n"
    b"3 0 obj<< /Type /Page >>endobj\n"
    b"xref\n0 4\n"
    b"trailer<< /Root 1 0 R >>\n%%EOF"
)

MINIMAL_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    b"\x00\x00\x01\x00\x00\x00\x00\x80\x08\x02\x00\x00\x00"  # 256 x 128
    b"\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\r\xefI5"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)

MINIMAL_JPEG_BYTES = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"
    b"\xff\xc0\x00\x11\x08\x00\x64\x00\x64\x01\x01\x11\x00"  # 100 x 100
    b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xff\xd9"
)


@pytest.fixture
def temp_store_dir():
    temp_dir = tempfile.mkdtemp(prefix="payoutproof_doc_store_")
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
        db_path=str(tmp_path / "doc_test.db"),
        audit_checkpoint_secret="test-audit-secret-32-chars-long-minimum",
    )


@pytest.fixture
def valid_doc_authority() -> Dict[str, Any]:
    return {
        "data_class": "FINANCIAL_DOCUMENT",
        "source": "VENDOR_INVOICE_SUBMISSION",
        "subject_category": "VENDOR",
        "submitter": "invoices@example.com",
        "purpose": "Corroboration of vendor payment instruction",
        "asserted_authority_ref": "REF-DOC-AUTH-4491",
        "permitted_uses": ["PAYOUT_VERIFICATION"],
        "processing_route": "LOCAL_ONLY",
        "redaction_declaration": "PII masked according to standard policy",
        "retention_days": 180,
        "legal_hold": False,
        "restrictions": [],
        "is_valid": True,
    }


# ─── 1. CONTAINER VALIDATION TESTS ──────────────────────────────────────────

def test_parse_pdf_metadata():
    """PDF parser detects page count and format."""
    meta = parse_document_metadata(MINIMAL_PDF_BYTES)
    assert meta.format == "application/pdf"
    assert meta.page_count >= 1
    assert meta.size_bytes == len(MINIMAL_PDF_BYTES)


def test_parse_png_metadata():
    """PNG parser detects dimensions and format."""
    meta = parse_document_metadata(MINIMAL_PNG_BYTES)
    assert meta.format == "image/png"
    assert meta.page_count == 1
    assert meta.width_px == 256
    assert meta.height_px == 128


def test_parse_jpeg_metadata():
    """JPEG parser detects SOF dimensions and format."""
    meta = parse_document_metadata(MINIMAL_JPEG_BYTES)
    assert meta.format == "image/jpeg"
    assert meta.page_count == 1
    assert meta.width_px == 100
    assert meta.height_px == 100


def test_corrupted_document_raises_error():
    """Truncated document header raises DocumentCorruptedError."""
    truncated = b"%PDF"
    with pytest.raises(DocumentCorruptedError):
        parse_document_metadata(truncated)


def test_unsupported_document_format_raises_error():
    """Unsupported binary format raises DocumentFormatError."""
    unsupported = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    with pytest.raises(DocumentFormatError):
        parse_document_metadata(unsupported)


# ─── 2. PDF EXTRACTION & BOUNDING BOX LOCATION PROVENANCE ───────────────────

def test_pdf_extraction_with_bounding_boxes(db, object_store, valid_doc_authority):
    """PDF invoice extracts PaymentIntent with exact page numbers and bounding box coordinates."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    adm_res = adm_service.admit_evidence(
        case_id="case-doc-pdf",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_doc_authority,
        content=MINIMAL_PDF_BYTES,
        declared_mime_type="application/pdf",
        title="Vendor Invoice PDF",
    )
    assert adm_res.status.value == "ADMITTED"

    job = agent_service.run_extraction_job(
        case_id="case-doc-pdf",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.DOCUMENT_SUCCESS_PDF,
    )

    assert job.status == JobStatus.SUCCEEDED
    assert job.confidence >= 0.80
    assert job.error_code is None

    # Verify Risk Case state
    case_row = db.load_case("case-doc-pdf")
    assert case_row is not None
    assert case_row.intent.status == IntentStatus.EXTRACTED
    assert case_row.intent.counterparty == "Acme Tech Solutions Ltd"
    assert case_row.intent.amount == "425000"
    assert case_row.intent.destination == "HDFC0001234:9876543210"
    assert case_row.intent.instruction_reference == "INV-2026-8819"

    # Verify location-aware bounding box provenance
    provs = case_row.intent.provenance
    assert len(provs) >= 5
    # Verify page, box, and hash formatting
    assert any("doc:field=counterparty" in p and "page=1" in p and "box=" in p for p in provs)
    assert any("doc:field=amount" in p and adm_res.content_hash[:12] in p for p in provs)
    assert any("doc:field=destination" in p and "box=" in p for p in provs)

    # Verify CaseInvestigation diagnostics
    assert case_row.investigation.model_status == "COMPLETED"
    assert case_row.investigation.attempt >= 1

    # Verify finding is SUPPORTED
    findings = [f for f in case_row.findings if f.name == FindingName.INSTRUCTION_CONSISTENCY.value]
    assert len(findings) == 1
    assert findings[0].truth_state == TruthState.SUPPORTED


# ─── 3. SCANNED IMAGE EXTRACTION ────────────────────────────────────────────

def test_image_extraction_png(db, object_store, valid_doc_authority):
    """Scanned PNG receipt extracts PaymentIntent with spatial coordinates."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    adm_res = adm_service.admit_evidence(
        case_id="case-doc-png",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_doc_authority,
        content=MINIMAL_PNG_BYTES,
        declared_mime_type="image/png",
        title="Scanned Receipt PNG",
    )

    job = agent_service.run_extraction_job(
        case_id="case-doc-png",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.DOCUMENT_SUCCESS_IMAGE,
    )

    assert job.status == JobStatus.SUCCEEDED

    case_row = db.load_case("case-doc-png")
    assert case_row.intent.status == IntentStatus.EXTRACTED
    assert case_row.intent.counterparty == "Acme Tech Solutions Ltd"
    assert case_row.investigation.model_status == "COMPLETED"


# ─── 4. MATERIAL CONTRADICTION & FAIL-CLOSED BEHAVIOR ───────────────────────

def test_document_contradiction_fails_closed(db, object_store, valid_doc_authority):
    """Contradictory remittance amounts or multiple bank accounts fail closed."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    adm_res = adm_service.admit_evidence(
        case_id="case-contradiction",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_doc_authority,
        content=MINIMAL_PDF_BYTES,
    )

    job = agent_service.run_extraction_job(
        case_id="case-contradiction",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.DOCUMENT_CONTRADICTION,
    )

    assert job.status == JobStatus.FAILED
    assert job.error_code == ExtractionFailureReason.MATERIAL_AMBIGUITY.value

    case_row = db.load_case("case-contradiction")
    # Intent MUST NOT be extracted or confirmed!
    assert case_row.intent.status == IntentStatus.NOT_EXTRACTED
    assert case_row.investigation.model_status == "AMBIGUOUS"

    inst_findings = [f for f in case_row.findings if f.name == FindingName.INSTRUCTION_CONSISTENCY.value]
    assert len(inst_findings) == 1
    assert inst_findings[0].truth_state == TruthState.INSUFFICIENT_QUALITY
    assert "contradiction" in inst_findings[0].detail.lower()


def test_document_low_confidence_fails_closed(db, object_store, valid_doc_authority):
    """Low OCR confidence (< 0.80) fails closed with INSUFFICIENT_QUALITY."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    adm_res = adm_service.admit_evidence(
        case_id="case-doc-low-conf",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_doc_authority,
        content=MINIMAL_PDF_BYTES,
    )

    job = agent_service.run_extraction_job(
        case_id="case-doc-low-conf",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.DOCUMENT_LOW_CONFIDENCE,
    )

    assert job.status == JobStatus.FAILED
    assert job.error_code == ExtractionFailureReason.LOW_CONFIDENCE.value

    case_row = db.load_case("case-doc-low-conf")
    assert case_row.intent.status == IntentStatus.NOT_EXTRACTED


def test_corrupted_document_fails_closed(db, object_store, valid_doc_authority):
    """Corrupted document fails closed with DOCUMENT_CORRUPTED."""
    adm_service = AdmissionService(db=db, object_store=object_store)
    agent_service = TrustAgentService(db=db, object_store=object_store)

    corrupted_bytes = b"%PDF-truncated-header"
    adm_res = adm_service.admit_evidence(
        case_id="case-corrupted-doc",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=valid_doc_authority,
        content=corrupted_bytes,
        declared_mime_type="application/pdf",
    )

    job = agent_service.run_extraction_job(
        case_id="case-corrupted-doc",
        evidence_id=adm_res.evidence_id,
        organization_id="org-1",
        tenant_id="tenant-1",
        simulation_mode=SimulationMode.DOCUMENT_CORRUPTED,
    )

    assert job.status == JobStatus.FAILED
    assert job.error_code == ExtractionFailureReason.DOCUMENT_CORRUPTED.value

    case_row = db.load_case("case-corrupted-doc")
    assert case_row.intent.status == IntentStatus.NOT_EXTRACTED


# ─── 5. API END-TO-END DOCUMENT EXTRACTION FLOW ──────────────────────────────

def test_api_document_extraction_flow(temp_store_dir, valid_doc_authority):
    """End-to-end API test: upload PDF invoice, run extraction, verify OCR provenance and diagnostics."""
    config = AppConfig.for_tests(
        grant_secret="test-grant-secret-32-chars-long-minimum",
        audit_checkpoint_secret="test-audit-secret-32-chars-long-minimum",
        object_store_path=str(temp_store_dir),
        db_path=str(temp_store_dir / "api_doc_test.db"),
    )
    app = create_app(config=config)
    client = TestClient(app)

    session_token = app.state.session_store.mint(
        subject="operator-doc-1",
        display_name="Document Operator",
        role=Role.PAYMENT_OPERATOR,
        tenant_id="tenant-docs",
        organization_id="org-docs",
        idp_issuer="https://idp.local",
    )
    client.cookies.set("payoutproof_session", session_token)

    # 1. Admit PDF invoice
    adm_payload = {
        "case_id": "case-api-doc",
        "item_type": "DOCUMENT",
        "title": "Vendor PDF Invoice",
        "content_base64": base64.b64encode(MINIMAL_PDF_BYTES).decode("ascii"),
        "declared_mime_type": "application/pdf",
        "processing_authority": valid_doc_authority,
    }
    adm_res = client.post("/api/evidence/admit", json=adm_payload)
    assert adm_res.status_code == 200
    evidence_id = adm_res.json()["evidence_id"]

    # 2. Run extraction job via API
    extract_payload = {
        "evidence_id": evidence_id,
        "simulation_mode": "DOCUMENT_SUCCESS_PDF",
    }
    job_res = client.post("/api/cases/case-api-doc/jobs/extract", json=extract_payload)
    assert job_res.status_code == 200, job_res.text
    job_data = job_res.json()
    assert job_data["status"] == "SUCCEEDED"
    assert job_data["result"] is not None
    assert "document_diagnostics" in job_data["result"]

    diag = job_data["result"]["document_diagnostics"]
    assert diag["ocr_provider_id"] == "pilot-doc-ocr-v1"
    assert diag["ocr_model_version"] == "layoutlm-in-v2.1"
    assert diag["ocr_confidence"] >= 0.80
    assert diag["metadata"]["format"] == "application/pdf"
    assert "counterparty" in diag["field_provenances"]
    assert diag["field_provenances"]["counterparty"]["bbox"] is not None
