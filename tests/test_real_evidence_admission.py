"""Comprehensive test suite for authorized real evidence admission and encrypted preservation (Issue #13)."""

from __future__ import annotations

import base64
import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Any

import pytest
from fastapi.testclient import TestClient

from payoutproof.admission.detector import (
    inspect_evidence_bytes,
    is_archive_payload,
    is_executable_or_malicious,
    EICAR_TEST_STRING,
)
from payoutproof.admission.service import (
    AdmissionService,
    AdmissionStatus,
    UploadStage,
    UploadProgress,
)
from payoutproof.admission.validator import AdmissionValidator
from payoutproof.api.app import create_app
from payoutproof.auth.roles import Role
from payoutproof.core.config import AppConfig
from payoutproof.core.enums import CasePhase, ReasonCode
from payoutproof.core.keys import KeyRing
from payoutproof.core.models import ProcessingAuthorityRecord
from payoutproof.core.providers import FixedClock, SystemClock
from payoutproof.storage.db import Database
from payoutproof.storage.encrypted_store import (
    EncryptedObjectStore,
    DecryptionIntegrityError,
    ObjectNotFoundError,
)


@pytest.fixture
def temp_store_dir():
    temp_dir = tempfile.mkdtemp(prefix="payoutproof_test_store_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_key():
    return "0123456789abcdef0123456789abcdef"  # 32 characters


@pytest.fixture
def object_store(temp_store_dir, test_key):
    return EncryptedObjectStore(base_dir=temp_store_dir, encryption_key=test_key)


@pytest.fixture
def db(tmp_path):
    return Database(
        db_path=str(tmp_path / "test.db"),
        audit_checkpoint_secret="test-audit-secret-32-chars-long-minimum",
    )


@pytest.fixture
def valid_authority() -> Dict[str, Any]:
    return {
        "data_class": "FINANCIAL_DOCUMENT",
        "source": "VENDOR_PORTAL",
        "subject_category": "VENDOR",
        "submitter": "operator@example.com",
        "purpose": "Evidence corroboration for pilot disbursement #442",
        "asserted_authority_ref": "REF-REG-2026-9912",
        "permitted_uses": ["PAYOUT_VERIFICATION"],
        "processing_route": "LOCAL_ONLY",
        "redaction_declaration": "PII masked according to standard policy",
        "retention_days": 180,
        "legal_hold": False,
        "restrictions": [],
        "is_valid": True,
    }


# ─── 1. AUTHORITY GATE TESTS ──────────────────────────────────────────────────

def test_missing_processing_authority_rejects_without_opening_case(db, object_store):
    """Missing Processing Authority produces Admission Rejection before a Risk Case is opened."""
    service = AdmissionService(db=db, object_store=object_store)
    content = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>%%EOF"

    stages = []
    result = service.admit_evidence(
        case_id="case-no-auth",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=None,
        content=content,
        progress_callback=lambda p: stages.append(p.stage),
    )

    assert result.status == AdmissionStatus.ADMISSION_REJECTED
    assert result.reason_code == ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE
    assert UploadStage.REJECTED.value in result.progress_history

    # Verify no case exists in the database
    with db.get_connection() as conn:
        row = conn.execute("SELECT * FROM risk_cases WHERE case_id = 'case-no-auth'").fetchone()
        assert row is None, "Risk case must NOT be created when processing authority is missing"

        # Verify no evidence was persisted
        ev_row = conn.execute("SELECT * FROM admitted_evidence WHERE case_id = 'case-no-auth'").fetchone()
        assert ev_row is None


def test_invalid_processing_authority_rejects_without_opening_case(db, object_store, valid_authority):
    """Invalid Processing Authority (e.g. marked invalid) rejects immediately."""
    service = AdmissionService(db=db, object_store=object_store)
    invalid_auth = dict(valid_authority)
    invalid_auth["is_valid"] = False

    result = service.admit_evidence(
        case_id="case-bad-auth",
        tenant_id="tenant-1",
        organization_id="org-1",
        processing_authority=invalid_auth,
        content=b"%PDF-1.4 test",
    )

    assert result.status == AdmissionStatus.ADMISSION_REJECTED
    assert result.reason_code == ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE

    with db.get_connection() as conn:
        assert conn.execute("SELECT * FROM risk_cases WHERE case_id = 'case-bad-auth'").fetchone() is None


# ─── 2. CONTENT DETECTION & ALLOWLIST TESTS ───────────────────────────────────

def test_content_detection_supported_media():
    """Verify content detection succeeds across all supported file types."""
    samples = {
        "application/pdf": b"%PDF-1.5 test pdf content %%EOF",
        "audio/wav": b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00data\x00\x00\x00\x00",
        "audio/mpeg": b"ID3\x03\x00\x00\x00\x00\x00#mp3 audio frames",
        "audio/ogg": b"OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00vorbis",
        "image/png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01",
        "image/jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9",
        "application/json": b'{"payout_intent_id": "pi_12345", "verified": true}',
        "text/plain": b"Payout transaction verification report text.",
    }

    for expected_mime, data in samples.items():
        ok, detected, err, reason = inspect_evidence_bytes(data)
        assert ok is True, f"Failed for {expected_mime}: {err}"
        assert detected == expected_mime


def test_client_mime_spoofing_rejected():
    """Client asserting audio/wav on plain text fails closed as MALFORMED_INPUT."""
    plain_text = b"This is plainly just an ASCII text payload, not audio."
    ok, detected, err, reason = inspect_evidence_bytes(
        plain_text, declared_mime_type="audio/wav"
    )
    assert ok is False
    assert reason == ReasonCode.MALFORMED_INPUT
    assert "spoofing detected" in err


def test_archive_payloads_strictly_prohibited():
    """ZIP, TAR, GZ, 7Z, RAR, BZ2 archives are strictly rejected as PROHIBITED_INPUT."""
    zip_header = b"PK\x03\x04\x14\x00\x00\x00"
    tar_header = b"\x00" * 257 + b"ustar\x00"
    gz_header = b"\x1f\x8b\x08\x00"
    seven_z = b"7z\xbc\xaf\x27\x1c"

    for payload in (zip_header, tar_header, gz_header, seven_z):
        is_arch, _ = is_archive_payload(payload)
        assert is_arch is True
        ok, _, err, reason = inspect_evidence_bytes(payload)
        assert ok is False
        assert reason == ReasonCode.PROHIBITED_INPUT


# ─── 3. MALWARE & QUARANTINE TESTS ────────────────────────────────────────────

def test_executable_and_eicar_quarantined(db, object_store, valid_authority):
    """Executables (ELF, PE, Mach-O), scripts, and EICAR strings are quarantined."""
    threats = {
        "eicar": EICAR_TEST_STRING.encode("ascii"),
        "pe_executable": b"MZ\x90\x00\x03\x00\x00\x00This program cannot be run in DOS mode",
        "elf_binary": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20,
        "script_injection": b"<html><body><script>alert('pwned')</script></body></html>",
    }

    service = AdmissionService(db=db, object_store=object_store)

    for name, payload in threats.items():
        is_threat, threat_desc = is_executable_or_malicious(payload)
        assert is_threat is True, f"Failed to identify threat: {name}"

        result = service.admit_evidence(
            case_id=f"case-threat-{name}",
            tenant_id="tenant-1",
            organization_id="org-1",
            processing_authority=valid_authority,
            content=payload,
        )

        assert result.status == AdmissionStatus.QUARANTINED
        assert result.reason_code == ReasonCode.PROHIBITED_INPUT
        assert result.quarantine_threat is not None
        assert UploadStage.QUARANTINED.value in result.progress_history

        # Quarantined record is persisted in ledger with status QUARANTINED
        record = db.load_admitted_evidence(result.evidence_id)
        assert record is not None
        assert record["lifecycle_status"] == "QUARANTINED"
        assert record["quarantine_reason"] == result.quarantine_threat


# ─── 4. ENCRYPTED OBJECT STORE TESTS ──────────────────────────────────────────

def test_encrypted_object_store_lifecycle(temp_store_dir, test_key):
    """Raw evidence is encrypted using AES-256-GCM and verified upon retrieval."""
    store = EncryptedObjectStore(base_dir=temp_store_dir, encryption_key=test_key)
    raw_evidence = b"%PDF-1.4 invoice payment corroboration payload bytes"

    ref = store.put(
        tenant_id="tenant-a",
        organization_id="org-b",
        case_id="case-100",
        evidence_id="ev-100",
        content=raw_evidence,
    )

    assert ref.storage_uri.startswith("enc-file://")
    assert ref.plaintext_size_bytes == len(raw_evidence)
    assert ref.ciphertext_size_bytes > len(raw_evidence)  # includes version, nonce, tag
    assert ref.encryption_algorithm == "AES-256-GCM"

    # Verify disk content is encrypted (does NOT match plaintext)
    raw_disk_bytes = store.get_raw_encrypted_bytes(ref.storage_uri)
    assert raw_disk_bytes != raw_evidence
    assert b"invoice payment corroboration" not in raw_disk_bytes

    # Retrieve and decrypt
    decrypted, out_ref = store.get(ref.storage_uri)
    assert decrypted == raw_evidence
    assert out_ref.content_hash == ref.content_hash

    # Representation must not leak key
    assert test_key not in repr(store)
    assert test_key not in str(store)
    assert "[REDACTED]" in repr(store)


def test_tampered_ciphertext_fails_decryption(temp_store_dir, test_key):
    """Tampering with encrypted bytes causes DecryptionIntegrityError."""
    store = EncryptedObjectStore(base_dir=temp_store_dir, encryption_key=test_key)
    ref = store.put(
        tenant_id="t1",
        organization_id="o1",
        case_id="c1",
        evidence_id="e1",
        content=b"%PDF-1.4 tamper test",
    )

    file_path = store._path_from_uri(ref.storage_uri)
    corrupted_bytes = bytearray(file_path.read_bytes())
    corrupted_bytes[-5] ^= 0xFF  # Corrupt the authentication tag
    file_path.write_bytes(corrupted_bytes)

    with pytest.raises(DecryptionIntegrityError):
        store.get(ref.storage_uri)


def test_aad_mismatch_prevents_cross_tenant_substitution(temp_store_dir, test_key):
    """Tampering with AAD parameters fails AEAD authentication."""
    store = EncryptedObjectStore(base_dir=temp_store_dir, encryption_key=test_key)
    ref = store.put(
        tenant_id="tenant-1",
        organization_id="org-1",
        case_id="case-1",
        evidence_id="ev-1",
        content=b"%PDF-1.4 secret",
    )

    # Attempting to decrypt with forged AAD (cross-tenant substitution)
    disk_data = store.get_raw_encrypted_bytes(ref.storage_uri)
    with pytest.raises(DecryptionIntegrityError):
        store._decrypt(
            payload=disk_data,
            tenant_id="tenant-2",  # Forged tenant!
            organization_id="org-1",
            case_id="case-1",
            evidence_id="ev-1",
        )


def test_key_rotation_retention_in_object_store(temp_store_dir):
    """Object store decrypts legacy records using retained keys in KeyRing."""
    ring_v1 = KeyRing(active_key_id="v1", keys={"v1": "key-secret-1-32-chars-long-min!!"})
    store_v1 = EncryptedObjectStore(base_dir=temp_store_dir, encryption_key=ring_v1)

    ref = store_v1.put(
        tenant_id="t",
        organization_id="o",
        case_id="c",
        evidence_id="e-rot",
        content=b"%PDF-1.4 pre-rotation document",
    )
    assert ref.key_id == "v1"

    # Rotate keys: v2 is active, v1 is retained
    ring_v2 = KeyRing(
        active_key_id="v2",
        keys={
            "v2": "key-secret-2-32-chars-long-min!!",
            "v1": "key-secret-1-32-chars-long-min!!",
        },
    )
    store_v2 = EncryptedObjectStore(base_dir=temp_store_dir, encryption_key=ring_v2)

    # Historical record still decrypts successfully using retained v1
    decrypted, out_ref = store_v2.get(ref.storage_uri, key_id=ref.key_id)
    assert decrypted == b"%PDF-1.4 pre-rotation document"

    # New write uses active v2 key
    ref_new = store_v2.put(
        tenant_id="t",
        organization_id="o",
        case_id="c",
        evidence_id="e-new",
        content=b"%PDF-1.4 post-rotation document",
    )
    assert ref_new.key_id == "v2"


# ─── 5. FULL ADMISSION WORKFLOW & DATABASE PERSISTENCE ────────────────────────

def test_successful_admission_workflow(db, object_store, valid_authority):
    """Valid evidence passes all gates, stores encrypted, and persists ledger."""
    service = AdmissionService(db=db, object_store=object_store)
    pdf_content = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>%%EOF"

    recorded_stages = []
    result = service.admit_evidence(
        case_id="case-valid-101",
        tenant_id="tenant-acme",
        organization_id="org-finance",
        processing_authority=valid_authority,
        content=pdf_content,
        declared_mime_type="application/pdf",
        title="Beneficiary Identity Verification",
        progress_callback=lambda p: recorded_stages.append(p.stage),
    )

    assert result.status == AdmissionStatus.ADMITTED
    assert result.reason_code is None
    assert result.detected_mime_type == "application/pdf"
    assert result.size_bytes == len(pdf_content)
    assert result.storage_uri is not None

    # Check progress stages visited
    assert UploadStage.INITIALIZED in recorded_stages
    assert UploadStage.VALIDATING_AUTHORITY in recorded_stages
    assert UploadStage.INSPECTING_CONTENT in recorded_stages
    assert UploadStage.SCANNING_SECURITY in recorded_stages
    assert UploadStage.ENCRYPTING_PAYLOAD in recorded_stages
    assert UploadStage.PERSISTING_LEDGER in recorded_stages
    assert UploadStage.COMPLETED in recorded_stages

    # Verify database persistence
    evidence_row = db.load_admitted_evidence(result.evidence_id)
    assert evidence_row is not None
    assert evidence_row["case_id"] == "case-valid-101"
    assert evidence_row["organization_id"] == "org-finance"
    assert evidence_row["lifecycle_status"] == "ADMITTED"
    assert evidence_row["plaintext_size_bytes"] == len(pdf_content)

    # Verify Risk Case was initialized
    with db.get_connection() as conn:
        case_row = conn.execute(
            "SELECT * FROM risk_cases WHERE case_id = 'case-valid-101'"
        ).fetchone()
        assert case_row is not None
        assert case_row["phase"] == CasePhase.INVESTIGATION.value


# ─── 6. API ENDPOINT TESTS ───────────────────────────────────────────────────

def test_api_admit_evidence_flow(temp_store_dir, valid_authority):
    """Test POST /api/evidence/admit and GET /api/evidence/{id}/status over HTTP."""
    config = AppConfig.for_tests(
        grant_secret="test-grant-secret-32-chars-long-minimum",
        audit_checkpoint_secret="test-audit-secret-32-chars-long-minimum",
        object_store_path=str(temp_store_dir),
        db_path=str(temp_store_dir / "api_test.db"),
    )
    app = create_app(config=config)
    client = TestClient(app)

    # Establish operator session
    session_store = app.state.session_store
    session_token = session_store.mint(
        subject="operator-42",
        display_name="Operator 42",
        role=Role.PAYMENT_OPERATOR,
        tenant_id="tenant-alpha",
        organization_id="org-beta",
        idp_issuer="https://idp.local",
    )
    client.cookies.set("payoutproof_session", session_token)

    # 1. Successful admission
    pdf_bytes = b"%PDF-1.4 test invoice receipt"
    req_body = {
        "case_id": "case-api-1",
        "item_type": "DOCUMENT",
        "title": "Vendor Invoice",
        "content_base64": base64.b64encode(pdf_bytes).decode("ascii"),
        "declared_mime_type": "application/pdf",
        "processing_authority": valid_authority,
    }

    res = client.post("/api/evidence/admit", json=req_body)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["status"] == "ADMITTED"
    assert data["detected_mime_type"] == "application/pdf"
    assert data["size_bytes"] == len(pdf_bytes)
    evidence_id = data["evidence_id"]

    # 2. Status inspection
    res_status = client.get(f"/api/evidence/{evidence_id}/status")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert status_data["evidence_id"] == evidence_id
    assert status_data["lifecycle_status"] == "ADMITTED"
    # Ensure no secrets leak
    assert "grant_secret" not in status_data
    assert "encryption_key" not in status_data

    # 3. List case evidence
    res_list = client.get("/api/cases/case-api-1/evidence")
    assert res_list.status_code == 200
    list_data = res_list.json()
    assert len(list_data["evidence"]) == 1
    assert list_data["evidence"][0]["evidence_id"] == evidence_id

    # 4. Rejection when authority is missing
    bad_req = dict(req_body)
    bad_req["case_id"] = "case-api-bad"
    bad_req["processing_authority"] = None
    res_bad = client.post("/api/evidence/admit", json=bad_req)
    assert res_bad.status_code == 400
    bad_data = res_bad.json()
    assert bad_data["status"] == "ADMISSION_REJECTED"

    # 5. Quarantine when malware is uploaded
    malware_req = dict(req_body)
    malware_req["case_id"] = "case-api-malware"
    malware_req["content_base64"] = base64.b64encode(EICAR_TEST_STRING.encode("ascii")).decode("ascii")
    res_malware = client.post("/api/evidence/admit", json=malware_req)
    assert res_malware.status_code == 422
    mal_data = res_malware.json()
    assert mal_data["status"] == "QUARANTINED"
    assert mal_data["quarantine_threat"] is not None
