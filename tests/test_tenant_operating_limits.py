"""Comprehensive test suite for Issue #10:
Enforce tenant operating limits and platform ceiling invariants.
"""

import json
import pytest
from fastapi.testclient import TestClient

from payoutproof.api.app import create_app
from payoutproof.core.config import AppConfig
from payoutproof.core.limits import (
    PLATFORM_GLOBAL_REQUESTS_PER_HOUR,
    PLATFORM_MAX_EVIDENCE_ITEM_BYTES,
    PLATFORM_MAX_PROCESSING_CONCURRENCY,
    PLATFORM_MAX_REQUEST_BODY_BYTES,
    PLATFORM_MAX_REQUESTS_PER_HOUR,
    PLATFORM_MAX_RETENTION_DAYS,
    PLATFORM_MIN_RETENTION_DAYS,
    PLATFORM_SUPPORTED_FORMATS,
    TenantOperatingLimits,
    effective_limits,
)
from payoutproof.admission.validator import ALLOWED_MIME_TYPES
from payoutproof.storage.db import Database
from tests.helpers import (
    TEST_AUDIT_CHECKPOINT_SECRET,
    TEST_GRANT_SECRET,
    make_authorized_bundle_action,
    make_valid_authority_record,
)

TEST_SETTINGS_TOKEN = "settings-admin-token-32-chars-long-secret"


@pytest.fixture
def limits_app(tmp_path):
    db_path = tmp_path / "limits_test.db"
    db = Database(db_path=db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    config = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(db_path),
        enable_settings_admin=True,
        settings_admin_token=TEST_SETTINGS_TOKEN,
    )
    app = create_app(config=config, db=db)
    client = TestClient(app)
    return {"app": app, "client": client, "db": db, "config": config}


def test_platform_ceilings_immutability_and_alignment():
    """Verify platform ceilings match core domain bounds."""
    # MIME formats align exactly
    assert PLATFORM_SUPPORTED_FORMATS == ALLOWED_MIME_TYPES
    # Retention ceiling aligns with models.py ProcessingAuthorityRecord bound
    assert PLATFORM_MAX_RETENTION_DAYS == 365
    assert PLATFORM_MIN_RETENTION_DAYS == 1
    # Evidence item bytes >= 10MB
    assert PLATFORM_MAX_EVIDENCE_ITEM_BYTES >= 10 * 1024 * 1024
    assert PLATFORM_MAX_REQUEST_BODY_BYTES >= PLATFORM_MAX_EVIDENCE_ITEM_BYTES


def test_payload_pure_415_unsupported_media_type(limits_app):
    """Refuse evidence bundle containing unsupported MIME format with HTTP 415."""
    client = limits_app["client"]
    org_id = "org_test_limits_415"
    headers = {"X-Organization-Id": org_id}

    case_id = "RC-LIMIT-415-01"
    # Create case
    r_create = client.post("/api/cases", headers=headers, json={"case_id": case_id, "tenant_id": "tenant_01", "organization_id": org_id})
    assert r_create.status_code == 200

    # Dispatch ADMIT_AUTHORIZED_BUNDLE with unsupported format (video/mp4)
    bad_payload = make_authorized_bundle_action(
        case_id=case_id,
        authority=make_valid_authority_record().model_dump(),
        evidence={"content": "abc", "mime_type": "video/mp4", "filename": "video.mp4"},
    )

    r_admit = client.post(f"/api/cases/{case_id}/dispatch", headers=headers, json=bad_payload)
    assert r_admit.status_code == 415
    detail = r_admit.json()["detail"]
    assert detail["error_code"] == "FORMAT_NOT_SUPPORTED"

    # ZERO PARTIAL MUTATION: Case is untouched
    r_get = client.get(f"/api/cases/{case_id}", headers=headers)
    assert r_get.status_code == 200
    assert r_get.json()["phase"] == "EVIDENCE_ADMISSION"
    assert r_get.json()["evidence"] == []


def test_payload_pure_422_retention_exceeds_limit(limits_app):
    """Refuse evidence bundle with retention_days > allowed with HTTP 422."""
    client = limits_app["client"]
    org_id = "org_test_limits_422"
    headers = {"X-Organization-Id": org_id}

    case_id = "RC-LIMIT-422-01"
    client.post("/api/cases", headers=headers, json={"case_id": case_id, "tenant_id": "tenant_01", "organization_id": org_id})

    # Authority with retention 400 > 365
    authority = make_valid_authority_record().model_dump()
    authority["retention_days"] = 400

    payload = make_authorized_bundle_action(case_id=case_id, authority=authority)
    r = client.post(f"/api/cases/{case_id}/dispatch", headers=headers, json=payload)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error_code"] == "RETENTION_EXCEEDS_TENANT_LIMIT"


def test_payload_pure_413_evidence_item_too_large(limits_app):
    """Refuse evidence bundle with size_bytes exceeding item ceiling with HTTP 413."""
    client = limits_app["client"]
    org_id = "org_test_limits_413"
    headers = {"X-Organization-Id": org_id}

    case_id = "RC-LIMIT-413-01"
    client.post("/api/cases", headers=headers, json={"case_id": case_id, "tenant_id": "tenant_01", "organization_id": org_id})

    # Item with content > 10MB
    large_content = "x" * (11 * 1024 * 1024)
    bad_payload = make_authorized_bundle_action(
        case_id=case_id,
        authority=make_valid_authority_record().model_dump(),
        evidence={"content": large_content, "mime_type": "text/plain", "filename": "large.txt"},
    )
    r = client.post(f"/api/cases/{case_id}/dispatch", headers=headers, json=bad_payload)
    assert r.status_code == 413
    detail = r.json()["detail"]
    assert detail["error_code"] == "EVIDENCE_TOO_LARGE"


def test_rate_limiting_hourly_quota(limits_app):
    """Exceeding hourly requests quota returns 429 Too Many Requests with Retry-After header."""
    client = limits_app["client"]
    db = limits_app["db"]
    org_id = "org_test_rate_limit"
    headers = {"X-Organization-Id": org_id}

    # Tighten requests_per_hour for this org to 3
    with db.get_connection() as conn:
        tight_limits = TenantOperatingLimits(requests_per_hour=3)
        db.save_tenant_limits_tx(conn, org_id, tight_limits, "test_admin")

    # First 3 requests succeed
    for i in range(3):
        r = client.post("/api/cases", headers=headers, json={"case_id": f"RC-RATE-{i}", "tenant_id": "tenant_01", "organization_id": org_id})
        assert r.status_code == 200

    # 4th request is rejected with 429
    r_blocked = client.post("/api/cases", headers=headers, json={"case_id": "RC-RATE-4", "tenant_id": "tenant_01", "organization_id": org_id})
    assert r_blocked.status_code == 429
    assert "Retry-After" in r_blocked.headers
    detail = r_blocked.json()["detail"]
    assert detail["error_code"] == "QUOTA_EXCEEDED"
    assert detail["quota_kind"] == "requests"


def test_open_cases_limit_enforcement(limits_app):
    """Exceeding max_open_cases limit returns 429 on case creation."""
    client = limits_app["client"]
    db = limits_app["db"]
    org_id = "org_test_open_cases"
    headers = {"X-Organization-Id": org_id}

    # Set max_open_cases to 2
    with db.get_connection() as conn:
        db.save_tenant_limits_tx(conn, org_id, TenantOperatingLimits(max_open_cases=2), "test_admin")

    # Create 2 cases
    client.post("/api/cases", headers=headers, json={"case_id": "RC-OPEN-1", "tenant_id": "tenant_01", "organization_id": org_id})
    client.post("/api/cases", headers=headers, json={"case_id": "RC-OPEN-2", "tenant_id": "tenant_01", "organization_id": org_id})

    # 3rd open case fails with 429
    r_fail = client.post("/api/cases", headers=headers, json={"case_id": "RC-OPEN-3", "tenant_id": "tenant_01", "organization_id": org_id})
    assert r_fail.status_code == 429
    assert r_fail.json()["detail"]["error_code"] == "QUOTA_EXCEEDED"
    assert r_fail.json()["detail"]["quota_kind"] == "max_open_cases"


def test_settings_admin_crud_and_audit(limits_app):
    """Settings administration is flag+token protected and appends audit events."""
    client = limits_app["client"]
    db = limits_app["db"]
    org_id = "org_settings_admin"
    base_headers = {"X-Organization-Id": org_id}
    auth_headers = {**base_headers, "Authorization": f"Bearer {TEST_SETTINGS_TOKEN}"}

    # 1. Without admin token -> 401
    r_unauth = client.get("/api/settings/limits", headers=base_headers)
    assert r_unauth.status_code == 401

    # 2. With admin token -> 200 default limits
    r_read = client.get("/api/settings/limits", headers=auth_headers)
    assert r_read.status_code == 200
    data = r_read.json()
    assert data["organization_id"] == org_id
    assert data["is_default"] is True

    # 3. Update limits -> 200
    new_settings = {
        "max_evidence_item_bytes": 5 * 1024 * 1024,
        "evidence_retention_days": 180,
        "max_open_cases": 50,
    }
    r_update = client.put("/api/settings/limits", headers=auth_headers, json=new_settings)
    assert r_update.status_code == 200
    assert r_update.json()["limits"]["max_evidence_item_bytes"] == 5 * 1024 * 1024
    assert r_update.json()["limits"]["evidence_retention_days"] == 180

    # 4. Reject update exceeding platform ceiling -> 422
    bad_settings = {"max_evidence_item_bytes": 50 * 1024 * 1024}  # ceiling is 10MB
    r_bad = client.put("/api/settings/limits", headers=auth_headers, json=bad_settings)
    assert r_bad.status_code == 422

    # 5. Check audit events: both ACCEPTED and REJECTED events recorded
    with db.get_connection() as conn:
        events = conn.execute(
            "SELECT action, reason_code FROM tenant_settings_audit_events WHERE organization_id = ? ORDER BY id ASC",
            (org_id,),
        ).fetchall()
    assert len(events) >= 2
    actions = [e["action"] for e in events]
    assert "ACCEPTED" in actions
    assert "REJECTED" in actions
