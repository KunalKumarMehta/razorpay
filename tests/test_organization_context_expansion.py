"""Focused tests for Issue #3: [Expand] Introduce compatible organization context.

Covers:
1. Newly created Risk Cases can carry organization context across state machine, persistence, and API.
2. Legacy records without organization context receive deterministic compatibility (organization_id is None).
3. Byte-identical snapshot hash invariance: legacy cases with organization_id=None produce the exact
   same snapshot hash, preserving validity of existing Handoff Grants and HMAC signatures.
4. Non-null organization context is cryptographically bound into the snapshot hash.
5. API endpoints (POST /api/cases, GET /api/cases, GET /api/cases/{case_id}) accept and return organization_id.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from payoutproof.core.models import RiskCaseState, PaymentIntent
from payoutproof.core.enums import CasePhase
from payoutproof.core.crypto import compute_snapshot_hash
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.storage.db import Database
from payoutproof.api.app import create_app
from payoutproof.core.config import AppConfig
from payoutproof.grants.issuer import GrantIssuer, GrantVerifier
from tests.helpers import (
    TEST_GRANT_SECRET,
    TEST_AUDIT_CHECKPOINT_SECRET,
    make_authorized_bundle_action,
    make_admitted_case_state,
)


def test_initial_state_supports_organization_context():
    """StateMachine.initial_state accepts and preserves organization_id."""
    state_unscoped = StateMachine.initial_state(case_id="RC-EXPAND-01")
    assert state_unscoped.organization_id is None
    assert state_unscoped.tenant_id == "tenant_default"

    state_org = StateMachine.initial_state(
        case_id="RC-EXPAND-02",
        tenant_id="tenant_custom",
        organization_id="org_fintech_corp",
    )
    assert state_org.organization_id == "org_fintech_corp"
    assert state_org.tenant_id == "tenant_custom"


def test_legacy_snapshot_hash_byte_identical():
    """Omitting organization_id preserves byte-identical snapshot hash for legacy grants."""
    # Build legacy-style state with organization_id=None
    base_state = make_admitted_case_state(case_id="RC-LEGACY-01")
    assert base_state.organization_id is None

    hash_legacy = compute_snapshot_hash(base_state)

    # Recompute manually reproducing the pre-Issue-3 canonical dict (no organization_id key)
    canonical_dict = {
        "case_id": base_state.case_id,
        "case_version": base_state.case_version,
        "tenant_id": base_state.tenant_id,
        "request_bundle_status": base_state.request_bundle_status,
        "processing_authority": base_state.processing_authority.value,
        "authority_record": base_state.authority_record.model_dump(),
        "intent": {
            "counterparty": base_state.intent.counterparty,
            "destination": base_state.intent.destination,
            "destination_status": base_state.intent.destination_status.value,
            "amount": base_state.intent.amount,
            "currency": base_state.intent.currency,
            "purpose": base_state.intent.purpose,
            "instruction_reference": base_state.intent.instruction_reference,
            "provenance": sorted(base_state.intent.provenance),
            "status": base_state.intent.status.value,
            "intent_hash": base_state.intent.intent_hash,
        },
        "evidence": sorted(
            [
                {
                    "id": e.id,
                    "item_type": e.item_type,
                    "title": e.title,
                    "content_hash": e.content_hash,
                    "finding": e.finding,
                    "truth_state": e.truth_state.value,
                    "admitted_at": e.admitted_at,
                    "metadata": e.metadata,
                }
                for e in base_state.evidence
            ],
            key=lambda x: x["id"],
        ),
        "findings": sorted(
            [
                {
                    "name": f.name,
                    "truth_state": f.truth_state.value,
                    "detail": f.detail,
                    "evidence_ref": f.evidence_ref,
                }
                for f in base_state.findings
            ],
            key=lambda x: (x["name"], x["truth_state"], x["detail"], str(x["evidence_ref"])),
        ),
        "investigation": {
            "model_status": base_state.investigation.model_status,
            "attempt": base_state.investigation.attempt,
            "asr_confidence": base_state.investigation.asr_confidence,
            "extraction_latency_ms": base_state.investigation.extraction_latency_ms,
            "language_stratum": base_state.investigation.language_stratum,
        },
    }
    from payoutproof.core.crypto import sha256_hex
    expected_legacy_hash = sha256_hex(json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")))

    assert hash_legacy == expected_legacy_hash, "Legacy snapshot hash must remain byte-identical"


def test_organization_context_alters_and_binds_snapshot_hash():
    """Non-null organization_id produces distinct snapshot hash bound to the tenant."""
    base_state = make_admitted_case_state(case_id="RC-TENANT-01")
    hash_unscoped = compute_snapshot_hash(base_state)

    org_state = base_state.model_copy(update={"organization_id": "org_acme_corp"})
    hash_scoped = compute_snapshot_hash(org_state)

    assert hash_unscoped != hash_scoped, "Organization-scoped case must have bound snapshot hash"


def test_database_persistence_and_reload_with_organization(tmp_path):
    """Database persists organization_id in state_json and reloads without drift."""
    db_file = tmp_path / "tenant_db.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    # 1. Create and persist scoped case
    state = StateMachine.initial_state(
        case_id="RC-PERSIST-01",
        organization_id="org_enterprise_99",
    )
    db.save_case(state)

    # 2. Reload and verify
    reloaded = db.load_case("RC-PERSIST-01")
    assert reloaded is not None
    assert reloaded.organization_id == "org_enterprise_99"

    # 3. Verify in list_cases
    cases_list = db.list_cases()
    matched = next(c for c in cases_list if c["case_id"] == "RC-PERSIST-01")
    assert matched["organization_id"] == "org_enterprise_99"


def test_database_legacy_compatibility_unscoped_case(tmp_path):
    """Database handles legacy records without organization_id deterministically."""
    db_file = tmp_path / "legacy_db.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    # Save legacy-style un-scoped case
    state = StateMachine.initial_state(case_id="RC-LEGACY-PERSIST")
    db.save_case(state)

    reloaded = db.load_case("RC-LEGACY-PERSIST")
    assert reloaded is not None
    assert reloaded.organization_id is None

    cases_list = db.list_cases()
    matched = next(c for c in cases_list if c["case_id"] == "RC-LEGACY-PERSIST")
    assert matched["organization_id"] is None


def test_api_case_creation_and_retrieval_with_organization(tmp_path):
    """POST /api/cases carries organization_id through API and responses."""
    config = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(tmp_path / "api_tenant.db"),
    )
    client = TestClient(create_app(config=config))

    # 1. Create with organization_id
    res = client.post("/api/cases", json={
        "case_id": "RC-API-ORG-01",
        "tenant_id": "tenant_api",
        "organization_id": "org_razorpay_pilot",
    })
    assert res.status_code == 200
    created = res.json()
    assert created["organization_id"] == "org_razorpay_pilot"
    assert created["tenant_id"] == "tenant_api"

    # 2. Retrieve via GET /api/cases/{case_id}
    res_get = client.get("/api/cases/RC-API-ORG-01")
    assert res_get.status_code == 200
    fetched = res_get.json()
    assert fetched["organization_id"] == "org_razorpay_pilot"

    # 3. List via GET /api/cases
    res_list = client.get("/api/cases")
    assert res_list.status_code == 200
    items = res_list.json()
    item = next(c for c in items if c["case_id"] == "RC-API-ORG-01")
    assert item["organization_id"] == "org_razorpay_pilot"


def test_admit_authorized_bundle_carries_organization():
    """ADMIT_AUTHORIZED_BUNDLE reducer preserves organization context onto opened Risk Case."""
    initial = StateMachine.initial_state(
        case_id="RC-ADMIT-ORG",
        organization_id="org_initial",
    )
    action = make_authorized_bundle_action(case_id="RC-ADMIT-ORG")
    admitted = StateMachine.reduce(initial, action)

    assert admitted.phase == CasePhase.INVESTIGATION
    assert admitted.organization_id == "org_initial"

    # Also test passing organization_id in payload overrides/sets
    action_with_org = make_authorized_bundle_action(case_id="RC-ADMIT-ORG")
    action_with_org["payload"]["organization_id"] = "org_payload_override"
    admitted_override = StateMachine.reduce(initial, action_with_org)
    assert admitted_override.organization_id == "org_payload_override"
