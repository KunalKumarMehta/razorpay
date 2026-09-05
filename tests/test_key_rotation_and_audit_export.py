"""Comprehensive test suite for Issue #12: Key Rotation and Verifiable Risk Case Audits.

Verifies:
1. KeyRing configuration, invariant validation, constant-time checks, and secret redaction.
2. Domain-separated cryptographic signing and backward compatibility.
3. Handoff grant issuance and verification across key rotations and retirements.
4. Database audit checkpoint tracking, key rotation, and fail-closed verification.
5. Adapter submission acceptance with retained signing keys.
6. Canonical point-in-time Risk Case audit export generation.
7. Pure offline audit export verifier tamper matrix (deletion, alteration, reordering,
   sequence gaps, checkpoint MAC forgery, key retirement, cross-tenant/cross-case contamination).
8. REST API endpoint GET /api/cases/{case_id}/audit-export RBAC and zero-existence oracle.
9. CLI payoutproof verify-case-export execution and error reporting.
"""

import json
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from payoutproof.core.keys import KeyRing, KeyRingError
from payoutproof.core.config import AppConfig, ConfigurationError
from payoutproof.core.enums import (
    AuditTrustState,
    CasePhase,
    PolicyOutcome,
    GrantStatus,
    AdapterDecision,
    ProcessingAuthorityStatus,
)
from payoutproof.auth.roles import Role
from payoutproof.core.models import (
    RiskCaseState,
    AuditEvent,
    HandoffGrant,
    CaseAuditCheckpoint,
    PolicyEvaluationResult,
)
from payoutproof.core.crypto import (
    compute_checkpoint_mac,
    verify_checkpoint_mac,
    create_grant_signature,
    verify_grant_signature,
    compute_snapshot_hash,
    derive_idempotency_key,
)
from payoutproof.storage.db import (
    Database,
    AuditLedgerIntegrityError,
)
from payoutproof.audit.chain import GENESIS_HASH
from payoutproof.audit.export import (
    build_case_export,
    verify_case_export,
    CaseExportError,
    EXPORT_VERSION,
)
from payoutproof.grants.issuer import GrantIssuer, GrantVerifier
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.auth.session import SessionRecord
from payoutproof.api.app import create_app
from tests.helpers import (
    make_admitted_case_state,
    make_confirmed_intent,
    make_authorized_bundle_action,
    TEST_GRANT_SECRET,
    TEST_AUDIT_CHECKPOINT_SECRET,
)

GRANT_KEY_V1 = "grant-secret-v1-must-be-at-least-32-chars-long"
GRANT_KEY_V2 = "grant-secret-v2-distinct-and-at-least-32-chars"
AUDIT_KEY_V1 = "audit-secret-v1-must-be-at-least-32-chars-long"
AUDIT_KEY_V2 = "audit-secret-v2-distinct-and-at-least-32-chars"
MEMBERSHIP_SEC = "membership-secret-fixed-32-chars-long-ok"


def test_keyring_core_and_invariants():
    """KeyRing guarantees non-empty active keys, minimum length, secret redaction, and constant-time matching."""
    ring = KeyRing(
        active_key_id="k1",
        keys={
            "k1": GRANT_KEY_V1,
            "k2": GRANT_KEY_V2,
        },
    )
    assert ring.active_key_id == "k1"
    assert ring.active_secret == GRANT_KEY_V1
    assert ring.get_secret("k2") == GRANT_KEY_V2
    assert ring.get_secret("k1") == GRANT_KEY_V1
    assert ring.get_secret(None) == GRANT_KEY_V1
    assert ring.get_secret("unknown") is None
    assert ring.has_key("k1")
    assert ring.has_key("k2")
    assert ring.has_key(None)
    assert not ring.has_key("unknown")

    # Secrets never leaked in repr or str
    rep = repr(ring)
    assert "[REDACTED]" in rep
    assert GRANT_KEY_V1 not in rep
    assert GRANT_KEY_V2 not in rep
    assert str(ring) == rep

    # Constant-time helpers
    assert ring.contains_secret(GRANT_KEY_V1)
    assert ring.contains_secret(GRANT_KEY_V2)
    assert not ring.contains_secret(AUDIT_KEY_V1)

    # Rejection of invalid configs
    with pytest.raises(KeyRingError, match="active_key_id"):
        KeyRing("", {"k1": GRANT_KEY_V1})

    with pytest.raises(KeyRingError, match="not present in provided keys"):
        KeyRing("missing", {"k1": GRANT_KEY_V1})

    with pytest.raises(KeyRingError, match="too weak"):
        KeyRing("k1", {"k1": "short"})

    # parse_retained_string
    parsed = KeyRing.parse_retained_string("k2:sec2-must-be-32-characters-or-more-here,k3:sec3-must-be-32-characters-or-more-here")
    assert "k2" in parsed
    assert "k3" in parsed


def test_keyring_config_and_safe_dict():
    """AppConfig validates disjointness across rings and exposes key IDs safely."""
    g_ring = KeyRing("v1", {"v1": GRANT_KEY_V1, "v0": GRANT_KEY_V2})
    a_ring = KeyRing("v1", {"v1": AUDIT_KEY_V1, "v0": AUDIT_KEY_V2})

    cfg = AppConfig.for_tests(
        grant_key_ring=g_ring,
        audit_key_ring=a_ring,
        membership_secret=MEMBERSHIP_SEC,
    )
    safe = cfg.to_safe_dict()
    assert safe["grant_active_key_id"] == "v1"
    assert safe["audit_active_key_id"] == "v1"
    assert "v0" in safe["grant_retained_key_ids"]
    assert "v0" in safe["audit_retained_key_ids"]
    assert safe["grant_secret"] == "[REDACTED]"
    assert safe["audit_checkpoint_secret"] == "[REDACTED]"

    # Disjointness check
    shared_ring = KeyRing("v1", {"v1": GRANT_KEY_V1})
    with pytest.raises(ConfigurationError, match="must be distinct"):
        AppConfig.for_tests(
            grant_key_ring=shared_ring,
            audit_key_ring=shared_ring,
            membership_secret=MEMBERSHIP_SEC,
        )


def test_signed_grants_record_key_id_and_verify_across_rotation():
    """HandoffGrant stamps key_id; planned rotation allows valid historical grant verification."""
    ring_v1 = KeyRing("v1", {"v1": GRANT_KEY_V1})

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        "RC-GRANT-01",
        organization_id="org_01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
            organization_id="org_01",
        ),
    )

    # 1. Issue grant under v1
    grant_v1 = GrantIssuer.issue_grant(state, secret=ring_v1)
    assert grant_v1.key_id == "v1"

    # Verify with v1 ring
    ok, err = GrantVerifier.verify(grant_v1, intent.intent_hash, secret=ring_v1, expected_organization_id="org_01")
    assert ok, err

    # 2. Rotate to v2 while retaining v1
    ring_v2 = KeyRing("v2", {"v2": GRANT_KEY_V2, "v1": GRANT_KEY_V1})

    # Old grant v1 verifies under rotated ring v2
    ok, err = GrantVerifier.verify(grant_v1, intent.intent_hash, secret=ring_v2, expected_organization_id="org_01")
    assert ok, err

    # New grant issued under v2 stamps v2
    grant_v2 = GrantIssuer.issue_grant(state, secret=ring_v2)
    assert grant_v2.key_id == "v2"

    # Both grants verify under ring_v2
    assert GrantVerifier.verify(grant_v1, intent.intent_hash, secret=ring_v2, expected_organization_id="org_01")[0]
    assert GrantVerifier.verify(grant_v2, intent.intent_hash, secret=ring_v2, expected_organization_id="org_01")[0]

    # 3. Retire key v1
    ring_v2_only = KeyRing("v2", {"v2": GRANT_KEY_V2})
    ok, err = GrantVerifier.verify(grant_v1, intent.intent_hash, secret=ring_v2_only, expected_organization_id="org_01")
    assert not ok
    assert "unknown or retired" in err.lower() or "signature" in err.lower()


def test_audit_checkpoints_record_key_id_and_verify_across_rotation(tmp_path):
    """Audit checkpoints record key_id; historical checkpoints verify under rotated rings and fail on retired keys."""
    db_path = tmp_path / "checkpoints_rotation.db"

    # 1. DB running with audit ring v1
    ring_v1 = KeyRing("audit-v1", {"audit-v1": AUDIT_KEY_V1})
    db_v1 = Database(db_path=db_path, audit_checkpoint_secret=ring_v1)

    s1 = StateMachine.initial_state(case_id="RC-ROT-01", tenant_id="tenant_01")
    db_v1.save_case(s1)

    with db_v1.get_connection() as conn:
        cp = conn.execute("SELECT * FROM case_audit_checkpoints WHERE case_id = 'RC-ROT-01'").fetchone()
        assert cp is not None
        assert cp["key_id"] == "audit-v1"

    # Verify audit succeeds under v1
    verify_res = db_v1.verify_case_audit("RC-ROT-01")
    assert verify_res is not None
    assert verify_res["trust_state"] == AuditTrustState.TRUSTED

    # 2. Rotate to audit ring v2 with audit-v1 retained
    ring_v2 = KeyRing("audit-v2", {"audit-v2": AUDIT_KEY_V2, "audit-v1": AUDIT_KEY_V1})
    db_v2 = Database(db_path=db_path, audit_checkpoint_secret=ring_v2)

    # Existing case loads and verifies under rotated ring
    loaded = db_v2.load_case("RC-ROT-01")
    assert loaded is not None
    verify_res2 = db_v2.verify_case_audit("RC-ROT-01")
    assert verify_res2 is not None
    assert verify_res2["trust_state"] == AuditTrustState.TRUSTED

    # Advance case under v2 (creates new checkpoint with audit-v2)
    s2 = StateMachine.reduce(loaded, make_authorized_bundle_action(case_id="RC-ROT-01"))
    db_v2.save_case(s2)

    with db_v2.get_connection() as conn:
        cp2 = conn.execute("SELECT * FROM case_audit_checkpoints WHERE case_id = 'RC-ROT-01'").fetchone()
        assert cp2["key_id"] == "audit-v2"
        assert cp2["event_count"] == 2

    # Verify case with v2 checkpoint
    verify_res3 = db_v2.verify_case_audit("RC-ROT-01")
    assert verify_res3 is not None
    assert verify_res3["trust_state"] == AuditTrustState.TRUSTED

    # 3. If audit-v1 is retired, historical checkpoints fail verification
    ring_v2_strict = KeyRing("audit-v2", {"audit-v2": AUDIT_KEY_V2})
    db_strict = Database(db_path=db_path, audit_checkpoint_secret=ring_v2_strict)

    with db_v2.get_connection() as conn:
        conn.execute("UPDATE case_audit_checkpoints SET key_id = 'audit-v1' WHERE case_id = 'RC-ROT-01'")

    with pytest.raises(AuditLedgerIntegrityError, match="unknown or retired"):
        db_strict.load_case("RC-ROT-01")


def test_adapter_submission_with_rotated_grant(tmp_path):
    """Adapter submission accepts grants signed by retained keys across planned rotation."""
    db_path = tmp_path / "adapter_rotation.db"

    ring_v1 = KeyRing("g-v1", {"g-v1": GRANT_KEY_V1})
    db = Database(db_path=db_path, audit_checkpoint_secret=AUDIT_KEY_V1)

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        "RC-SUB-01",
        intent=intent,
        organization_id="org_01",
        tenant_id="tenant_01",
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
            organization_id="org_01",
        ),
    )
    # Set to READY_FOR_HUMAN_HANDOFF and issue grant via state machine
    state = state.model_copy(update={"phase": CasePhase.READY_FOR_HUMAN_HANDOFF})
    db.save_case(state)

    state_with_grant = StateMachine.reduce(state, {"type": "ISSUE_GRANT"}, grant_secret=ring_v1)
    db.save_case(state_with_grant)
    grant_v1 = state_with_grant.grant
    assert grant_v1 is not None
    assert grant_v1.key_id == "g-v1"

    idempotency_key = derive_idempotency_key(
        tenant_id=state.tenant_id,
        case_id=state.case_id or "",
        case_version=state.case_version,
        grant_id=grant_v1.grant_id,
        organization_id=state.organization_id,
    )

    # Now execute submission using rotated KeyRing with g-v1 retained
    ring_v2 = KeyRing("g-v2", {"g-v2": GRANT_KEY_V2, "g-v1": GRANT_KEY_V1})

    with db.get_connection() as conn:
        decision, item, err = db.execute_adapter_submission_tx(
            conn,
            grant=grant_v1,
            intent=intent,
            idempotency_key=idempotency_key,
            grant_secret=ring_v2,
        )
    assert decision == AdapterDecision.PENDING_ITEM_CREATED
    assert err is None
    assert item is not None


def test_verifiable_audit_export_and_offline_verification(tmp_path):
    """Complete Risk Case audit export is generated and verified offline with zero database or network access."""
    db_path = tmp_path / "export_test.db"

    grant_ring = KeyRing("g-v1", {"g-v1": GRANT_KEY_V1})
    audit_ring = KeyRing("a-v1", {"a-v1": AUDIT_KEY_V1})
    db = Database(db_path=db_path, audit_checkpoint_secret=audit_ring)

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        "RC-EXP-01",
        intent=intent,
        organization_id="org_01",
        tenant_id="tenant_01",
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
            organization_id="org_01",
        ),
    )
    db.save_case(state)

    # Issue grant
    grant = GrantIssuer.issue_grant(state, secret=grant_ring)
    with db.get_connection() as conn:
        conn.execute("""
            INSERT INTO handoff_grants (
                grant_id, tenant_id, organization_id, case_id, bound_intent_hash,
                bound_snapshot_hash, policy_version, outcome, nonce, issued_at,
                expires_at, signature, status, used, key_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 0, ?);
        """, (
            grant.grant_id, grant.tenant_id, grant.organization_id, grant.case_id,
            grant.bound_intent_hash, grant.bound_snapshot_hash, grant.policy_version,
            grant.outcome, grant.nonce, grant.issued_at, grant.expires_at,
            grant.signature, grant.key_id,
        ))

    # Build canonical export
    export_payload = build_case_export(db, case_id="RC-EXP-01", organization_id="org_01")
    assert export_payload["export_version"] == EXPORT_VERSION
    assert export_payload["case_id"] == "RC-EXP-01"
    assert export_payload["tenant_id"] == "tenant_01"
    assert export_payload["organization_id"] == "org_01"
    assert len(export_payload["audit_events"]) >= 1
    assert len(export_payload["checkpoints"]) == 1
    assert len(export_payload["grants"]) == 1

    # Pure offline verification succeeds
    is_valid, msg = verify_case_export(export_payload, audit_ring=audit_ring, grant_ring=grant_ring)
    assert is_valid, msg
    assert "verified offline successfully" in msg


def test_audit_export_tamper_matrix_fails_closed(tmp_path):
    """Offline verifier detects every tampering vector and fails closed with descriptive diagnosis."""
    db_path = tmp_path / "tamper_test.db"

    grant_ring = KeyRing("g-v1", {"g-v1": GRANT_KEY_V1})
    audit_ring = KeyRing("a-v1", {"a-v1": AUDIT_KEY_V1})
    db = Database(db_path=db_path, audit_checkpoint_secret=audit_ring)

    intent = make_confirmed_intent()
    state = make_admitted_case_state(
        "RC-TAMPER-01",
        intent=intent,
        organization_id="org_01",
        tenant_id="tenant_01",
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
            organization_id="org_01",
        ),
    )
    db.save_case(state)

    # Advance case to have 2 events
    state2 = StateMachine.reduce(state, make_authorized_bundle_action(case_id="RC-TAMPER-01"))
    db.save_case(state2)

    export_clean = build_case_export(db, case_id="RC-TAMPER-01", organization_id="org_01")
    assert verify_case_export(export_clean, audit_ring=audit_ring, grant_ring=grant_ring)[0]

    # Vector 1: Event deletion (tail truncation)
    tampered = json.loads(json.dumps(export_clean))
    tampered["audit_events"].pop()
    ok, err = verify_case_export(tampered, audit_ring=audit_ring, grant_ring=grant_ring)
    assert not ok
    assert "records 2 events but export only contains 1" in err or "Sequence gap" in err

    # Vector 2: Event modification (summary altered)
    tampered = json.loads(json.dumps(export_clean))
    tampered["audit_events"][0]["summary"] = "Tampered summary here"
    ok, err = verify_case_export(tampered, audit_ring=audit_ring, grant_ring=grant_ring)
    assert not ok
    assert "Tampered event payload" in err

    # Vector 3: Event reordering
    tampered = json.loads(json.dumps(export_clean))
    tampered["audit_events"][0], tampered["audit_events"][1] = (
        tampered["audit_events"][1],
        tampered["audit_events"][0],
    )
    ok, err = verify_case_export(tampered, audit_ring=audit_ring, grant_ring=grant_ring)
    assert not ok
    assert "Sequence gap or reordering" in err or "prev_hash" in err

    # Vector 4: Sequence gap
    tampered = json.loads(json.dumps(export_clean))
    tampered["audit_events"][1]["seq"] = 3
    ok, err = verify_case_export(tampered, audit_ring=audit_ring, grant_ring=grant_ring)
    assert not ok
    assert "Sequence gap or reordering" in err

    # Vector 5: Genesis hash corruption
    tampered = json.loads(json.dumps(export_clean))
    tampered["audit_events"][0]["prev_hash"] = "tampered-genesis-hash"
    ok, err = verify_case_export(tampered, audit_ring=audit_ring, grant_ring=grant_ring)
    assert not ok
    assert "prev_hash" in err

    # Vector 6: Checkpoint MAC tampering
    tampered = json.loads(json.dumps(export_clean))
    tampered["checkpoints"][0]["checkpoint_mac"] = "bad-mac-000000000000000000000000"
    ok, err = verify_case_export(tampered, audit_ring=audit_ring, grant_ring=grant_ring)
    assert not ok
    assert "MAC verification failed" in err

    # Vector 7: Checkpoint references unknown / retired signing key
    tampered = json.loads(json.dumps(export_clean))
    tampered["checkpoints"][0]["key_id"] = "retired-key-99"
    ok, err = verify_case_export(tampered, audit_ring=audit_ring, grant_ring=grant_ring)
    assert not ok
    assert "unknown or retired" in err

    # Vector 8: Cross-tenant grant contamination
    grant = GrantIssuer.issue_grant(state, secret=grant_ring)
    grant_foreign = grant.model_copy(update={"tenant_id": "foreign_tenant"})
    tampered = json.loads(json.dumps(export_clean))
    tampered["grants"] = [grant_foreign.model_dump(mode="json")]
    ok, err = verify_case_export(tampered, audit_ring=audit_ring, grant_ring=grant_ring)
    assert not ok
    assert "Cross-tenant grant substitution" in err

    # Vector 9: Cross-case grant contamination
    grant_other = grant.model_copy(update={"case_id": "RC-OTHER-99"})
    tampered = json.loads(json.dumps(export_clean))
    tampered["grants"] = [grant_other.model_dump(mode="json")]
    ok, err = verify_case_export(tampered, audit_ring=audit_ring, grant_ring=grant_ring)
    assert not ok
    assert "injected into export" in err


def test_api_case_audit_export_endpoint_rbac_and_zero_existence(tmp_path):
    """GET /api/cases/{case_id}/audit-export enforces zero-existence 404, auditor RBAC 403, and returns valid export."""
    db_path = tmp_path / "api_export.db"
    grant_ring = KeyRing("g-v1", {"g-v1": GRANT_KEY_V1})
    audit_ring = KeyRing("a-v1", {"a-v1": AUDIT_KEY_V1})
    db = Database(db_path=db_path, audit_checkpoint_secret=audit_ring)

    intent = make_confirmed_intent()
    state = make_admitted_case_state("RC-API-01", intent=intent, organization_id="org_01", tenant_id="tenant_01")
    db.save_case(state)

    config = AppConfig.for_tests(
        grant_key_ring=grant_ring,
        audit_key_ring=audit_ring,
        db_path=str(db_path),
        membership_secret=MEMBERSHIP_SEC,
    )
    app = create_app(config, db=db)
    client = TestClient(app)

    # 1. Non-existent case returns 404 (zero-existence oracle)
    token_auditor = app.state.session_store.mint(
        subject="auditor_user",
        display_name="Auditor User",
        role=Role.AUDITOR,
        tenant_id="tenant_01",
        organization_id="org_01",
        idp_issuer="https://auth.payoutproof.local/idp",
    )
    client.cookies.set("payoutproof_session", token_auditor)

    res = client.get("/api/cases/RC-NONEXISTENT/audit-export")
    assert res.status_code == 404

    # 2. Case in another organization returns 404 before role check
    token_other_org = app.state.session_store.mint(
        subject="auditor_other",
        display_name="Auditor Other",
        role=Role.AUDITOR,
        tenant_id="tenant_01",
        organization_id="foreign_org",
        idp_issuer="https://auth.payoutproof.local/idp",
    )
    client.cookies.set("payoutproof_session", token_other_org)

    res = client.get("/api/cases/RC-API-01/audit-export")
    assert res.status_code == 404

    # 3. Non-Auditor role returns 403 Forbidden
    token_operator = app.state.session_store.mint(
        subject="operator_user",
        display_name="Operator User",
        role=Role.PAYMENT_OPERATOR,
        tenant_id="tenant_01",
        organization_id="org_01",
        idp_issuer="https://auth.payoutproof.local/idp",
    )
    client.cookies.set("payoutproof_session", token_operator)

    res = client.get("/api/cases/RC-API-01/audit-export")
    assert res.status_code == 403
    assert "restricted to the Auditor role" in res.json()["detail"]

    # 4. Auditor returns 200 OK with verifiable export
    client.cookies.set("payoutproof_session", token_auditor)
    res = client.get("/api/cases/RC-API-01/audit-export")
    assert res.status_code == 200
    export_data = res.json()
    assert export_data["case_id"] == "RC-API-01"

    # Offline verify the API response
    ok, msg = verify_case_export(export_data, audit_ring=audit_ring, grant_ring=grant_ring)
    assert ok, msg


def test_cli_verify_case_export_command(tmp_path, monkeypatch, capsys):
    """payoutproof verify-case-export runs cleanly offline, exits 0 on valid and 1 on tampered export."""
    from payoutproof.cli.main import main

    db_path = tmp_path / "cli_test.db"
    grant_ring = KeyRing("g-v1", {"g-v1": GRANT_KEY_V1})
    audit_ring = KeyRing("a-v1", {"a-v1": AUDIT_KEY_V1})
    db = Database(db_path=db_path, audit_checkpoint_secret=audit_ring)

    intent = make_confirmed_intent()
    state = make_admitted_case_state("RC-CLI-EXP-01", intent=intent, organization_id="org_01", tenant_id="tenant_01")
    db.save_case(state)

    export_payload = build_case_export(db, case_id="RC-CLI-EXP-01", organization_id="org_01")
    export_file = tmp_path / "valid_export.json"
    export_file.write_text(json.dumps(export_payload), encoding="utf-8")

    # 1. Valid export verification passes
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "payoutproof",
            "verify-case-export",
            "--file",
            str(export_file),
            "--audit-key-id",
            "a-v1",
            "--audit-secret",
            AUDIT_KEY_V1,
            "--grant-key-id",
            "g-v1",
            "--grant-secret",
            GRANT_KEY_V1,
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "verified successfully" in out

    # 2. Tampered export fails and exits 1
    tampered_file = tmp_path / "tampered_export.json"
    export_payload["audit_events"][0]["summary"] = "Tampered summary!"
    tampered_file.write_text(json.dumps(export_payload), encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "payoutproof",
            "verify-case-export",
            "--file",
            str(tampered_file),
            "--audit-key-id",
            "a-v1",
            "--audit-secret",
            AUDIT_KEY_V1,
            "--grant-key-id",
            "g-v1",
            "--grant-secret",
            GRANT_KEY_V1,
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    err_out = capsys.readouterr().out
    assert "verification FAILED" in err_out
