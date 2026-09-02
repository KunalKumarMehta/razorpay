"""Tests for hashing, HMAC signing, and Handoff Grants."""

import pytest
from datetime import datetime, timezone, timedelta
from payoutproof.core.models import PaymentIntent, RiskCaseState, PolicyEvaluationResult
from payoutproof.core.enums import IntentStatus, PolicyOutcome, GrantStatus, DestinationStatus
from payoutproof.core.crypto import (
    compute_intent_hash,
    compute_snapshot_hash,
    create_grant_signature,
    verify_grant_signature,
)
from payoutproof.grants.issuer import GrantIssuer, GrantVerifier, DEFAULT_GRANT_SECRET


def test_intent_hash_is_deterministic():
    i1 = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        instruction_reference="VOICE-1",
        status=IntentStatus.CONFIRMED,
    )
    i2 = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        instruction_reference="VOICE-1",
        status=IntentStatus.CONFIRMED,
    )
    h1 = compute_intent_hash(i1)
    h2 = compute_intent_hash(i2)
    assert h1 == h2
    assert len(h1) == 64


def test_intent_hash_changes_on_material_edit():
    i1 = PaymentIntent(counterparty="Kaveri", destination="HDFC ••4821", amount="425000")
    i2 = PaymentIntent(counterparty="Kaveri", destination="HDFC ••4821", amount="475000")
    assert compute_intent_hash(i1) != compute_intent_hash(i2)


def test_grant_issuance_and_verification():
    intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        status=IntentStatus.CONFIRMED,
        intent_hash="sample_intent_hash_1234567890abcdef",
    )
    state = RiskCaseState(
        case_id="RC-TEST-001",
        tenant_id="tenant_alpha",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )

    grant = GrantIssuer.issue_grant(state, secret=DEFAULT_GRANT_SECRET)
    assert grant.grant_id.startswith("HG-RC-TEST-001-")
    assert grant.bound_intent_hash == intent.intent_hash
    assert grant.status == GrantStatus.ACTIVE
    assert not grant.used

    # Verification succeeds with matching intent hash
    valid, err = GrantVerifier.verify(grant, intent.intent_hash, secret=DEFAULT_GRANT_SECRET)
    assert valid
    assert err is None

    # Verification fails if intent hash mutated
    valid_mutated, err_mutated = GrantVerifier.verify(grant, "mutated_intent_hash", secret=DEFAULT_GRANT_SECRET)
    assert not valid_mutated
    assert "material mutation" in err_mutated.lower()

    # Verification fails if secret is wrong
    valid_bad_secret, err_bad_secret = GrantVerifier.verify(grant, intent.intent_hash, secret="wrong-secret")
    assert not valid_bad_secret
    assert "signature verification failed" in err_bad_secret.lower()
