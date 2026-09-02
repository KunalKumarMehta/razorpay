"""Tests for Fake Action Adapter, replay prevention, and ambiguity reconciliation."""

import pytest
from payoutproof.core.models import PaymentIntent, RiskCaseState, PolicyEvaluationResult
from payoutproof.core.enums import IntentStatus, PolicyOutcome, AdapterDecision
from payoutproof.grants.issuer import GrantIssuer, DEFAULT_GRANT_SECRET
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter


def test_fake_adapter_creates_single_pending_item():
    adapter = FakeApprovalRailAdapter()
    intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        status=IntentStatus.CONFIRMED,
        intent_hash="sample_hash_987",
    )
    state = RiskCaseState(
        case_id="RC-ADAPT-01",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant = GrantIssuer.issue_grant(state, secret=DEFAULT_GRANT_SECRET)

    decision, item, err = adapter.submit_handoff(
        grant=grant,
        intent=intent,
        idempotency_key="IDEM-001",
    )

    assert decision == AdapterDecision.PENDING_ITEM_CREATED
    assert item is not None
    assert item.status == "PENDING_FINANCE_APPROVAL"
    assert err is None


def test_fake_adapter_rejects_replay_of_consumed_grant():
    adapter = FakeApprovalRailAdapter()
    intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        status=IntentStatus.CONFIRMED,
        intent_hash="sample_hash_987",
    )
    state = RiskCaseState(
        case_id="RC-ADAPT-02",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant = GrantIssuer.issue_grant(state, secret=DEFAULT_GRANT_SECRET)

    # First attempt succeeds
    decision1, item1, err1 = adapter.submit_handoff(grant=grant, intent=intent, idempotency_key="IDEM-002A")
    assert decision1 == AdapterDecision.PENDING_ITEM_CREATED

    # Replay attempt with same grant fails
    decision2, item2, err2 = adapter.submit_handoff(grant=grant, intent=intent, idempotency_key="IDEM-002B")
    assert decision2 == AdapterDecision.REPLAY_REJECTED
    assert item2 is None
    assert "already been consumed" in err2


def test_fake_adapter_rejects_duplicate_idempotency_key():
    adapter = FakeApprovalRailAdapter()
    intent = PaymentIntent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
        currency="INR",
        purpose="Tooling deposit",
        status=IntentStatus.CONFIRMED,
        intent_hash="sample_hash_987",
    )
    state = RiskCaseState(
        case_id="RC-ADAPT-03",
        tenant_id="tenant_01",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )
    grant1 = GrantIssuer.issue_grant(state, secret=DEFAULT_GRANT_SECRET)

    decision1, item1, err1 = adapter.submit_handoff(grant=grant1, intent=intent, idempotency_key="IDEM-SHARED")
    assert decision1 == AdapterDecision.PENDING_ITEM_CREATED

    # Second grant with same idempotency key
    grant2 = GrantIssuer.issue_grant(state, secret=DEFAULT_GRANT_SECRET)
    decision2, item2, err2 = adapter.submit_handoff(grant=grant2, intent=intent, idempotency_key="IDEM-SHARED")
    assert decision2 == AdapterDecision.REPLAY_REJECTED
    assert "duplicate idempotency key" in err2.lower()
