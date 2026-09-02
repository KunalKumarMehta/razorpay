"""Deterministic Fake Action Adapter for downstream maker-checker approval rail integration."""

from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timezone

from payoutproof.core.models import PaymentIntent, HandoffGrant, HandoffRecord
from payoutproof.core.enums import HandoffStatus, AdapterDecision, GrantStatus
from payoutproof.grants.issuer import GrantVerifier, DEFAULT_GRANT_SECRET


class PendingApprovalItem:
    """A pending payout review item in the downstream maker-checker approval rail."""
    def __init__(
        self,
        item_id: str,
        case_id: str,
        counterparty: str,
        destination: str,
        amount: str,
        currency: str,
        purpose: str,
        grant_id: str,
        idempotency_key: str,
        created_at: str,
    ):
        self.item_id = item_id
        self.case_id = case_id
        self.counterparty = counterparty
        self.destination = destination
        self.amount = amount
        self.currency = currency
        self.purpose = purpose
        self.grant_id = grant_id
        self.idempotency_key = idempotency_key
        self.created_at = created_at
        self.status = "PENDING_FINANCE_APPROVAL"


class FakeApprovalRailAdapter:
    """Deterministic, truthful action adapter.

    Accepts an unconsumed Handoff Grant + exact Payment Intent and creates
    exactly one pending approval item in the downstream maker-checker rail.
    Rejects replays, consumed grants, mutated intents, and expired grants.
    """

    def __init__(self, grant_secret: str = DEFAULT_GRANT_SECRET):
        self.grant_secret = grant_secret
        self.consumed_grants: set[str] = set()
        self.idempotency_records: Dict[str, PendingApprovalItem] = {}
        self.pending_rail_items: Dict[str, PendingApprovalItem] = {}

    def submit_handoff(
        self,
        grant: HandoffGrant,
        intent: PaymentIntent,
        idempotency_key: str,
        simulate_ambiguity: bool = False,
    ) -> Tuple[AdapterDecision, Optional[PendingApprovalItem], Optional[str]]:
        """Submit an authorized Payment Intent to create a pending item.

        Returns (decision, created_item, error_message).
        """
        # 1. Check idempotency replay
        if idempotency_key in self.idempotency_records:
            return AdapterDecision.REPLAY_REJECTED, self.idempotency_records[idempotency_key], "Replay detected: duplicate idempotency key rejected"

        # 2. Check grant replay / consumption
        if grant.grant_id in self.consumed_grants:
            return AdapterDecision.REPLAY_REJECTED, None, "Replay detected: Handoff Grant has already been consumed"

        # 3. Verify grant signature & validity
        if not intent.intent_hash:
            return AdapterDecision.INTENT_MISMATCH, None, "Payment Intent has not been confirmed/hashed"

        is_valid, err = GrantVerifier.verify(grant, intent.intent_hash, self.grant_secret)
        if not is_valid:
            return AdapterDecision.GRANT_INVALID_OR_EXPIRED, None, f"Grant verification failed: {err}"

        # 4. Consume grant atomically before processing
        self.consumed_grants.add(grant.grant_id)

        # 5. Handle simulated downstream ambiguity
        if simulate_ambiguity:
            return AdapterDecision.DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY, None, "Downstream response timed out; reconciliation required"

        # 6. Create pending approval item in downstream rail
        now_iso = datetime.now(timezone.utc).isoformat()
        item_id = f"RAIL-PENDING-{grant.case_id}-{len(self.pending_rail_items) + 1:03d}"
        item = PendingApprovalItem(
            item_id=item_id,
            case_id=grant.case_id,
            counterparty=intent.counterparty or "",
            destination=intent.destination or "",
            amount=intent.amount or "",
            currency=intent.currency or "INR",
            purpose=intent.purpose or "",
            grant_id=grant.grant_id,
            idempotency_key=idempotency_key,
            created_at=now_iso,
        )

        self.idempotency_records[idempotency_key] = item
        self.pending_rail_items[item_id] = item

        return AdapterDecision.PENDING_ITEM_CREATED, item, None
