"""Deterministic Fake Action Adapter for downstream maker-checker approval rail integration."""

import hmac
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

from payoutproof.core.models import PaymentIntent, HandoffGrant, HandoffRecord, PendingApprovalItem
from payoutproof.core.enums import HandoffStatus, AdapterDecision, GrantStatus, CasePhase
from payoutproof.storage.db import Database


class FakeApprovalRailAdapter:
    """Deterministic, truthful action adapter.

    Accepts an unconsumed Handoff Grant + exact Payment Intent and creates
    exactly one pending approval item in the downstream maker-checker rail.
    Rejects replays, consumed grants, mutated intents, and expired grants.
    SQLite is the authoritative replay/idempotency store.
    """

    def __init__(
        self,
        db: Optional[Database | str | Path | Any] = None,
        *,
        grant_secret: str,
        audit_checkpoint_secret: Optional[str] = None,
    ):
        if not grant_secret or not str(grant_secret).strip():
            raise ValueError("grant_secret is required and cannot be empty")
        self.grant_secret = grant_secret

        if audit_checkpoint_secret is not None:
            if hmac.compare_digest(grant_secret, audit_checkpoint_secret):
                raise ValueError("grant_secret and audit_checkpoint_secret must be distinct")

        if isinstance(db, Database):
            self.db = db
            if audit_checkpoint_secret is not None and not hmac.compare_digest(
                self.db.audit_checkpoint_secret, audit_checkpoint_secret
            ):
                raise ValueError("Injected Database audit_checkpoint_secret does not match supplied audit_checkpoint_secret")
            if hmac.compare_digest(self.db.audit_checkpoint_secret, grant_secret):
                raise ValueError("grant_secret and audit_checkpoint_secret must be distinct")
        elif isinstance(db, (str, Path)) or db is None:
            if not audit_checkpoint_secret:
                raise ValueError("audit_checkpoint_secret is required when constructing Database")
            self.db = Database(db_path=db, audit_checkpoint_secret=audit_checkpoint_secret) if db is not None else Database(audit_checkpoint_secret=audit_checkpoint_secret)
        else:
            # Arbitrary wrapper / proxy object
            self.db = db
            db_secret = getattr(db, "audit_checkpoint_secret", None)
            if db_secret is not None:
                if audit_checkpoint_secret is not None and not hmac.compare_digest(str(db_secret), audit_checkpoint_secret):
                    raise ValueError("Injected db audit_checkpoint_secret does not match supplied audit_checkpoint_secret")
                if hmac.compare_digest(str(db_secret), grant_secret):
                    raise ValueError("grant_secret and audit_checkpoint_secret must be distinct")
            else:
                if not audit_checkpoint_secret:
                    raise ValueError("audit_checkpoint_secret is required when db does not expose audit_checkpoint_secret")
                if hmac.compare_digest(audit_checkpoint_secret, grant_secret):
                    raise ValueError("grant_secret and audit_checkpoint_secret must be distinct")

    @property
    def consumed_grants(self) -> set[str]:
        """Read-only compatibility property querying SQLite."""
        return self.db.get_consumed_grant_ids()

    @property
    def pending_rail_items(self) -> Dict[str, PendingApprovalItem]:
        """Read-only compatibility property querying SQLite."""
        return self.db.get_all_pending_items()

    @property
    def idempotency_records(self) -> Dict[str, PendingApprovalItem]:
        """Read-only compatibility property querying SQLite."""
        return self.db.get_idempotency_records()

    def submit_handoff(
        self,
        grant: HandoffGrant,
        intent: PaymentIntent,
        simulate_ambiguity: bool = False,
    ) -> Tuple[AdapterDecision, Optional[PendingApprovalItem], Optional[str]]:
        """Submit an authorized Payment Intent to create a pending item.

        Returns (decision, created_item, error_message).
        Uses an explicit SQLite BEGIN IMMEDIATE transaction for durable atomicity.
        Derives server-owned idempotency key from authoritative persisted case data.
        """
        with self.db.get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                # 1. Authoritative case check
                case_id = grant.case_id
                persisted_case = self.db.load_case_tx(conn, case_id)
                if not persisted_case:
                    return AdapterDecision.GRANT_INVALID_OR_EXPIRED, None, "Authoritative case not found"

                if not persisted_case.grant or persisted_case.grant.grant_id != grant.grant_id:
                    return AdapterDecision.GRANT_INVALID_OR_EXPIRED, None, "Authoritative grant not found on case"

                # 2. Authoritative case intent consistency check
                from payoutproof.core.crypto import compute_intent_hash, derive_idempotency_key
                persisted_recomputed_hash = compute_intent_hash(persisted_case.intent)
                if (
                    not persisted_case.intent.intent_hash
                    or persisted_recomputed_hash != persisted_case.intent.intent_hash
                    or persisted_case.intent.intent_hash != grant.bound_intent_hash
                    or persisted_case.intent.intent_hash != persisted_case.grant.bound_intent_hash
                ):
                    return AdapterDecision.INTENT_MISMATCH, None, "Authoritative case intent is inconsistent or unconfirmed"

                # 3. Supplied intent verification (never trust self-asserted intent_hash)
                if not intent.intent_hash:
                    return AdapterDecision.INTENT_MISMATCH, None, "Payment Intent has not been confirmed/hashed"

                supplied_recomputed_hash = compute_intent_hash(intent)
                if supplied_recomputed_hash != intent.intent_hash:
                    return AdapterDecision.INTENT_MISMATCH, None, "Supplied intent hash does not match canonical recomputation"

                if (
                    intent.canonical_string() != persisted_case.intent.canonical_string()
                    or intent.provenance != persisted_case.intent.provenance
                    or intent.status != persisted_case.intent.status
                    or intent.destination_status != persisted_case.intent.destination_status
                    or intent.intent_hash != persisted_case.intent.intent_hash
                ):
                    return AdapterDecision.INTENT_MISMATCH, None, "Supplied intent does not match authoritative case intent"

                # 4. Derive exact server-owned idempotency key from authoritative fields
                idempotency_key = derive_idempotency_key(
                    tenant_id=persisted_case.tenant_id,
                    case_id=persisted_case.case_id or "",
                    case_version=persisted_case.case_version,
                    grant_id=grant.grant_id,
                    organization_id=persisted_case.organization_id,
                )

                decision, item, err = self.db.execute_adapter_submission_tx(
                    conn=conn,
                    grant=grant,
                    intent=persisted_case.intent,
                    idempotency_key=idempotency_key,
                    simulate_ambiguity=simulate_ambiguity,
                    grant_secret=self.grant_secret,
                )

                # Synchronize risk_cases state to prevent desync between durable tables and state_json
                from payoutproof.case_workflow.state_machine import StateMachine
                if decision in (
                    AdapterDecision.PENDING_ITEM_CREATED,
                    AdapterDecision.DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY,
                ):
                    item_id = item.item_id if item else None
                    updated_case = StateMachine.apply_adapter_decision(
                        state=persisted_case,
                        decision=decision,
                        pending_item_id=item_id,
                        error_message=err,
                    )
                    self.db.save_case_tx(conn, updated_case)
                elif decision == AdapterDecision.REPLAY_REJECTED:
                    # If case_json is stale due to a prior crash gap, reconcile with durable attempt
                    if persisted_case.phase not in (CasePhase.COMPLETE, CasePhase.RECONCILIATION_REQUIRED):
                        existing_attempt = conn.execute(
                            "SELECT decision, pending_item_id, error_message FROM adapter_attempts WHERE grant_id = ?",
                            (grant.grant_id,),
                        ).fetchone()
                        if existing_attempt:
                            att_dec = AdapterDecision(existing_attempt["decision"])
                            updated_case = StateMachine.apply_adapter_decision(
                                state=persisted_case,
                                decision=att_dec,
                                pending_item_id=existing_attempt["pending_item_id"],
                                error_message=existing_attempt["error_message"],
                            )
                            self.db.save_case_tx(conn, updated_case)

                conn.commit()
                return decision, item, err
            except Exception:
                conn.rollback()
                raise
