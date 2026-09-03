"""Server-owned handoff orchestration service."""

from typing import Any, Optional

from payoutproof.core.models import RiskCaseState
from payoutproof.core.enums import CasePhase, GrantStatus, HandoffStatus, AdapterDecision
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.core.crypto import derive_idempotency_key, compute_snapshot_hash


def _row_organization(row: Any) -> Optional[str]:
    """Read the organization scope from a durable row, tolerating a legacy column-less schema.

    Older rows (or a pre-migration table) have no organization_id at all; those
    read as None so they still match un-scoped legacy cases.
    """
    try:
        keys = row.keys()
    except Exception:
        return None
    if "organization_id" not in keys:
        return None
    return row["organization_id"]


class HandoffService:
    """Dedicated application service for server-owned handoff orchestration."""

    @classmethod
    def execute_handoff(
        cls,
        state: RiskCaseState,
        adapter: FakeApprovalRailAdapter,
        *,
        grant_secret: str,
        simulate_ambiguity: bool = False,
    ) -> RiskCaseState:
        """Execute server-owned handoff attempt atomically inside a SQLite transaction.

        1. Authoritative state is loaded inside an explicit SQLite BEGIN IMMEDIATE transaction.
           Requires persisted authoritative case and matching durable handoff_grants row.
           Never falls back to caller state.
        2. Recovery checks if a durable attempt already exists (e.g. from crash gap);
           validates complete terminal tuple and reconciles state without creating a second item.
           Any tuple corruption triggers typed RECOVERY_INTEGRITY_FAILURE_NO_RETRY.
        3. Validates authoritative case snapshot hash against grant.bound_snapshot_hash.
        4. Validates fresh active exact-intent grant.
        5. Derives server-owned deterministic idempotency key.
        6. Atomically claims grant (rowcount == 1), records attempt, and persists pending item.
        7. Persists final case state, audit events, and grant atomically in that same transaction.
        """
        if not grant_secret or not str(grant_secret).strip():
            raise ValueError("grant_secret is required and cannot be empty")
        db = adapter.db
        with db.get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                # 1. Authoritative state MUST pre-exist in persistence (never fall back to caller state)
                case_id = state.case_id or ""
                persisted_state = db.load_case_tx(conn, case_id) if case_id else None
                if persisted_state is None:
                    conn.rollback()
                    msg = "Refused “initiate human handoff”: authoritative case record not found in persistence."
                    return state.model_copy(update={
                        "last_change": msg,
                        "handoff": state.handoff.model_copy(update={
                            "status": HandoffStatus.FAILED,
                        }),
                    })

                if not persisted_state.grant:
                    conn.rollback()
                    msg = "Refused “initiate human handoff”: no grant found on authoritative case."
                    return persisted_state.model_copy(update={
                        "last_change": msg,
                    })

                # Require matching durable handoff_grants row
                grant_row = conn.execute(
                    "SELECT * FROM handoff_grants WHERE grant_id = ?",
                    (persisted_state.grant.grant_id,),
                ).fetchone()
                if not grant_row:
                    conn.rollback()
                    msg = "Refused “initiate human handoff”: authoritative grant record not found in persistence."
                    return persisted_state.model_copy(update={
                        "last_change": msg,
                    })

                outcome_val = (
                    persisted_state.grant.outcome.value
                    if hasattr(persisted_state.grant.outcome, "value")
                    else str(persisted_state.grant.outcome)
                )
                if (
                    grant_row["tenant_id"] != persisted_state.grant.tenant_id
                    or grant_row["case_id"] != persisted_state.grant.case_id
                    or grant_row["bound_intent_hash"] != persisted_state.grant.bound_intent_hash
                    or grant_row["bound_snapshot_hash"] != persisted_state.grant.bound_snapshot_hash
                    or grant_row["policy_version"] != persisted_state.grant.policy_version
                    or grant_row["outcome"] != outcome_val
                    or grant_row["nonce"] != persisted_state.grant.nonce
                    or grant_row["issued_at"] != persisted_state.grant.issued_at
                    or grant_row["expires_at"] != persisted_state.grant.expires_at
                    or grant_row["signature"] != persisted_state.grant.signature
                    or _row_organization(grant_row) != persisted_state.grant.organization_id
                ):
                    conn.rollback()
                    msg = "Refused “initiate human handoff”: authoritative grant record mismatch."
                    return persisted_state.model_copy(update={
                        "last_change": msg,
                    })



                curr_state = persisted_state

                # Helper to handle recovery integrity failures fail-closed without retry
                def fail_recovery_integrity(reason: str) -> RiskCaseState:
                    g_row = conn.execute(
                        "SELECT status, used FROM handoff_grants WHERE grant_id = ?",
                        (curr_state.grant.grant_id,),
                    ).fetchone()
                    if g_row:
                        curr_g_status = g_row["status"]
                        curr_g_used = g_row["used"]
                        if curr_g_status == "ACTIVE":
                            conn.execute(
                                "UPDATE handoff_grants SET status = 'INVALIDATED', used = 0 WHERE grant_id = ?",
                                (curr_state.grant.grant_id,),
                            )
                            durable_status = GrantStatus.INVALIDATED
                            durable_used = False
                        elif curr_g_status in ("INVALIDATED", "EXPIRED"):
                            durable_status = GrantStatus(curr_g_status)
                            durable_used = bool(curr_g_used)
                        elif curr_g_status in ("CONSUMED", "SUSPENDED_FOR_RECONCILIATION"):
                            durable_status = GrantStatus(curr_g_status)
                            durable_used = True
                            conn.execute(
                                "UPDATE handoff_grants SET used = 1 WHERE grant_id = ?",
                                (curr_state.grant.grant_id,),
                            )
                        else:
                            durable_status = GrantStatus.SUSPENDED_FOR_RECONCILIATION
                            durable_used = True
                    else:
                        durable_status = GrantStatus.SUSPENDED_FOR_RECONCILIATION
                        durable_used = True

                    state_to_reconcile = curr_state
                    if curr_state.grant:
                        state_to_reconcile = curr_state.model_copy(update={
                            "grant": curr_state.grant.model_copy(update={
                                "status": durable_status,
                                "used": durable_used,
                            })
                        })
                    reconciled = StateMachine.apply_adapter_decision(
                        state=state_to_reconcile,
                        decision=AdapterDecision.RECOVERY_INTEGRITY_FAILURE_NO_RETRY,
                        error_message=reason,
                    )
                    db.save_case_tx(conn, reconciled)
                    conn.commit()
                    return reconciled

                # 2. Recovery check: ONLY if grant exists, check exact matching grant_id
                existing_attempt = conn.execute(
                    "SELECT * FROM adapter_attempts WHERE grant_id = ?",
                    (curr_state.grant.grant_id,),
                ).fetchone()

                if not existing_attempt:
                    if grant_row["used"] == 1 and grant_row["status"] in ("CONSUMED", "SUSPENDED_FOR_RECONCILIATION"):
                        return fail_recovery_integrity("Authoritative grant is already used/terminal but durable attempt record is missing")

                    if grant_row["status"] in ("INVALIDATED", "EXPIRED"):
                        reconciled = StateMachine.apply_adapter_decision(
                            state=curr_state,
                            decision=AdapterDecision.GRANT_INVALID_OR_EXPIRED,
                            error_message=f"Handoff refused: grant status is {grant_row['status']}",
                        )
                        db.save_case_tx(conn, reconciled)
                        conn.commit()
                        return reconciled

                if existing_attempt:
                    expected_idem = derive_idempotency_key(
                        tenant_id=curr_state.tenant_id,
                        case_id=curr_state.case_id or "",
                        case_version=curr_state.case_version,
                        grant_id=curr_state.grant.grant_id,
                        organization_id=curr_state.organization_id,
                    )
                    attempt_case_id = existing_attempt["case_id"]
                    attempt_idem_key = existing_attempt["idempotency_key"]
                    attempt_grant_id = existing_attempt["grant_id"]

                    if (
                        attempt_case_id != curr_state.case_id
                        or attempt_idem_key != expected_idem
                        or attempt_grant_id != curr_state.grant.grant_id
                    ):
                        return fail_recovery_integrity("Attempt correlation mismatch with current authoritative state")

                    # Restart recovery re-checks the organization scope: a durable attempt
                    # or pending item from another organization can never satisfy this case.
                    if _row_organization(existing_attempt) != curr_state.organization_id:
                        return fail_recovery_integrity("Attempt organization scope mismatch with current authoritative state")

                    decision_str = existing_attempt["decision"]
                    status_str = existing_attempt["status"]
                    ambiguity_str = existing_attempt["ambiguity_state"]
                    pending_item_id = existing_attempt["pending_item_id"]
                    err_code = existing_attempt["error_code"]
                    err_msg = existing_attempt["error_message"]

                    # Validate complete attempt terminal tuple
                    if decision_str == AdapterDecision.PENDING_ITEM_CREATED.value:
                        if status_str != "COMPLETED":
                            return fail_recovery_integrity("Recovery validation failed: attempt status is not COMPLETED")
                        if ambiguity_str not in ("NONE", None, ""):
                            return fail_recovery_integrity("Recovery validation failed: ambiguity_state is not NONE")
                        if not pending_item_id:
                            return fail_recovery_integrity("Recovery validation failed: missing pending_item_id in attempt record")
                        if err_code is not None or err_msg is not None:
                            return fail_recovery_integrity("Recovery validation failed: error_code or error_message is not null")

                        # Require matching pending approval item
                        item_row = conn.execute(
                            "SELECT * FROM pending_approval_items WHERE item_id = ?",
                            (pending_item_id,),
                        ).fetchone()
                        if (
                            not item_row
                            or item_row["case_id"] != curr_state.case_id
                            or item_row["grant_id"] != curr_state.grant.grant_id
                            or item_row["idempotency_key"] != expected_idem
                            or item_row["status"] != "PENDING_FINANCE_APPROVAL"
                            or _row_organization(item_row) != curr_state.organization_id
                        ):
                            return fail_recovery_integrity("Recovery validation failed: pending approval item missing or inconsistent")

                        # Require durable handoff_grants to be used=1 and CONSUMED
                        d_grant_row = conn.execute(
                            "SELECT used, status FROM handoff_grants WHERE grant_id = ?",
                            (curr_state.grant.grant_id,),
                        ).fetchone()
                        if not d_grant_row or d_grant_row["used"] != 1 or d_grant_row["status"] != "CONSUMED":
                            return fail_recovery_integrity("Recovery validation failed: durable grant is not used=1 and CONSUMED")

                        if curr_state.phase != CasePhase.COMPLETE:
                            base_state = curr_state
                            if base_state.phase != CasePhase.HANDOFF_IN_PROGRESS:
                                base_state = StateMachine.reduce(
                                    state=base_state,
                                    action={"type": "INITIATE_HANDOFF", "payload": {}},
                                    grant_secret=grant_secret,
                                )
                            reconciled = StateMachine.apply_adapter_decision(
                                state=base_state,
                                decision=AdapterDecision.PENDING_ITEM_CREATED,
                                pending_item_id=pending_item_id,
                            )
                            db.save_case_tx(conn, reconciled)
                            conn.commit()
                            return reconciled
                        else:
                            retried = StateMachine.reduce(
                                state=curr_state,
                                action={"type": "INITIATE_HANDOFF", "payload": {}},
                                grant_secret=grant_secret,
                            )
                            db.save_case_tx(conn, retried)
                            conn.commit()
                            return retried

                    elif decision_str == AdapterDecision.DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY.value:
                        if status_str != "RECONCILIATION_REQUIRED":
                            return fail_recovery_integrity("Recovery validation failed: attempt status is not RECONCILIATION_REQUIRED")
                        if ambiguity_str != "RECONCILIATION_REQUIRED":
                            return fail_recovery_integrity("Recovery validation failed: ambiguity_state is not RECONCILIATION_REQUIRED")
                        if pending_item_id is not None:
                            return fail_recovery_integrity("Recovery validation failed: pending_item_id is not null for ambiguous attempt")
                        if err_code is None:
                            return fail_recovery_integrity("Recovery validation failed: missing error_code for ambiguous attempt")

                        # Require NO pending item for the grant or idempotency_key
                        item_row = conn.execute(
                            "SELECT * FROM pending_approval_items WHERE grant_id = ? OR idempotency_key = ?",
                            (curr_state.grant.grant_id, expected_idem),
                        ).fetchone()
                        if item_row is not None:
                            return fail_recovery_integrity("Recovery validation failed: unexpected pending item found for ambiguous attempt")

                        # Require durable handoff_grants used=1 and SUSPENDED_FOR_RECONCILIATION
                        d_grant_row = conn.execute(
                            "SELECT used, status FROM handoff_grants WHERE grant_id = ?",
                            (curr_state.grant.grant_id,),
                        ).fetchone()
                        if not d_grant_row or d_grant_row["used"] != 1 or d_grant_row["status"] != "SUSPENDED_FOR_RECONCILIATION":
                            return fail_recovery_integrity("Recovery validation failed: durable grant is not used=1 and SUSPENDED_FOR_RECONCILIATION")

                        if curr_state.phase != CasePhase.RECONCILIATION_REQUIRED:
                            base_state = curr_state
                            if base_state.phase != CasePhase.HANDOFF_IN_PROGRESS:
                                base_state = StateMachine.reduce(
                                    state=base_state,
                                    action={"type": "INITIATE_HANDOFF", "payload": {}},
                                    grant_secret=grant_secret,
                                )
                            reconciled = StateMachine.apply_adapter_decision(
                                state=base_state,
                                decision=AdapterDecision.DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY,
                                error_message=err_msg,
                            )
                            db.save_case_tx(conn, reconciled)
                            conn.commit()
                            return reconciled
                        else:
                            retried = StateMachine.reduce(
                                state=curr_state,
                                action={"type": "INITIATE_HANDOFF", "payload": {}},
                                grant_secret=grant_secret,
                            )
                            db.save_case_tx(conn, retried)
                            conn.commit()
                            return retried

                    else:
                        # Unknown / legacy / corrupt decision: fail closed with typed recovery integrity failure
                        return fail_recovery_integrity("Unknown or corrupt adapter attempt decision cannot be recovered")

                # 3. Snapshot hash verification before producing HANDOFF_IN_PROGRESS
                authoritative_snapshot_hash = compute_snapshot_hash(curr_state)
                if curr_state.grant.bound_snapshot_hash != authoritative_snapshot_hash:
                    conn.rollback()
                    msg = "Refused “initiate human handoff”: case snapshot does not match bound grant snapshot hash."
                    return curr_state.model_copy(update={"last_change": msg})

                # Cross-tenant substitution: the grant on the case must carry the
                # case's own tenant and organization identity.
                if (
                    curr_state.grant.tenant_id != curr_state.tenant_id
                    or curr_state.grant.organization_id != curr_state.organization_id
                ):
                    conn.rollback()
                    msg = "Refused “initiate human handoff”: grant tenant or organization scope does not match the authoritative case scope."
                    return curr_state.model_copy(update={
                        "last_change": msg,
                    })

                # 4. Check eligibility via pure StateMachine.reduce
                pending_state = StateMachine.reduce(
                    state=curr_state,
                    action={"type": "INITIATE_HANDOFF", "payload": {}},
                    grant_secret=grant_secret,
                )

                if (
                    pending_state.phase != CasePhase.HANDOFF_IN_PROGRESS
                    or pending_state.handoff.status != HandoffStatus.PENDING
                    or not pending_state.grant
                ):
                    db.save_case_tx(conn, pending_state)
                    conn.commit()
                    return pending_state

                # 5. Server-owned deterministic idempotency key
                idem_key = derive_idempotency_key(
                    tenant_id=pending_state.tenant_id,
                    case_id=pending_state.case_id or "UNKNOWN",
                    case_version=pending_state.case_version,
                    grant_id=pending_state.grant.grant_id,
                    organization_id=pending_state.organization_id,
                )

                # Persist pending state so authoritative case and grant pre-exist for adapter submission
                db.save_case_tx(conn, pending_state)

                # 6. Execute adapter submission atomically inside this transaction
                decision, created_item, err_msg = db.execute_adapter_submission_tx(
                    conn=conn,
                    grant=pending_state.grant,
                    intent=pending_state.intent,
                    idempotency_key=idem_key,
                    simulate_ambiguity=simulate_ambiguity,
                    grant_secret=grant_secret,
                )

                # 7. Apply adapter decision to state
                pending_item_id = created_item.item_id if created_item else None
                final_state = StateMachine.apply_adapter_decision(
                    state=pending_state,
                    decision=decision,
                    pending_item_id=pending_item_id,
                    error_message=err_msg,
                )

                # 8. Persist final state and audit events in the same transaction
                db.save_case_tx(conn, final_state)
                conn.commit()
                return final_state
            except Exception:
                conn.rollback()
                raise
