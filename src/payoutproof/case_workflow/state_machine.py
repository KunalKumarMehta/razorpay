"""Pure, deterministic state machine for PayoutProof Risk Case lifecycle."""

import copy
from typing import Dict, Any, Optional, List
from payoutproof.core.models import (
    RiskCaseState,
    PaymentIntent,
    EvidenceItem,
    Finding,
    PolicyEvaluationResult,
    HandoffGrant,
    HandoffRecord,
    AuditEvent,
    CaseInvestigation,
    ProcessingAuthorityRecord,
)
from payoutproof.core.enums import (
    TruthState,
    PolicyOutcome,
    CasePhase,
    IntentStatus,
    DestinationStatus,
    GrantStatus,
    HandoffStatus,
    ProcessingAuthorityStatus,
    AdapterDecision,
    ReasonCode,
)
from payoutproof.core.crypto import compute_intent_hash
from payoutproof.admission.validator import AdmissionValidator
from payoutproof.intent.extractor import confirm_intent, modify_intent, normalize_inr_amount
from payoutproof.policy.evaluator import PolicyGate, POLICY_VERSION
from payoutproof.grants.issuer import GrantIssuer, GrantVerifier, DEFAULT_GRANT_SECRET
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.audit.chain import AuditChain


class StateMachine:
    """Pure functional state machine managing Risk Case lifecycle transitions."""

    @staticmethod
    def initial_state(case_id: Optional[str] = None, tenant_id: str = "tenant_default") -> RiskCaseState:
        """Create initial state before admission."""
        s = RiskCaseState(
            case_id=case_id,
            tenant_id=tenant_id,
            case_version=0,
            phase=CasePhase.EVIDENCE_ADMISSION,
            processing_authority=ProcessingAuthorityStatus.NOT_CHECKED,
            request_bundle_status="NOT_ADMITTED",
            last_change="Urgent instruction submitted for authority checks; no Risk Case exists yet.",
        )
        initial_event = AuditChain.create_event(
            events=[],
            event_type="EVIDENCE_ADMISSION_STARTED",
            summary="Urgent out-of-band instruction submitted",
            actor="Payment Operator",
            case_id=case_id,
            details={"tenant_id": tenant_id},
        )
        return s.model_copy(update={"audit": [initial_event]})

    @classmethod
    def reduce(
        cls,
        state: RiskCaseState,
        action: Dict[str, Any],
        adapter: Optional[FakeApprovalRailAdapter] = None,
        grant_secret: str = DEFAULT_GRANT_SECRET,
    ) -> RiskCaseState:
        """Pure reducer: state + action -> new immutable RiskCaseState."""
        action_type = action.get("type")
        payload = action.get("payload", {})

        def with_event(curr: RiskCaseState, event_type: str, summary: str, actor: str = "PayoutProof", details: Optional[Dict[str, Any]] = None) -> List[AuditEvent]:
            new_ev = AuditChain.create_event(
                events=curr.audit,
                event_type=event_type,
                summary=summary,
                actor=actor,
                case_id=curr.case_id,
                details=details or {},
            )
            return list(curr.audit) + [new_ev]

        def refuse(curr: RiskCaseState, act_name: str, reason: str) -> RiskCaseState:
            msg = f"Refused “{act_name}”: {reason}"
            new_audit = with_event(curr, "ACTION_REFUSED", msg, "Policy boundary", {"action": act_name, "reason": reason})
            return curr.model_copy(update={"last_change": msg, "audit": new_audit})

        def revoke_grant(curr: RiskCaseState) -> Optional[HandoffGrant]:
            if curr.grant and curr.grant.status == GrantStatus.ACTIVE:
                return curr.grant.model_copy(update={"status": GrantStatus.INVALIDATED})
            return curr.grant

        if action_type == "RESET":
            return cls.initial_state(case_id=state.case_id, tenant_id=state.tenant_id)

        elif action_type == "ADMIT_AUTHORIZED_BUNDLE":
            if state.request_bundle_status == "ADMITTED":
                return refuse(state, "admit authorized request", "the request bundle is already admitted")

            case_id = payload.get("case_id", state.case_id or "RC-DEMO-042")
            evidence_title = payload.get("title", "Urgent voice note + message")
            content_hash = payload.get("content_hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

            new_ev_item = EvidenceItem(
                id=f"EV-{case_id}-01",
                item_type="VOICE_AND_TEXT_BUNDLE",
                title=evidence_title,
                content_hash=content_hash,
                finding="admitted",
                truth_state=TruthState.SUPPORTED,
            )

            msg = f"Processing authority validated; evidence was admitted and Risk Case {case_id} opened."
            s_next = state.model_copy(update={
                "case_id": case_id,
                "case_version": 1,
                "phase": CasePhase.INVESTIGATION,
                "processing_authority": ProcessingAuthorityStatus.VALID,
                "request_bundle_status": "ADMITTED",
                "evidence": [new_ev_item],
                "last_change": msg,
            })
            new_audit = with_event(s_next, "RISK_CASE_OPENED", msg, "Payment Operator", {"case_id": case_id})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "SUBMIT_UNAUTHORIZED_BUNDLE":
            if state.request_bundle_status == "ADMITTED":
                return refuse(state, "submit incomplete processing authority", "admitted evidence cannot be replaced silently")

            msg = "Admission Rejection: evidence was not admitted, no Risk Case exists, and the Policy Gate did not run."
            s_next = state.model_copy(update={
                "phase": CasePhase.ADMISSION_REJECTED,
                "processing_authority": ProcessingAuthorityStatus.INCOMPLETE,
                "request_bundle_status": "REJECTED",
                "last_change": msg,
            })
            new_audit = with_event(s_next, "ADMISSION_REJECTED", msg, "Evidence admission control", {"reason": "Incomplete Processing Authority Record"})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "EXTRACT_INTENT":
            if state.request_bundle_status != "ADMITTED":
                return refuse(state, "extract Payment Intent", "no authorized evidence has been admitted")

            counterparty = payload.get("counterparty", "Kaveri Components")
            destination = payload.get("destination", "HDFC ••4821")
            amount = str(payload.get("amount", "425000"))
            currency = payload.get("currency", "INR")
            purpose = payload.get("purpose", "Urgent tooling deposit")
            instruction_ref = payload.get("instruction_reference", "VOICE-17 + MSG-17")
            provenance = payload.get("provenance", [
                "VOICE-17: transcript spans 00:04–00:12",
                "MSG-17: destination and amount",
            ])

            extracted_intent = PaymentIntent(
                counterparty=counterparty,
                destination=destination,
                destination_status=DestinationStatus.UNAPPROVED,
                amount=amount,
                currency=currency,
                purpose=purpose,
                instruction_reference=instruction_ref,
                provenance=provenance,
                status=IntentStatus.EXTRACTED,
                intent_hash=None,
            )

            new_findings = [
                Finding(name="Destination relationship", truth_state=TruthState.NOT_OBSERVED, detail=f"No prior approval for {destination}"),
                Finding(name="Instruction consistency", truth_state=TruthState.SUPPORTED, detail="Voice note and message agree on amount and destination"),
            ]

            msg = "Trust Agent extracted an unconfirmed Payment Intent with field-level provenance."
            s_next = state.model_copy(update={
                "intent": extracted_intent,
                "findings": new_findings,
                "investigation": CaseInvestigation(model_status="SUCCEEDED", attempt=state.investigation.attempt + 1),
                "last_change": msg,
            })
            new_audit = with_event(s_next, "INTENT_EXTRACTED", msg, "Trust Agent", {"intent": extracted_intent.model_dump()})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "FAIL_MODEL":
            if state.request_bundle_status != "ADMITTED":
                return refuse(state, "simulate unusable extraction", "no authorized evidence has been admitted")

            fail_status = payload.get("model_status", "FAILED_UNUSABLE_AUDIO")
            msg = "Investigation failed closed; missing output did not become safe evidence."
            s_next = state.model_copy(update={
                "investigation": CaseInvestigation(model_status=fail_status, attempt=state.investigation.attempt + 1),
                "last_change": msg,
            })
            eval_result = PolicyGate.evaluate(s_next)
            s_next = s_next.model_copy(update={
                "policy": eval_result,
                "phase": CasePhase.OPERATOR_INTERVENTION,
            })
            new_audit = with_event(s_next, "INVESTIGATION_FAILED_CLOSED", msg, "Trust Agent", {"failure_status": fail_status})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "CONFIRM_INTENT":
            if state.intent.status not in (IntentStatus.EXTRACTED, IntentStatus.INVALIDATED):
                return refuse(state, "confirm Payment Intent", "there is no extracted intent ready for confirmation")

            confirmed = confirm_intent(state.intent)
            msg = "Payment Operator confirmed the exact material fields; a frozen intent hash was created."
            s_next = state.model_copy(update={
                "intent": confirmed,
                "case_version": state.case_version + 1,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "INTENT_CONFIRMED", msg, "Payment Operator", {"intent_hash": confirmed.intent_hash})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "ADD_CALLBACK_EVIDENCE":
            if state.request_bundle_status != "ADMITTED":
                return refuse(state, "record independent callback", "there is no admitted case to support")

            cb_finding = payload.get("finding", "exact destination and purpose confirmed")
            new_ev = EvidenceItem(
                id=f"EV-{state.case_id}-CB",
                item_type="CALLBACK_RECORD",
                title="Independent callback record",
                content_hash="cb8902f5a6b7c8d9e0f1a2b3c4d5e6f7",
                finding=cb_finding,
                truth_state=TruthState.SUPPORTED,
            )
            updated_evidence = list(state.evidence) + [new_ev]
            updated_findings = [f for f in state.findings if f.name != "Independent callback"] + [
                Finding(name="Independent callback", truth_state=TruthState.SUPPORTED, detail="Known number; exact intent repeated back")
            ]
            msg = "Specified step-up evidence was added without changing the Payment Intent."
            s_next = state.model_copy(update={
                "evidence": updated_evidence,
                "findings": updated_findings,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "STEP_UP_EVIDENCE_ADDED", msg, "Payment Operator", {"finding": cb_finding})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "ADD_DESTINATION_APPROVAL":
            if state.request_bundle_status != "ADMITTED" or state.intent.status == IntentStatus.NOT_EXTRACTED:
                return refuse(state, "record destination-approval evidence", "there is no admitted Payment Intent to bind it to")

            dest = state.intent.destination or "HDFC ••4821"
            cp = state.intent.counterparty or "Counterparty"
            new_ev = EvidenceItem(
                id=f"EV-{state.case_id}-DA",
                item_type="DESTINATION_APPROVAL_RECORD",
                title="Destination approval record",
                content_hash="da1234567890abcdef1234567890abcdef",
                finding=f"{dest} approved for {cp}",
                truth_state=TruthState.SUPPORTED,
            )
            updated_evidence = list(state.evidence) + [new_ev]
            updated_findings = [f for f in state.findings if f.name != "Destination approval"] + [
                Finding(name="Destination approval", truth_state=TruthState.SUPPORTED, detail="Separately approved under finance policy; exact counterparty and destination bound")
            ]
            updated_intent = state.intent.model_copy(update={"destination_status": DestinationStatus.APPROVED_FOR_COUNTERPARTY})
            if updated_intent.status == IntentStatus.CONFIRMED:
                updated_intent = updated_intent.model_copy(update={"intent_hash": compute_intent_hash(updated_intent)})

            msg = "Separate policy-governed destination-approval evidence was recorded; callback alone did not create this approval."
            s_next = state.model_copy(update={
                "evidence": updated_evidence,
                "findings": updated_findings,
                "intent": updated_intent,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "DESTINATION_APPROVAL_EVIDENCE_ADDED", msg, "Payment Operator", {"destination": dest})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "ADD_CONTRADICTION":
            if state.request_bundle_status != "ADMITTED":
                return refuse(state, "add contradictory invoice", "there is no admitted case to compare")

            new_ev = EvidenceItem(
                id=f"EV-{state.case_id}-INV",
                item_type="INVOICE_DOCUMENT",
                title="Supplier invoice",
                content_hash="inv9930f5a6b7c8d9e0f1a2b3c4d5e6f7",
                finding="destination HDFC ••9930",
                truth_state=TruthState.CONTRADICTED,
            )
            updated_evidence = list(state.evidence) + [new_ev]
            updated_findings = list(state.findings) + [
                Finding(name="Destination consistency", truth_state=TruthState.CONTRADICTED, detail="Invoice says HDFC ••9930; instruction says HDFC ••4821")
            ]
            s_next = state.model_copy(update={
                "evidence": updated_evidence,
                "findings": updated_findings,
                "grant": revoke_grant(state),
            })
            eval_result = PolicyGate.evaluate(s_next)
            msg = "Contradiction forced a Hold; urgency cannot override the mismatch."
            s_next = s_next.model_copy(update={
                "policy": eval_result,
                "phase": CasePhase.OPERATOR_INTERVENTION,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "CONTRADICTION_RECORDED", msg, "Trust Agent", {"contradiction": "Invoice destination mismatch"})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "SUBMIT_TAMPERED_SNAPSHOT":
            if state.intent.status != IntentStatus.CONFIRMED or not state.intent.intent_hash:
                return refuse(state, "submit tampered canonical snapshot", "there is no confirmed canonical snapshot to integrity-check")

            s_next = state.model_copy(update={
                "request_bundle_status": "TAMPERED",
                "grant": revoke_grant(state),
            })
            eval_result = PolicyGate.evaluate(s_next)
            msg = "Policy Gate blocked an admitted canonical snapshot whose integrity check failed."
            s_next = s_next.model_copy(update={
                "policy": eval_result,
                "phase": CasePhase.OPERATOR_INTERVENTION,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "CANONICAL_SNAPSHOT_BLOCKED", msg, "Policy Gate", {"reason": "Snapshot integrity check failed"})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "EVALUATE_POLICY":
            if state.intent.status != IntentStatus.CONFIRMED or not state.intent.intent_hash:
                return refuse(state, "run Policy Gate", "the Payment Intent is not confirmed and frozen")

            eval_result = PolicyGate.evaluate(state)
            new_phase = (
                CasePhase.READY_FOR_HUMAN_HANDOFF
                if eval_result.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
                else CasePhase.OPERATOR_INTERVENTION
            )
            msg = f"Policy Gate returned {eval_result.outcome.value.replace('_', ' ')} for the frozen intent."
            s_next = state.model_copy(update={
                "policy": eval_result,
                "phase": new_phase,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "POLICY_EVALUATED", msg, "Policy Gate", {"outcome": eval_result.outcome.value, "reasons": [r.value for r in eval_result.reasons]})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "ISSUE_GRANT":
            if state.policy.outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF or state.policy.evaluated_intent_hash != state.intent.intent_hash:
                return refuse(state, "issue Handoff Grant", "the current frozen intent is not eligible")

            grant = GrantIssuer.issue_grant(state, secret=grant_secret)
            msg = "A single-use Handoff Grant was bound to this case, policy result, and exact intent."
            s_next = state.model_copy(update={
                "grant": grant,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "HANDOFF_GRANT_ISSUED", msg, "Policy Gate", {"grant_id": grant.grant_id})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "EDIT_AMOUNT" or action_type == "MODIFY_INTENT":
            if state.intent.status == IntentStatus.NOT_EXTRACTED:
                return refuse(state, "edit intent", "there is no extracted Payment Intent")

            new_amount = payload.get("amount", "475000" if state.intent.amount == "425000" else "425000")
            new_intent, is_material = modify_intent(state.intent, amount=new_amount)

            # Invalidate callback findings because intent has changed
            updated_findings = [
                Finding(name=f.name, truth_state=TruthState.NOT_OBSERVED, detail="Prior callback predates the material edit and does not confirm the changed exact intent")
                if f.name == "Independent callback" else f
                for f in state.findings
            ]

            msg = "Material edit invalidated the prior evaluation and any active Handoff Grant."
            s_next = state.model_copy(update={
                "intent": new_intent,
                "findings": updated_findings,
                "case_version": state.case_version + 1,
                "grant": revoke_grant(state),
            })
            eval_result = PolicyGate.evaluate(s_next)
            s_next = s_next.model_copy(update={
                "policy": eval_result,
                "phase": CasePhase.OPERATOR_INTERVENTION,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "MATERIAL_INTENT_EDITED", msg, "Payment Operator", {"new_amount": new_amount})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "INITIATE_HANDOFF":
            if not state.grant or state.grant.status != GrantStatus.ACTIVE or state.grant.used or state.grant.bound_intent_hash != state.intent.intent_hash:
                return refuse(state, "initiate human handoff", "no fresh, active grant matches the exact current intent")

            idem_key = payload.get("idempotency_key", f"HO-{state.case_id}-V{state.case_version}")
            msg = "Fresh operator gesture started one idempotent handoff attempt; maker-checker approval remains downstream."
            s_next = state.model_copy(update={
                "handoff": HandoffRecord(
                    status=HandoffStatus.PENDING,
                    idempotency_key=idem_key,
                    attempts=state.handoff.attempts + 1,
                    last_adapter_decision=AdapterDecision.FRESH_HUMAN_GESTURE_ACCEPTED,
                ),
                "phase": CasePhase.HANDOFF_IN_PROGRESS,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "HANDOFF_INITIATED", msg, "Payment Operator", {"idempotency_key": idem_key})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "HANDOFF_ACCEPTED":
            if state.handoff.status != HandoffStatus.PENDING:
                return refuse(state, "record accepted handoff", "there is no pending adapter attempt")

            msg = "Exact unchanged intent became a pending item in the existing approval rail; PayoutProof stopped."
            item_id = payload.get("pending_item_id", f"RAIL-PENDING-{state.case_id}-001")
            s_next = state.model_copy(update={
                "handoff": state.handoff.model_copy(update={
                    "status": HandoffStatus.PENDING_IN_APPROVAL_RAIL,
                    "last_adapter_decision": AdapterDecision.PENDING_ITEM_CREATED,
                    "pending_item_id": item_id,
                }),
                "grant": state.grant.model_copy(update={
                    "status": GrantStatus.CONSUMED,
                    "used": True,
                }) if state.grant else None,
                "phase": CasePhase.COMPLETE,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "HANDOFF_CONFIRMED", msg, "Action Adapter", {"pending_item_id": item_id})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "HANDOFF_AMBIGUOUS":
            if state.handoff.status != HandoffStatus.PENDING:
                return refuse(state, "simulate ambiguous handoff", "there is no pending adapter attempt")

            msg = "Adapter status is ambiguous: historical eligibility remains, the grant cannot be reused, and reconciliation will not retry blindly."
            s_next = state.model_copy(update={
                "handoff": state.handoff.model_copy(update={
                    "status": HandoffStatus.RECONCILIATION_REQUIRED,
                    "last_adapter_decision": AdapterDecision.DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY,
                }),
                "grant": state.grant.model_copy(update={
                    "status": GrantStatus.SUSPENDED_FOR_RECONCILIATION,
                    "used": True,
                }) if state.grant else None,
                "phase": CasePhase.RECONCILIATION_REQUIRED,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "HANDOFF_STATUS_AMBIGUOUS", msg, "Action Adapter", {"reason": "Downstream timeout / network uncertainty"})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "REPLAY_GRANT":
            msg = "Replay rejected: the same grant or idempotency key cannot create another pending item."
            s_next = state.model_copy(update={
                "handoff": state.handoff.model_copy(update={
                    "attempts": state.handoff.attempts + 1,
                    "last_adapter_decision": AdapterDecision.REPLAY_REJECTED,
                }),
                "last_change": msg,
            })
            new_audit = with_event(s_next, "HANDOFF_REPLAY_REJECTED", msg, "Action Adapter", {"reason": "Duplicate submission prevented"})
            return s_next.model_copy(update={"audit": new_audit})

        else:
            return refuse(state, str(action_type), f"unknown action type '{action_type}'")
