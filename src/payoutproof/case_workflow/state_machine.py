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
    FindingName,
)
from payoutproof.core.crypto import compute_intent_hash, derive_idempotency_key, compute_snapshot_hash
from payoutproof.admission.validator import AdmissionValidator
from payoutproof.intent.extractor import confirm_intent, modify_intent, normalize_inr_amount
from payoutproof.policy.evaluator import PolicyGate, POLICY_VERSION
from payoutproof.grants.issuer import GrantIssuer, GrantVerifier
from payoutproof.audit.chain import AuditChain
from payoutproof.core.providers import (
    ClockProvider,
    NonceProvider,
    SystemClock,
    SystemNonce,
)


class StateMachine:
    """Pure functional state machine managing Risk Case lifecycle transitions."""

    @staticmethod
    def initial_state(
        case_id: Optional[str] = None,
        tenant_id: str = "tenant_default",
        clock: Optional[ClockProvider] = None,
        organization_id: Optional[str] = None,
    ) -> RiskCaseState:
        """Create initial state before admission."""
        resolved_clock = clock if clock is not None else SystemClock()
        s = RiskCaseState(
            case_id=case_id,
            tenant_id=tenant_id,
            organization_id=organization_id,
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
            clock=resolved_clock,
        )
        return s.model_copy(update={"audit": [initial_event]})

    @classmethod
    def reduce(
        cls,
        state: RiskCaseState,
        action: Dict[str, Any],
        grant_secret: Optional[str] = None,
        clock: Optional[ClockProvider] = None,
        nonce_provider: Optional[NonceProvider] = None,
    ) -> RiskCaseState:
        """Pure reducer: state + action -> new immutable RiskCaseState."""
        resolved_clock = clock if clock is not None else SystemClock()
        resolved_nonce_provider = nonce_provider if nonce_provider is not None else SystemNonce()

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
                clock=resolved_clock,
            )
            return list(curr.audit) + [new_ev]

        def refuse(curr: RiskCaseState, act_name: str, reason: str) -> RiskCaseState:
            msg = f"Refused “{act_name}”: {reason}"
            new_audit = with_event(curr, "ACTION_REFUSED", msg, "Policy boundary", {"action": act_name, "reason": reason})
            return curr.model_copy(update={"last_change": msg, "audit": new_audit})

        if isinstance(payload, dict) and "idempotency_key" in payload:
            return refuse(state, str(action_type or "action"), "client-supplied idempotency_key is rejected; idempotency keys are strictly server-owned")

        def revoke_grant(curr: RiskCaseState) -> Optional[HandoffGrant]:
            if curr.grant and curr.grant.status == GrantStatus.ACTIVE:
                return curr.grant.model_copy(update={"status": GrantStatus.INVALIDATED})
            return curr.grant

        def make_admission_rejection(
            curr: RiskCaseState,
            error_msg: str,
            reason_code: ReasonCode,
            safe_meta: Dict[str, Any],
            authority_status: ProcessingAuthorityStatus = ProcessingAuthorityStatus.INCOMPLETE,
        ) -> RiskCaseState:
            msg = f"Admission Rejection: evidence was not admitted, no Risk Case exists, and the Policy Gate did not run. ({error_msg})"
            s_next = curr.model_copy(update={
                "case_version": 0,
                "phase": CasePhase.ADMISSION_REJECTED,
                "processing_authority": authority_status,
                "authority_record": None,
                "request_bundle_status": "REJECTED",
                "evidence": [],
                "findings": [],
                "intent": PaymentIntent(),
                "policy": PolicyEvaluationResult(outcome=None),
                "grant": None,
                "last_change": msg,
            })
            audit_details = {
                "reason": error_msg,
                "reason_code": reason_code.value,
                "safe_metadata": safe_meta,
            }
            new_audit = with_event(s_next, "ADMISSION_REJECTED", msg, "Evidence admission control", audit_details)
            return s_next.model_copy(update={"audit": new_audit})

        if action_type == "RESET":
            if (
                state.grant is not None
                or state.phase in (CasePhase.HANDOFF_IN_PROGRESS, CasePhase.COMPLETE, CasePhase.RECONCILIATION_REQUIRED)
                or state.authority_record is not None
                or state.processing_authority != ProcessingAuthorityStatus.NOT_CHECKED
                or state.request_bundle_status == "ADMITTED"
                or state.handoff.status != HandoffStatus.NOT_STARTED
                or state.handoff.attempts > 0
            ):
                return refuse(
                    state,
                    "reset case",
                    "cannot reset case after authority, grant, or handoff exists; terminal or active lifecycle cannot be erased",
                )
            return cls.initial_state(case_id=state.case_id, tenant_id=state.tenant_id, clock=resolved_clock)

        elif action_type == "ADMIT_AUTHORIZED_BUNDLE":
            if state.request_bundle_status == "ADMITTED":
                return refuse(state, "admit authorized request", "the request bundle is already admitted")

            case_id = payload.get("case_id") or state.case_id
            if not case_id or not str(case_id).strip():
                return make_admission_rejection(
                    state,
                    "Missing case identifier",
                    ReasonCode.MALFORMED_INPUT,
                    {},
                    ProcessingAuthorityStatus.INCOMPLETE,
                )
            case_id = str(case_id).strip()

            # 1. Processing Authority Record validation
            raw_authority = payload.get("processing_authority")
            auth_record: Optional[ProcessingAuthorityRecord] = None
            if isinstance(raw_authority, ProcessingAuthorityRecord):
                auth_record = raw_authority
            elif isinstance(raw_authority, dict):
                try:
                    auth_record = ProcessingAuthorityRecord(**raw_authority)
                except Exception:
                    return make_admission_rejection(
                        state,
                        "Malformed or incomplete Processing Authority Record",
                        ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE,
                        {},
                        ProcessingAuthorityStatus.INCOMPLETE,
                    )
            elif raw_authority is None:
                return make_admission_rejection(
                    state,
                    "Missing Processing Authority Record",
                    ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE,
                    {},
                    ProcessingAuthorityStatus.INCOMPLETE,
                )
            else:
                return make_admission_rejection(
                    state,
                    "Invalid Processing Authority Record type",
                    ReasonCode.MALFORMED_INPUT,
                    {},
                    ProcessingAuthorityStatus.INCOMPLETE,
                )

            auth_valid, auth_err = AdmissionValidator.validate_authority(auth_record)
            if not auth_valid:
                r_code = AdmissionValidator.classify_rejection_reason(auth_err or "Incomplete Processing Authority Record")
                pa_status = (
                    ProcessingAuthorityStatus.REJECTED
                    if (auth_record and not auth_record.is_valid)
                    else ProcessingAuthorityStatus.INCOMPLETE
                )
                return make_admission_rejection(
                    state,
                    auth_err or "Incomplete Processing Authority Record",
                    r_code,
                    {},
                    pa_status,
                )

            # 2. Evidence Payload validation
            ev_input = payload.get("evidence")
            if isinstance(ev_input, dict):
                content = ev_input.get("content")
                mime_type = ev_input.get("mime_type")
            else:
                content = payload.get("content")
                mime_type = payload.get("mime_type")

            payload_valid, content_hash, payload_err = AdmissionValidator.validate_payload(
                content=content,
                mime_type=mime_type,
            )
            if not payload_valid:
                r_code = AdmissionValidator.classify_rejection_reason(payload_err or "Malformed evidence payload")
                safe_meta: Dict[str, Any] = {}
                if isinstance(content, (str, bytes, bytearray)):
                    content_len = len(content.encode("utf-8") if isinstance(content, str) else content)
                    safe_meta["byte_size"] = content_len
                return make_admission_rejection(
                    state,
                    payload_err or "Malformed evidence payload",
                    r_code,
                    safe_meta,
                    ProcessingAuthorityStatus.INCOMPLETE,
                )

            # 3. Successful Admission: strictly no raw content, caller title, or filename persisted!
            content_bytes = content.encode("utf-8") if isinstance(content, str) else bytes(content)
            normalized_mime = str(mime_type).strip().lower()
            safe_ev_metadata = {
                "mime_type": normalized_mime,
                "size_bytes": len(content_bytes),
                "data_class": auth_record.data_class,
                "processing_route": auth_record.processing_route,
                "redaction_declaration": auth_record.redaction_declaration,
                "retention_days": auth_record.retention_days,
                "legal_hold": auth_record.legal_hold,
                "is_valid": auth_record.is_valid,
            }

            new_ev_item = EvidenceItem(
                id=f"EV-{case_id}-01",
                item_type="VOICE_AND_TEXT_BUNDLE" if ("audio" in normalized_mime or "text" in normalized_mime) else "EVIDENCE_BUNDLE",
                title="Admitted Evidence",
                content_hash=content_hash,
                finding="admitted",
                truth_state=TruthState.SUPPORTED,
                admitted_at=resolved_clock.now().isoformat(),
                metadata=safe_ev_metadata,
            )

            msg = f"Processing authority validated; evidence was admitted and Risk Case {case_id} opened."
            org_id = payload.get("organization_id") if "organization_id" in payload else state.organization_id
            s_next = state.model_copy(update={
                "case_id": case_id,
                "organization_id": org_id,
                "case_version": 1,
                "phase": CasePhase.INVESTIGATION,
                "processing_authority": ProcessingAuthorityStatus.VALID,
                "authority_record": auth_record,
                "request_bundle_status": "ADMITTED",
                "evidence": [new_ev_item],
                "last_change": msg,
            })
            new_audit = with_event(
                s_next,
                "RISK_CASE_OPENED",
                msg,
                "Payment Operator",
                {
                    "case_id": case_id,
                    "organization_id": org_id,
                    "content_hash": content_hash,
                    "data_class": auth_record.data_class,
                    "purpose": auth_record.purpose,
                    "processing_route": auth_record.processing_route,
                    "retention_days": auth_record.retention_days,
                    "legal_hold": auth_record.legal_hold,
                },
            )
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "SUBMIT_UNAUTHORIZED_BUNDLE":
            if state.request_bundle_status == "ADMITTED":
                return refuse(state, "submit incomplete processing authority", "admitted evidence cannot be replaced silently")

            return make_admission_rejection(
                state,
                "Incomplete Processing Authority Record",
                ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE,
                {},
                ProcessingAuthorityStatus.INCOMPLETE,
            )

        elif action_type == "EXTRACT_INTENT":
            if (
                state.request_bundle_status != "ADMITTED"
                or state.phase == CasePhase.ADMISSION_REJECTED
                or state.processing_authority != ProcessingAuthorityStatus.VALID
                or state.authority_record is None
                or not state.evidence
            ):
                return refuse(state, "extract Payment Intent", "no valid processing authority or admitted evidence")

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
            eval_result = PolicyGate.evaluate(s_next, clock=resolved_clock)
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
                admitted_at=resolved_clock.now().isoformat(),
            )
            updated_evidence = list(state.evidence) + [new_ev]
            updated_findings = [f for f in state.findings if f.name != FindingName.INDEPENDENT_CALLBACK.value] + [
                Finding(name=FindingName.INDEPENDENT_CALLBACK.value, truth_state=TruthState.SUPPORTED, detail="Known number; exact intent repeated back")
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
                admitted_at=resolved_clock.now().isoformat(),
            )
            updated_evidence = list(state.evidence) + [new_ev]
            updated_findings = [f for f in state.findings if f.name != FindingName.DESTINATION_APPROVAL.value] + [
                Finding(
                    name=FindingName.DESTINATION_APPROVAL.value,
                    truth_state=TruthState.SUPPORTED,
                    detail="Separately approved under finance policy; exact counterparty and destination bound",
                    # The approval is accepted under this organization's finance policy.
                    organization_id=state.organization_id,
                )
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
                admitted_at=resolved_clock.now().isoformat(),
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
            eval_result = PolicyGate.evaluate(s_next, clock=resolved_clock)
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
            eval_result = PolicyGate.evaluate(s_next, clock=resolved_clock)
            msg = "Policy Gate blocked an admitted canonical snapshot whose integrity check failed."
            s_next = s_next.model_copy(update={
                "policy": eval_result,
                "phase": CasePhase.OPERATOR_INTERVENTION,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "CANONICAL_SNAPSHOT_BLOCKED", msg, "Policy Gate", {"reason": "Snapshot integrity check failed"})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "EVALUATE_POLICY":
            if (
                state.request_bundle_status != "ADMITTED"
                or state.phase == CasePhase.ADMISSION_REJECTED
                or state.processing_authority != ProcessingAuthorityStatus.VALID
                or state.authority_record is None
                or not state.evidence
            ):
                return refuse(state, "run Policy Gate", "no valid processing authority or admitted evidence")

            if state.intent.status != IntentStatus.CONFIRMED or not state.intent.intent_hash:
                return refuse(state, "run Policy Gate", "the Payment Intent is not confirmed and frozen")

            eval_result = PolicyGate.evaluate(state, clock=resolved_clock)
            new_phase = (
                CasePhase.READY_FOR_HUMAN_HANDOFF
                if eval_result.outcome == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
                else CasePhase.OPERATOR_INTERVENTION
            )
            msg = f"Policy Gate returned {eval_result.outcome.value.replace('_', ' ')} for the frozen intent." if eval_result.outcome else "Policy Gate refused unadmitted case snapshot."
            s_next = state.model_copy(update={
                "policy": eval_result,
                "phase": new_phase,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "POLICY_EVALUATED", msg, "Policy Gate", {"outcome": eval_result.outcome.value if eval_result.outcome else None, "reasons": [r.value for r in eval_result.reasons]})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "ISSUE_GRANT":
            if not grant_secret or not str(grant_secret).strip():
                return refuse(state, "issue Handoff Grant", "missing required grant signing secret")

            if (
                state.request_bundle_status != "ADMITTED"
                or state.phase == CasePhase.ADMISSION_REJECTED
                or state.processing_authority != ProcessingAuthorityStatus.VALID
                or state.authority_record is None
                or not state.evidence
            ):
                return refuse(state, "issue Handoff Grant", "no valid processing authority or admitted evidence")

            if state.policy.outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF or state.policy.evaluated_intent_hash != state.intent.intent_hash:
                return refuse(state, "issue Handoff Grant", "the current frozen intent is not eligible")

            grant = GrantIssuer.issue_grant(state, secret=grant_secret, clock=resolved_clock, nonce_provider=resolved_nonce_provider)
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
                if f.name == FindingName.INDEPENDENT_CALLBACK.value else f
                for f in state.findings
            ]

            msg = "Material edit invalidated the prior evaluation and any active Handoff Grant."
            s_next = state.model_copy(update={
                "intent": new_intent,
                "findings": updated_findings,
                "case_version": state.case_version + 1,
                "grant": revoke_grant(state),
            })
            eval_result = PolicyGate.evaluate(s_next, clock=resolved_clock)
            s_next = s_next.model_copy(update={
                "policy": eval_result,
                "phase": CasePhase.OPERATOR_INTERVENTION,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "MATERIAL_INTENT_EDITED", msg, "Payment Operator", {"new_amount": new_amount})
            return s_next.model_copy(update={"audit": new_audit})

        elif action_type == "INITIATE_HANDOFF":
            if not grant_secret or not str(grant_secret).strip():
                return refuse(state, "initiate human handoff", "missing required grant signing secret")

            if state.grant:
                is_valid, verify_err = GrantVerifier.verify(
                    grant=state.grant,
                    current_intent_hash=state.intent.intent_hash or "",
                    secret=grant_secret,
                    clock=resolved_clock,
                    expected_organization_id=state.organization_id,
                )
                if not is_valid:
                    return refuse(state, "initiate human handoff", f"grant verification failed: {verify_err}")
                if state.grant.tenant_id != state.tenant_id or state.grant.organization_id != state.organization_id:
                    return refuse(
                        state,
                        "initiate human handoff",
                        "grant tenant or organization scope does not match the authoritative case scope",
                    )

            recomputed_intent_hash = compute_intent_hash(state.intent)
            recomputed_snapshot_hash = compute_snapshot_hash(state)
            if (
                not state.grant
                or state.grant.status != GrantStatus.ACTIVE
                or state.grant.used
                or not state.intent.intent_hash
                or state.intent.status != IntentStatus.CONFIRMED
                or recomputed_intent_hash != state.intent.intent_hash
                or state.grant.bound_intent_hash != state.intent.intent_hash
                or state.grant.bound_intent_hash != recomputed_intent_hash
                or state.grant.bound_snapshot_hash != recomputed_snapshot_hash
            ):
                return refuse(state, "initiate human handoff", "no fresh, active grant matches the exact current intent or snapshot")

            idem_key = derive_idempotency_key(
                tenant_id=state.tenant_id,
                case_id=state.case_id or "UNKNOWN",
                case_version=state.case_version,
                grant_id=state.grant.grant_id,
                organization_id=state.organization_id,
            )
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

        else:
            return refuse(state, str(action_type), f"unknown action type '{action_type}'")

    @classmethod
    def apply_adapter_decision(
        cls,
        state: RiskCaseState,
        decision: AdapterDecision,
        pending_item_id: Optional[str] = None,
        error_message: Optional[str] = None,
        clock: Optional[ClockProvider] = None,
    ) -> RiskCaseState:
        """Apply an authoritative Action Adapter decision via internal typed transition.

        Not client-dispatchable. Maps typed AdapterDecision into immutable state updates.
        Rejects impossible/unexpected decisions fail closed.
        """
        resolved_clock = clock if clock is not None else SystemClock()

        def with_event(curr: RiskCaseState, event_type: str, summary: str, actor: str = "Action Adapter", details: Optional[Dict[str, Any]] = None) -> List[AuditEvent]:
            new_ev = AuditChain.create_event(
                events=curr.audit,
                event_type=event_type,
                summary=summary,
                actor=actor,
                case_id=curr.case_id,
                details=details or {},
                clock=resolved_clock,
            )
            return list(curr.audit) + [new_ev]

        if not isinstance(decision, AdapterDecision):
            raise ValueError(f"Reject fail closed: invalid or unexpected adapter decision '{decision}'")

        if decision == AdapterDecision.PENDING_ITEM_CREATED:
            if not pending_item_id:
                raise ValueError("pending_item_id is required when AdapterDecision is PENDING_ITEM_CREATED")

            msg = "Exact unchanged intent became a pending item in the existing approval rail; PayoutProof stopped."
            s_next = state.model_copy(update={
                "handoff": state.handoff.model_copy(update={
                    "status": HandoffStatus.PENDING_IN_APPROVAL_RAIL,
                    "last_adapter_decision": AdapterDecision.PENDING_ITEM_CREATED,
                    "pending_item_id": pending_item_id,
                }),
                "grant": state.grant.model_copy(update={
                    "status": GrantStatus.CONSUMED,
                    "used": True,
                }) if state.grant else None,
                "phase": CasePhase.COMPLETE,
                "last_change": msg,
            })
            new_audit = with_event(s_next, "HANDOFF_CONFIRMED", msg, "Action Adapter", {"pending_item_id": pending_item_id})
            return s_next.model_copy(update={"audit": new_audit})

        elif decision == AdapterDecision.DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY:
            # Preserves historical ELIGIBLE_FOR_HANDOFF, enters RECONCILIATION_REQUIRED, makes grant unusable
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
            new_audit = with_event(
                s_next,
                "HANDOFF_STATUS_AMBIGUOUS",
                msg,
                "Action Adapter",
                {"reason": error_message or "Downstream timeout / network uncertainty"},
            )
            return s_next.model_copy(update={"audit": new_audit})

        elif decision == AdapterDecision.RECOVERY_INTEGRITY_FAILURE_NO_RETRY:
            msg = f"Recovery integrity failure: {error_message or 'durable attempt or pending item inconsistency detected; no retry permitted.'}"
            curr_grant = state.grant
            if curr_grant:
                if curr_grant.status in (GrantStatus.CONSUMED, GrantStatus.SUSPENDED_FOR_RECONCILIATION):
                    updated_grant = curr_grant.model_copy(update={"status": curr_grant.status, "used": True})
                elif curr_grant.status in (GrantStatus.INVALIDATED, GrantStatus.EXPIRED):
                    updated_grant = curr_grant.model_copy(update={"status": curr_grant.status, "used": curr_grant.used})
                else:  # ACTIVE
                    updated_grant = curr_grant.model_copy(update={"status": GrantStatus.INVALIDATED, "used": False})
            else:
                updated_grant = None

            s_next = state.model_copy(update={
                "handoff": state.handoff.model_copy(update={
                    "status": HandoffStatus.RECONCILIATION_REQUIRED,
                    "last_adapter_decision": AdapterDecision.RECOVERY_INTEGRITY_FAILURE_NO_RETRY,
                    "pending_item_id": None,
                }),
                "grant": updated_grant,
                "phase": CasePhase.OPERATOR_INTERVENTION,
                "last_change": msg,
            })
            new_audit = with_event(
                s_next,
                "RECOVERY_INTEGRITY_FAILURE",
                msg,
                "Action Adapter",
                {"reason": error_message or "Durable attempt tuple corruption"},
            )
            return s_next.model_copy(update={"audit": new_audit})

        elif decision == AdapterDecision.REPLAY_REJECTED:
            # Refuses safely with no new pending item
            msg = f"Replay rejected: {error_message or 'the same grant or idempotency key cannot create another pending item.'}"
            s_next = state.model_copy(update={
                "handoff": state.handoff.model_copy(update={
                    "last_adapter_decision": AdapterDecision.REPLAY_REJECTED,
                }),
                "last_change": msg,
            })
            new_audit = with_event(
                s_next,
                "HANDOFF_REPLAY_REJECTED",
                msg,
                "Action Adapter",
                {"reason": error_message or "Duplicate submission prevented"},
            )
            return s_next.model_copy(update={"audit": new_audit})

        elif decision in (AdapterDecision.GRANT_INVALID_OR_EXPIRED, AdapterDecision.INTENT_MISMATCH):
            # Refuses safely with no new pending item, invalidates active grant
            msg = f"Handoff refused: {error_message or decision.value}"
            s_next = state.model_copy(update={
                "handoff": state.handoff.model_copy(update={
                    "last_adapter_decision": decision,
                }),
                "grant": state.grant.model_copy(update={
                    "status": GrantStatus.INVALIDATED,
                }) if state.grant and state.grant.status == GrantStatus.ACTIVE else state.grant,
                "phase": CasePhase.OPERATOR_INTERVENTION,
                "last_change": msg,
            })
            new_audit = with_event(
                s_next,
                "ACTION_REFUSED",
                msg,
                "Action Adapter",
                {"decision": decision.value, "reason": error_message},
            )
            return s_next.model_copy(update={"audit": new_audit})

        else:
            raise ValueError(f"Reject fail closed: impossible or unexpected adapter decision '{decision}'")
