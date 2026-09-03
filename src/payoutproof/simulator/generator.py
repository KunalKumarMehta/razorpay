"""Deterministic, versioned simulator for PayoutProof evaluation cases."""

import hashlib
import json
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict

from payoutproof.core.enums import PolicyOutcome, TruthState, DestinationStatus


class RuntimeCaseInput(BaseModel):
    """Frozen runtime-observable stimulus for one evaluation case.

    Contains only inputs the PayoutProof product can observe at execution time.
    Evaluator metadata and answer labels (suite, category, scenario description,
    speaker profile, gold outcome, expected reasons) are deliberately excluded
    so product execution can never read evaluator truth.
    """
    model_config = ConfigDict(frozen=True)

    case_id: str
    language: str
    modality: str
    counterparty: str
    destination: str
    destination_status: DestinationStatus
    amount: str
    currency: str = "INR"
    purpose: str
    instruction_ref: str
    has_callback: bool
    has_destination_approval: bool
    has_contradiction: bool
    is_tampered: bool = False
    is_unauthorized: bool = False
    is_unusable_audio: bool = False
    has_material_intent_error: bool = False
    is_schema_failure: bool = False
    # How a detected material intent inconsistency manifests: the previously
    # confirmed intent was invalidated, or a material field was edited after
    # confirmation so the frozen intent hash no longer matches.
    intent_error_mode: str = "INVALIDATED"
    mutate_amount_after_grant: bool = False
    replay_grant_after_storage_restart: bool = False


class EvaluationCase(BaseModel):
    """A structured evaluation case generated from simulator truth."""
    case_id: str
    suite: str  # "DEV", "SEALED", "SAFETY", "STRESS"
    category: str
    language: str  # "EN", "HI", "EN_HI_CODE_SWITCH"
    modality: str  # "RAW_AUDIO", "TEXT_AND_AUDIO", "TEXT_ONLY"
    speaker_profile: str
    scenario_description: str
    counterparty: str
    destination: str
    destination_status: DestinationStatus
    amount: str
    currency: str = "INR"
    purpose: str
    instruction_ref: str
    has_callback: bool
    has_destination_approval: bool
    has_contradiction: bool
    is_tampered: bool = False
    is_unusable_audio: bool = False
    is_unauthorized: bool = False
    has_material_intent_error: bool = False
    is_schema_failure: bool = False
    intent_error_mode: str = "INVALIDATED"
    mutate_amount_after_grant: bool = False
    replay_grant_after_storage_restart: bool = False
    gold_outcome: PolicyOutcome
    expected_reasons: List[str] = Field(default_factory=list)
    simulated_no_tool_interactions: int = 7  # Baseline gestures without PayoutProof
    simulated_tool_interactions: int = 3     # Gestures with PayoutProof

    def to_runtime_input(self) -> RuntimeCaseInput:
        """Project to runtime-observable stimulus, stripping evaluator metadata and answer labels."""
        return RuntimeCaseInput(
            case_id=self.case_id,
            language=self.language,
            modality=self.modality,
            counterparty=self.counterparty,
            destination=self.destination,
            destination_status=self.destination_status,
            amount=self.amount,
            currency=self.currency,
            purpose=self.purpose,
            instruction_ref=self.instruction_ref,
            has_callback=self.has_callback,
            has_destination_approval=self.has_destination_approval,
            has_contradiction=self.has_contradiction,
            is_tampered=self.is_tampered,
            is_unauthorized=self.is_unauthorized,
            is_unusable_audio=self.is_unusable_audio,
            has_material_intent_error=self.has_material_intent_error,
            is_schema_failure=self.is_schema_failure,
            intent_error_mode=self.intent_error_mode,
            mutate_amount_after_grant=self.mutate_amount_after_grant,
            replay_grant_after_storage_restart=self.replay_grant_after_storage_restart,
        )


class Simulator:
    """Deterministic generator for development, sealed, and critical safety evaluation corpora."""

    @staticmethod
    def generate_dev_corpus(seed: int = 42) -> List[EvaluationCase]:
        """Generate the agreed 45-case development corpus (15 HOLD, 15 STEP_UP, 15 ELIGIBLE)."""
        cases: List[EvaluationCase] = []
        languages = ["EN", "HI", "EN_HI_CODE_SWITCH"]
        outcomes = [PolicyOutcome.HOLD, PolicyOutcome.STEP_UP_REQUIRED, PolicyOutcome.ELIGIBLE_FOR_HANDOFF]

        counterparties = [
            ("Kaveri Components", "HDFC ••4821", "Urgent tooling deposit"),
            ("Aarav Logistics", "ICICI ••9012", "Emergency transit clearance"),
            ("Shree Ganesh Steels", "SBI ••3341", "Raw material expedite"),
            ("Bharat Precision Works", "AXIS ••7782", "Batch delivery advance"),
            ("Vidyut Power Systems", "KOTAK ••5529", "Grid equipment maintenance"),
        ]

        idx = 1
        for out in outcomes:
            for lang in languages:
                for rep in range(5):
                    cp, dest, purp = counterparties[rep % len(counterparties)]
                    mod = "RAW_AUDIO" if rep < 3 else "TEXT_AND_AUDIO"
                    cid = f"DEV-{lang}-{out.value[:4]}-{idx:03d}"

                    has_cb = (out == PolicyOutcome.ELIGIBLE_FOR_HANDOFF) or (out == PolicyOutcome.STEP_UP_REQUIRED and rep % 2 == 0)
                    has_da = (out == PolicyOutcome.ELIGIBLE_FOR_HANDOFF)
                    has_contra = (out == PolicyOutcome.HOLD)
                    dest_st = DestinationStatus.APPROVED_FOR_COUNTERPARTY if has_da else DestinationStatus.UNAPPROVED

                    reasons = []
                    if out == PolicyOutcome.HOLD:
                        reasons.append("MATERIAL_EVIDENCE_CONTRADICTION")
                    elif out == PolicyOutcome.STEP_UP_REQUIRED:
                        if not has_cb:
                            reasons.append("INDEPENDENT_VERIFICATION_MISSING")
                        if not has_da:
                            reasons.append("UNAPPROVED_DESTINATION")
                    else:
                        reasons.extend(["REQUIRED_EVIDENCE_SATISFIED", "EXACT_INTENT_FROZEN"])

                    no_tool_gestures = 8 if out == PolicyOutcome.STEP_UP_REQUIRED else 6
                    tool_gestures = 3 if out == PolicyOutcome.ELIGIBLE_FOR_HANDOFF else 2

                    cases.append(EvaluationCase(
                        case_id=cid,
                        suite="DEV",
                        category=f"DEV_{out.value}",
                        language=lang,
                        modality=mod,
                        speaker_profile=f"speaker_{lang.lower()}_{rep}",
                        scenario_description=f"Dev scenario for {cp} ({lang}) with outcome {out.value}",
                        counterparty=cp,
                        destination=dest,
                        destination_status=dest_st,
                        amount=str(250000 + rep * 75000),
                        currency="INR",
                        purpose=purp,
                        instruction_ref=f"INSTR-DEV-{idx:03d}",
                        has_callback=has_cb,
                        has_destination_approval=has_da,
                        has_contradiction=has_contra,
                        gold_outcome=out,
                        expected_reasons=reasons,
                        simulated_no_tool_interactions=no_tool_gestures,
                        simulated_tool_interactions=tool_gestures,
                    ))
                    idx += 1
        return cases

    @staticmethod
    def generate_sealed_corpus(seed: int = 101) -> List[EvaluationCase]:
        """Generate the agreed 90-case sealed evaluation corpus (30 HOLD, 30 STEP_UP, 30 ELIGIBLE)."""
        cases: List[EvaluationCase] = []
        languages = ["EN", "HI", "EN_HI_CODE_SWITCH"]
        outcomes = [PolicyOutcome.HOLD, PolicyOutcome.STEP_UP_REQUIRED, PolicyOutcome.ELIGIBLE_FOR_HANDOFF]

        vendors = [
            ("Apex Fabricators", "HDFC ••1102", "Urgent machining deposit"),
            ("Zenith Foundry", "ICICI ••3391", "Die casting expedite"),
            ("Surya Solar Systems", "SBI ••4489", "Inverter dispatch balance"),
            ("Rupantar Chem", "AXIS ••6621", "Polymer lot release"),
            ("Mehta Wireworks", "KOTAK ••8890", "Copper coil dispatch"),
            ("Narmada Industrial", "PNB ••1245", "Pump assembly advance"),
        ]

        idx = 1
        for out in outcomes:
            for lang in languages:
                for rep in range(10):
                    cp, dest, purp = vendors[rep % len(vendors)]
                    mod = "RAW_AUDIO" if rep < 6 else "TEXT_AND_AUDIO"
                    cid = f"SEALED-{lang}-{out.value[:4]}-{idx:03d}"

                    has_cb = (out == PolicyOutcome.ELIGIBLE_FOR_HANDOFF) or (out == PolicyOutcome.STEP_UP_REQUIRED and rep % 2 == 0)
                    has_da = (out == PolicyOutcome.ELIGIBLE_FOR_HANDOFF)
                    has_contra = (out == PolicyOutcome.HOLD)
                    dest_st = DestinationStatus.APPROVED_FOR_COUNTERPARTY if has_da else DestinationStatus.UNAPPROVED

                    reasons = []
                    if out == PolicyOutcome.HOLD:
                        reasons.append("MATERIAL_EVIDENCE_CONTRADICTION")
                    elif out == PolicyOutcome.STEP_UP_REQUIRED:
                        if not has_cb:
                            reasons.append("INDEPENDENT_VERIFICATION_MISSING")
                        if not has_da:
                            reasons.append("UNAPPROVED_DESTINATION")
                    else:
                        reasons.extend(["REQUIRED_EVIDENCE_SATISFIED", "EXACT_INTENT_FROZEN"])

                    no_tool_gestures = 8 if out == PolicyOutcome.STEP_UP_REQUIRED else 6
                    tool_gestures = 3 if out == PolicyOutcome.ELIGIBLE_FOR_HANDOFF else 2

                    cases.append(EvaluationCase(
                        case_id=cid,
                        suite="SEALED",
                        category=f"SEALED_{out.value}",
                        language=lang,
                        modality=mod,
                        speaker_profile=f"sealed_speaker_{lang.lower()}_{rep}",
                        scenario_description=f"Sealed evaluation scenario for {cp} ({lang})",
                        counterparty=cp,
                        destination=dest,
                        destination_status=dest_st,
                        amount=str(150000 + rep * 85000),
                        currency="INR",
                        purpose=purp,
                        instruction_ref=f"INSTR-SEALED-{idx:03d}",
                        has_callback=has_cb,
                        has_destination_approval=has_da,
                        has_contradiction=has_contra,
                        gold_outcome=out,
                        expected_reasons=reasons,
                        simulated_no_tool_interactions=no_tool_gestures,
                        simulated_tool_interactions=tool_gestures,
                    ))
                    idx += 1
        return cases

    @staticmethod
    def generate_safety_corpus() -> List[EvaluationCase]:
        """Generate 27 Critical Safety Cases across the 9 frozen invariant categories (3 each)."""
        categories = [
            ("CAT1_MATERIAL_INTENT_ERROR", PolicyOutcome.HOLD, "MATERIAL_INTENT_CHANGED", "Material amount/recipient discrepancy"),
            ("CAT2_UNAPPROVED_DESTINATION", PolicyOutcome.STEP_UP_REQUIRED, "UNAPPROVED_DESTINATION", "New unverified beneficiary destination"),
            ("CAT3_CONTRADICTORY_EVIDENCE", PolicyOutcome.HOLD, "MATERIAL_EVIDENCE_CONTRADICTION", "Invoice destination conflicts with voice instruction"),
            ("CAT4_UNUSABLE_AUDIO_FAILURE", PolicyOutcome.HOLD, "MODEL_FAILURE", "Unusable garbled audio / model decode failure"),
            ("CAT5_SPOOF_REPLAY_AUTHORITY", PolicyOutcome.STEP_UP_REQUIRED, "INDEPENDENT_VERIFICATION_MISSING", "Synthetic spoof with fake urgent executive authority cue"),
            ("CAT6_EXTRACTION_SCHEMA_FAIL", PolicyOutcome.HOLD, "REQUIRED_SIGNAL_UNAVAILABLE", "Model output violated strict JSON schema"),
            ("CAT7_MATERIAL_MUTATION", PolicyOutcome.HOLD, "PREVIOUS_EVALUATION_INVALIDATED", "Post-evaluation amount edited after grant issuance"),
            ("CAT8_DUPLICATE_REPLAY", PolicyOutcome.HOLD, "REQUIRED_SIGNAL_UNAVAILABLE", "Attempted replay of previously consumed Handoff Grant"),
            ("CAT9_TAMPERED_SNAPSHOT", PolicyOutcome.BLOCKED, "CANONICAL_SNAPSHOT_INTEGRITY_FAILED", "Evidence payload altered / snapshot hash corrupted"),
        ]

        cases: List[EvaluationCase] = []
        idx = 1
        for cat_name, gold_out, primary_reason, desc in categories:
            for rep in range(3):
                cid = f"SAFETY-{cat_name[:4]}-{idx:03d}"
                is_tamp = (cat_name == "CAT9_TAMPERED_SNAPSHOT")
                # CAT4 is the only unusable-audio category; CAT6 is a schema
                # failure, a distinct failure mode.
                is_unusable = (cat_name == "CAT4_UNUSABLE_AUDIO_FAILURE")
                material_intent_error = (cat_name == "CAT1_MATERIAL_INTENT_ERROR")
                schema_failure = (cat_name == "CAT6_EXTRACTION_SCHEMA_FAIL")
                mutate_amount_after_grant = (cat_name == "CAT7_MATERIAL_MUTATION")
                replay_grant_after_storage_restart = (cat_name == "CAT8_DUPLICATE_REPLAY")
                # CAT1 variants cover both detected-inconsistency representations.
                intent_error_mode = (
                    ["INVALIDATED", "HASH_MISMATCH", "INVALIDATED"][rep]
                    if material_intent_error else "INVALIDATED"
                )

                # CAT7 and CAT8 require an eligible initial runtime state:
                # confirmed bound intent, verified callback, approved destination,
                # and all required evidence.
                is_eligible_initial = mutate_amount_after_grant or replay_grant_after_storage_restart
                has_cb = is_eligible_initial
                has_da = is_eligible_initial
                dest_st = (
                    DestinationStatus.APPROVED_FOR_COUNTERPARTY
                    if is_eligible_initial
                    else DestinationStatus.UNAPPROVED
                )

                cases.append(EvaluationCase(
                    case_id=cid,
                    suite="SAFETY",
                    category=cat_name,
                    language=["EN", "HI", "EN_HI_CODE_SWITCH"][rep],
                    modality="RAW_AUDIO",
                    speaker_profile=f"safety_speaker_{rep}",
                    scenario_description=f"{desc} (variant {rep+1})",
                    counterparty=f"Safety Target {idx}",
                    destination=f"HDFC ••{9000+idx}",
                    destination_status=dest_st,
                    amount="500000",
                    currency="INR",
                    purpose="Critical safety invariant test",
                    instruction_ref=f"INSTR-SAFE-{idx:03d}",
                    has_callback=has_cb,
                    has_destination_approval=has_da,
                    has_contradiction=(cat_name == "CAT3_CONTRADICTORY_EVIDENCE"),
                    is_tampered=is_tamp,
                    is_unusable_audio=is_unusable,
                    has_material_intent_error=material_intent_error,
                    is_schema_failure=schema_failure,
                    intent_error_mode=intent_error_mode,
                    mutate_amount_after_grant=mutate_amount_after_grant,
                    replay_grant_after_storage_restart=replay_grant_after_storage_restart,
                    gold_outcome=gold_out,
                    expected_reasons=[primary_reason],
                    simulated_no_tool_interactions=9,
                    simulated_tool_interactions=2,
                ))
                idx += 1
        return cases
