"""Centralized evaluation execution service for PayoutProof benchmark suites.

Owns suite selection, normalization, deterministic repetition, product boundary
execution loops, oracle comparison, and comprehensive audit reporting.
No caller should reconstruct suite selection or repetition loops independently.
"""

import copy
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field, ConfigDict, model_validator

from payoutproof.core.enums import PolicyOutcome
from payoutproof.simulator.generator import Simulator, EvaluationCase, RuntimeCaseInput
from payoutproof.oracle.oracle import PolicyOracle
from payoutproof.scorer.scorer import (
    EvaluationResult,
    BenchmarkReport,
    EvaluationScorer,
)
from payoutproof.scorer import runner as runner_module


def execute_runtime_case(
    stimulus: RuntimeCaseInput,
    evaluation_time: Optional[datetime] = None,
) -> runner_module.RuntimeCaseDiagnostics:
    """Service-bound execution boundary symbol wrapping runner.execute_runtime_case.

    Exported at module level to provide an explicitly patchable boundary symbol
    for call-count spying and interception tests.
    """
    return runner_module.execute_runtime_case(stimulus, evaluation_time=evaluation_time)


SYNTHETIC_SCOPE_DECLARATION = "SYNTHETIC_INVARIANT_HARNESS_ONLY_NOT_HELD_OUT"


class _FrozenDict(dict):
    """Immutable dictionary subclass preventing mutation after creation."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __setitem__(self, key, value):
        raise TypeError(f"'{self.__class__.__name__}' object does not support item assignment")

    def __delitem__(self, key):
        raise TypeError(f"'{self.__class__.__name__}' object does not support item deletion")

    def clear(self):
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def pop(self, *args, **kwargs):
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def popitem(self):
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def setdefault(self, *args, **kwargs):
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def update(self, *args, **kwargs):
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def __ior__(self, other):
        raise TypeError(f"'{self.__class__.__name__}' object does not support in-place or (|=)")

    def copy(self) -> "_FrozenDict":
        """Return a shallow copy of self as a new immutable _FrozenDict."""
        res = self.__class__(self)
        if hasattr(self, "__dict__"):
            res.__dict__.update(self.__dict__)
        return res

    def __copy__(self) -> "_FrozenDict":
        """Return a shallow copy for copy.copy protocol."""
        return self.copy()

    def __deepcopy__(self, memo: Optional[Dict[int, Any]] = None) -> "_FrozenDict":
        """Return a deep copy for copy.deepcopy, handling memo correctly without unfreezing."""
        if memo is not None and id(self) in memo:
            return memo[id(self)]
        res = self.__class__.__new__(self.__class__)
        if memo is not None:
            memo[id(self)] = res
        for k, v in self.items():
            dict.__setitem__(res, copy.deepcopy(k, memo), copy.deepcopy(v, memo))
        if hasattr(self, "__dict__"):
            for k, v in self.__dict__.items():
                res.__dict__[copy.deepcopy(k, memo)] = copy.deepcopy(v, memo)
        return res

    def __reduce__(self):
        """Reduce protocol for pickle compatibility without invoking blocked __setitem__."""
        state = getattr(self, "__dict__", None)
        if state:
            return (self.__class__, (dict(self),), state)
        return (self.__class__, (dict(self),))


def _freeze_value(value: Any) -> Any:
    """Recursively freeze mapping and sequence collections into immutable forms."""
    if isinstance(value, _FrozenDict):
        if any(isinstance(v, (dict, list)) and not isinstance(v, _FrozenDict) for v in value.values()):
            return _FrozenDict({k: _freeze_value(v) for k, v in value.items()})
        return value
    if isinstance(value, dict):
        return _FrozenDict({k: _freeze_value(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(v) for v in value)
    return value


class RepetitionAuditRecord(BaseModel):
    """Audit record for one repetition iteration within an evaluation suite run."""
    model_config = ConfigDict(frozen=True)

    repetition_index: int  # 0-based
    repetition_number: int  # 1-based
    case_count: int
    base_case_ids: Tuple[str, ...]
    execution_ids: Tuple[str, ...]


class ExecutionAuditRecord(BaseModel):
    """Audit record for one individual case execution."""
    model_config = ConfigDict(frozen=True)

    execution_id: str
    base_case_id: str
    repetition_index: int  # 0-based
    repetition_number: int  # 1-based
    category: str
    predicted_outcome: Optional[PolicyOutcome]
    gold_outcome: PolicyOutcome
    oracle_outcome: Optional[PolicyOutcome]
    is_exact_match: bool
    is_unsafe_handoff: bool
    is_intent_binding_correct: bool = True
    is_correct_abstention: bool = True
    language: str = "EN"
    predicted_reasons: Tuple[str, ...] = Field(default_factory=tuple)
    simulated_no_tool_interactions: int = 0
    simulated_tool_interactions: int = 0

    @property
    def base_case(self) -> str:
        return self.base_case_id

    @property
    def repetition(self) -> int:
        return self.repetition_number

    @property
    def exact_match(self) -> bool:
        return self.is_exact_match

    @property
    def unsafe_handoff(self) -> bool:
        return self.is_unsafe_handoff


class SuiteExecutionReport(BenchmarkReport):
    """Comprehensive, deterministic evaluation report for a suite execution.

    Preserves all BenchmarkReport statistical fields while providing full
    transparency into repetition counts, base cases, individual executions,
    mismatch tracking, and synthetic scope declarations.
    """
    model_config = ConfigDict(frozen=True)

    suite: str
    scope_declaration: str = SYNTHETIC_SCOPE_DECLARATION
    repetition_count: int
    base_case_count: int
    total_executions: int
    product_boundary_call_count: int
    exact_mismatches_count: int
    mismatched_execution_ids: Tuple[str, ...]
    category_counts: Dict[str, int]
    base_case_counts: Dict[str, int]
    execution_ids: Tuple[str, ...]
    repetition_records: Tuple[RepetitionAuditRecord, ...]
    execution_records: Tuple[ExecutionAuditRecord, ...]

    @model_validator(mode="after")
    def _freeze_all_mappings(self) -> "SuiteExecutionReport":
        for field_name in list(self.__dict__.keys()):
            val = getattr(self, field_name)
            frozen_val = _freeze_value(val)
            if frozen_val is not val:
                object.__setattr__(self, field_name, frozen_val)
        return self

    @property
    def repetitions(self) -> Tuple[RepetitionAuditRecord, ...]:
        return self.repetition_records

    @property
    def executions(self) -> Tuple[ExecutionAuditRecord, ...]:
        return self.execution_records

    @property
    def results(self) -> Tuple[ExecutionAuditRecord, ...]:
        return self.execution_records


class EvaluationExecutionService:
    """Centralized orchestration service for running evaluation suites."""

    SUITE_CONFIGS: Dict[str, Dict[str, Any]] = {
        "dev": {
            "generator": Simulator.generate_dev_corpus,
            "repetitions": 1,
            "expected_base_count": 45,
        },
        "sealed": {
            "generator": Simulator.generate_sealed_corpus,
            "repetitions": 1,
            "expected_base_count": 90,
        },
        "safety": {
            "generator": Simulator.generate_safety_corpus,
            "repetitions": 3,
            "expected_base_count": 27,
        },
    }

    @classmethod
    def normalize_suite_name(cls, suite: str) -> str:
        """Validate and normalize suite name, raising ValueError on unsupported names."""
        if not suite or not isinstance(suite, str):
            raise ValueError(f"Invalid suite name: {suite}. Permitted suites: {list(cls.SUITE_CONFIGS.keys())}")
        norm = suite.strip().lower()
        if norm not in cls.SUITE_CONFIGS:
            raise ValueError(
                f"Unknown evaluation suite: '{suite}'. Permitted suites: {list(cls.SUITE_CONFIGS.keys())}"
            )
        return norm

    @classmethod
    def run_suite(
        cls,
        suite: str,
        evaluation_time: Optional[datetime] = None,
    ) -> SuiteExecutionReport:
        """Execute a full evaluation suite through the centralized pipeline.

        Performs:
        1. Suite name validation and normalization.
        2. Corpus generation, expected base count validation, and base case ID uniqueness/non-emptiness validation.
        3. Deterministic execution ID assignment (repetition-major order).
        4. Product boundary execution (only RuntimeCaseInput with case_id=execution_id).
        5. Admission rejection inspection before oracle call.
        6. Post-execution scoring against independent PolicyOracle and frozen gold.
        7. Aggregation and immutable audit report assembly.
        """
        suite_key = cls.normalize_suite_name(suite)
        config = cls.SUITE_CONFIGS[suite_key]
        generator_fn = config["generator"]
        repetition_count: int = config["repetitions"]
        expected_base_count: int = config["expected_base_count"]

        base_cases: List[EvaluationCase] = generator_fn()

        # Enforce expected base case count invariant before executing any case
        if len(base_cases) != expected_base_count:
            raise ValueError(
                f"Corpus base case count drift for suite '{suite_key}': "
                f"expected exactly {expected_base_count}, got {len(base_cases)}"
            )

        # Validate base case IDs are non-empty and unique within generated corpus
        for idx, case in enumerate(base_cases):
            if not case.case_id or not isinstance(case.case_id, str) or not case.case_id.strip():
                raise ValueError(f"Corpus contains invalid or empty base case ID at index {idx}")

        base_case_ids = [c.case_id for c in base_cases]
        if len(base_case_ids) != len(set(base_case_ids)):
            raise ValueError(f"Corpus base case IDs must be unique within suite '{suite_key}'")

        # Prepare audit and aggregation structures
        repetition_records: List[RepetitionAuditRecord] = []
        execution_records: List[ExecutionAuditRecord] = []
        evaluation_results_for_scorer: List[EvaluationResult] = []
        ordered_execution_ids: List[str] = []
        seen_execution_ids: set = set()
        mismatched_execution_ids: List[str] = []

        base_case_counts: Dict[str, int] = {cid: 0 for cid in base_case_ids}
        category_counts: Dict[str, int] = {}
        for case in base_cases:
            if case.category not in category_counts:
                category_counts[case.category] = 0

        boundary_call_count = 0

        # Execute repetitions in repetition-major order, then corpus order
        for rep_idx in range(repetition_count):
            rep_num = rep_idx + 1
            rep_execution_ids: List[str] = []

            for case in base_cases:
                execution_id = f"{case.case_id}-R{rep_num}"
                if execution_id in seen_execution_ids:
                    raise ValueError(f"Generated duplicate execution ID: {execution_id}")

                seen_execution_ids.add(execution_id)
                rep_execution_ids.append(execution_id)
                ordered_execution_ids.append(execution_id)
                base_case_counts[case.case_id] += 1
                category_counts[case.category] += 1

                # Stimulus: frozen RuntimeCaseInput with case_id=execution_id.
                # Absolutely no evaluator metadata (category, gold, oracle, expected reasons, suite)
                runtime_stimulus = case.to_runtime_input().model_copy(update={"case_id": execution_id})

                # Product execution boundary
                boundary_call_count += 1
                diagnostics = execute_runtime_case(runtime_stimulus, evaluation_time=evaluation_time)

                predicted = diagnostics.predicted_outcome
                if predicted is None:
                    raise runner_module.AdmissionRejectedScoringError(
                        f"cannot score admission-rejected case {case.case_id}: it produced "
                        "no Policy Outcome, and EvaluationResult cannot represent None"
                    )

                # Evaluator-side comparison against frozen gold and PolicyOracle
                # PolicyOracle is only evaluated after product boundary execution and admission check
                oracle_outcome, _ = PolicyOracle.evaluate_expected(case)

                # Exact match rule:
                # Predicted outcome equals both frozen case.gold_outcome and PolicyOracle output,
                # and frozen gold equals oracle output.
                is_exact = (
                    predicted == case.gold_outcome
                    and predicted == oracle_outcome
                    and case.gold_outcome == oracle_outcome
                )

                if not is_exact:
                    mismatched_execution_ids.append(execution_id)

                is_unsafe = (
                    predicted == PolicyOutcome.ELIGIBLE_FOR_HANDOFF
                    and (
                        case.gold_outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF
                        or oracle_outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF
                    )
                )

                is_abstain_correct = (
                    predicted in (PolicyOutcome.HOLD, PolicyOutcome.STEP_UP_REQUIRED, PolicyOutcome.BLOCKED)
                    if case.gold_outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF
                    else True
                )

                eval_res = EvaluationResult(
                    case_id=execution_id,
                    suite=case.suite,
                    language=case.language,
                    gold_outcome=case.gold_outcome,
                    predicted_outcome=predicted,
                    is_unsafe_handoff=is_unsafe,
                    is_exact_match=is_exact,
                    is_intent_binding_correct=diagnostics.is_intent_binding_correct,
                    is_correct_abstention=is_abstain_correct,
                    simulated_no_tool_interactions=case.simulated_no_tool_interactions,
                    simulated_tool_interactions=case.simulated_tool_interactions,
                )
                evaluation_results_for_scorer.append(eval_res)

                exec_audit = ExecutionAuditRecord(
                    execution_id=execution_id,
                    base_case_id=case.case_id,
                    repetition_index=rep_idx,
                    repetition_number=rep_num,
                    category=case.category,
                    predicted_outcome=predicted,
                    gold_outcome=case.gold_outcome,
                    oracle_outcome=oracle_outcome,
                    is_exact_match=is_exact,
                    is_unsafe_handoff=is_unsafe,
                    is_intent_binding_correct=diagnostics.is_intent_binding_correct,
                    is_correct_abstention=is_abstain_correct,
                    language=case.language,
                    predicted_reasons=tuple(diagnostics.predicted_reasons),
                    simulated_no_tool_interactions=case.simulated_no_tool_interactions,
                    simulated_tool_interactions=case.simulated_tool_interactions,
                )
                execution_records.append(exec_audit)

            repetition_records.append(
                RepetitionAuditRecord(
                    repetition_index=rep_idx,
                    repetition_number=rep_num,
                    case_count=len(base_cases),
                    base_case_ids=tuple(base_case_ids),
                    execution_ids=tuple(rep_execution_ids),
                )
            )

        # Statistical report via EvaluationScorer
        benchmark_report = EvaluationScorer.score_results(evaluation_results_for_scorer)
        total_executions = len(execution_records)

        return SuiteExecutionReport(
            **benchmark_report.model_dump(),
            suite=suite_key,
            scope_declaration=SYNTHETIC_SCOPE_DECLARATION,
            repetition_count=repetition_count,
            base_case_count=len(base_cases),
            total_executions=total_executions,
            product_boundary_call_count=boundary_call_count,
            exact_mismatches_count=len(mismatched_execution_ids),
            mismatched_execution_ids=tuple(mismatched_execution_ids),
            category_counts=category_counts,
            base_case_counts=base_case_counts,
            execution_ids=tuple(ordered_execution_ids),
            repetition_records=tuple(repetition_records),
            execution_records=tuple(execution_records),
        )
