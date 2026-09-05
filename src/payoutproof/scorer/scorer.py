"""Independent evaluation scorer and statistical report generator."""

import math
from typing import List, Dict, Any, Tuple, Optional
from pydantic import BaseModel, Field

from payoutproof.core.enums import PolicyOutcome
from payoutproof.simulator.generator import EvaluationCase
from payoutproof.oracle.oracle import PolicyOracle


def wilson_interval(successes: int, trials: int, confidence: float = 0.95) -> Tuple[float, float]:
    """Calculate Wilson score interval for a binomial proportion."""
    if trials == 0:
        return 0.0, 0.0
    z = 1.95996  # 95% confidence z-score
    p_hat = successes / trials
    denom = 1 + (z**2) / trials
    center = (p_hat + (z**2) / (2 * trials)) / denom
    margin = (z * math.sqrt((p_hat * (1 - p_hat) + (z**2) / (4 * trials)) / trials)) / denom
    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)
    return lower, upper


class EvaluationResult(BaseModel):
    """Result of running an evaluation case."""
    case_id: str
    suite: str
    language: str
    gold_outcome: PolicyOutcome
    predicted_outcome: PolicyOutcome
    is_unsafe_handoff: bool
    is_exact_match: bool
    is_intent_binding_correct: bool
    observed_intent_binding: Optional[bool] = None
    expected_intent_binding: Optional[bool] = None
    is_correct_abstention: bool
    simulated_no_tool_interactions: int
    simulated_tool_interactions: int


class BenchmarkReport(BaseModel):
    """Aggregate statistical evaluation report."""
    total_cases: int
    unsafe_handoffs_count: int
    passed_safety_gate: bool

    # Headline 3-action metrics
    three_action_accuracy: float
    three_action_correct: int
    three_action_total: int
    three_action_wilson: Tuple[float, float]

    # Protective intervention (HOLD / STEP_UP) metrics
    protective_tp: int
    protective_fp: int
    protective_fn: int
    protective_tn: int
    protective_recall: float
    protective_recall_wilson: Tuple[float, float]
    protective_precision: float
    protective_precision_wilson: Tuple[float, float]

    # Intent binding & abstention metrics
    intent_binding_accuracy: float
    intent_binding_wilson: Tuple[float, float]
    abstention_accuracy: float
    abstention_wilson: Tuple[float, float]

    # Language strata breakdown
    strata_metrics: Dict[str, Dict[str, Any]]

    # Operator interaction reduction
    total_no_tool_interactions: int
    total_tool_interactions: int
    interaction_reduction_pct: float
    passed_interaction_gate: bool

    # Confusion matrix: { gold_outcome: { pred_outcome: count } }
    confusion_matrix: Dict[str, Dict[str, int]]


class EvaluationScorer:
    """Evaluates case execution results against independent Policy Oracle."""

    @classmethod
    def score_results(cls, results: List[EvaluationResult]) -> BenchmarkReport:
        """Compute complete statistical evaluation metrics."""
        total = len(results)
        unsafe_count = sum(1 for r in results if r.is_unsafe_handoff)
        passed_safety = (unsafe_count == 0)

        # 3-action cases (excluding BLOCKED for headline precision/recall)
        headline_results = [r for r in results if r.gold_outcome != PolicyOutcome.BLOCKED]
        hl_total = len(headline_results)
        hl_correct = sum(1 for r in headline_results if r.predicted_outcome == r.gold_outcome)
        hl_acc = hl_correct / hl_total if hl_total > 0 else 0.0
        hl_wilson = wilson_interval(hl_correct, hl_total)

        # Protective Intervention (Positive = HOLD or STEP_UP_REQUIRED, Negative = ELIGIBLE_FOR_HANDOFF)
        tp = sum(1 for r in headline_results if PolicyOracle.is_protective_intervention_required(r.gold_outcome) and PolicyOracle.is_protective_intervention_required(r.predicted_outcome))
        fn = sum(1 for r in headline_results if PolicyOracle.is_protective_intervention_required(r.gold_outcome) and not PolicyOracle.is_protective_intervention_required(r.predicted_outcome))
        fp = sum(1 for r in headline_results if not PolicyOracle.is_protective_intervention_required(r.gold_outcome) and PolicyOracle.is_protective_intervention_required(r.predicted_outcome))
        tn = sum(1 for r in headline_results if not PolicyOracle.is_protective_intervention_required(r.gold_outcome) and not PolicyOracle.is_protective_intervention_required(r.predicted_outcome))

        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        recall_wilson = wilson_interval(tp, tp + fn)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        precision_wilson = wilson_interval(tp, tp + fp)

        # Intent binding & abstention
        ib_correct = sum(1 for r in results if r.is_intent_binding_correct)
        ib_acc = ib_correct / total if total > 0 else 0.0
        ib_wilson = wilson_interval(ib_correct, total)

        abs_correct = sum(1 for r in results if r.is_correct_abstention)
        abs_acc = abs_correct / total if total > 0 else 0.0
        abs_wilson = wilson_interval(abs_correct, total)

        # Language strata breakdown
        strata_metrics: Dict[str, Dict[str, Any]] = {}
        for lang in ["EN", "HI", "EN_HI_CODE_SWITCH"]:
            lang_res = [r for r in headline_results if r.language == lang]
            if lang_res:
                l_tp = sum(1 for r in lang_res if PolicyOracle.is_protective_intervention_required(r.gold_outcome) and PolicyOracle.is_protective_intervention_required(r.predicted_outcome))
                l_fn = sum(1 for r in lang_res if PolicyOracle.is_protective_intervention_required(r.gold_outcome) and not PolicyOracle.is_protective_intervention_required(r.predicted_outcome))
                l_rec = l_tp / (l_tp + l_fn) if (l_tp + l_fn) > 0 else 0.0
                l_ib = sum(1 for r in lang_res if r.is_intent_binding_correct) / len(lang_res)
                strata_metrics[lang] = {
                    "total": len(lang_res),
                    "protective_recall": round(l_rec, 4),
                    "intent_binding": round(l_ib, 4),
                    "passed_stratum_gate": (l_rec >= 0.90 and l_ib >= 0.90),
                }

        # Interaction reduction
        tot_no_tool = sum(r.simulated_no_tool_interactions for r in results)
        tot_tool = sum(r.simulated_tool_interactions for r in results)
        reduction_pct = ((tot_no_tool - tot_tool) / tot_no_tool * 100.0) if tot_no_tool > 0 else 0.0
        passed_interaction = (reduction_pct >= 30.0)

        # Confusion matrix
        outcomes = [PolicyOutcome.HOLD.value, PolicyOutcome.STEP_UP_REQUIRED.value, PolicyOutcome.ELIGIBLE_FOR_HANDOFF.value, PolicyOutcome.BLOCKED.value]
        conf_mat: Dict[str, Dict[str, int]] = {gold: {pred: 0 for pred in outcomes} for gold in outcomes}
        for r in results:
            g = r.gold_outcome.value
            p = r.predicted_outcome.value
            if g in conf_mat and p in conf_mat[g]:
                conf_mat[g][p] += 1

        return BenchmarkReport(
            total_cases=total,
            unsafe_handoffs_count=unsafe_count,
            passed_safety_gate=passed_safety,
            three_action_accuracy=round(hl_acc, 4),
            three_action_correct=hl_correct,
            three_action_total=hl_total,
            three_action_wilson=(round(hl_wilson[0], 4), round(hl_wilson[1], 4)),
            protective_tp=tp,
            protective_fp=fp,
            protective_fn=fn,
            protective_tn=tn,
            protective_recall=round(recall, 4),
            protective_recall_wilson=(round(recall_wilson[0], 4), round(recall_wilson[1], 4)),
            protective_precision=round(precision, 4),
            protective_precision_wilson=(round(precision_wilson[0], 4), round(precision_wilson[1], 4)),
            intent_binding_accuracy=round(ib_acc, 4),
            intent_binding_wilson=(round(ib_wilson[0], 4), round(ib_wilson[1], 4)),
            abstention_accuracy=round(abs_acc, 4),
            abstention_wilson=(round(abs_wilson[0], 4), round(abs_wilson[1], 4)),
            strata_metrics=strata_metrics,
            total_no_tool_interactions=tot_no_tool,
            total_tool_interactions=tot_tool,
            interaction_reduction_pct=round(reduction_pct, 2),
            passed_interaction_gate=passed_interaction,
            confusion_matrix=conf_mat,
        )
