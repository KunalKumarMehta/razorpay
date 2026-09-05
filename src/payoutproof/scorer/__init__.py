"""Scorer package."""

from payoutproof.scorer.scorer import (
    wilson_interval,
    EvaluationResult,
    BenchmarkReport,
    EvaluationScorer,
)
from payoutproof.scorer.runner import execute_case_under_test
from payoutproof.scorer.service import (
    EvaluationExecutionService,
    SuiteExecutionReport,
    RepetitionAuditRecord,
    ExecutionAuditRecord,
    SYNTHETIC_SCOPE_DECLARATION,
)

__all__ = [
    "wilson_interval",
    "EvaluationResult",
    "BenchmarkReport",
    "EvaluationScorer",
    "execute_case_under_test",
    "EvaluationExecutionService",
    "SuiteExecutionReport",
    "RepetitionAuditRecord",
    "ExecutionAuditRecord",
    "SYNTHETIC_SCOPE_DECLARATION",
]
