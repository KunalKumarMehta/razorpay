"""Secret-free immutable release metadata for PayoutProof.

Defines the stable identifiers that pin an exact application build to the
policy, schema, model configuration, and Evaluation Version it was produced
with. The dataclass is deliberately free of secrets, paths, and timestamps:
it may be published at the public health and evaluation boundaries without
redaction, unlike ``AppConfig`` which carries cryptographic secrets and must
only be exposed via ``to_safe_dict()``.

These identifiers are declarative constants. They do not certify that a
sealed or held-out evaluation has been executed; synthetic-harness evidence
remains synthetic, as the evaluation reports themselves declare.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any

# ── Stable identifier constants ──────────────────────────────────────────────
# Application version mirrors pyproject [project].version; changing it requires
# updating pyproject.toml in the same commit.
APPLICATION_VERSION = "0.1.0"

# Deterministic Policy Gate identifier, mirrored by
# payoutproof.policy.evaluator.POLICY_VERSION and persisted in every
# PolicyEvaluationResult and HandoffGrant.
POLICY_VERSION = "PP-POLICY-V1"

# Authoritative persistence schema identifier for the SQLite tables created
# by payoutproof.storage.db.Database (risk_cases, audit_events, handoff_grants,
# adapter_attempts, pending_approval_items, case_audit_checkpoints). Bumped
# V1 -> V2 with Issue #10's additive tenant operating-limits tables
# (tenant_quota_counters, tenant_operating_limits,
# tenant_settings_audit_events); bumped V2 -> V3 with Issue #9's additive
# versioned-policy and approved-destination tables (policy_configs,
# destination_records, destination_audit_events, config_audit_events,
# config_audit_checkpoints); mirrored at payoutproof.storage.db.SCHEMA_VERSION.
SCHEMA_VERSION = "PP-SCHEMA-V3"

# Audit checkpoint MAC domain-separation identifier, mirrored by
# payoutproof.core.crypto.compute_checkpoint_mac.
AUDIT_CHECKPOINT_VERSION = "PAYOUTPROOF_AUDIT_CHECKPOINT_V1"

# Model-configuration identifier for the Trust Agent extraction configuration
# exercised by the synthetic structured-policy harnesses. The MVP harness
# executes structured synthetic stimuli; no real ASR or AASIST model
# configuration is wired yet (that material change will mint a new identifier).
MODEL_CONFIGURATION_VERSION = "PP-MODEL-CONFIG-V1-SYNTHETIC-STRUCTURED"

# Evaluation Version identifier binding the synthetic corpus, policy, model
# configuration, and scorer for the current dev (45), sealed (90), and safety
# (27x3) harnesses. Per CONTEXT.md, an Evaluation Version is immutable: a
# material change to any bound component requires a fresh identifier and a
# full rerun.
EVALUATION_VERSION = "PP-EVAL-V1-SYNTHETIC-STRUCTURED"

# Honest scope declaration mirrored from the evaluation service; this release
# metadata describes a synthetic invariant harness, not held-out or pilot proof.
EVIDENCE_SCOPE = "SYNTHETIC_INVARIANT_HARNESS_ONLY_NOT_HELD_OUT"


@dataclass(frozen=True)
class ReleaseMetadata:
    """Immutable, secret-free release identity for public boundaries."""

    application_version: str = APPLICATION_VERSION
    policy_version: str = POLICY_VERSION
    schema_version: str = SCHEMA_VERSION
    audit_checkpoint_version: str = AUDIT_CHECKPOINT_VERSION
    model_configuration_version: str = MODEL_CONFIGURATION_VERSION
    evaluation_version: str = EVALUATION_VERSION
    evidence_scope: str = EVIDENCE_SCOPE
    maturity: str = "IN_DEVELOPMENT"

    def __post_init__(self) -> None:
        for label, value in (
            ("application_version", self.application_version),
            ("policy_version", self.policy_version),
            ("schema_version", self.schema_version),
            ("audit_checkpoint_version", self.audit_checkpoint_version),
            ("model_configuration_version", self.model_configuration_version),
            ("evaluation_version", self.evaluation_version),
            ("evidence_scope", self.evidence_scope),
            ("maturity", self.maturity),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"ReleaseMetadata field '{label}' must be a non-empty string")

    def to_public_dict(self) -> Dict[str, Any]:
        """Return the publishable mapping (every field is safe by construction)."""
        return {
            "application_version": self.application_version,
            "policy_version": self.policy_version,
            "schema_version": self.schema_version,
            "audit_checkpoint_version": self.audit_checkpoint_version,
            "model_configuration_version": self.model_configuration_version,
            "evaluation_version": self.evaluation_version,
            "evidence_scope": self.evidence_scope,
            "maturity": self.maturity,
        }


# Singleton release identity used by the API and evaluation boundaries.
RELEASE_METADATA = ReleaseMetadata()


def get_release_metadata() -> ReleaseMetadata:
    """Return the frozen process-wide release metadata instance."""
    return RELEASE_METADATA
