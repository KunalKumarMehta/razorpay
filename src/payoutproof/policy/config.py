"""Immutable, versioned policy configuration for PayoutProof (Issue #9).

A PolicyConfig freezes the Policy Gate's thresholds and stopping rules into
an insert-only, hash-chained record. The lifecycle mirrors the grant
lattice: DRAFT -> ACTIVE -> RETIRED, irreversible, with at most one ACTIVE
config per organization. Once ACTIVE, the config's content can never be
edited — a change mints a new version row, which is what makes the "exact
immutable policy version" recorded by every Policy Outcome meaningful.

Content integrity is cryptographic, not just structural: a canonical
serialization is hashed at write time and re-verified on every read.
Immutability is enforced twice over:
  - structurally: policy_configs has no content UPDATE path; and
  - cryptographically: the model refuses to represent a config whose
    content_hash disagrees with its own canonical content, and refuses
    frozen-lifecycle fields on configs still in DRAFT.

The canonical serialization follows the explicit-field-list idiom of
``PaymentIntent.canonical_string`` (an ordered pipe projection, then
SHA-256) — the same function runs at write and at verify, by construction.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from payoutproof.core.crypto import sha256_hex
from payoutproof.core.enums import PolicyConfigStatus
from payoutproof.policy.evaluator import GRANT_TTL_SECONDS, POLICY_VERSION

# Canonical, explicit field order for the content hash. Never reorder or
# append casually: changing this list re-hashes every existing config and
# reads as tampering. Additions only, in the same spirit as
# compute_snapshot_hash's explicit projection.
_POLICY_CONFIG_HASH_FIELDS = (
    "organization_id",
    "version_id",
    "grant_ttl_seconds",
    "step_up_rules",
    "block_conditions",
)


class StepUpRules(BaseModel):
    """Explicit threshold rules for Policy Gate step-up decisions.

    Every field names a rule the gate applies deterministically; the values
    are the exact thresholds an evaluation records. A rule engine is
    deliberately out of scope for Issue #9 — the versioning spine, not a
    data-driven rule language, is the deliverable.
    """
    model_config = ConfigDict(frozen=True)

    require_independent_callback: bool = True
    require_approved_destination: bool = True
    step_up_outcome: str = "STEP_UP_REQUIRED"


class BlockConditions(BaseModel):
    """Explicit stopping rules that block or hold an evaluation."""
    model_config = ConfigDict(frozen=True)

    block_on_snapshot_integrity_failure: bool = True
    block_on_policy_config_tamper: bool = True
    hold_on_model_failure: bool = True
    hold_on_evidence_contradiction: bool = True
    hold_on_material_intent_change: bool = True


class PolicyConfig(BaseModel):
    """One immutable policy configuration version, scoped to an organization.

    ``content_hash`` is SHA-256 over the canonical projection of the content
    fields only (never lifecycle metadata), computed by ``canonical_string``.
    The immutability guards make an incoherent config unrepresentable:
    activating or retiring a config, or asserting a mismatched content hash,
    raises rather than persisting a lie.
    """
    model_config = ConfigDict(frozen=True)

    config_id: str
    version_id: str = "PP-POLICY-V1"
    organization_id: str
    status: PolicyConfigStatus = PolicyConfigStatus.DRAFT
    grant_ttl_seconds: int = Field(default=GRANT_TTL_SECONDS, ge=1)
    step_up_rules: StepUpRules = Field(default_factory=StepUpRules)
    block_conditions: BlockConditions = Field(default_factory=BlockConditions)
    content_hash: str
    created_by: str
    created_at: str
    activated_by: Optional[str] = None
    activated_at: Optional[str] = None
    retired_by: Optional[str] = None
    retired_at: Optional[str] = None

    def canonical_string(self) -> str:
        """Deterministic canonical representation of the hashed content.

        Covers exactly the content fields — thresholds and stopping rules —
        in a fixed order, JSON-canonical for the two rule dicts so key order
        can never drift. Lifecycle metadata (who/when) and identifiers stay
        out: retiring a config must not change what content was evaluated.
        """
        import json

        parts = [
            self.organization_id,
            self.version_id,
            str(self.grant_ttl_seconds),
            json.dumps(self.step_up_rules.model_dump(), sort_keys=True, separators=(",", ":")),
            json.dumps(self.block_conditions.model_dump(), sort_keys=True, separators=(",", ":")),
        ]
        return "|".join(parts)

    def compute_content_hash(self) -> str:
        """SHA-256 over the canonical content — the single hash authority.

        The identical function runs at write (minting) and at verify
        (verify_content_hash / Database read paths); any divergence between
        the two would produce false tamper alarms, so there is exactly one.
        """
        return sha256_hex(self.canonical_string())

    def verify_content_hash(self) -> bool:
        """True iff the stored content_hash matches the recomputed canonical hash."""
        return self.compute_content_hash() == self.content_hash

    @model_validator(mode="after")
    def _guard_immutability(self) -> "PolicyConfig":
        """Immutability guards, enforced at the model boundary.

        1. A config that is ACTIVE or RETIRED must carry its activation
           attribution (frozen lifecycle fields cannot appear or vanish).
        2. The stored content_hash must equal the canonical recomputation —
           a tampered config row is unrepresentable in memory.
        3. A DRAFT config cannot carry retirement attribution.
        """
        if self.status in (PolicyConfigStatus.ACTIVE, PolicyConfigStatus.RETIRED):
            if not self.activated_by or not self.activated_at:
                raise ValueError(
                    f"PolicyConfig {self.config_id} is {self.status.value} but lacks activation attribution"
                )
        if self.status == PolicyConfigStatus.DRAFT:
            if self.retired_by is not None or self.retired_at is not None:
                raise ValueError(
                    f"PolicyConfig {self.config_id} is DRAFT but carries retirement attribution"
                )
        if not self.verify_content_hash():
            raise ValueError(
                f"PolicyConfig {self.config_id} content hash mismatch: stored {self.content_hash} "
                f"!= canonical {self.compute_content_hash()} (content tampered)"
            )
        return self

    def with_status(
        self,
        status: PolicyConfigStatus,
        *,
        activated_by: Optional[str] = None,
        activated_at: Optional[str] = None,
        retired_by: Optional[str] = None,
        retired_at: Optional[str] = None,
    ) -> "PolicyConfig":
        """Return the next lifecycle state as a new frozen config.

        Content never changes across a lifecycle move — only the status and
        attribution fields — so the content hash is carried over untouched.
        Callers apply validate_policy_version_transition first; the model
        validator is the second, in-memory guard.
        """
        return self.model_copy(
            update={
                "status": status,
                "activated_by": activated_by if activated_by is not None else self.activated_by,
                "activated_at": activated_at if activated_at is not None else self.activated_at,
                "retired_by": retired_by if retired_by is not None else self.retired_by,
                "retired_at": retired_at if retired_at is not None else self.retired_at,
            }
        )

    def to_audit_details(self) -> Dict[str, Any]:
        """Provenance block recorded in audit events and Policy Outcomes."""
        return {
            "policy_config_id": self.config_id,
            "policy_config_version": self.version_id,
            "policy_config_hash": self.content_hash,
            "policy_config_status": self.status.value,
        }


def next_version_id(current: Optional[str]) -> str:
    """Monotonic version label: PP-POLICY-V1 -> PP-POLICY-V2 -> ..."""
    if current is None or not str(current).strip():
        return "PP-POLICY-V1"
    try:
        suffix = int(str(current).strip().rsplit("V", 1)[1])
        return f"PP-POLICY-V{suffix + 1}"
    except (ValueError, IndexError):
        raise ValueError(f"Unparseable policy version id '{current}'")


def mint_policy_config(
    *,
    organization_id: str,
    config_id: str,
    created_by: str,
    created_at: Optional[str] = None,
    version_id: Optional[str] = None,
    grant_ttl_seconds: int = GRANT_TTL_SECONDS,
    step_up_rules: Optional[StepUpRules] = None,
    block_conditions: Optional[BlockConditions] = None,
) -> PolicyConfig:
    """Mint a DRAFT config, computing the canonical content hash exactly once.

    The hash is derived, never caller-supplied: a client cannot assert a
    hash for content it did not write. The candidate is assembled without
    validation (the hash does not exist yet), hashed once, and then fully
    re-validated — so the guards provably hold on the returned object and the
    same compute function backs every later verification.
    """
    resolved_at = created_at or datetime.now(timezone.utc).isoformat()
    resolved_rules = StepUpRules.model_validate(step_up_rules) if step_up_rules else StepUpRules()
    resolved_conditions = (
        BlockConditions.model_validate(block_conditions) if block_conditions else BlockConditions()
    )
    candidate = PolicyConfig.model_construct(
        config_id=config_id,
        version_id=version_id or "PP-POLICY-V1",
        organization_id=organization_id,
        status=PolicyConfigStatus.DRAFT,
        grant_ttl_seconds=grant_ttl_seconds,
        step_up_rules=resolved_rules,
        block_conditions=resolved_conditions,
        content_hash="",
        created_by=created_by,
        created_at=resolved_at,
        activated_by=None,
        activated_at=None,
        retired_by=None,
        retired_at=None,
    )
    hashed = candidate.model_copy(update={"content_hash": candidate.compute_content_hash()})
    return PolicyConfig.model_validate(hashed.model_dump())


def default_active_config(
    organization_id: Optional[str] = None,
    *,
    config_id: str = "PP-POLCFG-DEFAULT",
) -> PolicyConfig:
    """The backward-compatible default: exactly today's gate behavior.

    PolicyGate.evaluate accepts a resolved config defaulting to one
    equivalent to the current in-code rules (GRANT_TTL_SECONDS, the inline
    step-up and blocking rules, POLICY_VERSION), so every pre-existing
    caller — scorer/runner, state machine, the full legacy corpus — keeps
    its byte-identical outcomes without edits.
    """
    minted = mint_policy_config(
        organization_id=organization_id or "UNSCOPED",
        config_id=config_id,
        created_by="PayoutProof",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
        version_id=POLICY_VERSION,
    )
    return minted.with_status(
        PolicyConfigStatus.ACTIVE,
        activated_by="PayoutProof",
        activated_at=datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
    )


__all__ = [
    "PolicyConfig",
    "PolicyConfigStatus",
    "StepUpRules",
    "BlockConditions",
    "next_version_id",
    "mint_policy_config",
    "default_active_config",
]
