# ADR 0009: Versioned Policy Configuration and Approved Destinations

## Status

Accepted

## Context

PayoutProof enforces System Invariant 1 (Zero Autonomous Money Actions) and deterministic payment safety. In earlier milestones, policy thresholds (grant TTL, step-up requirements) were hardcoded constants (`GRANT_TTL_SECONDS = 900`, `POLICY_VERSION = "PP-POLICY-V1"`), and counterparty destination verification relied solely on per-case heuristic observations rather than an organization-governed registry of approved destinations.

To satisfy GitHub Issue #9:
1. Organizations must be able to configure and version their policy rules (step-up requirements, grant TTL, stopping conditions) without mutating past evaluation history.
2. Counterparty destinations must be explicitly approved by Finance Control Owners with effective approval windows (`[valid_from, valid_to)`).
3. Evaluated Risk Cases must record the exact policy version, config hash, and destination snapshot used at evaluation time for immutable audit reproducibility.

## Decision

1. **Policy Configuration Lifecycle and Immutability**:
   - `PolicyConfig` is an insert-only record with states `DRAFT -> ACTIVE -> RETIRED`.
   - At most one `PolicyConfig` per organization may be `ACTIVE` at any given time (enforced via partial unique index `idx_policy_configs_single_active`).
   - Content hash is computed canonically over canonical fields (`_POLICY_CONFIG_HASH_FIELDS`) using SHA-256 (`compute_policy_config_hash`).
   - Monotonic version sequencing (`PP-POLICY-V1`, `PP-POLICY-V2`, etc.) prevents out-of-order activations.
   - Any tampering with a persisted configuration row fails closed and triggers quarantine.

2. **Approved Destinations Registry**:
   - `ApprovedDestinationRecord` represents a durable approved destination for an organization.
   - Lifecycle: `CREATED -> ACTIVE -> RETIRED` (with `CREATED -> RETIRED` permitted for cancelling pending approvals). `RETIRED` is strictly terminal.
   - Effectiveness is computed at evaluation time using half-open intervals: `status == ACTIVE and valid_from <= eval_dt and (valid_to is None or eval_dt < valid_to)`.
   - Naive datetimes are rejected or converted to UTC fail-closed.
   - Overlapping active windows for the same `(organization_id, counterparty, destination)` are strictly prohibited.

3. **Policy Gate Integration & Provenance**:
   - `PolicyGate.evaluate` accepts optional `policy_config: Optional[PolicyConfig]` and `destination_snapshot: Optional[DestinationApprovalSnapshot]`.
   - When provided, `PolicyEvaluationResult` stamps `policy_config_id`, `policy_config_hash`, and `destination_snapshot`.
   - If `policy_config.step_up_rules.require_approved_destination` is true, an unapproved or expired destination forces `outcome = STEP_UP_REQUIRED` with `ReasonCode.UNAPPROVED_DESTINATION`.
   - If neither is provided, default backward-compatible in-code rules apply, ensuring legacy tests and replayed cases evaluate identically.

4. **Audit Chains**:
   - `config_audit_events` and `destination_audit_events` record all creation, activation, and retirement transitions in append-only SHA-256 hash chains rooted at `GENESIS_HASH`.
   - `config_audit_checkpoints` stores HMAC-signed checkpoints using the injected `audit_checkpoint_secret`.

5. **API & Role Boundaries**:
   - All management endpoints under `/api/destinations` and `/api/policy/configs` require a valid session and enforce the caller's session organization scope.
   - Mutations are strictly restricted to the `FINANCE_CONTROL_OWNER` role.
   - Missing or cross-organization targets strictly return HTTP 404 (zero-existence oracle) before role evaluation.

## Consequences

- Policy evaluations are now cryptographically bound to explicit, auditable configuration versions.
- Historical case evaluations remain reproducible and immutable even after policy rotation or destination retirement.
- Schema upgraded to `PP-SCHEMA-V3`.
