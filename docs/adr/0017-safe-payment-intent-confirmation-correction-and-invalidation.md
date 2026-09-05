# ADR 0017: Safe Payment Intent Confirmation, Correction, and Invalidation

## Status

Accepted

## Context

GitHub Issue #17 requires providing Payment Operators and reviewers a safe, auditable lifecycle interface to:
1. Review extracted intent fields alongside fine-grained provenance, confidence scores, provider diagnostics, and detected conflicts.
2. Correct extraction mistakes before or after confirmation, recording original and corrected values safely in the tamper-evident audit ledger.
3. Explicitly confirm the exact counterparty, destination, amount, purpose, and originating instruction into a frozen, immutable `intent_hash`.
4. Guarantee that any material edit after confirmation immediately invalidates the prior evaluation, invalidates any existing Handoff Grant, and requires re-evaluation.

## Decision

1. **Review Surface (`GET /api/cases/{case_id}/intent`)**:
   - Exposes every material field (`counterparty`, `destination`, `amount`, `currency`, `purpose`, `instruction_reference`), its fine-grained provenance, extraction confidence, provider/model versions, detected contradictions/conflicts, unresolved state, and a boolean `can_confirm`.
   - `can_confirm` requires that all mandatory fields (`counterparty`, `destination`, `amount`) are populated, the intent is in `EXTRACTED` or `INVALIDATED` status, and there are zero unresolved contradictions or conflicts.

2. **Pre-Confirmation and Post-Confirmation Corrections (`POST /api/cases/{case_id}/intent/correct` / `CORRECT_INTENT`)**:
   - Implemented in `src/payoutproof/intent/extractor.py:correct_intent`.
   - Modifies any subset of fields (`counterparty`, `destination`, `amount`, `currency`, `purpose`, `instruction_reference`) and appends `operator_correction:{reason}` to provenance.
   - Pre-confirmation: Intent remains `EXTRACTED` ready for confirmation; audits `PAYMENT_INTENT_CORRECTED` with full before/after diffs.
   - Post-confirmation: Any material edit transitions status from `CONFIRMED` to `INVALIDATED`, clears `intent_hash`, revokes active Handoff Grants (`grant.status = INVALIDATED`), and resets the Policy Gate outcome to `HOLD`, auditing `MATERIAL_INTENT_EDITED`.

3. **Explicit Invalidation (`POST /api/cases/{case_id}/intent/invalidate` / `INVALIDATE_INTENT`)**:
   - Implemented in `src/payoutproof/intent/extractor.py:invalidate_intent`.
   - Transitions intent status to `INVALIDATED`, clears `intent_hash`, revokes active Handoff Grants, resets Policy Gate evaluation to `HOLD`, and audits `PAYMENT_INTENT_INVALIDATED`.
   - Accessible by both `PAYMENT_OPERATOR` (maker) and `FINANCE_CONTROL_OWNER` (checker).

4. **Explicit Confirmation (`POST /api/cases/{case_id}/intent/confirm` / `CONFIRM_INTENT`)**:
   - Restores/freezes canonical intent identity by computing SHA-256 `intent_hash = compute_intent_hash(intent)` over the canonical representation (`counterparty|destination|amount|currency|purpose|instruction_reference`).
   - Sets status to `CONFIRMED` and audits `INTENT_CONFIRMED`.
   - Fails closed if mandatory fields (`counterparty`, `destination`, `amount`) are missing.

5. **Strict Maker-Checker and Role Enforcement**:
   - `CORRECT_INTENT` and `CONFIRM_INTENT` are restricted to `Role.PAYMENT_OPERATOR`.
   - `INVALIDATE_INTENT` is permitted for both `Role.PAYMENT_OPERATOR` and `Role.FINANCE_CONTROL_OWNER`.
   - Action vocabulary `ALLOWED_ACTIONS` and `ACTION_ROLE_MATRIX` are updated and asserted in test coverage.

## Consequences

- **Immutability & Safety**: No confirmed payment intent can be silently modified; any material change destroys downstream grants and demands re-evaluation.
- **Audit Defensibility**: Complete before-and-after states and operator reasons are logged to the tamper-evident SHA-256 audit ledger.
- **Fail-Closed Downstream Rails**: Cleared or mismatched `intent_hash` causes all downstream action adapter handoffs to reject automatically.
