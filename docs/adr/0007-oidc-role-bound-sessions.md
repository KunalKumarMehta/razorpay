# 7. OIDC Authentication, Role-Bound Sessions, and Maker-Checker Authorization

Date: 2026-09-04
Status: Accepted

## Context
Prior to Issue #7, PayoutProof used header-based organization identification (`X-Organization-Id`) and lacked authenticated operator sessions. Anyone capable of authoring HTTP requests could dispatch arbitrary mutating actions provided the header matched.

To fulfill PayoutProof core invariants (especially Invariant 1: Zero Autonomous Money Actions), operator requests must be authenticated via standard OpenID Connect (OIDC), bound to tamper-evident server-side sessions, and restricted by a code-level Role-Based Access Control (RBAC) matrix and maker-checker constraints.

## Decision
1. **OIDC Code Flow**: Authentication executes standard OIDC authorization-code flow with PKCE/nonce state parameters persisted in SQLite (`auth_login_states`).
2. **Deterministic In-Process Test Provider**: To avoid external network dependencies and protect staging/production environments, tests inject `FakeOIDCProvider` directly in-process via `create_app(oidc_client=...)`.
3. **Session Store**: Sessions are tracked server-side in SQLite (`operator_sessions`) with SHA-256 token hashing, bounded TTL, cryptographic revocation, and explicit audit logging.
4. **Frozen Role Vocabulary & RBAC**:
   - `Payment Operator`: Evidence ingestion, intent extraction, intent confirmation.
   - `Finance Control Owner`: Destination approval, Policy Gate evaluation, Handoff Grant issuance, and human handoff initiation.
   - `Auditor`: Strictly read-only access (case reading and cryptographic audit verification).
   - `Tenant Administrator`: Tenant identity and lifecycle administration.
   - `Platform Operator`: Cross-tenant platform maintenance and evaluation runs.
5. **Maker-Checker Constraint**: The operator subject who confirmed the Payment Intent cannot initiate human handoff on that same case, enforced at the API boundary before state machine dispatch.
6. **Zero-Existence Oracle**: Scope verification precedes role authorization. An unauthorized role attempting to access an out-of-scope or absent case receives HTTP 404, never revealing the case's existence.

## Consequences
- Every protected route enforces session authentication or fails with HTTP 401.
- Incompatible role actions fail with HTTP 403.
- Maker-checker violations fail with HTTP 403.
- All 323 existing unit, integration, and security tests pass.
