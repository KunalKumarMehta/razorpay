# ADR 0008: Organization Membership Administration Without Money Action Authority

## Context
Issue #8 requires administering organization membership (inviting, assigning roles, and removing members) without conferring any Money Action authority or compromising Invariant 1 (Zero Autonomous Money Actions).

## Decision
1. **Cryptographic & Substrate Separation**:
   - Additive SQLite tables (`organization_members`, `member_roles`, `membership_invitations`, `membership_audit_events`, `membership_audit_checkpoints`) operate completely independent of the core risk case tables (`risk_cases`, `handoff_grants`, `pending_approval_items`, `adapter_attempts`).
   - Mechanical barrier verified: dropping all 5 membership tables leaves Money Action flows 100% operational.
   - Bearer tokens are stateless HMAC-SHA256 tokens signed with `membership_secret`, strictly disjoint from `grant_secret` and `audit_checkpoint_secret`.

2. **Revocation Bound**:
   - Removing a member immediately flips their status to `REMOVED` and bumps `token_version` within a single atomic SQLite transaction (`BEGIN IMMEDIATE`).
   - Every authenticated request re-validates the member row fresh from SQLite without caching.
   - Consequently, token invalidation takes effect at the member's very next authenticated request.

3. **RBAC & Self-Mutation Locks**:
   - Elevated operations (invite, remove, role assignment) strictly require the `TENANT_ADMINISTRATOR` role.
   - Self-removal and self-demotion are blocked (`403 Forbidden`).
   - Last-admin protection prevents demoting or removing the final administrator of an organization (`409 Conflict`).
   - Cross-organization access attempts return `401/404`, preserving the zero-existence oracle.

4. **Tamper-Evident Audit Logging**:
   - Membership mutations append sequential SHA-256 hash-chained audit events with HMAC-authenticated checkpoints per organization.

## Consequences
- Clean separation between tenant administrative identity and operational Money Actions.
- 100% backward compatibility with all existing test suites and scorers.
