# ADR 0012: Key Rotation and Verifiable Risk Case Audit Exports

## Status

Accepted

## Context

Risk Case auditability and handoff grant integrity in PayoutProof previously relied on static, single-key HMAC configurations (`grant_secret` and `audit_checkpoint_secret`). As production pilots expand and security compliance demands regular cryptographic key lifecycle management, the system requires:

1. **Key Rotation with Retention**:
   - The ability to rotate cryptographic signing keys without invalidating historical risk case audits or existing unspent handoff grants.
   - Distinct domain separation between grant signature keys and audit checkpoint HMAC keys.
   - Dual-key validation: active signing key stamps new checkpoints and grants with a key identifier (`key_id`), while a retained ring of historical keys remains available for verifying past records.

2. **Tamper-Evident, Portable Audit Exports**:
   - Authorized compliance auditors must be able to export a complete, self-contained, canonical audit bundle for any closed or active Risk Case.
   - The export must be independently verifiable in an air-gapped / offline environment using standard CLI tooling without connecting to the database or running web services.
   - Verification must fail closed against any manipulation: event deletion, payload alteration, sequence gaps, timestamp tampering, out-of-order execution, checkpoint MAC corruption, cross-tenant/cross-case grant binding substitution, or unknown/retired signing keys.

3. **Strict RBAC & Tenant Isolation**:
   - Audit export endpoints must be restricted strictly to the `auditor` role (`CAPABILITY_EXPORT_CASE_AUDIT`).
   - Zero-existence information leak prevention: attempting to export or access a non-existent or cross-tenant case returns HTTP 404 before evaluating role capabilities.

## Decision

1. **KeyRing Abstraction (`src/payoutproof/core/keys.py`)**:
   - Introduced `KeyRing` to encapsulate an active signing key (`active_key_id` -> `active_secret`) and zero or more retained historical verification keys (`retained_keys`).
   - Constant-time verification using `hmac.compare_digest`.
   - Complete secret redaction: string formatting, representations (`__repr__`, `__str__`), and serialization expose only key identifiers, never raw secret bytes.
   - Configuration via environment:
     - `PAYOUTPROOF_GRANT_SECRET` / `PAYOUTPROOF_GRANT_KEY_ID` / `PAYOUTPROOF_GRANT_RETAINED_KEYS` (format `key_id:secret,...`)
     - `PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET` / `PAYOUTPROOF_AUDIT_KEY_ID` / `PAYOUTPROOF_AUDIT_RETAINED_KEYS`
   - `AppConfig` validates disjointness: grant keys and audit keys must not share secrets, and individual rings cannot contain duplicate secrets across active and retained slots.

2. **Domain-Separated Cryptographic Formats (`src/payoutproof/core/crypto.py`)**:
   - Checkpoint MACs support explicit domain separation:
     - V1 (legacy unkeyed): `PAYOUTPROOF_AUDIT_CHECKPOINT_V1|{case_id}|{sequence}|{event_hash}`
     - V2 (key-identified): `PAYOUTPROOF_AUDIT_CHECKPOINT_V2|{key_id}|{case_id}|{sequence}|{event_hash}`
   - Grant signatures support explicit `key_id`:
     - Payload appends `|KID[{key_id}]` when signed under an identified key ring.
   - Full backward compatibility: verifiers seamlessly fall back to V1 MAC checks when `key_id` is None.

3. **Storage Engine & Schema Updates (`src/payoutproof/storage/db.py`)**:
   - Added `key_id TEXT` column to `case_audit_checkpoints` and `handoff_grants` in SQLite and PostgreSQL DDLs.
   - Database transactions verify checkpoint integrity on write and read using the audit `KeyRing`.
   - `execute_adapter_submission_tx` verifies grant signatures and validates that the grant table's `key_id` matches the grant token.

4. **Canonical Audit Export Engine (`src/payoutproof/audit/export.py`)**:
   - `build_case_export`: Generates canonical JSON-serializable dictionaries containing:
     - Case metadata and terminal or current status
     - Sequential event ledger with payload hashes and sequence indices
     - Audit checkpoints with domain-separated MACs and key IDs
     - Associated handoff grants with signatures, expiration, and actor bindings
     - Complete actor attribution and export metadata
   - `verify_case_export`: Standalone, zero-dependency offline validator verifying:
     - Sequence continuity (`0, 1, 2, ... n`)
     - Genesis hash matching
     - Event hash chain recomputation
     - Checkpoint MAC cryptographic validity against the audit `KeyRing`
     - Grant signature validity and tenant/case cross-binding integrity against the grant `KeyRing`

5. **REST API & CLI Verifier**:
   - API: `GET /api/cases/{case_id}/audit-export` protected by `authenticate_request` and `require_role(Role.AUDITOR)`. Enforces 404 on missing/cross-tenant cases, 403 on non-auditor tokens, and 409 if ledger corruption is detected.
   - CLI: `payoutproof verify-case-export --file <path> [--audit-secret ...] [--audit-keys ...] [--grant-secret ...] [--grant-keys ...]`. Exits 0 on valid verifiable audit, exits 1 on tampering or signature mismatch with precise diagnostic error messages.

## Consequences

- Key rotation can now be executed seamlessly without service downtime or losing the ability to verify historical financial audit trails.
- External auditors and regulatory compliance entities can ingest portable, cryptographically provable risk case audit packs.
- Zero secrets are ever included in the exported audit bundles or CLI outputs.
