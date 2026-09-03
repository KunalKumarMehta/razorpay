# ADR 0010: Tenant Operating Limits and Platform Ceilings

## Status
Accepted

## Context
As PayoutProof expands into multi-tenant operations, tenants require operating bounds (concurrency, hourly rates, maximum file sizes, retention limits, open case limits) to prevent noisy-neighbor exhaustion and respect evidentiary policies. However, tenants must never be allowed to configure limits looser than the immutable platform ceilings defined by system invariants.

## Decision
1. **Two-Tier Limits Hierarchy**:
   - Platform Ceilings (`PlatformCeilings` in `src/payoutproof/core/limits.py`) are immutable Python literals that cannot be overridden by configuration, environment variables, or administrative actions.
   - Per-Tenant Operating Limits (`TenantOperatingLimits`) are persisted per organization and defensively clamped to platform ceilings at read time.
2. **Fail-Safe HTTP Enforcement**:
   - Fast-path payload-pure gates (HTTP 413 for oversized evidence/request body, HTTP 415 for unsupported media types, HTTP 422 for retention limits) reject invalid requests before touching the database or mutating Risk Case state.
   - Hourly request limits and concurrency/case limits fail closed with HTTP 429 (`QUOTA_EXCEEDED`) and expose standard `Retry-After` headers.
3. **Additive Storage Model**:
   - Added `tenant_quota_counters`, `tenant_operating_limits`, and `tenant_settings_audit_events` tables to SQLite schema `PP-SCHEMA-V2`.
   - Settings writes and rejections append audit events with actor attribution.
4. **Settings Administration**:
   - Gated behind `PAYOUTPROOF_ENABLE_SETTINGS_ADMIN` and dedicated bearer token `PAYOUTPROOF_SETTINGS_ADMIN_TOKEN`.

## Consequences
- Guarantees zero partial mutation on limit-rejected actions.
- Preserves all core Risk Case Money Action invariants.
- Fully backwards compatible with `PP-SCHEMA-V1` databases via additive idempotent migrations.
