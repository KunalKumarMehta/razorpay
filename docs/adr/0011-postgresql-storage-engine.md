# ADR 0011: PostgreSQL Storage Engine and Versioned Schema Migrations

## Status

Accepted

## Context

PayoutProof originated with SQLite WAL mode as its initial storage engine. While SQLite is suitable for single-node development, testing, and edge execution, production pilot deployment requires:

1. **Dual-Dialect Support**: The ability to run transparently on either SQLite or PostgreSQL based on configuration (`PAYOUTPROOF_DATABASE_URL` / `database_url`), without fracturing the domain model or duplicating business logic.
2. **Explicit Versioned Migrations**: Replacing implicit runtime `CREATE TABLE IF NOT EXISTS` scripts with dense, forward-only migrations (`0001` through `0003` up to `SCHEMA_VERSION = "PP-SCHEMA-V3"`), tracked in a `schema_migrations` ledger with SHA-256 content checksums.
3. **Fail-Closed Schema Gate**: Production and staging deployments must verify that the database schema exactly matches the expected release version without performing implicit runtime mutations, raising `IncompatibleSchemaError` on drift, missing versions, or future versions.
4. **Locking Parity**: Replacing SQLite's table-level `BEGIN IMMEDIATE` writer serialization with PostgreSQL row-level `SELECT ... FOR UPDATE` locks on mutable keys (cases, grants, attempts, pending items) while preserving atomic single-writer invariants.

## Decision

1. **Migration Runner & Tracking**:
   - `src/payoutproof/storage/migrations.py` defines the canonical schema migration runner `MigrationRunner`.
   - `schema_migrations` table records `(version, version_id, applied_at, checksum)` for every applied migration.
   - Version numbering maps to release identifiers:
     - `1` -> `PP-SCHEMA-V1` (Core Money Action schema)
     - `2` -> `PP-SCHEMA-V2` (Tenant operating limits and quota counters, Issue #10)
     - `3` -> `PP-SCHEMA-V3` (Versioned policy configs and approved destinations, Issue #9)
   - `translate_ddl` deterministically translates authoring SQLite DDL to PostgreSQL (e.g. `AUTOINCREMENT -> BIGSERIAL`, dropping SQLite-specific PRAGMAs).
   - `check_schema_compatibility(conn, dialect)` enforces strict version parity on startup.

2. **Dual-Dialect Storage Abstraction**:
   - `src/payoutproof/storage/db.py` supports both `DIALECT_SQLITE` and `DIALECT_POSTGRESQL`.
   - Connection selection is driven by `database_url` or `db_path` prefixed with `postgresql://` or `postgres://`.
   - Statement translation (`_translate_query`) translates SQL `?` parameter markers to `%s` for PostgreSQL without altering string literals.
   - `_PostgresConnection`, `_PostgresCursor`, and `_PostgresRow` adapt `psycopg` to the exact row and cursor protocols expected by the application.

3. **Concurrency and Locking Parity**:
   - SQLite uses `BEGIN IMMEDIATE` for writer serialization.
   - PostgreSQL intercepts `BEGIN IMMEDIATE` and uses `SELECT ... FOR UPDATE` row locks on target entity IDs, guaranteeing identical race protection and rowcount arbitration (`rowcount == 1`).

4. **Secret-Free Configuration**:
   - `database_url` is added to `AppConfig`, loaded from `PAYOUTPROOF_DATABASE_URL`, and strictly redacted to `[REDACTED]` in `to_safe_dict()` and `__repr__()`.

## Consequences

- Full backward compatibility with SQLite for fast, isolated test execution (`341+` tests passing without external dependencies).
- Production-ready PostgreSQL engine support with auditable, reproducible schema states.
- Secret credentials in database URLs are never leaked in logs, representations, or error traces.
