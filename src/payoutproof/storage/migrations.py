"""Explicit versioned schema migrations for the dual-dialect storage engine.

PayoutProof persisted its schema for ten issues as implicit, idempotent
``CREATE TABLE IF NOT EXISTS`` scripts executed on every startup. That is
acceptable while the only engine is SQLite and the only deployment is a local
file, but the Risk Case workflow now has to run on PostgreSQL (Issue #11), and
Postgres deployments need the two properties implicit creation cannot give:

1. **Auditable, replayable history** — an operator must be able to answer
   "which schema version is this database on, applied when, from what exact
   SQL?" without diffing live tables against source code.
2. **Fail-closed production startup** — production and staging databases are
   never mutated implicitly by an application boot. Either the database is on
   the exact expected schema version, or the process refuses to start with an
   actionable, secret-free error. Implicit creation remains available only for
   local development and the test corpus (``AppConfig.for_tests``), where a
   throwaway database is initialized from scratch on every run.

The unit of migration here is the *version*: ``0001`` through ``0003``, where
``0003`` corresponds to ``SCHEMA_VERSION = "PP-SCHEMA-V3"``. Version numbers
are dense integers so gaps are detectable drift; the ``PP-SCHEMA-Vx`` label is
the human-facing identity mirrored at ``payoutproof.core.release.SCHEMA_VERSION``.

Dialect handling is deliberately conservative. Migrations are authored in the
SQLite dialect (the historical authorship of every table) and adapted to
PostgreSQL by a small, explicit statement rewriter (``translate_ddl``) rather
than by an ORM or a general SQL translator. Only constructs that actually
occur in the PayoutProof schema are rewritten:

- ``INTEGER PRIMARY KEY AUTOINCREMENT`` -> ``BIGSERIAL PRIMARY KEY``. Postgres
  has no AUTOINCREMENT; sequences are the native equivalent, and BIGSERIAL
  keeps headroom for the append-only audit chains.
- ``PRAGMA`` statements are dropped: WAL/busy-timeout pragmas are
  SQLite-specific connection settings and are applied on the connection path,
  not in migrations.
- Everything else (``CREATE TABLE``, ``CREATE INDEX``, ``ON CONFLICT ... DO
  UPDATE/NOTHING``, ``TRIM``, half-open window predicates, composite primary
  keys with non-null sentinel parts) is already standard SQL:92+ and works on
  both engines unchanged. The storage layer has deliberately avoided
  SQLite-only functions since Issue #6 precisely so this day would stay cheap.

The DDL for each version is held in this module as Python data (not ``.sql``
files) so the checksum recorded in ``schema_migrations`` is derived from the
exact statements the runner executed — there is no second artifact that can
drift from the code.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

__all__ = [
    "IncompatibleSchemaError",
    "Migration",
    "MIGRATIONS",
    "LATEST_VERSION",
    "LATEST_VERSION_ID",
    "MigrationRunner",
    "translate_ddl",
    "check_schema_compatibility",
]


class IncompatibleSchemaError(Exception):
    """Raised when a database's schema version is unusable by this build.

    Secret-free by construction: the message carries versions, counts, and the
    next operator action, never connection strings or credentials (a
    ``database_url`` may embed a password, and this error is expected to reach
    process logs and health endpoints).
    """

    pass


# ── Version identity ─────────────────────────────────────────────────────────
# Migration 0001 corresponds to PP-SCHEMA-V1 (the pre-#10 core Money Action
# schema), 0002 to PP-SCHEMA-V2 (Issue #10 tenant operating-limits tables),
# and 0003 to PP-SCHEMA-V3 (Issue #9 versioned policy + approved destinations).
# SCHEMA_VERSION stays the release-identity constant at storage.db; the integer
# migration numbers are the runner's ordering key. The two must move together:
# adding a migration without bumping SCHEMA_VERSION (or vice versa) is drift,
# and tests/test_postgresql_storage.py pins the pairing.

VERSION_ID_BY_NUMBER: Dict[int, str] = {
    1: "PP-SCHEMA-V1",
    2: "PP-SCHEMA-V2",
    3: "PP-SCHEMA-V3",
}


@dataclass(frozen=True)
class Migration:
    """One immutable, forward-only schema step.

    ``sqlite_statements`` is authored in the SQLite dialect (the historical
    authorship of the schema) and is translated per-dialect by the runner.
    """

    version: int
    description: str
    sqlite_statements: Tuple[str, ...]

    @property
    def version_id(self) -> str:
        return VERSION_ID_BY_NUMBER[self.version]

    def checksum(self) -> str:
        """Stable SHA-256 over this migration's exact executable content.

        Computed over the SQLite-authoritative statements so a checksum is
        dialect-independent: a SQLite and a PostgreSQL database migrated with
        the same runner record the same checksum for the same version, which
        is what makes cross-engine drift detectable.
        """
        payload = json.dumps(
            {
                "version": self.version,
                "description": self.description,
                "statements": list(self.sqlite_statements),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── Migration 0001: the core Money Action schema (PP-SCHEMA-V1) ─────────────
# risk_cases, the case audit chain and checkpoints, handoff grants, adapter
# attempts and their quarantine table, and pending approval items — the
# invariant-bearing tables from Issues #1-#6. Authoritative column shapes are
# the final V3 shapes minus what 0002/0003 add; the legacy ALTER-based column
# backfills (case_version, phase, created_at, updated_at, organization_id)
# are folded into the initial definition because a fresh database never needs
# the intermediate shapes, and 0001's job is to describe a new database, not
# to replay history.

_MIGRATION_0001 = Migration(
    version=1,
    description="Core Money Action schema: cases, audit chains, grants, adapter attempts, approval items",
    sqlite_statements=(
        """
        CREATE TABLE IF NOT EXISTS risk_cases (
            case_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            organization_id TEXT,
            case_version INTEGER NOT NULL,
            phase TEXT NOT NULL,
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_risk_cases_tenant ON risk_cases(tenant_id);",
        "CREATE INDEX IF NOT EXISTS idx_risk_cases_organization ON risk_cases(organization_id);",
        """
        CREATE TABLE IF NOT EXISTS case_audit_checkpoints (
            case_id TEXT PRIMARY KEY,
            event_count INTEGER NOT NULL,
            tip_hash TEXT NOT NULL,
            trust_state TEXT NOT NULL,
            checkpoint_mac TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_case ON case_audit_checkpoints(case_id);",
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            actor TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details_json TEXT NOT NULL,
            UNIQUE(case_id, seq)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_events(case_id);",
        """
        CREATE TABLE IF NOT EXISTS handoff_grants (
            grant_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            organization_id TEXT,
            case_id TEXT NOT NULL,
            bound_intent_hash TEXT NOT NULL,
            bound_snapshot_hash TEXT NOT NULL,
            policy_version TEXT NOT NULL,
            outcome TEXT NOT NULL,
            nonce TEXT UNIQUE NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            status TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_grants_case ON handoff_grants(case_id);",
        """
        CREATE TABLE IF NOT EXISTS adapter_attempts_quarantine (
            quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
            quarantine_reason TEXT NOT NULL,
            quarantined_at TEXT NOT NULL,
            original_idempotency_key TEXT,
            original_grant_id TEXT,
            original_case_id TEXT,
            original_data_json TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS adapter_attempts (
            idempotency_key TEXT NOT NULL PRIMARY KEY,
            case_id TEXT NOT NULL,
            organization_id TEXT,
            grant_id TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL,
            decision TEXT NOT NULL,
            ambiguity_state TEXT,
            pending_item_id TEXT,
            error_code TEXT,
            error_message TEXT,
            attempts INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_adapter_attempts_grant_id ON adapter_attempts(grant_id);",
        "CREATE INDEX IF NOT EXISTS idx_adapter_attempts_case_id ON adapter_attempts(case_id);",
        """
        CREATE TABLE IF NOT EXISTS pending_approval_items (
            item_id TEXT NOT NULL PRIMARY KEY,
            case_id TEXT NOT NULL,
            organization_id TEXT,
            grant_id TEXT NOT NULL UNIQUE,
            idempotency_key TEXT NOT NULL UNIQUE,
            counterparty TEXT NOT NULL,
            destination TEXT NOT NULL,
            amount TEXT NOT NULL,
            currency TEXT NOT NULL,
            purpose TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING_FINANCE_APPROVAL',
            created_at TEXT NOT NULL
        )
        """,
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_items_grant_id ON pending_approval_items(grant_id);",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_items_idempotency_key ON pending_approval_items(idempotency_key);",
        "CREATE INDEX IF NOT EXISTS idx_pending_items_case_id ON pending_approval_items(case_id);",
        """
        CREATE TABLE IF NOT EXISTS operator_sessions (
            session_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            subject TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            idp_issuer TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_seen_at TEXT,
            revoked_at TEXT
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_operator_sessions_token ON operator_sessions(token_hash);",
        "CREATE INDEX IF NOT EXISTS idx_operator_sessions_subject ON operator_sessions(subject);",
        """
        CREATE TABLE IF NOT EXISTS auth_login_states (
            state_token TEXT PRIMARY KEY,
            nonce TEXT NOT NULL,
            code TEXT UNIQUE,
            redirect_uri TEXT,
            issuer TEXT NOT NULL,
            code_expires_at TEXT,
            consumed_at TEXT,
            created_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS case_action_actors (
            case_id TEXT NOT NULL,
            organization_id TEXT,
            action_type TEXT NOT NULL,
            actor_subject TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_case_action_actors_case ON case_action_actors(case_id, action_type, recorded_at);",
        # The unique index below is the authoritative shape for a clean
        # database. Databases carrying pre-#3c duplicate (case_id, seq) rows
        # are handled by storage.Database's legacy reconciliation, not by
        # replaying it here: a versioned migration must be a fresh-database
        # definition plus additive changes, never a destructive repair.
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_case_seq ON audit_events(case_id, seq);",
    ),
)


# ── Migration 0002: tenant operating limits (PP-SCHEMA-V2, Issue #10) ──────

_MIGRATION_0002 = Migration(
    version=2,
    description="Tenant operating limits: quota counters, settings rows, and settings audit",
    sqlite_statements=(
        # window_key is a non-null string even for the 'CUMULATIVE' sentinel
        # so the composite PRIMARY KEY stays valid under PostgreSQL, where
        # primary-key columns may not be NULL (SQLite tolerates it; Postgres
        # does not — a concrete example of the V2 schema being authored
        # Postgres-aware from day one).
        """
        CREATE TABLE IF NOT EXISTS tenant_quota_counters (
            organization_id TEXT NOT NULL,
            quota_kind TEXT NOT NULL,
            window_key TEXT NOT NULL,
            counter INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (organization_id, quota_kind, window_key)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_tenant_quota_org ON tenant_quota_counters(organization_id);",
        """
        CREATE TABLE IF NOT EXISTS tenant_operating_limits (
            organization_id TEXT PRIMARY KEY,
            limits_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS tenant_settings_audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            changes_json TEXT NOT NULL,
            reason_code TEXT,
            recorded_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_tenant_settings_audit_org ON tenant_settings_audit_events(organization_id);",
    ),
)


# ── Migration 0003: versioned policy + approved destinations (PP-SCHEMA-V3, Issue #9) ──

_MIGRATION_0003 = Migration(
    version=3,
    description="Versioned policy configurations, approved destinations, and config audit chains",
    sqlite_statements=(
        """
        CREATE TABLE IF NOT EXISTS policy_configs (
            config_id TEXT PRIMARY KEY,
            organization_id TEXT NOT NULL,
            version_id TEXT NOT NULL,
            status TEXT NOT NULL,
            grant_ttl_seconds INTEGER NOT NULL,
            require_independent_callback INTEGER NOT NULL,
            require_approved_destination INTEGER NOT NULL,
            block_on_snapshot_integrity_failure INTEGER NOT NULL,
            block_on_policy_config_tamper INTEGER NOT NULL,
            hold_on_model_failure INTEGER NOT NULL,
            hold_on_evidence_contradiction INTEGER NOT NULL,
            hold_on_material_intent_change INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            activated_by TEXT,
            activated_at TEXT,
            retired_by TEXT,
            retired_at TEXT,
            UNIQUE(organization_id, version_id)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_policy_configs_organization ON policy_configs(organization_id);",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_configs_single_active ON policy_configs(organization_id) WHERE status = 'ACTIVE';",
        """
        CREATE TABLE IF NOT EXISTS destination_records (
            destination_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            organization_id TEXT NOT NULL,
            counterparty TEXT NOT NULL,
            destination TEXT NOT NULL,
            destination_type TEXT NOT NULL,
            status TEXT NOT NULL,
            valid_from TEXT NOT NULL,
            valid_to TEXT,
            policy_config_id TEXT NOT NULL,
            policy_config_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL,
            retired_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_destination_records_organization ON destination_records(organization_id);",
        "CREATE INDEX IF NOT EXISTS idx_destination_records_lookup ON destination_records(organization_id, counterparty, destination);",
        """
        CREATE TABLE IF NOT EXISTS destination_audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            destination_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            actor TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details_json TEXT NOT NULL,
            UNIQUE(destination_id, seq)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_destination_audit_events_destination ON destination_audit_events(destination_id);",
        """
        CREATE TABLE IF NOT EXISTS config_audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            actor TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details_json TEXT NOT NULL,
            UNIQUE(organization_id, seq)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_config_audit_events_organization ON config_audit_events(organization_id);",
        """
        CREATE TABLE IF NOT EXISTS config_audit_checkpoints (
            organization_id TEXT PRIMARY KEY,
            event_count INTEGER NOT NULL,
            tip_hash TEXT NOT NULL,
            trust_state TEXT NOT NULL,
            checkpoint_mac TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_config_audit_checkpoints_organization ON config_audit_checkpoints(organization_id);",
    ),
)


MIGRATIONS: Tuple[Migration, ...] = (_MIGRATION_0001, _MIGRATION_0002, _MIGRATION_0003)
LATEST_VERSION = MIGRATIONS[-1].version
LATEST_VERSION_ID = MIGRATIONS[-1].version_id

# Membership administration (Issue #8) predates the versioned runner. Its
# tables are additive with no cross-version column changes and are therefore
# recorded as part of the core schema rather than as a separate migration
# version: SCHEMA_VERSION moved V1 -> V2 with Issue #10, not with #8, and the
# runner's history must match the published version identity exactly.
_MEMBERSHIP_TABLES_DDL = (
    """
    CREATE TABLE IF NOT EXISTS organization_members (
        member_id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        email TEXT NOT NULL,
        display_name TEXT NOT NULL,
        status TEXT NOT NULL,
        token_version INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(organization_id, email)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_org_members_organization ON organization_members(organization_id);",
    """
    CREATE TABLE IF NOT EXISTS member_roles (
        organization_id TEXT NOT NULL,
        member_id TEXT NOT NULL,
        role TEXT NOT NULL,
        granted_by TEXT NOT NULL,
        granted_at TEXT NOT NULL,
        PRIMARY KEY (member_id, role)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_member_roles_organization ON member_roles(organization_id);",
    """
    CREATE TABLE IF NOT EXISTS membership_invitations (
        invitation_id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        invited_by TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        accepted_at TEXT,
        created_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_invitations_organization ON membership_invitations(organization_id);",
    """
    CREATE TABLE IF NOT EXISTS membership_audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        summary TEXT NOT NULL,
        actor TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        current_hash TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        details_json TEXT NOT NULL,
        UNIQUE(organization_id, seq)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_membership_audit_organization ON membership_audit_events(organization_id);",
    """
    CREATE TABLE IF NOT EXISTS membership_audit_checkpoints (
        organization_id TEXT PRIMARY KEY,
        event_count INTEGER NOT NULL,
        tip_hash TEXT NOT NULL,
        trust_state TEXT NOT NULL,
        checkpoint_mac TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_membership_audit_checkpoints_organization ON membership_audit_checkpoints(organization_id);",
)

# Fold the membership tables into version 1's executable content without
# changing 0001's published description: a fresh database gets every
# pre-versioned table, and the recorded checksum covers exactly what ran.
# (Constructed as a new frozen Migration so _MIGRATION_0001 above stays a
# readable rendering of the historical core schema.)
_MIGRATION_0001 = Migration(
    version=_MIGRATION_0001.version,
    description=_MIGRATION_0001.description,
    sqlite_statements=_MIGRATION_0001.sqlite_statements + _MEMBERSHIP_TABLES_DDL,
)
MIGRATIONS = (_MIGRATION_0001, _MIGRATION_0002, _MIGRATION_0003)


# ── Dialect translation ─────────────────────────────────────────────────────

def translate_ddl(sql: str, dialect: str) -> str:
    """Translate one SQLite-authored DDL statement to the target dialect.

    ``dialect`` is ``"sqlite"`` or ``"postgresql"``. SQLite passes through
    unchanged. PostgreSQL rewrites only the two constructs in the PayoutProof
    schema that are not portable, and raises on any other SQLite-only
    construct it encounters rather than sending it to Postgres to fail with an
    opaque server error.
    """
    if dialect == "sqlite":
        return sql
    if dialect != "postgresql":
        raise IncompatibleSchemaError(f"Unsupported migration dialect '{dialect}'")

    body = sql.strip()
    if not body:
        return sql

    upper = body.upper()
    if upper.startswith("PRAGMA"):
        # Connection-level pragmas (WAL, busy timeout, foreign keys) are
        # applied by the connection factory for the engines that have them;
        # they are not schema and do not belong in a Postgres migration.
        return ""

    if "AUTOINCREMENT" in upper:
        body = body.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY")
        if "AUTOINCREMENT" in body.upper():
            raise IncompatibleSchemaError(
                "Unsupported SQLite AUTOINCREMENT form in PostgreSQL DDL: " + sql.strip()[:80]
            )

    return body


# ── Runner ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MigrationRunner:
    """Applies the explicit versioned migrations and tracks them in ``schema_migrations``.

    The tracking table is created first, on both engines, with a dialect-
    portable definition. One row per applied version records the version
    number, its human identity, when it was applied, and the SHA-256 checksum
    of the exact statements executed. ``version`` is the primary key, so a
    version is applied at most once per database.

    Backward compatibility with pre-runner databases (the ten issues of
    implicit creation) is handled by ``baseline_existing``: a database whose
    tables exist but that has no tracking rows is stamped with the versions
    it demonstrably already contains, determined by probing for each
    migration's signature tables. This runs only in the modes where implicit
    initialization is allowed (local dev / tests); production startup calls
    ``check_schema_compatibility`` instead and refuses to mutate anything.
    """

    TRACKING_TABLE = "schema_migrations"

    # Signature table per migration version: presence of these tables (empty
    # is fine — presence is what matters) proves the database already carries
    # that version's schema.
    _SIGNATURE_TABLES: Dict[int, Tuple[str, ...]] = {
        1: ("risk_cases", "audit_events", "handoff_grants", "adapter_attempts", "pending_approval_items"),
        2: ("tenant_quota_counters", "tenant_operating_limits", "tenant_settings_audit_events"),
        3: ("policy_configs", "destination_records", "config_audit_events", "config_audit_checkpoints"),
    }

    def __init__(self, conn: Any, dialect: str):
        if dialect not in ("sqlite", "postgresql"):
            raise IncompatibleSchemaError(f"Unsupported migration dialect '{dialect}'")
        self.conn = conn
        self.dialect = dialect

    # ── Tracking table ──────────────────────────────────────────────────────

    def _create_tracking_table(self) -> None:
        self.conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.TRACKING_TABLE} (
                version INTEGER PRIMARY KEY,
                version_id TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                checksum TEXT NOT NULL
            )
            """
        )

    # ── Introspection helpers (dialect-portable) ────────────────────────────

    def _existing_tables(self) -> set[str]:
        if self.dialect == "sqlite":
            rows = self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            ).fetchall()
        names: set[str] = set()
        for row in rows:
            # sqlite3.Row and DB-API tuple both index positionally.
            names.add(row[0])
        return names

    def _table_has_all_columns(self, table: str, columns: Sequence[str]) -> bool:
        """True when ``table`` exists and contains every named column.

        Used by the baseline probe: a V1 database that predates a column is
        distinguishable from one that has it, without any engine-specific
        ``PRAGMA``/``information_schema`` column query on this path.
        """
        present = self._existing_columns(table)
        if present is None:
            return False
        return set(columns).issubset(present)

    def _existing_columns(self, table: str) -> Optional[set[str]]:
        if self.dialect == "sqlite":
            rows = self.conn.execute(f"PRAGMA table_info({table})").fetchall()
            names = [row[1] for row in rows]
        else:
            rows = self.conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = %s",
                (table,),
            ).fetchall()
            names = [row[0] for row in rows]
        if not names:
            return None
        return set(names)

    def _applied_versions(self) -> List[int]:
        if self.TRACKING_TABLE not in self._existing_tables():
            return []
        rows = self.conn.execute(
            f"SELECT version FROM {self.TRACKING_TABLE} ORDER BY version ASC"
        ).fetchall()
        return [int(r[0]) for r in rows]

    def _recorded_checksum(self, version: int) -> Optional[str]:
        if self.TRACKING_TABLE not in self._existing_tables():
            return None
        row = self.conn.execute(
            f"SELECT checksum FROM {self.TRACKING_TABLE} WHERE version = ?",
            (version,),
        ).fetchone() if self.dialect == "sqlite" else self.conn.execute(
            f"SELECT checksum FROM {self.TRACKING_TABLE} WHERE version = %s",
            (version,),
        ).fetchone()
        if row is None:
            return None
        return str(row[0])

    def _insert_version_row(self, migration: Migration) -> None:
        checksum = migration.checksum()
        if self.dialect == "sqlite":
            self.conn.execute(
                f"INSERT INTO {self.TRACKING_TABLE} (version, version_id, applied_at, checksum) VALUES (?, ?, ?, ?)",
                (migration.version, migration.version_id, _now_iso(), checksum),
            )
        else:
            self.conn.execute(
                f"INSERT INTO {self.TRACKING_TABLE} (version, version_id, applied_at, checksum) VALUES (%s, %s, %s, %s)",
                (migration.version, migration.version_id, _now_iso(), checksum),
            )

    # ── Public API ───────────────────────────────────────────────────────────

    def ensure_tracking_table(self) -> None:
        """Create the ``schema_migrations`` table if absent (idempotent)."""
        self._create_tracking_table()

    def applied_versions(self) -> List[int]:
        """Versions recorded in ``schema_migrations`` (dense, ascending)."""
        return self._applied_versions()

    def detect_baselined_versions(self) -> List[int]:
        """Versions whose signature tables already exist but are untracked.

        This is the pre-runner compatibility probe: an existing SQLite file
        from Issues #1-#9 has every V3 table and no tracking rows, so a fresh
        ``Database()`` open must stamp it rather than refuse or re-run DDL.
        """
        tables = self._existing_tables()
        if not tables:
            return []
        detected: List[int] = []
        for migration in MIGRATIONS:
            if self.TRACKING_TABLE in tables:
                break
            if set(self._SIGNATURE_TABLES[migration.version]).issubset(tables):
                detected.append(migration.version)
            else:
                break
        return detected

    def baseline_existing(self) -> List[int]:
        """Stamp already-present schema into ``schema_migrations`` without executing DDL.

        For each detected-but-untracked version, inserts the tracking row with
        that migration's canonical checksum. Returns the versions stamped. A
        database that already has tracking rows is left untouched (an empty
        list), because tracked history is authoritative.
        """
        if self.TRACKING_TABLE in self._existing_tables() and self._applied_versions():
            # Tracked history exists; never rewrite it.
            return []
        detected = self.detect_baselined_versions()
        self._create_tracking_table()
        stamped: List[int] = []
        for version in detected:
            migration = next(m for m in MIGRATIONS if m.version == version)
            # Idempotent under a fresh table: no row for this version exists yet.
            self._insert_version_row(migration)
            stamped.append(version)
        return stamped

    def apply_pending(self) -> List[int]:
        """Apply every unapplied migration in order and record it. Returns applied versions.

        The caller owns the transaction: this method executes statements on
        ``self.conn`` only, so the whole batch (DDL + tracking rows) commits or
        rolls back as one unit on the caller's connection.
        """
        self._create_tracking_table()
        applied = self._applied_versions()
        if applied and applied != sorted(set(applied)):
            raise IncompatibleSchemaError(
                f"schema_migrations rows are not dense and ascending: {applied}"
            )
        already = set(applied)
        # Checksum integrity: a recorded checksum must still match this build's
        # migration content, otherwise the database was migrated by a modified
        # migration and cannot be reasoned about.
        for migration in MIGRATIONS:
            if migration.version in already:
                recorded = self._recorded_checksum(migration.version)
                if recorded is not None and recorded != migration.checksum():
                    raise IncompatibleSchemaError(
                        f"schema_migrations checksum mismatch for version {migration.version} "
                        f"({migration.version_id}): recorded {recorded[:12]}... but this build "
                        f"computes {migration.checksum()[:12]}... — the migration source changed "
                        "after this database was migrated; restore the original migration or "
                        "rebuild the database."
                    )

        newly: List[int] = []
        for migration in MIGRATIONS:
            if migration.version in already:
                continue
            for raw_sql in migration.sqlite_statements:
                translated = translate_ddl(raw_sql, self.dialect)
                if not translated.strip():
                    continue
                self.conn.execute(translated)
            self._insert_version_row(migration)
            newly.append(migration.version)
        return newly

    def status(self) -> Dict[str, Any]:
        """Return a secret-free summary of this database's migration state."""
        try:
            applied = self._applied_versions()
            tracked = True
        except Exception:
            applied = []
            tracked = False
        expected = [m.version for m in MIGRATIONS]
        return {
            "dialect": self.dialect,
            "applied_versions": applied,
            "expected_versions": expected,
            "latest_version": LATEST_VERSION,
            "latest_version_id": LATEST_VERSION_ID,
            "is_current": applied == expected,
            "tracking_table_present": tracked,
        }


# ── Compatibility gate ───────────────────────────────────────────────────────

def check_schema_compatibility(
    conn: Any,
    dialect: str,
    *,
    expected_version: Optional[int] = None,
    allow_untracked: bool = False,
) -> Dict[str, Any]:
    """Fail-closed schema gate for production/staging startup.

    Verifies, without mutating anything, that ``conn``'s schema is at exactly
    the expected version. Raises ``IncompatibleSchemaError`` when:

    - the tracking table is absent and ``allow_untracked`` is False (an
      untracked database may be anything — refuse rather than guess);
    - any expected version is missing (unapplied migrations — the operator
      must run the migration path explicitly);
    - the database carries versions beyond this build's latest (deployed
      from a future build — rolling back is not supported);
    - a recorded checksum disagrees with this build's migration content.

    With ``allow_untracked=True`` (local dev / tests), an absent tracking
    table with no application tables is treated as a fresh database rather
    than an error, so test initialization can migrate from zero.

    Returns the same secret-free status mapping as ``MigrationRunner.status``.
    Never raises with connection strings or credentials in the message.
    """
    runner = MigrationRunner(conn=conn, dialect=dialect)
    target = LATEST_VERSION if expected_version is None else int(expected_version)
    expected_versions = [v for v in (m.version for m in MIGRATIONS) if v <= target]

    tables = runner._existing_tables()
    tracking_present = runner.TRACKING_TABLE in tables
    has_application_tables = bool(tables - {runner.TRACKING_TABLE})

    if not tracking_present:
        if allow_untracked and not has_application_tables:
            return runner.status()
        if allow_untracked and has_application_tables:
            # Dev/test opening a pre-runner database: the caller will baseline
            # and migrate; report not-current rather than refuse.
            status = runner.status()
            status["is_current"] = False
            status["reason"] = "untracked pre-existing schema"
            return status
        raise IncompatibleSchemaError(
            f"Database schema is untracked: table '{runner.TRACKING_TABLE}' is absent and the "
            "database already contains application tables. This build refuses to run against an "
            "unknown schema in production/staging. Run the migration path to record schema "
            "history, or point the deployment at an initialized database."
        )

    applied = runner._applied_versions()
    if not applied:
        # Tracking table exists but is empty: either a brand-new database (no
        # application tables) or a wiped history. Refuse in either case unless
        # the caller allows untracked initialization.
        if allow_untracked and not has_application_tables:
            return runner.status()
        raise IncompatibleSchemaError(
            f"Table '{runner.TRACKING_TABLE}' exists but records no applied versions while the "
            "database contains application tables; schema history is incomplete. Refusing to "
            "start against an incompletely tracked schema."
        )

    missing = [v for v in expected_versions if v not in applied]
    if missing:
        raise IncompatibleSchemaError(
            f"Database schema is not at the required version {VERSION_ID_BY_NUMBER.get(target, target)}: "
            f"unapplied migrations {missing}. This build refuses to run against an unapplied "
            "schema. Apply the pending migrations (development/test databases migrate "
            "automatically; production requires the operator-driven migration path) and restart."
        )

    ahead = [v for v in applied if v > LATEST_VERSION]
    if ahead:
        raise IncompatibleSchemaError(
            f"Database schema versions {ahead} are newer than this build's latest "
            f"{LATEST_VERSION} ({LATEST_VERSION_ID}). This build would run against a schema it "
            "does not understand. Deploy the build that owns these migrations, or provision a "
            "fresh database."
        )

    for migration in MIGRATIONS:
        if migration.version in applied:
            recorded = runner._recorded_checksum(migration.version)
            if recorded is not None and recorded != migration.checksum():
                raise IncompatibleSchemaError(
                    f"schema_migrations checksum mismatch for version {migration.version} "
                    f"({migration.version_id}): the migration source changed after this "
                    "database was migrated. Restore the original migration source or rebuild "
                    "the database from a trusted backup."
                )

    status = runner.status()
    status["is_current"] = applied == [m.version for m in MIGRATIONS]
    return status


def describe_migrations() -> List[Dict[str, Any]]:
    """Return the migration inventory (secret-free) for diagnostics and tests."""
    return [
        {
            "version": m.version,
            "version_id": m.version_id,
            "description": m.description,
            "statement_count": len(m.sqlite_statements),
            "checksum": m.checksum(),
        }
        for m in MIGRATIONS
    ]
