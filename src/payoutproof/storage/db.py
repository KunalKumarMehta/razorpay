"""SQLite WAL persistence for cases, audit events, grants, and adapter attempts."""

import sqlite3
import json
import uuid
import hmac
import hashlib
import secrets
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime, timezone, timedelta

from payoutproof.core.models import (
    RiskCaseState,
    AuditEvent,
    HandoffGrant,
    PaymentIntent,
    PendingApprovalItem,
    CaseAuditCheckpoint,
)
from payoutproof.core.enums import (
    CasePhase,
    GrantStatus,
    HandoffStatus,
    AdapterDecision,
    PolicyOutcome,
    ProcessingAuthorityStatus,
    AuditTrustState,
    InvitationStatus,
    MembershipAuditEventType,
    MembershipRole,
    MembershipStatus,
)
from payoutproof.grants.issuer import GrantVerifier
from payoutproof.core.limits import (
    CUMULATIVE_WINDOW_KEY,
    DEFAULT_TENANT_LIMITS,
    TenantOperatingLimits,
    effective_limits,
)
from payoutproof.core.crypto import (
    compute_snapshot_hash,
    compute_audit_hash,
    compute_checkpoint_mac,
    verify_checkpoint_mac,
    sha256_hex,
)
from payoutproof.audit.chain import GENESIS_HASH

# Authoritative persistence schema identifier for SQLite tables.
# Bumped V1 -> V2 with Issue #10's additive tenant operating-limits tables
# (tenant_quota_counters, tenant_operating_limits, tenant_settings_audit_events);
# mirrored at payoutproof.core.release.SCHEMA_VERSION and pinned by an
# equality-asserting test (tests/test_release_metadata.py).
SCHEMA_VERSION = "PP-SCHEMA-V2"

# Sentinel for explicitly querying un-scoped (organization_id IS NULL) rows.
UNSCOPED = object()


class DatabaseSchemaError(Exception):
    """Raised when the database schema has unsupported or incoherent drift."""
    pass


class DatabaseConsistencyError(Exception):
    """Raised when row columns and state_json disagree on organization scope."""
    pass


class UnscopedCaseError(ValueError):
    """Raised when a new Risk Case is persisted without an organization scope.

    Every newly created case must carry a non-empty organization_id; there is
    no default organization and no un-scoped creation path.
    """
    pass


class AuditLedgerIntegrityError(Exception):
    """Raised when audit event chain or checkpoint fails cryptographic integrity verification."""
    pass



class StaleCaseStateError(ValueError):
    """Raised when attempting to persist a stale or incoherent case state conflicting with durable authority."""
    pass


class GrantTransitionError(ValueError):
    """Raised when a durable grant status transition violates the irreversible lifecycle lattice."""
    pass


class UnscopedMembershipError(ValueError):
    """Raised when a membership operation lacks a non-blank mandatory organization scope.

    Every membership store method requires an explicit organization; there is no
    default organization, no UNSCOPED sentinel mode, and no un-scoped branch.
    """
    pass


class MembershipNotFoundError(ValueError):
    """Raised when a member or invitation is absent, expired, revoked, already used,
    or belongs to a different organization (cross-org is indistinguishable from absent)."""
    pass


class MembershipConflictError(ValueError):
    """Raised on unique-constraint conflicts, e.g. inviting an email that is already
    an ACTIVE member of the organization."""
    pass


class SelfMutationError(ValueError):
    """Raised when a principal attempts self-role-change (R1) or self-removal (R2)."""
    pass


class LastAdministratorError(ValueError):
    """Raised when an operation would leave the organization with zero ACTIVE
    Tenant Administrators (R3)."""
    pass


class InvitationNotFoundError(MembershipNotFoundError):
    """Raised when a single-use invitation cannot be claimed: unknown, expired,
    revoked, already accepted, or issued by a different organization."""
    pass


TERMINAL_GRANT_STATUSES = {
    GrantStatus.CONSUMED,
    GrantStatus.SUSPENDED_FOR_RECONCILIATION,
    GrantStatus.INVALIDATED,
    GrantStatus.EXPIRED,
}


def validate_grant_transition(
    current_status: Optional[GrantStatus | str],
    current_used: bool | int,
    new_status: GrantStatus | str,
    new_used: bool | int,
) -> None:
    """Validate that transition from current durable grant state to new grant state adheres to the irreversible lattice.

    Allowed durable transitions:
    - NOT_ISSUED / no row may only become ACTIVE unused.
    - ACTIVE unused may become CONSUMED used, SUSPENDED_FOR_RECONCILIATION used, INVALIDATED unused, EXPIRED unused.
    - CONSUMED and SUSPENDED require used=true.
    - INVALIDATED and EXPIRED require used=false unless preserving a legacy incoherent row fail-closed/quarantined.
    - Same-state idempotent only with coherent used flag.
    - No terminal-to-terminal switch and no terminal-to-ACTIVE.
    - If status is ACTIVE while durable used=1 or candidate used=1, reject as invariant violation.
    """
    c_status = GrantStatus(current_status) if current_status else None
    n_status = GrantStatus(new_status)
    c_used_bool = bool(current_used)
    n_used_bool = bool(new_used)

    # 1. Used flag monotonicity: cannot revert used True -> False
    if c_used_bool and not n_used_bool:
        raise StaleCaseStateError("Cannot revert used grant from used=True to used=False")

    # 2. Candidate status & used coherence checks
    if n_status == GrantStatus.ACTIVE and n_used_bool:
        raise ValueError("Invariant violation: grant cannot have status ACTIVE while used=True")

    if n_status in (GrantStatus.CONSUMED, GrantStatus.SUSPENDED_FOR_RECONCILIATION) and not n_used_bool:
        raise GrantTransitionError(f"Invariant violation: grant status {n_status.value} requires used=True")

    if n_status in (GrantStatus.INVALIDATED, GrantStatus.EXPIRED) and n_used_bool:
        # Allowed only if preserving an existing legacy incoherent row
        if not (c_used_bool and c_status == n_status):
            raise GrantTransitionError(f"Invariant violation: grant status {n_status.value} requires used=False")

    # 3. Same-state idempotent writes: allowed only with coherent used flag
    if c_status == n_status:
        if n_status in (GrantStatus.INVALIDATED, GrantStatus.EXPIRED) and n_used_bool and not c_used_bool:
            raise GrantTransitionError(f"Cannot mark {n_status.value} grant as used=True")
        return

    # 4. Initial transition: NOT_ISSUED / None may only become ACTIVE unused
    if c_status is None or c_status == GrantStatus.NOT_ISSUED:
        if n_status == GrantStatus.ACTIVE and not n_used_bool:
            return
        raise GrantTransitionError(
            f"Initial grant state from {c_status} may only become ACTIVE unused; got {n_status.value} (used={n_used_bool})"
        )

    # 5. From ACTIVE unused: may transition to any terminal status with coherent used flag
    if c_status == GrantStatus.ACTIVE:
        if c_used_bool:
            raise ValueError("Invariant violation: current grant is ACTIVE while used=True")
        if n_status == GrantStatus.CONSUMED and n_used_bool:
            return
        if n_status == GrantStatus.SUSPENDED_FOR_RECONCILIATION and n_used_bool:
            return
        if n_status == GrantStatus.INVALIDATED and not n_used_bool:
            return
        if n_status == GrantStatus.EXPIRED and not n_used_bool:
            return
        raise GrantTransitionError(f"Invalid transition from ACTIVE to {n_status.value} with used={n_used_bool}")

    # 6. From any terminal status: no terminal-to-terminal switch and no terminal-to-ACTIVE
    if c_status in TERMINAL_GRANT_STATUSES:
        if n_status == GrantStatus.ACTIVE:
            raise StaleCaseStateError(f"Terminal grant status {c_status.value} cannot transition to ACTIVE")
        raise StaleCaseStateError(f"Terminal grant status {c_status.value} cannot transition to {n_status.value}")

    raise GrantTransitionError(f"Disallowed grant transition from {c_status.value} to {n_status.value}")


def _assert_audit_event_exact_match(
    candidate: AuditEvent,
    auth_row: sqlite3.Row,
    expected_case_id: str,
) -> None:
    """Exact field-by-field comparator between candidate AuditEvent and authoritative DB row.

    Validates every persisted AuditEvent field:
    seq, case_id, event_type, summary, actor, prev_hash, current_hash, timestamp, details.
    Recomputes candidate hash from canonical fields and validates against both candidate.current_hash
    and authoritative row current_hash. Rejects any mismatch.
    """
    if candidate.seq != auth_row["seq"]:
        raise AuditLedgerIntegrityError(
            f"Candidate audit seq mismatch at seq {candidate.seq}: "
            f"candidate seq {candidate.seq} != authoritative seq {auth_row['seq']}"
        )
    if candidate.case_id != auth_row["case_id"]:
        raise AuditLedgerIntegrityError(
            f"Candidate audit field rewrite at seq {candidate.seq}: cross-case case_id mismatch "
            f"(candidate '{candidate.case_id}' != authoritative '{auth_row['case_id']}')"
        )
    if auth_row["case_id"] != expected_case_id:
        raise AuditLedgerIntegrityError(
            f"Authoritative audit cross-case ownership violation at seq {candidate.seq}: "
            f"row case_id '{auth_row['case_id']}' != expected '{expected_case_id}'"
        )
    if candidate.event_type != auth_row["event_type"]:
        raise AuditLedgerIntegrityError(
            f"Candidate audit field rewrite at seq {candidate.seq}: event_type mismatch"
        )
    if candidate.summary != auth_row["summary"]:
        raise AuditLedgerIntegrityError(
            f"Candidate audit field rewrite at seq {candidate.seq}: summary mismatch"
        )
    if candidate.actor != auth_row["actor"]:
        raise AuditLedgerIntegrityError(
            f"Candidate audit field rewrite at seq {candidate.seq}: actor mismatch"
        )
    if candidate.prev_hash != auth_row["prev_hash"]:
        raise AuditLedgerIntegrityError(
            f"Candidate audit field rewrite at seq {candidate.seq}: prev_hash mismatch"
        )
    if candidate.current_hash != auth_row["current_hash"]:
        raise AuditLedgerIntegrityError(
            f"Candidate audit field rewrite at seq {candidate.seq}: hash rewrite"
        )
    if candidate.timestamp != auth_row["timestamp"]:
        raise AuditLedgerIntegrityError(
            f"Candidate audit field rewrite at seq {candidate.seq}: timestamp mismatch"
        )

    try:
        auth_details = json.loads(auth_row["details_json"])
    except Exception:
        raise AuditLedgerIntegrityError(
            f"Authoritative audit details_json malformed at seq {auth_row['seq']}"
        )

    if candidate.details != auth_details:
        raise AuditLedgerIntegrityError(
            f"Candidate audit field rewrite at seq {candidate.seq}: details mismatch"
        )

    recomputed = compute_audit_hash(
        prev_hash=candidate.prev_hash,
        seq=candidate.seq,
        event_type=candidate.event_type,
        summary=candidate.summary,
        actor=candidate.actor,
        timestamp=candidate.timestamp,
        details=candidate.details,
    )
    if recomputed != candidate.current_hash:
        raise AuditLedgerIntegrityError(
            f"Candidate audit prefix self-hash mismatch at seq {candidate.seq}"
        )
    if recomputed != auth_row["current_hash"]:
        raise AuditLedgerIntegrityError(
            f"Candidate audit prefix recomputed hash mismatch with authoritative at seq {candidate.seq}"
        )


class Database:
    """SQLite WAL storage engine for PayoutProof."""

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        audit_checkpoint_secret: Optional[str] = None,
    ):
        if db_path is None:
            import os
            self.db_path = os.environ.get("PAYOUTPROOF_DB_PATH", "payoutproof.db")
        else:
            self.db_path = str(db_path)

        if not audit_checkpoint_secret or not str(audit_checkpoint_secret).strip():
            raise ValueError("audit_checkpoint_secret is required and cannot be empty")
        if len(str(audit_checkpoint_secret).strip()) < 32:
            raise ValueError("audit_checkpoint_secret must be at least 32 characters")

        self.audit_checkpoint_secret = str(audit_checkpoint_secret)
        self._test_fail_after_audit_insert = False
        self._init_db()

    def __repr__(self) -> str:
        return f"Database(db_path={self.db_path!r}, audit_checkpoint_secret='[REDACTED]')"

    def get_connection(self, timeout: float = 30.0) -> sqlite3.Connection:
        """Get connection with WAL mode enabled, foreign keys ON, busy timeout, and Row factory."""
        conn = sqlite3.connect(self.db_path, timeout=timeout)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute(f"PRAGMA busy_timeout={int(timeout * 1000)};")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize database tables and run schema migrations."""
        with self.get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS risk_cases (
                    case_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    organization_id TEXT,
                    case_version INTEGER NOT NULL,
                    phase TEXT NOT NULL,
                    state_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS case_audit_checkpoints (
                    case_id TEXT PRIMARY KEY,
                    event_count INTEGER NOT NULL,
                    tip_hash TEXT NOT NULL,
                    trust_state TEXT NOT NULL,
                    checkpoint_mac TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

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
                );

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
                );

                CREATE TABLE IF NOT EXISTS adapter_attempts_quarantine (
                    quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    quarantine_reason TEXT NOT NULL,
                    quarantined_at TEXT NOT NULL,
                    original_idempotency_key TEXT,
                    original_grant_id TEXT,
                    original_case_id TEXT,
                    original_data_json TEXT
                );

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
                );

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
                );

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
                );

                CREATE TABLE IF NOT EXISTS auth_login_states (
                    state_token TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL,
                    code TEXT UNIQUE,
                    redirect_uri TEXT,
                    issuer TEXT NOT NULL,
                    code_expires_at TEXT,
                    consumed_at TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS case_action_actors (
                    case_id TEXT NOT NULL,
                    organization_id TEXT,
                    action_type TEXT NOT NULL,
                    actor_subject TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_risk_cases_tenant ON risk_cases(tenant_id);
                CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_events(case_id);
                CREATE INDEX IF NOT EXISTS idx_grants_case ON handoff_grants(case_id);
                CREATE INDEX IF NOT EXISTS idx_pending_items_case_id ON pending_approval_items(case_id);
                CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_case ON case_audit_checkpoints(case_id);
                CREATE INDEX IF NOT EXISTS idx_operator_sessions_token ON operator_sessions(token_hash);
                CREATE INDEX IF NOT EXISTS idx_operator_sessions_subject ON operator_sessions(subject);
                CREATE INDEX IF NOT EXISTS idx_case_action_actors_case ON case_action_actors(case_id, action_type, recorded_at);

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
                );
                CREATE INDEX IF NOT EXISTS idx_org_members_organization ON organization_members(organization_id);

                CREATE TABLE IF NOT EXISTS member_roles (
                    organization_id TEXT NOT NULL,
                    member_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    granted_by TEXT NOT NULL,
                    granted_at TEXT NOT NULL,
                    PRIMARY KEY (member_id, role)
                );
                CREATE INDEX IF NOT EXISTS idx_member_roles_organization ON member_roles(organization_id);

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
                );
                CREATE INDEX IF NOT EXISTS idx_invitations_organization ON membership_invitations(organization_id);

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
                );
                CREATE INDEX IF NOT EXISTS idx_membership_audit_organization ON membership_audit_events(organization_id);

                CREATE TABLE IF NOT EXISTS membership_audit_checkpoints (
                    organization_id TEXT PRIMARY KEY,
                    event_count INTEGER NOT NULL,
                    tip_hash TEXT NOT NULL,
                    trust_state TEXT NOT NULL,
                    checkpoint_mac TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_membership_audit_checkpoints_organization ON membership_audit_checkpoints(organization_id);

                -- Tenant operating limits (Issue #10). "tenant" is the issue's
                -- vocabulary for the enforcement scope of an organization: every
                -- row keys on organization_id, the session-owned scope used by
                -- every existing seam. quota_kind is 'requests' (per-org hourly
                -- window), 'requests_global' (the '__PLATFORM__' backstop
                -- bucket), or 'evidence_bytes' (monotonic cumulative, keyed
                -- 'CUMULATIVE'). window_key is a fixed UTC window derivation or
                -- the 'CUMULATIVE' sentinel; sentinel keys are non-null strings
                -- so the composite PRIMARY KEY stays valid under Postgres.
                CREATE TABLE IF NOT EXISTS tenant_quota_counters (
                    organization_id TEXT NOT NULL,
                    quota_kind TEXT NOT NULL,
                    window_key TEXT NOT NULL,
                    counter INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (organization_id, quota_kind, window_key)
                );
                CREATE INDEX IF NOT EXISTS idx_tenant_quota_org ON tenant_quota_counters(organization_id);

                CREATE TABLE IF NOT EXISTS tenant_operating_limits (
                    organization_id TEXT PRIMARY KEY,
                    limits_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL
                );

                -- Org-scoped settings audit: append-only, org-bound, riding the
                -- same BEGIN IMMEDIATE transaction as the settings upsert (or
                -- committed alone for a REJECTED write). Deliberately NOT
                -- audit_events: that table is case-owned with a NOT NULL
                -- case_id and UNIQUE(case_id, seq) chain semantics that are
                -- wrong for org-scoped settings events.
                CREATE TABLE IF NOT EXISTS tenant_settings_audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    changes_json TEXT NOT NULL,
                    reason_code TEXT,
                    recorded_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tenant_settings_audit_org ON tenant_settings_audit_events(organization_id);
            """)
            conn.commit()
            self._migrate_db(conn)
            conn.commit()
            # Issue #10 additive tables are created idempotently above and
            # re-asserted here so a pre-#10 database file upgraded in place
            # (where _migrate_db runs against legacy tables) also gains them.
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tenant_quota_counters (
                    organization_id TEXT NOT NULL,
                    quota_kind TEXT NOT NULL,
                    window_key TEXT NOT NULL,
                    counter INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (organization_id, quota_kind, window_key)
                );
                CREATE INDEX IF NOT EXISTS idx_tenant_quota_org ON tenant_quota_counters(organization_id);

                CREATE TABLE IF NOT EXISTS tenant_operating_limits (
                    organization_id TEXT PRIMARY KEY,
                    limits_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tenant_settings_audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    organization_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    changes_json TEXT NOT NULL,
                    reason_code TEXT,
                    recorded_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tenant_settings_audit_org ON tenant_settings_audit_events(organization_id);
            """)
            conn.commit()

    def _migrate_db(self, conn: sqlite3.Connection):
        """Idempotently migrate older schemas to required columns and constraints with duplicate quarantine."""
        # Inspect and validate risk_cases schema
        rc_info = {row["name"]: dict(row) for row in conn.execute("PRAGMA table_info(risk_cases)").fetchall()}
        if rc_info:
            # Critical columns must exist
            if "case_id" not in rc_info or "state_json" not in rc_info or "tenant_id" not in rc_info:
                raise DatabaseSchemaError("Unsupported schema drift: risk_cases missing critical columns")
            if rc_info["case_id"].get("pk") != 1:
                raise DatabaseSchemaError("Unsupported schema drift: risk_cases case_id is not PRIMARY KEY")
            # Migrate known legacy columns idempotently without data loss
            if "case_version" not in rc_info:
                conn.execute("ALTER TABLE risk_cases ADD COLUMN case_version INTEGER NOT NULL DEFAULT 0;")
            if "phase" not in rc_info:
                conn.execute("ALTER TABLE risk_cases ADD COLUMN phase TEXT NOT NULL DEFAULT 'EVIDENCE_ADMISSION';")
            if "created_at" not in rc_info:
                conn.execute("ALTER TABLE risk_cases ADD COLUMN created_at TEXT NOT NULL DEFAULT '';")
            if "updated_at" not in rc_info:
                conn.execute("ALTER TABLE risk_cases ADD COLUMN updated_at TEXT NOT NULL DEFAULT '';")
            # Organization scoping seam: legacy rows stay NULL (un-scoped, compatible).
            # Only ALTER when the column is absent so repeated migration is crash-free.
            if "organization_id" not in rc_info:
                conn.execute("ALTER TABLE risk_cases ADD COLUMN organization_id TEXT;")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_risk_cases_organization ON risk_cases(organization_id);"
            )

        # Inspect and validate handoff_grants schema
        hg_info = {row["name"]: dict(row) for row in conn.execute("PRAGMA table_info(handoff_grants)").fetchall()}
        if hg_info:
            # Critical columns must exist
            critical_hg_cols = ["grant_id", "case_id", "bound_intent_hash", "signature", "status", "nonce"]
            for col in critical_hg_cols:
                if col not in hg_info:
                    raise DatabaseSchemaError(f"Unsupported schema drift: handoff_grants missing critical column '{col}'")
            if hg_info["grant_id"].get("pk") != 1:
                raise DatabaseSchemaError("Unsupported schema drift: handoff_grants grant_id is not PRIMARY KEY")
            # Migrate known legacy columns idempotently without data loss
            if "bound_snapshot_hash" not in hg_info:
                conn.execute("ALTER TABLE handoff_grants ADD COLUMN bound_snapshot_hash TEXT NOT NULL DEFAULT '';")
            if "used" not in hg_info:
                conn.execute("ALTER TABLE handoff_grants ADD COLUMN used INTEGER NOT NULL DEFAULT 0;")
            if "organization_id" not in hg_info:
                conn.execute("ALTER TABLE handoff_grants ADD COLUMN organization_id TEXT;")

        # Migrate adapter_attempts schema
        aa_info = {row["name"]: dict(row) for row in conn.execute("PRAGMA table_info(adapter_attempts)").fetchall()}
        if aa_info and "organization_id" not in aa_info:
            conn.execute("ALTER TABLE adapter_attempts ADD COLUMN organization_id TEXT;")

        # Migrate pending_approval_items schema
        pai_info = {row["name"]: dict(row) for row in conn.execute("PRAGMA table_info(pending_approval_items)").fetchall()}
        if pai_info and "organization_id" not in pai_info:
            conn.execute("ALTER TABLE pending_approval_items ADD COLUMN organization_id TEXT;")

        # Ensure quarantine table exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS adapter_attempts_quarantine (
                quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
                quarantine_reason TEXT NOT NULL,
                quarantined_at TEXT NOT NULL,
                original_idempotency_key TEXT,
                original_grant_id TEXT,
                original_case_id TEXT,
                original_data_json TEXT
            );
        """)

        # Ensure pending_approval_items exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_approval_items (
                item_id TEXT NOT NULL PRIMARY KEY,
                case_id TEXT NOT NULL,
                grant_id TEXT NOT NULL UNIQUE,
                idempotency_key TEXT NOT NULL UNIQUE,
                counterparty TEXT NOT NULL,
                destination TEXT NOT NULL,
                amount TEXT NOT NULL,
                currency TEXT NOT NULL,
                purpose TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING_FINANCE_APPROVAL',
                created_at TEXT NOT NULL
            );
        """)

        info = conn.execute("PRAGMA table_info(adapter_attempts)").fetchall()
        col_info = {row["name"]: dict(row) for row in info}

        required_cols = {
            "idempotency_key",
            "case_id",
            "grant_id",
            "status",
            "decision",
            "ambiguity_state",
            "pending_item_id",
            "error_code",
            "error_message",
            "attempts",
            "created_at",
            "updated_at",
        }
        has_all_cols = required_cols.issubset(col_info.keys())

        # Check NOT NULL constraints on critical columns
        notnull_ok = False
        if has_all_cols:
            critical_notnull_cols = ["idempotency_key", "case_id", "grant_id", "status", "decision", "created_at", "updated_at"]
            notnull_ok = all(col_info[c].get("notnull") == 1 for c in critical_notnull_cols if c in col_info)

        # Check unique constraint on grant_id
        has_unique_grant_id = False
        if has_all_cols:
            indexes = conn.execute("PRAGMA index_list(adapter_attempts)").fetchall()
            for idx in indexes:
                if idx["unique"] == 1:
                    idx_cols = [r["name"] for r in conn.execute(f"PRAGMA index_info('{idx['name']}')").fetchall()]
                    if idx_cols == ["grant_id"]:
                        has_unique_grant_id = True
                        break

        # Check for duplicate or empty grant_ids in adapter_attempts
        dup_count = 0
        unfit_count = 0
        try:
            dup_row = conn.execute("""
                SELECT COUNT(*) FROM (
                    SELECT grant_id FROM adapter_attempts GROUP BY grant_id HAVING COUNT(*) > 1
                )
            """).fetchone()
            dup_count = dup_row[0] if dup_row else 0

            unfit_row = conn.execute("""
                SELECT COUNT(*) FROM adapter_attempts
                WHERE grant_id IS NULL OR grant_id = '' OR idempotency_key IS NULL OR idempotency_key = '' OR decision IS NULL
            """).fetchone()
            unfit_count = unfit_row[0] if unfit_row else 0
        except Exception:
            pass

        needs_rebuild = (not has_all_cols) or (not notnull_ok) or (not has_unique_grant_id) or (dup_count > 0) or (unfit_count > 0)

        if needs_rebuild:
            # Safe transactional rebuild of adapter_attempts table
            conn.execute("DROP TABLE IF EXISTS adapter_attempts_rebuild;")
            conn.execute("""
                CREATE TABLE adapter_attempts_rebuild (
                    idempotency_key TEXT NOT NULL PRIMARY KEY,
                    case_id TEXT NOT NULL,
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
                );
            """)

            rows = conn.execute("SELECT * FROM adapter_attempts ORDER BY updated_at DESC, created_at DESC, idempotency_key DESC").fetchall()
            seen_grants = set()
            now_iso = datetime.now(timezone.utc).isoformat()

            for row in rows:
                r_dict = dict(row)
                g_id = (r_dict.get("grant_id") or "").strip()
                idem_key = (r_dict.get("idempotency_key") or "").strip()

                if not g_id:
                    # Missing / empty grant_id: preserve in quarantine
                    conn.execute("""
                        INSERT INTO adapter_attempts_quarantine (
                            quarantine_reason, quarantined_at, original_idempotency_key,
                            original_grant_id, original_case_id, original_data_json
                        ) VALUES (?, ?, ?, ?, ?, ?);
                    """, (
                        "MISSING_GRANT_ID",
                        now_iso,
                        r_dict.get("idempotency_key"),
                        r_dict.get("grant_id"),
                        r_dict.get("case_id"),
                        json.dumps(r_dict),
                    ))
                    continue

                if not idem_key:
                    # Missing / empty idempotency_key: preserve in quarantine
                    conn.execute("""
                        INSERT INTO adapter_attempts_quarantine (
                            quarantine_reason, quarantined_at, original_idempotency_key,
                            original_grant_id, original_case_id, original_data_json
                        ) VALUES (?, ?, ?, ?, ?, ?);
                    """, (
                        "MISSING_IDEMPOTENCY_KEY",
                        now_iso,
                        r_dict.get("idempotency_key"),
                        g_id,
                        r_dict.get("case_id"),
                        json.dumps(r_dict),
                    ))
                    continue

                if g_id in seen_grants:
                    # Conflicting duplicate: preserve in quarantine table
                    conn.execute("""
                        INSERT INTO adapter_attempts_quarantine (
                            quarantine_reason, quarantined_at, original_idempotency_key,
                            original_grant_id, original_case_id, original_data_json
                        ) VALUES (?, ?, ?, ?, ?, ?);
                    """, (
                        "DUPLICATE_GRANT_ID_CONFLICT",
                        now_iso,
                        r_dict.get("idempotency_key"),
                        g_id,
                        r_dict.get("case_id"),
                        json.dumps(r_dict),
                    ))
                else:
                    seen_grants.add(g_id)
                    dec_val = r_dict.get("decision") or r_dict.get("last_decision") or "UNKNOWN"
                    conn.execute("""
                        INSERT INTO adapter_attempts_rebuild (
                            idempotency_key, case_id, grant_id, status, decision,
                            ambiguity_state, pending_item_id, error_code, error_message,
                            attempts, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        idem_key,
                        r_dict.get("case_id") or "",
                        g_id,
                        r_dict.get("status") or "UNKNOWN",
                        dec_val,
                        r_dict.get("ambiguity_state"),
                        r_dict.get("pending_item_id"),
                        r_dict.get("error_code"),
                        r_dict.get("error_message"),
                        r_dict.get("attempts") if r_dict.get("attempts") is not None else 1,
                        r_dict.get("created_at") or now_iso,
                        r_dict.get("updated_at") or now_iso,
                    ))

            conn.execute("DROP TABLE adapter_attempts;")
            conn.execute("ALTER TABLE adapter_attempts_rebuild RENAME TO adapter_attempts;")

        # Ensure unique index on grant_id in adapter_attempts
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_adapter_attempts_grant_id ON adapter_attempts(grant_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_adapter_attempts_case_id ON adapter_attempts(case_id);")

        # Ensure unique indexes on pending_approval_items
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_items_grant_id ON pending_approval_items(grant_id);")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_items_idempotency_key ON pending_approval_items(idempotency_key);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pending_items_case_id ON pending_approval_items(case_id);")

        # Ensure case_audit_checkpoints table and index exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS case_audit_checkpoints (
                case_id TEXT PRIMARY KEY,
                event_count INTEGER NOT NULL,
                tip_hash TEXT NOT NULL,
                trust_state TEXT NOT NULL,
                checkpoint_mac TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_case ON case_audit_checkpoints(case_id);")

        now_iso = datetime.now(timezone.utc).isoformat()

        # Check for pre-existing duplicate (case_id, seq) in audit_events
        dup_rows = conn.execute("""
            SELECT case_id, seq, COUNT(*) as cnt
            FROM audit_events
            WHERE case_id IS NOT NULL AND TRIM(case_id) != ''
            GROUP BY case_id, seq
            HAVING cnt > 1
        """).fetchall()

        if not dup_rows:
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_case_seq ON audit_events(case_id, seq);")
        else:
            # Pre-existing duplicates exist: preserve all rows (never delete/drop)
            # Create non-unique index and quarantine affected cases into LEGACY_UNTRUSTED state
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_events(case_id);")
            dup_case_ids = {r["case_id"] for r in dup_rows}
            for cid in dup_case_ids:
                conn.execute("""
                    INSERT INTO case_audit_checkpoints (case_id, event_count, tip_hash, trust_state, checkpoint_mac, updated_at)
                    VALUES (?, 0, '', 'LEGACY_UNTRUSTED', 'LEGACY_UNTRUSTED', ?)
                    ON CONFLICT(case_id) DO UPDATE SET
                        trust_state = 'LEGACY_UNTRUSTED',
                        checkpoint_mac = 'LEGACY_UNTRUSTED',
                        updated_at = excluded.updated_at;
                """, (cid, now_iso))

        # Safely clean/ignore any malformed NULL or empty case_id checkpoint rows
        try:
            conn.execute("DELETE FROM case_audit_checkpoints WHERE case_id IS NULL OR TRIM(case_id) = '';")
        except Exception:
            pass

        # Migrate pre-P0-3C uncheckpointed risk cases as LEGACY_UNTRUSTED without deleting data (using NOT EXISTS)
        uncheckpointed_cases = conn.execute("""
            SELECT r.case_id FROM risk_cases r
            WHERE r.case_id IS NOT NULL AND TRIM(r.case_id) != ''
              AND NOT EXISTS (
                  SELECT 1 FROM case_audit_checkpoints c
                  WHERE c.case_id = r.case_id AND c.case_id IS NOT NULL AND TRIM(c.case_id) != ''
              )
        """).fetchall()
        for r in uncheckpointed_cases:
            cid = r["case_id"]
            ev_rows = conn.execute("SELECT seq, current_hash FROM audit_events WHERE case_id = ? ORDER BY seq ASC", (cid,)).fetchall()
            ev_cnt = len(ev_rows)
            tip = ev_rows[-1]["current_hash"] if ev_rows else GENESIS_HASH
            conn.execute("""
                INSERT INTO case_audit_checkpoints (case_id, event_count, tip_hash, trust_state, checkpoint_mac, updated_at)
                VALUES (?, ?, ?, 'LEGACY_UNTRUSTED', 'LEGACY_UNTRUSTED', ?)
                ON CONFLICT(case_id) DO NOTHING;
            """, (cid, ev_cnt, tip, now_iso))

        # Migrate orphan audit rows (events for cases not in case_audit_checkpoints) as LEGACY_UNTRUSTED (using NOT EXISTS)
        orphan_audits = conn.execute("""
            SELECT DISTINCT a.case_id FROM audit_events a
            WHERE a.case_id IS NOT NULL AND TRIM(a.case_id) != ''
              AND NOT EXISTS (
                  SELECT 1 FROM case_audit_checkpoints c
                  WHERE c.case_id = a.case_id AND c.case_id IS NOT NULL AND TRIM(c.case_id) != ''
              )
        """).fetchall()
        for r in orphan_audits:
            cid = r["case_id"]
            ev_rows = conn.execute("SELECT seq, current_hash FROM audit_events WHERE case_id = ? ORDER BY seq ASC", (cid,)).fetchall()
            ev_cnt = len(ev_rows)
            tip = ev_rows[-1]["current_hash"] if ev_rows else GENESIS_HASH
            conn.execute("""
                INSERT INTO case_audit_checkpoints (case_id, event_count, tip_hash, trust_state, checkpoint_mac, updated_at)
                VALUES (?, ?, ?, 'LEGACY_UNTRUSTED', 'LEGACY_UNTRUSTED', ?)
                ON CONFLICT(case_id) DO NOTHING;
            """, (cid, ev_cnt, tip, now_iso))



    def save_case_tx(self, conn: sqlite3.Connection, state: RiskCaseState):
        """Save or update a Risk Case within an active transaction connection.

        Enforces authenticated authoritative audit checkpoints and strictly validates
        candidate audit history as an exact match of authoritative ledger plus append-only suffix.
        Atomic persistence ensures partial updates never survive.
        """
        if not state.case_id:
            raise ValueError("Cannot persist case without case_id")

        # 1. Inspect existing state and durable records for this case_id
        existing_case_row = conn.execute(
            "SELECT tenant_id, organization_id, phase, state_json FROM risk_cases WHERE case_id = ?",
            (state.case_id,),
        ).fetchone()

        if existing_case_row:
            cp_row = conn.execute(
                "SELECT * FROM case_audit_checkpoints WHERE case_id = ?",
                (state.case_id,),
            ).fetchone()
            if cp_row is None:
                raise AuditLedgerIntegrityError(f"Case '{state.case_id}' lacks audit checkpoint; mutations refused")
            if cp_row["trust_state"] != AuditTrustState.TRUSTED.value:
                raise AuditLedgerIntegrityError(f"Case '{state.case_id}' is in untrusted state '{cp_row['trust_state']}'; mutations refused")

            if state.tenant_id != existing_case_row["tenant_id"]:
                raise AuditLedgerIntegrityError(
                    f"Candidate tenant_id '{state.tenant_id}' conflicts with authoritative row tenant_id '{existing_case_row['tenant_id']}'"
                )
            # Organization scope is checked inside this BEGIN IMMEDIATE transaction,
            # so a case can never be re-scoped or cross-written after its first write.
            if state.organization_id != existing_case_row["organization_id"]:
                raise DatabaseConsistencyError(
                    f"Candidate organization_id '{state.organization_id}' conflicts with authoritative row organization_id '{existing_case_row['organization_id']}'"
                )
        else:
            # New case creation: reject whitespace-only scope if provided
            if state.organization_id is not None and not str(state.organization_id).strip():
                raise UnscopedCaseError(
                    f"Cannot create case '{state.case_id}' with whitespace-only organization_id"
                )
            cp_row = conn.execute(
                "SELECT * FROM case_audit_checkpoints WHERE case_id = ?",
                (state.case_id,),
            ).fetchone()

        auth_rows = conn.execute(
            "SELECT * FROM audit_events WHERE case_id = ? ORDER BY seq ASC",
            (state.case_id,),
        ).fetchall()

        durable_grants = conn.execute(
            "SELECT grant_id, status, used FROM handoff_grants WHERE case_id = ?",
            (state.case_id,),
        ).fetchall()

        durable_attempts = conn.execute(
            "SELECT idempotency_key, grant_id FROM adapter_attempts WHERE case_id = ?",
            (state.case_id,),
        ).fetchall()

        durable_items = conn.execute(
            "SELECT item_id FROM pending_approval_items WHERE case_id = ?",
            (state.case_id,),
        ).fetchall()

        # Reject candidate state lacking grant if case has active/terminal grant, attempt, item, or terminal phase
        if state.grant is None:
            if existing_case_row:
                ex_phase = existing_case_row["phase"]
                if ex_phase in (
                    CasePhase.HANDOFF_IN_PROGRESS.value,
                    CasePhase.COMPLETE.value,
                    CasePhase.RECONCILIATION_REQUIRED.value,
                ):
                    raise StaleCaseStateError(
                        f"Cannot overwrite case '{state.case_id}' in phase '{ex_phase}' with candidate state lacking grant"
                    )
            if durable_grants:
                raise StaleCaseStateError(
                    f"Cannot overwrite case '{state.case_id}' having durable grants with candidate state lacking grant"
                )
            if durable_attempts:
                raise StaleCaseStateError(
                    f"Cannot overwrite case '{state.case_id}' having durable adapter attempts with candidate state lacking grant"
                )
            if durable_items:
                raise StaleCaseStateError(
                    f"Cannot overwrite case '{state.case_id}' having durable pending approval items with candidate state lacking grant"
                )

        # Inspect candidate grant against durable state
        if state.grant:
            g = state.grant
            grant_row = conn.execute(
                "SELECT status, used FROM handoff_grants WHERE grant_id = ?",
                (g.grant_id,),
            ).fetchone()

            if grant_row:
                validate_grant_transition(
                    current_status=grant_row["status"],
                    current_used=grant_row["used"],
                    new_status=g.status,
                    new_used=g.used,
                )
                # Reject if candidate is ACTIVE while durable row is already terminal or used
                if g.status == GrantStatus.ACTIVE and (
                    grant_row["used"] == 1
                    or grant_row["status"] in ("CONSUMED", "SUSPENDED_FOR_RECONCILIATION", "INVALIDATED", "EXPIRED")
                ):
                    raise StaleCaseStateError(
                        f"Cannot overwrite terminal/used durable grant {g.grant_id} with ACTIVE candidate state"
                    )
            elif g.status == GrantStatus.ACTIVE and g.used:
                raise ValueError("Invariant violation: grant cannot have status ACTIVE while used=True")

            if existing_case_row:
                try:
                    ex_data = json.loads(existing_case_row["state_json"])
                    ex_grant = ex_data.get("grant")
                    if ex_grant and ex_grant.get("grant_id") == g.grant_id:
                        d_g_row = conn.execute(
                            "SELECT status, used FROM handoff_grants WHERE grant_id = ?",
                            (g.grant_id,),
                        ).fetchone()
                        if d_g_row and (
                            d_g_row["used"] == 1
                            or d_g_row["status"] in ("CONSUMED", "SUSPENDED_FOR_RECONCILIATION", "INVALIDATED", "EXPIRED")
                        ):
                            if g.status == GrantStatus.ACTIVE:
                                raise StaleCaseStateError(
                                    f"Cannot overwrite terminal/used durable grant {g.grant_id} with ACTIVE candidate state"
                                )
                except StaleCaseStateError:
                    raise
                except Exception:
                    pass

        # Protect against phase rollback from terminal or reconciliation states
        if existing_case_row:
            ex_phase = existing_case_row["phase"]
            if ex_phase == CasePhase.COMPLETE.value and state.phase not in (
                CasePhase.COMPLETE,
                CasePhase.OPERATOR_INTERVENTION,
            ):
                raise StaleCaseStateError(
                    f"Cannot revert case '{state.case_id}' from phase COMPLETE to '{state.phase.value}'"
                )
            if ex_phase == CasePhase.RECONCILIATION_REQUIRED.value and state.phase not in (
                CasePhase.RECONCILIATION_REQUIRED,
                CasePhase.OPERATOR_INTERVENTION,
            ):
                raise StaleCaseStateError(
                    f"Cannot revert case '{state.case_id}' from phase RECONCILIATION_REQUIRED to '{state.phase.value}'"
                )

        now_iso = datetime.now(timezone.utc).isoformat()

        # Audit ledger validation and checkpoint updating
        if existing_case_row is None:
            # --- Case A: New Case Creation ---
            if cp_row is not None:
                raise AuditLedgerIntegrityError(f"Integrity violation: checkpoint already exists for new case '{state.case_id}'")
            if auth_rows:
                raise AuditLedgerIntegrityError(f"Integrity violation: orphan audit rows already exist for new case '{state.case_id}'")

            events_to_persist = state.audit
            if not events_to_persist:
                initial_ev = AuditEvent(
                    seq=1,
                    case_id=state.case_id,
                    event_type="EVIDENCE_ADMISSION_STARTED",
                    summary="Case initialized",
                    actor="PayoutProof",
                    prev_hash=GENESIS_HASH,
                    current_hash=compute_audit_hash(
                        prev_hash=GENESIS_HASH,
                        seq=1,
                        event_type="EVIDENCE_ADMISSION_STARTED",
                        summary="Case initialized",
                        actor="PayoutProof",
                        timestamp=now_iso,
                        details={"tenant_id": state.tenant_id},
                    ),
                    timestamp=now_iso,
                    details={"tenant_id": state.tenant_id},
                )
                events_to_persist = [initial_ev]

            # Verify candidate events form a contiguous, valid chain starting at seq 1
            for idx, ev in enumerate(events_to_persist):
                expected_seq = idx + 1
                if ev.seq != expected_seq:
                    raise AuditLedgerIntegrityError(f"Candidate audit sequence gap: expected seq {expected_seq}, found {ev.seq}")
                if ev.case_id and ev.case_id != state.case_id:
                    raise AuditLedgerIntegrityError(f"Cross-case audit event rejected: event has case_id '{ev.case_id}', expected '{state.case_id}'")
                expected_prev = events_to_persist[idx - 1].current_hash if idx > 0 else GENESIS_HASH
                if ev.prev_hash != expected_prev:
                    raise AuditLedgerIntegrityError(f"Candidate audit broken prev_hash at seq {ev.seq}")
                recomputed = compute_audit_hash(
                    prev_hash=ev.prev_hash,
                    seq=ev.seq,
                    event_type=ev.event_type,
                    summary=ev.summary,
                    actor=ev.actor,
                    timestamp=ev.timestamp,
                    details=ev.details,
                )
                if recomputed != ev.current_hash:
                    raise AuditLedgerIntegrityError(f"Candidate audit hash mismatch at seq {ev.seq}")

            # Insert risk_cases omitting audit from state_json (audit_events is authoritative)
            state_dict = state.model_dump()
            state_dict["audit"] = []
            state_json = json.dumps(state_dict)

            rc_cur = conn.execute("""
                INSERT INTO risk_cases (case_id, tenant_id, organization_id, case_version, phase, state_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (state.case_id, state.tenant_id, state.organization_id, state.case_version, state.phase.value, state_json, now_iso, now_iso))
            if rc_cur.rowcount != 1:
                raise AuditLedgerIntegrityError(f"Failed to insert risk_cases row for case '{state.case_id}': expected 1 row affected, got {rc_cur.rowcount}")

            # Insert audit events (NEVER INSERT OR IGNORE!)
            for ev in events_to_persist:
                ev_details = json.dumps(ev.details)
                ev_cur = conn.execute("""
                    INSERT INTO audit_events (case_id, seq, event_type, summary, actor, prev_hash, current_hash, timestamp, details_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (state.case_id, ev.seq, ev.event_type, ev.summary, ev.actor, ev.prev_hash, ev.current_hash, ev.timestamp, ev_details))
                if ev_cur.rowcount != 1:
                    raise AuditLedgerIntegrityError(f"Failed to insert audit event row at seq {ev.seq} for case '{state.case_id}': expected 1 row affected, got {ev_cur.rowcount}")

            # Deterministic failure injection hook
            if getattr(self, "_test_fail_after_audit_insert", False):
                raise RuntimeError("Deterministic failure injection: crash after audit insert before checkpoint update")

            # Insert initial TRUSTED authenticated checkpoint
            count = len(events_to_persist)
            tip = events_to_persist[-1].current_hash
            mac = compute_checkpoint_mac(self.audit_checkpoint_secret, state.case_id, count, tip, AuditTrustState.TRUSTED.value)
            cp_cur = conn.execute("""
                INSERT INTO case_audit_checkpoints (case_id, event_count, tip_hash, trust_state, checkpoint_mac, updated_at)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (state.case_id, count, tip, AuditTrustState.TRUSTED.value, mac, now_iso))
            if cp_cur.rowcount != 1:
                raise AuditLedgerIntegrityError(f"Failed to insert case_audit_checkpoints row for case '{state.case_id}': expected 1 row affected, got {cp_cur.rowcount}")

        else:
            # --- Case B: Existing Case Mutation ---
            if cp_row is None:
                raise AuditLedgerIntegrityError(f"Case '{state.case_id}' lacks audit checkpoint; mutations refused")
            if cp_row["trust_state"] != AuditTrustState.TRUSTED.value:
                raise AuditLedgerIntegrityError(f"Case '{state.case_id}' is in untrusted state '{cp_row['trust_state']}'; mutations refused")
            if not isinstance(cp_row["event_count"], int) or isinstance(cp_row["event_count"], bool):
                raise AuditLedgerIntegrityError(f"Checkpoint event_count is not an integer for case '{state.case_id}'")

            is_mac_valid = verify_checkpoint_mac(
                secret=self.audit_checkpoint_secret,
                case_id=state.case_id,
                event_count=cp_row["event_count"],
                tip_hash=cp_row["tip_hash"],
                trust_state=cp_row["trust_state"],
                checkpoint_mac=cp_row["checkpoint_mac"],
            )
            if not is_mac_valid:
                raise AuditLedgerIntegrityError(f"Audit checkpoint MAC verification failed for case '{state.case_id}'")

            # Verify authoritative ledger against checkpoint
            count_auth = len(auth_rows)
            if count_auth != cp_row["event_count"]:
                raise AuditLedgerIntegrityError(f"Authoritative audit count {count_auth} does not match checkpoint count {cp_row['event_count']}")
            expected_tip = auth_rows[-1]["current_hash"] if auth_rows else GENESIS_HASH
            if cp_row["tip_hash"] != expected_tip:
                raise AuditLedgerIntegrityError("Authoritative audit tip does not match checkpoint tip")

            seen_seqs = set()
            for idx, r in enumerate(auth_rows):
                if r["seq"] in seen_seqs:
                    raise AuditLedgerIntegrityError(f"Authoritative audit duplicate sequence at seq {r['seq']}")
                seen_seqs.add(r["seq"])
                expected_seq = idx + 1
                if r["seq"] != expected_seq:
                    raise AuditLedgerIntegrityError(f"Authoritative audit sequence gap at seq {r['seq']}")
                if r["case_id"] != state.case_id:
                    raise AuditLedgerIntegrityError(f"Authoritative audit cross-case ownership violation: {r['case_id']}")
                expected_prev = auth_rows[idx - 1]["current_hash"] if idx > 0 else GENESIS_HASH
                if r["prev_hash"] != expected_prev:
                    raise AuditLedgerIntegrityError(f"Authoritative audit broken prev_hash at seq {r['seq']}")
                try:
                    details = json.loads(r["details_json"])
                except Exception:
                    raise AuditLedgerIntegrityError(f"Authoritative audit details_json malformed at seq {r['seq']}")
                recomputed = compute_audit_hash(
                    prev_hash=r["prev_hash"],
                    seq=r["seq"],
                    event_type=r["event_type"],
                    summary=r["summary"],
                    actor=r["actor"],
                    timestamp=r["timestamp"],
                    details=details,
                )
                if recomputed != r["current_hash"]:
                    raise AuditLedgerIntegrityError(f"Authoritative audit payload tampered at seq {r['seq']}")

            # Validate candidate audit against authoritative ledger
            N = count_auth
            M = len(state.audit)
            if M < N:
                raise AuditLedgerIntegrityError(f"Candidate audit truncated: candidate has {M} events, authoritative ledger has {N}")

            # Verify prefix of candidate matches authoritative history exactly
            for i in range(N):
                _assert_audit_event_exact_match(state.audit[i], auth_rows[i], state.case_id)

            if M == N:
                new_suffix = []
            else:
                new_suffix = state.audit[N:]
                for idx_s, ev in enumerate(new_suffix):
                    expected_seq = N + 1 + idx_s
                    if ev.seq != expected_seq:
                        raise AuditLedgerIntegrityError(f"Candidate audit suffix sequence gap: expected seq {expected_seq}, found {ev.seq}")
                    if ev.case_id and ev.case_id != state.case_id:
                        raise AuditLedgerIntegrityError(f"Cross-case audit event rejected: event has case_id '{ev.case_id}', expected '{state.case_id}'")
                    expected_prev = state.audit[N + idx_s - 1].current_hash
                    if ev.prev_hash != expected_prev:
                        raise AuditLedgerIntegrityError(f"Candidate audit suffix broken prev_hash at seq {ev.seq}")
                    recomputed = compute_audit_hash(
                        prev_hash=ev.prev_hash,
                        seq=ev.seq,
                        event_type=ev.event_type,
                        summary=ev.summary,
                        actor=ev.actor,
                        timestamp=ev.timestamp,
                        details=ev.details,
                    )
                    if recomputed != ev.current_hash:
                        raise AuditLedgerIntegrityError(f"Candidate audit suffix hash mismatch at seq {ev.seq}")

            # Update risk_cases omitting audit from state_json
            state_dict = state.model_dump()
            state_dict["audit"] = []
            state_json = json.dumps(state_dict)

            rc_cur = conn.execute("""
                UPDATE risk_cases
                SET case_version = ?, phase = ?, organization_id = ?, state_json = ?, updated_at = ?
                WHERE case_id = ?;
            """, (state.case_version, state.phase.value, state.organization_id, state_json, now_iso, state.case_id))
            if rc_cur.rowcount != 1:
                raise AuditLedgerIntegrityError(f"Failed to update risk_cases row for case '{state.case_id}': expected 1 row affected, got {rc_cur.rowcount}")

            # Insert new suffix audit events (if any) and update checkpoint atomically
            if new_suffix:
                for ev in new_suffix:
                    ev_details = json.dumps(ev.details)
                    ev_cur = conn.execute("""
                        INSERT INTO audit_events (case_id, seq, event_type, summary, actor, prev_hash, current_hash, timestamp, details_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (state.case_id, ev.seq, ev.event_type, ev.summary, ev.actor, ev.prev_hash, ev.current_hash, ev.timestamp, ev_details))
                    if ev_cur.rowcount != 1:
                        raise AuditLedgerIntegrityError(f"Failed to insert audit event row at seq {ev.seq} for case '{state.case_id}': expected 1 row affected, got {ev_cur.rowcount}")

                # Deterministic failure injection hook
                if getattr(self, "_test_fail_after_audit_insert", False):
                    raise RuntimeError("Deterministic failure injection: crash after audit insert before checkpoint update")

                new_tip = state.audit[-1].current_hash
                new_mac = compute_checkpoint_mac(self.audit_checkpoint_secret, state.case_id, M, new_tip, AuditTrustState.TRUSTED.value)
                cp_cur = conn.execute("""
                    UPDATE case_audit_checkpoints
                    SET event_count = ?, tip_hash = ?, trust_state = ?, checkpoint_mac = ?, updated_at = ?
                    WHERE case_id = ?;
                """, (M, new_tip, AuditTrustState.TRUSTED.value, new_mac, now_iso, state.case_id))
                if cp_cur.rowcount != 1:
                    raise AuditLedgerIntegrityError(f"Failed to update case_audit_checkpoints row for case '{state.case_id}': expected 1 row affected, got {cp_cur.rowcount}")
            else:
                cp_cur = conn.execute("""
                    UPDATE case_audit_checkpoints
                    SET updated_at = ?
                    WHERE case_id = ?;
                """, (now_iso, state.case_id))
                if cp_cur.rowcount != 1:
                    raise AuditLedgerIntegrityError(f"Failed to update case_audit_checkpoints row for case '{state.case_id}': expected 1 row affected, got {cp_cur.rowcount}")

        # If grant exists, persist grant monotonically
        if state.grant:
            g = state.grant
            conn.execute("""
                INSERT INTO handoff_grants (
                    grant_id, tenant_id, organization_id, case_id, bound_intent_hash, bound_snapshot_hash,
                    policy_version, outcome, nonce, issued_at, expires_at, signature, status, used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(grant_id) DO UPDATE SET
                    organization_id = excluded.organization_id,
                    used = CASE
                        WHEN handoff_grants.used = 1 THEN 1
                        ELSE excluded.used
                    END,
                    status = CASE
                        WHEN handoff_grants.status IN ('CONSUMED', 'SUSPENDED_FOR_RECONCILIATION', 'INVALIDATED', 'EXPIRED')
                            AND excluded.status = 'ACTIVE' THEN handoff_grants.status
                        WHEN (handoff_grants.used = 1 OR excluded.used = 1) AND excluded.status = 'ACTIVE'
                            THEN handoff_grants.status
                        WHEN handoff_grants.status IN ('CONSUMED', 'SUSPENDED_FOR_RECONCILIATION', 'INVALIDATED', 'EXPIRED')
                            THEN handoff_grants.status
                        ELSE excluded.status
                    END;
            """, (
                g.grant_id, g.tenant_id, g.organization_id, g.case_id, g.bound_intent_hash,
                g.bound_snapshot_hash, g.policy_version, g.outcome.value,
                g.nonce, g.issued_at, g.expires_at, g.signature,
                g.status.value, 1 if g.used else 0
            ))

    def save_case(self, state: RiskCaseState):
        """Save or update a Risk Case within a BEGIN IMMEDIATE transaction."""
        with self.get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                self.save_case_tx(conn, state)
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def load_case_tx(self, conn: sqlite3.Connection, case_id: str) -> Optional[RiskCaseState]:
        """Load a Risk Case by ID within an active connection (non-mutating read).

        Verifies checkpoint MAC, trust state, event count, tip hash, and continuous sequence.
        Hydrates RiskCaseState.audit strictly from verified authoritative audit_events rows.
        Raises AuditLedgerIntegrityError on any verification or corruption failure.
        """
        row = conn.execute(
            "SELECT case_id, tenant_id, organization_id, state_json FROM risk_cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if not row:
            return None

        cp_row = conn.execute("SELECT * FROM case_audit_checkpoints WHERE case_id = ?", (case_id,)).fetchone()
        if not cp_row:
            raise AuditLedgerIntegrityError(f"Case '{case_id}' lacks audit checkpoint; case is untrusted")

        if cp_row["trust_state"] != AuditTrustState.TRUSTED.value:
            raise AuditLedgerIntegrityError(f"Case '{case_id}' is in untrusted state '{cp_row['trust_state']}'")

        if not isinstance(cp_row["event_count"], int) or isinstance(cp_row["event_count"], bool):
            raise AuditLedgerIntegrityError(f"Checkpoint event_count is not an integer for case '{case_id}'")

        is_mac_valid = verify_checkpoint_mac(
            secret=self.audit_checkpoint_secret,
            case_id=case_id,
            event_count=cp_row["event_count"],
            tip_hash=cp_row["tip_hash"],
            trust_state=cp_row["trust_state"],
            checkpoint_mac=cp_row["checkpoint_mac"],
        )
        if not is_mac_valid:
            raise AuditLedgerIntegrityError(f"Audit checkpoint MAC verification failed for case '{case_id}'")

        auth_rows = conn.execute("SELECT * FROM audit_events WHERE case_id = ? ORDER BY seq ASC", (case_id,)).fetchall()
        if len(auth_rows) != cp_row["event_count"]:
            raise AuditLedgerIntegrityError(f"Audit event count mismatch: checkpoint records {cp_row['event_count']}, ledger has {len(auth_rows)}")

        expected_tip = auth_rows[-1]["current_hash"] if auth_rows else GENESIS_HASH
        if cp_row["tip_hash"] != expected_tip:
            raise AuditLedgerIntegrityError("Audit tip mismatch with checkpoint")

        seen_seqs = set()
        events = []
        for idx, r in enumerate(auth_rows):
            if r["seq"] in seen_seqs:
                raise AuditLedgerIntegrityError(f"Duplicate audit sequence at seq {r['seq']} for case '{case_id}'")
            seen_seqs.add(r["seq"])
            expected_seq = idx + 1
            if r["seq"] != expected_seq:
                raise AuditLedgerIntegrityError(f"Audit sequence gap or out-of-order at seq {r['seq']}, expected {expected_seq}")
            if r["case_id"] != case_id:
                raise AuditLedgerIntegrityError(f"Cross-case audit ownership violation: {r['case_id']}")
            expected_prev = auth_rows[idx - 1]["current_hash"] if idx > 0 else GENESIS_HASH
            if r["prev_hash"] != expected_prev:
                raise AuditLedgerIntegrityError(f"Broken audit prev_hash chain at seq {r['seq']}")
            try:
                details = json.loads(r["details_json"])
            except Exception:
                raise AuditLedgerIntegrityError(f"Malformed details_json at seq {r['seq']}")
            recomputed = compute_audit_hash(
                prev_hash=r["prev_hash"],
                seq=r["seq"],
                event_type=r["event_type"],
                summary=r["summary"],
                actor=r["actor"],
                timestamp=r["timestamp"],
                details=details,
            )
            if recomputed != r["current_hash"]:
                raise AuditLedgerIntegrityError(f"Tampered audit event payload at seq {r['seq']}: current_hash mismatch")

            events.append(AuditEvent(
                seq=r["seq"],
                case_id=r["case_id"],
                event_type=r["event_type"],
                summary=r["summary"],
                actor=r["actor"],
                prev_hash=r["prev_hash"],
                current_hash=r["current_hash"],
                timestamp=r["timestamp"],
                details=details,
            ))

        try:
            data = json.loads(row["state_json"])
        except Exception:
            raise AuditLedgerIntegrityError(f"Malformed state_json for case '{case_id}'")

        if data.get("case_id") is not None and data.get("case_id") != row["case_id"]:
            raise AuditLedgerIntegrityError(f"state_json case_id '{data.get('case_id')}' conflicts with authoritative row case_id '{row['case_id']}'")
        if data.get("tenant_id") is not None and data.get("tenant_id") != row["tenant_id"]:
            raise AuditLedgerIntegrityError(f"state_json tenant_id '{data.get('tenant_id')}' conflicts with authoritative row tenant_id '{row['tenant_id']}'")
        # Organization scope must agree between the row column and state_json; NULL (un-scoped
        # legacy) and an absent key are the same scope, any other disagreement is corruption.
        if "organization_id" in data and data["organization_id"] != row["organization_id"]:
            raise DatabaseConsistencyError(
                f"state_json organization_id '{data.get('organization_id')}' conflicts with authoritative row organization_id '{row['organization_id']}'"
            )
        data["case_id"] = row["case_id"]
        data["tenant_id"] = row["tenant_id"]
        data["organization_id"] = row["organization_id"]
        data["audit"] = events
        try:
            return RiskCaseState.model_validate(data)
        except Exception:
            raise AuditLedgerIntegrityError(f"Malformed state model validation for case '{case_id}'")

    def load_case(self, case_id: str) -> Optional[RiskCaseState]:
        """Load a Risk Case by ID (non-mutating read)."""
        with self.get_connection() as conn:
            return self.load_case_tx(conn, case_id)

    def get_case_scope(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Return existence and organization scope of a case row, or None when absent.

        Read-only and unverified by design: lets callers enforce a zero-existence
        oracle (missing case and cross-organization case are indistinguishable)
        without leaking integrity diagnostics for cases outside their scope.
        """
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT case_id, tenant_id, organization_id FROM risk_cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "case_id": row["case_id"],
                "tenant_id": row["tenant_id"],
                "organization_id": row["organization_id"],
            }

    def verify_case_audit_tx(self, conn: sqlite3.Connection, case_id: str) -> Optional[Dict[str, Any]]:
        """Verify cryptographic integrity of case audit ledger within a connection."""
        row = conn.execute("SELECT case_id FROM risk_cases WHERE case_id = ?", (case_id,)).fetchone()
        if not row:
            return None

        cp_row = conn.execute("SELECT * FROM case_audit_checkpoints WHERE case_id = ?", (case_id,)).fetchone()
        if not cp_row:
            return {
                "case_id": case_id,
                "is_valid": False,
                "trust_state": AuditTrustState.LEGACY_UNTRUSTED.value,
                "event_count": 0,
                "broken_at_seq": None,
                "reason": "Missing audit checkpoint; case is in legacy untrusted quarantine",
            }

        if cp_row["trust_state"] == AuditTrustState.LEGACY_UNTRUSTED.value:
            return {
                "case_id": case_id,
                "is_valid": False,
                "trust_state": AuditTrustState.LEGACY_UNTRUSTED.value,
                "event_count": cp_row["event_count"] if isinstance(cp_row["event_count"], int) else 0,
                "broken_at_seq": None,
                "reason": "Case is quarantined in LEGACY_UNTRUSTED state; recovery requires opening a new case ID",
            }

        if cp_row["trust_state"] != AuditTrustState.TRUSTED.value:
            return {
                "case_id": case_id,
                "is_valid": False,
                "trust_state": "CORRUPTED",
                "event_count": cp_row["event_count"] if isinstance(cp_row["event_count"], int) else 0,
                "broken_at_seq": None,
                "reason": f"Invalid checkpoint trust state '{cp_row['trust_state']}'",
            }

        if not isinstance(cp_row["event_count"], int) or isinstance(cp_row["event_count"], bool):
            return {
                "case_id": case_id,
                "is_valid": False,
                "trust_state": "CORRUPTED",
                "event_count": 0,
                "broken_at_seq": None,
                "reason": "Checkpoint event_count is not an integer",
            }

        is_mac_valid = verify_checkpoint_mac(
            secret=self.audit_checkpoint_secret,
            case_id=case_id,
            event_count=cp_row["event_count"],
            tip_hash=cp_row["tip_hash"],
            trust_state=cp_row["trust_state"],
            checkpoint_mac=cp_row["checkpoint_mac"],
        )
        if not is_mac_valid:
            return {
                "case_id": case_id,
                "is_valid": False,
                "trust_state": "CORRUPTED",
                "event_count": cp_row["event_count"],
                "broken_at_seq": None,
                "reason": "Audit checkpoint MAC verification failed (tampered checkpoint or wrong audit secret)",
            }

        rows = conn.execute("SELECT * FROM audit_events WHERE case_id = ? ORDER BY seq ASC", (case_id,)).fetchall()
        if len(rows) != cp_row["event_count"]:
            return {
                "case_id": case_id,
                "is_valid": False,
                "trust_state": "CORRUPTED",
                "event_count": len(rows),
                "broken_at_seq": None,
                "reason": f"Event count mismatch: checkpoint records {cp_row['event_count']} events, found {len(rows)}",
            }

        expected_tip = rows[-1]["current_hash"] if rows else GENESIS_HASH
        if cp_row["tip_hash"] != expected_tip:
            return {
                "case_id": case_id,
                "is_valid": False,
                "trust_state": "CORRUPTED",
                "event_count": len(rows),
                "broken_at_seq": None,
                "reason": "Audit tip hash mismatch with checkpoint",
            }

        seen_seqs = set()
        for idx, r in enumerate(rows):
            if r["seq"] in seen_seqs:
                return {
                    "case_id": case_id,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Duplicate audit sequence at seq {r['seq']}",
                }
            seen_seqs.add(r["seq"])
            expected_seq = idx + 1
            if r["seq"] != expected_seq:
                return {
                    "case_id": case_id,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Sequence gap: expected seq {expected_seq}, found {r['seq']}",
                }
            if r["case_id"] != case_id:
                return {
                    "case_id": case_id,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Cross-case audit ownership violation: {r['case_id']}",
                }
            expected_prev = rows[idx - 1]["current_hash"] if idx > 0 else GENESIS_HASH
            if r["prev_hash"] != expected_prev:
                return {
                    "case_id": case_id,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Broken prev_hash chain at seq {r['seq']}",
                }
            try:
                details = json.loads(r["details_json"])
            except Exception:
                return {
                    "case_id": case_id,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Malformed details_json at seq {r['seq']}",
                }
            recomputed = compute_audit_hash(
                prev_hash=r["prev_hash"],
                seq=r["seq"],
                event_type=r["event_type"],
                summary=r["summary"],
                actor=r["actor"],
                timestamp=r["timestamp"],
                details=details,
            )
            if recomputed != r["current_hash"]:
                return {
                    "case_id": case_id,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Tampered event payload at seq {r['seq']}: current_hash mismatch",
                }

        return {
            "case_id": case_id,
            "is_valid": True,
            "trust_state": AuditTrustState.TRUSTED.value,
            "event_count": cp_row["event_count"],
            "tip_hash": cp_row["tip_hash"],
            "broken_at_seq": None,
            "reason": None,
        }

    def verify_case_audit(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Verify cryptographic integrity of case audit ledger."""
        with self.get_connection() as conn:
            return self.verify_case_audit_tx(conn, case_id)

    def list_cases(self, organization_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List cases with summary metadata, verifying integrity per row.

        - organization_id=<str>: only cases scoped to that organization
          (`IS ?` is NULL-safe, so a scoped query never matches un-scoped legacy rows).
        - organization_id=None is not a supported caller mode: listing without
          an explicit organization scope is rejected. Un-scoped legacy rows have
          no caller and no access path.
        """
        with self.get_connection() as conn:
            if organization_id is None:
                rows = conn.execute("""
                    SELECT case_id, tenant_id, organization_id, case_version, phase, updated_at
                    FROM risk_cases
                    ORDER BY updated_at DESC
                """).fetchall()
            elif organization_id is UNSCOPED:
                rows = conn.execute("""
                    SELECT case_id, tenant_id, organization_id, case_version, phase, updated_at
                    FROM risk_cases
                    WHERE organization_id IS NULL
                    ORDER BY updated_at DESC
                """).fetchall()
            else:
                rows = conn.execute("""
                    SELECT case_id, tenant_id, organization_id, case_version, phase, updated_at
                    FROM risk_cases
                    WHERE organization_id = ?
                    ORDER BY updated_at DESC
                """, (organization_id,)).fetchall()
            results = []
            for r in rows:
                c_id = r["case_id"]
                v = self.verify_case_audit_tx(conn, c_id)
                if v is None:
                    trust_status = "CORRUPTED"
                elif v["is_valid"]:
                    trust_status = AuditTrustState.TRUSTED.value
                elif v.get("trust_state") == AuditTrustState.LEGACY_UNTRUSTED.value:
                    trust_status = AuditTrustState.LEGACY_UNTRUSTED.value
                else:
                    trust_status = "CORRUPTED"

                results.append({
                    "case_id": c_id,
                    "tenant_id": r["tenant_id"],
                    "organization_id": r["organization_id"],
                    "case_version": r["case_version"],
                    "phase": r["phase"],
                    "updated_at": r["updated_at"],
                    "trust_state": trust_status,
                })
            return results

    # ==========================================================================
    # Operator sessions, OIDC login states, and action attribution (Issue #7)
    # ==========================================================================

    def create_operator_session(
        self,
        session_id: str,
        token_hash: str,
        subject: str,
        display_name: str,
        role: str,
        tenant_id: str,
        organization_id: str,
        idp_issuer: str,
        issued_at: str,
        expires_at: str,
        last_seen_at: Optional[str] = None,
    ) -> None:
        """Persist a new operator session row keyed by the hashed opaque token."""
        if not token_hash or not str(token_hash).strip():
            raise ValueError("token_hash is required")
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO operator_sessions (
                    session_id, token_hash, subject, display_name, role, tenant_id,
                    organization_id, idp_issuer, issued_at, expires_at, last_seen_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL);
            """, (
                session_id, token_hash, subject, display_name, role, tenant_id,
                organization_id, idp_issuer, issued_at, expires_at, last_seen_at,
            ))
            conn.commit()

    def get_operator_session(self, token_hash: str) -> Optional[Dict[str, Any]]:
        """Fetch an operator session row by hashed token, or None when absent."""
        if not token_hash:
            return None
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM operator_sessions WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            return dict(row) if row else None

    def revoke_operator_session(self, token_hash: str, revoked_at: str) -> bool:
        """Mark a session revoked; returns False when the row does not exist."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "UPDATE operator_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (revoked_at, token_hash),
            )
            conn.commit()
            return cur.rowcount == 1

    def touch_operator_session(self, token_hash: str, last_seen_at: str) -> bool:
        """Update last_seen_at for activity tracking; no-op on unknown tokens."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "UPDATE operator_sessions SET last_seen_at = ? WHERE token_hash = ?",
                (last_seen_at, token_hash),
            )
            conn.commit()
            return cur.rowcount == 1

    def create_login_state(
        self,
        state_token: str,
        nonce: str,
        issuer: str,
        created_at: str,
        redirect_uri: Optional[str] = None,
        code: Optional[str] = None,
        code_expires_at: Optional[str] = None,
    ) -> None:
        """Persist a single-use OIDC authorization state (CSRF defense in depth)."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO auth_login_states (
                    state_token, nonce, code, redirect_uri, issuer, code_expires_at, consumed_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?);
            """, (state_token, nonce, code, redirect_uri, issuer, code_expires_at, created_at))
            conn.commit()

    def record_login_state_code(
        self,
        state_token: str,
        code: str,
        code_expires_at: Optional[str],
    ) -> bool:
        """Attach the provider-issued authorization code to its login state.

        Fails (returns False) when the state row is absent or already carries a
        code, so a replayed authorize redirect cannot bind a second code.
        """
        with self.get_connection() as conn:
            cur = conn.execute(
                "UPDATE auth_login_states SET code = ?, code_expires_at = ? "
                "WHERE state_token = ? AND code IS NULL AND consumed_at IS NULL",
                (code, code_expires_at, state_token),
            )
            conn.commit()
            return cur.rowcount == 1

    def consume_login_state(self, state_token: str, consumed_at: str) -> Optional[Dict[str, Any]]:
        """Atomically consume a login state (single-use) and return its row.

        Returns None when the state is absent, already consumed, or concurrently
        claimed — the caller then refuses the callback fail-closed.
        """
        with self.get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                row = conn.execute(
                    "SELECT * FROM auth_login_states WHERE state_token = ?",
                    (state_token,),
                ).fetchone()
                if row is None:
                    conn.rollback()
                    return None
                if row["consumed_at"] is not None:
                    conn.rollback()
                    return None
                cur = conn.execute(
                    "UPDATE auth_login_states SET consumed_at = ? WHERE state_token = ? AND consumed_at IS NULL",
                    (consumed_at, state_token),
                )
                if cur.rowcount != 1:
                    conn.rollback()
                    return None
                conn.commit()
                return dict(row)
            except Exception:
                conn.rollback()
                raise

    def record_case_action(
        self,
        case_id: str,
        action_type: str,
        actor_subject: str,
        actor_role: str,
        recorded_at: str,
        organization_id: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> None:
        """Record who dispatched which action on a case (session-derived attribution).

        With `conn` provided the insert rides the caller's BEGIN IMMEDIATE
        transaction, so attribution and state mutation commit atomically.
        """
        params = (case_id, organization_id, action_type, actor_subject, actor_role, recorded_at)
        sql = """
            INSERT INTO case_action_actors (
                case_id, organization_id, action_type, actor_subject, actor_role, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?);
        """
        if conn is not None:
            conn.execute(sql, params)
            return
        with self.get_connection() as c:
            c.execute(sql, params)
            c.commit()

    def get_latest_case_action(
        self,
        case_id: str,
        action_type: str,
        conn: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Return the most recent recorded dispatch of `action_type` on a case, or None."""
        sql = (
            "SELECT * FROM case_action_actors WHERE case_id = ? AND action_type = ? "
            "ORDER BY recorded_at DESC, rowid DESC LIMIT 1"
        )
        if conn is not None:
            row = conn.execute(sql, (case_id, action_type)).fetchone()
            return dict(row) if row else None
        with self.get_connection() as c:
            row = c.execute(sql, (case_id, action_type)).fetchone()
            return dict(row) if row else None


    @staticmethod
    def _row_to_pending_item(row: sqlite3.Row) -> PendingApprovalItem:
        org_id = row["organization_id"] if "organization_id" in row.keys() else None
        return PendingApprovalItem(
            item_id=row["item_id"],
            case_id=row["case_id"],
            counterparty=row["counterparty"],
            destination=row["destination"],
            amount=row["amount"],
            currency=row["currency"],
            purpose=row["purpose"],
            grant_id=row["grant_id"],
            idempotency_key=row["idempotency_key"],
            created_at=row["created_at"],
            status=row["status"],
            organization_id=org_id,
        )

    def get_pending_item(
        self,
        grant_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        item_id: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> Optional[PendingApprovalItem]:
        """Fetch a pending approval item by grant_id, idempotency_key, or item_id."""
        def _query(c: sqlite3.Connection):
            if item_id:
                row = c.execute("SELECT * FROM pending_approval_items WHERE item_id = ?", (item_id,)).fetchone()
            elif grant_id:
                row = c.execute("SELECT * FROM pending_approval_items WHERE grant_id = ?", (grant_id,)).fetchone()
            elif idempotency_key:
                row = c.execute("SELECT * FROM pending_approval_items WHERE idempotency_key = ?", (idempotency_key,)).fetchone()
            else:
                return None
            return self._row_to_pending_item(row) if row else None

        if conn is not None:
            return _query(conn)
        with self.get_connection() as c:
            return _query(c)

    def get_all_pending_items(self, conn: Optional[sqlite3.Connection] = None) -> Dict[str, PendingApprovalItem]:
        """Fetch all pending approval items keyed by item_id."""
        def _query(c: sqlite3.Connection):
            rows = c.execute("SELECT * FROM pending_approval_items").fetchall()
            return {r["item_id"]: self._row_to_pending_item(r) for r in rows}

        if conn is not None:
            return _query(conn)
        with self.get_connection() as c:
            return _query(c)

    def get_consumed_grant_ids(self, conn: Optional[sqlite3.Connection] = None) -> set[str]:
        """Fetch all consumed/used grant IDs from SQLite."""
        def _query(c: sqlite3.Connection):
            rows = c.execute("SELECT grant_id FROM handoff_grants WHERE used = 1").fetchall()
            return {r["grant_id"] for r in rows}

        if conn is not None:
            return _query(conn)
        with self.get_connection() as c:
            return _query(c)

    def get_idempotency_records(self, conn: Optional[sqlite3.Connection] = None) -> Dict[str, PendingApprovalItem]:
        """Fetch all pending items keyed by idempotency_key."""
        def _query(c: sqlite3.Connection):
            rows = c.execute("SELECT * FROM pending_approval_items").fetchall()
            return {r["idempotency_key"]: self._row_to_pending_item(r) for r in rows}

        if conn is not None:
            return _query(conn)
        with self.get_connection() as c:
            return _query(c)

    def get_adapter_attempt(
        self,
        grant_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        case_id: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch adapter attempt record from SQLite."""
        def _query(c: sqlite3.Connection):
            if idempotency_key:
                row = c.execute("SELECT * FROM adapter_attempts WHERE idempotency_key = ?", (idempotency_key,)).fetchone()
            elif grant_id:
                row = c.execute("SELECT * FROM adapter_attempts WHERE grant_id = ?", (grant_id,)).fetchone()
            elif case_id:
                row = c.execute("SELECT * FROM adapter_attempts WHERE case_id = ? ORDER BY updated_at DESC LIMIT 1", (case_id,)).fetchone()
            else:
                return None
            return dict(row) if row else None

        if conn is not None:
            return _query(conn)
        with self.get_connection() as c:
            return _query(c)

    def execute_adapter_submission_tx(
        self,
        conn: sqlite3.Connection,
        grant: HandoffGrant,
        intent: PaymentIntent,
        idempotency_key: str,
        simulate_ambiguity: bool = False,
        *,
        grant_secret: str,
    ) -> Tuple[AdapterDecision, Optional[PendingApprovalItem], Optional[str]]:
        """Submit handoff within an existing transaction connection.

        Atomically validates against authoritative durable state, claims the grant
        conditionally with rowcount == 1, and writes adapter_attempts and pending_approval_items.
        NEVER inserts missing grants.
        """
        if not grant_secret or not str(grant_secret).strip():
            raise ValueError("grant_secret is required and cannot be empty")
        from payoutproof.core.crypto import compute_intent_hash, derive_idempotency_key

        # 1. Authoritative Case record check & full state_json validation
        persisted_case = self.load_case_tx(conn, grant.case_id)
        if not persisted_case:
            return AdapterDecision.GRANT_INVALID_OR_EXPIRED, None, "Authoritative case record not found"

        # Claim admission authority prerequisites
        if (
            persisted_case.request_bundle_status != "ADMITTED"
            or persisted_case.phase == CasePhase.ADMISSION_REJECTED
            or persisted_case.processing_authority != ProcessingAuthorityStatus.VALID
            or persisted_case.authority_record is None
            or not persisted_case.authority_record.is_valid
            or not persisted_case.evidence
            or not persisted_case.policy
            or persisted_case.policy.outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF
        ):
            return AdapterDecision.GRANT_INVALID_OR_EXPIRED, None, "Authoritative case lacks valid processing authority or admitted evidence"

        if not persisted_case.grant or persisted_case.grant.grant_id != grant.grant_id:
            return AdapterDecision.GRANT_INVALID_OR_EXPIRED, None, "Authoritative grant not found on case"

        # Authoritative case snapshot hash verification
        persisted_snapshot_hash = compute_snapshot_hash(persisted_case)
        if (
            not grant.bound_snapshot_hash
            or grant.bound_snapshot_hash != persisted_snapshot_hash
            or persisted_case.grant.bound_snapshot_hash != persisted_snapshot_hash
        ):
            return AdapterDecision.GRANT_INVALID_OR_EXPIRED, None, "Authoritative case snapshot hash mismatch (post-grant state mutation detected)"

        # 2. Authoritative case intent consistency check
        persisted_recomputed_hash = compute_intent_hash(persisted_case.intent)
        if (
            not persisted_case.intent.intent_hash
            or persisted_recomputed_hash != persisted_case.intent.intent_hash
            or persisted_case.intent.intent_hash != grant.bound_intent_hash
            or persisted_case.intent.intent_hash != persisted_case.grant.bound_intent_hash
        ):
            return AdapterDecision.INTENT_MISMATCH, None, "Authoritative case intent is inconsistent or unconfirmed"

        # 3. Supplied intent verification (never trust self-asserted intent_hash)
        if not intent.intent_hash:
            return AdapterDecision.INTENT_MISMATCH, None, "Payment Intent has not been confirmed/hashed"

        supplied_recomputed_hash = compute_intent_hash(intent)
        if supplied_recomputed_hash != intent.intent_hash:
            return AdapterDecision.INTENT_MISMATCH, None, "Supplied intent hash does not match canonical recomputation"

        if (
            intent.canonical_string() != persisted_case.intent.canonical_string()
            or intent.provenance != persisted_case.intent.provenance
            or intent.status != persisted_case.intent.status
            or intent.destination_status != persisted_case.intent.destination_status
            or intent.intent_hash != persisted_case.intent.intent_hash
        ):
            return AdapterDecision.INTENT_MISMATCH, None, "Supplied intent does not match authoritative case intent"

        # 4. Server-owned idempotency key verification
        expected_key = derive_idempotency_key(
            tenant_id=persisted_case.tenant_id,
            case_id=grant.case_id,
            case_version=persisted_case.case_version,
            grant_id=grant.grant_id,
            organization_id=persisted_case.organization_id,
        )
        if idempotency_key != expected_key:
            return AdapterDecision.GRANT_INVALID_OR_EXPIRED, None, "Idempotency key does not match authoritative case derivation"

        # 5. Check authoritative grant row in handoff_grants (MUST pre-exist)
        grant_row = conn.execute(
            "SELECT * FROM handoff_grants WHERE grant_id = ?",
            (grant.grant_id,),
        ).fetchone()
        if not grant_row:
            return AdapterDecision.GRANT_INVALID_OR_EXPIRED, None, "Authoritative grant record not found"

        outcome_val = grant.outcome.value if hasattr(grant.outcome, "value") else str(grant.outcome)
        if (
            grant_row["tenant_id"] != grant.tenant_id
            or grant_row["case_id"] != grant.case_id
            or grant_row["bound_intent_hash"] != grant.bound_intent_hash
            or grant_row["bound_snapshot_hash"] != grant.bound_snapshot_hash
            or grant_row["policy_version"] != grant.policy_version
            or grant_row["outcome"] != outcome_val
            or grant_row["nonce"] != grant.nonce
            or grant_row["issued_at"] != grant.issued_at
            or grant_row["expires_at"] != grant.expires_at
            or grant_row["signature"] != grant.signature
        ):
            return AdapterDecision.GRANT_INVALID_OR_EXPIRED, None, "Authoritative grant record mismatch"

        if grant_row["used"] == 1 or grant_row["status"] != "ACTIVE":
            return AdapterDecision.REPLAY_REJECTED, None, "Replay detected: Handoff Grant has already been consumed"

        # 6. Grant signature & validity check
        is_valid, err = GrantVerifier.verify(grant, intent.intent_hash, secret=grant_secret)
        if not is_valid:
            return AdapterDecision.GRANT_INVALID_OR_EXPIRED, None, f"Grant verification failed: {err}"

        # 7. Check duplicate idempotency key in adapter_attempts
        existing_by_key = conn.execute(
            "SELECT * FROM adapter_attempts WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if existing_by_key:
            item = self.get_pending_item(idempotency_key=idempotency_key, conn=conn)
            return AdapterDecision.REPLAY_REJECTED, item, "Replay detected: duplicate idempotency key rejected"

        # 8. Check duplicate grant_id in adapter_attempts
        existing_by_grant = conn.execute(
            "SELECT * FROM adapter_attempts WHERE grant_id = ?",
            (grant.grant_id,),
        ).fetchone()
        if existing_by_grant:
            return AdapterDecision.REPLAY_REJECTED, None, "Replay detected: Handoff Grant has already been consumed"

        # 9. Conditional claim: claim grant atomically requiring rowcount == 1
        cursor = conn.execute(
            "UPDATE handoff_grants SET used = 1 WHERE grant_id = ? AND used = 0 AND status = 'ACTIVE'",
            (grant.grant_id,),
        )
        if cursor.rowcount != 1:
            return AdapterDecision.REPLAY_REJECTED, None, "Replay detected: Handoff Grant has already been consumed"

        # 10. Grant claimed: handle simulation of downstream ambiguity
        now_iso = datetime.now(timezone.utc).isoformat()
        if simulate_ambiguity:
            conn.execute(
                "UPDATE handoff_grants SET status = 'SUSPENDED_FOR_RECONCILIATION' WHERE grant_id = ?",
                (grant.grant_id,),
            )
            conn.execute("""
                INSERT INTO adapter_attempts (
                    idempotency_key, grant_id, case_id, organization_id, attempts, status, decision,
                    ambiguity_state, pending_item_id, error_code, error_message, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 1, 'RECONCILIATION_REQUIRED', ?, 'RECONCILIATION_REQUIRED', NULL, 'DOWNSTREAM_TIMEOUT', 'Downstream response timed out; reconciliation required', ?, ?);
            """, (
                idempotency_key, grant.grant_id, grant.case_id, persisted_case.organization_id,
                AdapterDecision.DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY.value,
                now_iso, now_iso
            ))
            return AdapterDecision.DOWNSTREAM_STATUS_UNKNOWN_NO_RETRY, None, "Downstream response timed out; reconciliation required"

        # 11. Successful handoff: consume grant and persist pending approval item using authoritative intent
        conn.execute(
            "UPDATE handoff_grants SET status = 'CONSUMED' WHERE grant_id = ?",
            (grant.grant_id,),
        )
        count_row = conn.execute(
            "SELECT count(*) FROM pending_approval_items WHERE case_id = ?",
            (grant.case_id,),
        ).fetchone()
        item_seq = (count_row[0] if count_row else 0) + 1
        item_id = f"RAIL-PENDING-{grant.case_id}-{item_seq:03d}"

        # Downstream item creation uses authoritative persisted intent
        authoritative_intent = persisted_case.intent
        conn.execute("""
            INSERT INTO pending_approval_items (
                item_id, case_id, organization_id, grant_id, idempotency_key, counterparty, destination,
                amount, currency, purpose, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_FINANCE_APPROVAL', ?);
        """, (
            item_id, grant.case_id, persisted_case.organization_id, grant.grant_id, idempotency_key,
            authoritative_intent.counterparty or "", authoritative_intent.destination or "",
            authoritative_intent.amount or "", authoritative_intent.currency or "INR",
            authoritative_intent.purpose or "", now_iso
        ))

        conn.execute("""
            INSERT INTO adapter_attempts (
                idempotency_key, grant_id, case_id, organization_id, attempts, status, decision,
                ambiguity_state, pending_item_id, error_code, error_message, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 1, 'COMPLETED', ?, 'NONE', ?, NULL, NULL, ?, ?);
        """, (
            idempotency_key, grant.grant_id, grant.case_id, persisted_case.organization_id,
            AdapterDecision.PENDING_ITEM_CREATED.value, item_id, now_iso, now_iso
        ))

        item = PendingApprovalItem(
            item_id=item_id,
            case_id=grant.case_id,
            counterparty=authoritative_intent.counterparty or "",
            destination=authoritative_intent.destination or "",
            amount=authoritative_intent.amount or "",
            currency=authoritative_intent.currency or "INR",
            purpose=authoritative_intent.purpose or "",
            grant_id=grant.grant_id,
            idempotency_key=idempotency_key,
            created_at=now_iso,
            status="PENDING_FINANCE_APPROVAL",
            organization_id=persisted_case.organization_id,
        )
        return AdapterDecision.PENDING_ITEM_CREATED, item, None

    # ==========================================================================
    # Organization membership administration (Issue #8)
    #
    # Zero Autonomous Money Actions: this section administers membership only.
    # It must never grant authority to approve, release, or initiate money
    # actions, and it shares zero tables and zero code paths with the Money
    # Action surface (risk_cases, handoff_grants, pending_approval_items,
    # adapter_attempts, case_audit_checkpoints).
    # ==========================================================================

    MEMBERSHIP_AUDIT_GENESIS_SEQ = 1

    @staticmethod
    def _require_membership_scope(organization_id: Optional[str]) -> str:
        """Return the stripped organization scope or raise UnscopedMembershipError.

        Blank, None, or whitespace-only scopes are rejected: there is no
        default organization, no UNSCOPED sentinel mode, and no un-scoped
        membership caller mode.
        """
        if organization_id is None or not isinstance(organization_id, str) or not organization_id.strip():
            raise UnscopedMembershipError(
                "Membership operations require an explicit non-blank organization_id; "
                "there is no un-scoped membership mode."
            )
        return organization_id.strip()

    @staticmethod
    def _validate_membership_roles(new_roles: List[MembershipRole]) -> List[MembershipRole]:
        """Validate the closed role vocabulary (R4) and return the canonical sorted set."""
        if not isinstance(new_roles, (list, tuple)):
            raise MembershipConflictError("new_roles must be a list of MembershipRole values")
        seen: set[str] = set()
        normalized: List[MembershipRole] = []
        for r in new_roles:
            if not isinstance(r, MembershipRole):
                raise MembershipConflictError(
                    f"Role '{r!r}' is not a MembershipRole; roles come only from the closed enum vocabulary"
                )
            if r in seen:
                raise MembershipConflictError(f"Duplicate role '{r.value}' in role set")
            seen.add(r)
            normalized.append(r)
        return sorted(normalized, key=lambda role: role.value)

    def _append_membership_audit_tx(
        self,
        conn: sqlite3.Connection,
        *,
        organization_id: str,
        event_type: MembershipAuditEventType,
        summary: str,
        actor: str,
        details: Dict[str, Any],
        timestamp: str,
    ) -> None:
        """Append one event and advance the org-keyed checkpoint inside the caller's transaction.

        Mirrors the case-ledger checkpoint discipline: the checkpoint is read
        inside the same BEGIN IMMEDIATE, trust_state must be TRUSTED and its
        MAC must verify (mutations are refused otherwise), and both the event
        insert and the checkpoint advance require rowcount == 1.
        """
        cp_row = conn.execute(
            """
            SELECT event_count, tip_hash, trust_state, checkpoint_mac
            FROM membership_audit_checkpoints
            WHERE organization_id = ?;
            """,
            (organization_id,),
        ).fetchone()

        if cp_row is None:
            seq = 1
            prev_hash = GENESIS_HASH
        else:
            if cp_row["trust_state"] != AuditTrustState.TRUSTED.value:
                raise AuditLedgerIntegrityError(
                    f"Membership audit for organization '{organization_id}' is in untrusted state "
                    f"'{cp_row['trust_state']}'; mutations refused"
                )
            if not isinstance(cp_row["event_count"], int) or isinstance(cp_row["event_count"], bool):
                raise AuditLedgerIntegrityError(
                    f"Membership audit checkpoint event_count is not an integer for '{organization_id}'"
                )
            if not verify_checkpoint_mac(
                secret=self.audit_checkpoint_secret,
                case_id=organization_id,
                event_count=cp_row["event_count"],
                tip_hash=cp_row["tip_hash"],
                trust_state=cp_row["trust_state"],
                checkpoint_mac=cp_row["checkpoint_mac"],
            ):
                raise AuditLedgerIntegrityError(
                    f"Membership audit checkpoint MAC verification failed for '{organization_id}'"
                )
            durable_count = conn.execute(
                "SELECT COUNT(*) FROM membership_audit_events WHERE organization_id = ?;",
                (organization_id,),
            ).fetchone()[0]
            if durable_count != cp_row["event_count"]:
                raise AuditLedgerIntegrityError(
                    f"Membership audit event count mismatch for '{organization_id}': "
                    f"checkpoint records {cp_row['event_count']}, ledger has {durable_count}"
                )
            seq = cp_row["event_count"] + 1
            prev_hash = cp_row["tip_hash"]

        details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
        current_hash = compute_audit_hash(
            prev_hash=prev_hash,
            seq=seq,
            event_type=event_type.value,
            summary=summary,
            actor=actor,
            timestamp=timestamp,
            details=details,
        )

        cur = conn.execute(
            """
            INSERT INTO membership_audit_events (
                organization_id, seq, event_type, summary, actor, prev_hash, current_hash, timestamp, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                organization_id,
                seq,
                event_type.value,
                summary,
                actor,
                prev_hash,
                current_hash,
                timestamp,
                details_json,
            ),
        )
        if cur.rowcount != 1:
            raise AuditLedgerIntegrityError(
                f"Failed to insert membership audit event at seq {seq} for '{organization_id}'"
            )

        new_mac = compute_checkpoint_mac(
            self.audit_checkpoint_secret,
            organization_id,
            seq,
            current_hash,
            AuditTrustState.TRUSTED.value,
        )
        cp_cur = conn.execute(
            """
            INSERT INTO membership_audit_checkpoints (
                organization_id, event_count, tip_hash, trust_state, checkpoint_mac, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(organization_id) DO UPDATE SET
                event_count = excluded.event_count,
                tip_hash = excluded.tip_hash,
                trust_state = 'TRUSTED',
                checkpoint_mac = excluded.checkpoint_mac,
                updated_at = excluded.updated_at;
            """,
            (organization_id, seq, current_hash, AuditTrustState.TRUSTED.value, new_mac, timestamp),
        )
        if cp_cur.rowcount != 1:
            raise AuditLedgerIntegrityError(
                f"Failed to advance membership audit checkpoint for '{organization_id}'"
            )

    @staticmethod
    def _count_other_active_administrators_tx(
        conn: sqlite3.Connection,
        *,
        organization_id: str,
        excluding_member_id: str,
    ) -> int:
        """Count ACTIVE Tenant Administrators other than the given member (R3 lock input)."""
        row = conn.execute(
            """
            SELECT COUNT(*) FROM organization_members AS m
            JOIN member_roles AS r
              ON r.member_id = m.member_id AND r.organization_id = m.organization_id
            WHERE m.organization_id = ? AND m.status = ?
              AND r.role = ? AND m.member_id != ?;
            """,
            (
                organization_id,
                MembershipStatus.ACTIVE.value,
                MembershipRole.TENANT_ADMINISTRATOR.value,
                excluding_member_id,
            ),
        ).fetchone()
        return int(row[0]) if row else 0

    @staticmethod
    def _mint_membership_token(
        *,
        membership_secret: str,
        member_id: str,
        organization_id: str,
        token_version: int,
        issued_at: str,
        expires_at: str,
    ) -> str:
        """Mint the stateless HMAC bearer token with explicit domain separation.

        Signed with membership_secret — never grant_secret — so administration
        and the Money Action surface are separated cryptographically, not
        merely by convention.
        """
        message = (
            f"MEMBERSHIP_TOKEN_V1|{member_id}|{organization_id}|{token_version}|{issued_at}|{expires_at}"
        )
        signature = hmac.new(
            membership_secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"{message}|{signature}"

    def resolve_membership_principal_tx(
        self,
        conn: sqlite3.Connection,
        *,
        organization_id: str,
        bearer_token: str,
        membership_secret: str,
        now: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Verify the stateless bearer token and re-read the member row fresh from SQLite.

        Returns a principal dict {member_id, organization_id, email, roles}
        or None on ANY of: bad signature, malformed token, expired token,
        member REMOVED, token_version mismatch, organization mismatch.
        Callers map None to 401/404 without distinguishing which check
        failed. There is no cache: every authorization decision re-reads the
        authoritative member row inside this call.
        """
        scope = self._require_membership_scope(organization_id)
        if not membership_secret or len(str(membership_secret).strip()) < 32:
            raise ValueError("membership_secret is required and must be at least 32 characters")

        if not bearer_token or not isinstance(bearer_token, str):
            return None
        parts = bearer_token.split("|")
        if len(parts) != 7 or parts[0] != "MEMBERSHIP_TOKEN_V1":
            return None
        member_id, token_org, token_version_raw, issued_at, expires_at, signature = parts[1:]
        message = (
            f"MEMBERSHIP_TOKEN_V1|{member_id}|{token_org}|{token_version_raw}|{issued_at}|{expires_at}"
        )
        expected = hmac.new(
            str(membership_secret).encode("utf-8"), message.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return None

        # Organization confinement: the token's org must equal the mandatory
        # caller scope; a cross-org token is indistinguishable from absent.
        if token_org != scope:
            return None

        try:
            token_version = int(token_version_raw)
        except ValueError:
            return None
        if token_version < 0:
            return None

        now_iso = now if now is not None else datetime.now(timezone.utc).isoformat()
        try:
            now_dt = datetime.fromisoformat(now_iso)
            exp_dt = datetime.fromisoformat(expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if now_dt.tzinfo is None:
                now_dt = now_dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None
        if exp_dt <= now_dt:
            return None

        row = conn.execute(
            """
            SELECT member_id, organization_id, email, status, token_version
            FROM organization_members
            WHERE member_id = ? AND organization_id = ?;
            """,
            (member_id, scope),
        ).fetchone()
        if row is None:
            return None
        if row["status"] != MembershipStatus.ACTIVE.value:
            return None
        if int(row["token_version"]) != token_version:
            return None

        role_rows = conn.execute(
            """
            SELECT role FROM member_roles
            WHERE member_id = ? AND organization_id = ?
            ORDER BY role ASC;
            """,
            (member_id, scope),
        ).fetchall()
        roles = frozenset(MembershipRole(r["role"]) for r in role_rows)

        return {
            "member_id": row["member_id"],
            "organization_id": row["organization_id"],
            "email": row["email"],
            "roles": roles,
        }

    def resolve_membership_principal(
        self,
        *,
        organization_id: str,
        bearer_token: str,
        membership_secret: str,
        now: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Connection-managed wrapper around resolve_membership_principal_tx (fresh read, no cache)."""
        scope = self._require_membership_scope(organization_id)
        with self.get_connection() as conn:
            return self.resolve_membership_principal_tx(
                conn,
                organization_id=scope,
                bearer_token=bearer_token,
                membership_secret=membership_secret,
                now=now,
            )

    def invite_member_tx(
        self,
        conn: sqlite3.Connection,
        *,
        organization_id: str,
        email: str,
        role: MembershipRole,
        invited_by: str,
        expires_at: str,
        invitation_id: Optional[str] = None,
        invitation_secret: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Create a PENDING single-use invitation inside the caller's transaction.

        Returns (invitation_id, invitation_secret) — the raw secret is
        returned exactly once and only its SHA-256 is persisted. Multiple
        PENDING invitations for one email are permitted; single-use is
        enforced per invitation at acceptance.
        """
        scope = self._require_membership_scope(organization_id)
        if not email or not str(email).strip():
            raise MembershipConflictError("email is required to invite a member")
        if not isinstance(role, MembershipRole):
            raise MembershipConflictError("role must be a MembershipRole value")
        if not invited_by or not str(invited_by).strip():
            raise MembershipConflictError("invited_by must be the verified administrator member_id")
        if not expires_at or not str(expires_at).strip():
            raise MembershipConflictError("expires_at is required (ISO-8601 UTC)")

        normalized_email = str(email).strip()
        now_iso = datetime.now(timezone.utc).isoformat()

        duplicate = conn.execute(
            """
            SELECT member_id FROM organization_members
            WHERE organization_id = ? AND email = ? AND status = ?;
            """,
            (scope, normalized_email, MembershipStatus.ACTIVE.value),
        ).fetchone()
        if duplicate is not None:
            raise MembershipConflictError(
                f"Email '{normalized_email}' is already an ACTIVE member of organization '{scope}'"
            )

        resolved_id = invitation_id or uuid.uuid4().hex
        resolved_secret = invitation_secret or secrets.token_urlsafe(32)

        cur = conn.execute(
            """
            INSERT INTO membership_invitations (
                invitation_id, organization_id, email, role, status,
                secret_hash, invited_by, expires_at, accepted_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?);
            """,
            (
                resolved_id,
                scope,
                normalized_email,
                role.value,
                InvitationStatus.PENDING.value,
                sha256_hex(resolved_secret),
                str(invited_by).strip(),
                str(expires_at).strip(),
                now_iso,
            ),
        )
        if cur.rowcount != 1:
            raise AuditLedgerIntegrityError(
                f"Failed to insert membership invitation '{resolved_id}' for '{scope}'"
            )

        self._append_membership_audit_tx(
            conn,
            organization_id=scope,
            event_type=MembershipAuditEventType.MEMBER_INVITED,
            summary=f"Member invitation issued for {normalized_email}",
            actor=str(invited_by).strip(),
            details={
                "target_email": normalized_email,
                "assigned_role": role.value,
                "invitation_id": resolved_id,
                "expires_at": str(expires_at).strip(),
            },
            timestamp=now_iso,
        )
        return resolved_id, resolved_secret

    def invite_member(
        self,
        *,
        organization_id: str,
        email: str,
        role: MembershipRole,
        invited_by: str,
        expires_at: str,
        invitation_id: Optional[str] = None,
        invitation_secret: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Invite a member within a BEGIN IMMEDIATE transaction."""
        scope = self._require_membership_scope(organization_id)
        with self.get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                result = self.invite_member_tx(
                    conn,
                    organization_id=scope,
                    email=email,
                    role=role,
                    invited_by=invited_by,
                    expires_at=expires_at,
                    invitation_id=invitation_id,
                    invitation_secret=invitation_secret,
                )
                conn.commit()
                return result
            except Exception:
                conn.rollback()
                raise

    def accept_invitation_tx(
        self,
        conn: sqlite3.Connection,
        *,
        organization_id: str,
        invitation_id: str,
        invitation_secret: str,
        display_name: str,
        membership_secret: str,
        session_ttl_seconds: int = 3600,
        now: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Claim a PENDING invitation and create (or reactivate) the member atomically.

        The claim is conditional with rowcount == 1, so unknown, expired,
        revoked, cross-org, and already-accepted invitations are all
        indistinguishable failures. The stateless bearer token is minted
        after the caller commits and returned exactly once — acceptance is
        the ONLY session-issuance path.
        """
        scope = self._require_membership_scope(organization_id)
        if not invitation_id or not str(invitation_id).strip():
            raise InvitationNotFoundError("invitation_id is required")
        if not invitation_secret or not str(invitation_secret).strip():
            raise InvitationNotFoundError("invitation secret is required")
        if not display_name or not str(display_name).strip():
            raise MembershipConflictError("display_name is required")
        if not membership_secret or len(str(membership_secret).strip()) < 32:
            raise ValueError("membership_secret is required and must be at least 32 characters")
        if session_ttl_seconds <= 0:
            raise ValueError("session_ttl_seconds must be positive")

        if now is None:
            now_dt = datetime.now(timezone.utc)
            now_iso = now_dt.isoformat()
        else:
            now_iso = now
            try:
                now_dt = datetime.fromisoformat(now_iso)
                if now_dt.tzinfo is None:
                    now_dt = now_dt.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                raise ValueError("now must be an ISO-8601 timestamp")

        normalized_invitation_id = str(invitation_id).strip()
        normalized_display_name = str(display_name).strip()

        invitation_row = conn.execute(
            """
            SELECT invitation_id, email, role FROM membership_invitations
            WHERE invitation_id = ? AND organization_id = ? AND status = ? AND secret_hash = ?;
            """,
            (
                normalized_invitation_id,
                scope,
                InvitationStatus.PENDING.value,
                sha256_hex(str(invitation_secret).strip()),
            ),
        ).fetchone()
        if invitation_row is None:
            raise InvitationNotFoundError(
                f"Invitation '{normalized_invitation_id}' is unknown, expired, revoked, or already used"
            )

        claim = conn.execute(
            """
            UPDATE membership_invitations
            SET status = ?, accepted_at = ?
            WHERE invitation_id = ?
              AND organization_id = ?
              AND status = ?
              AND expires_at > ?;
            """,
            (
                InvitationStatus.ACCEPTED.value,
                now_iso,
                normalized_invitation_id,
                scope,
                InvitationStatus.PENDING.value,
                now_iso,
            ),
        )
        if claim.rowcount != 1:
            raise InvitationNotFoundError(
                f"Invitation '{normalized_invitation_id}' is unknown, expired, revoked, or already used"
            )

        invited_email = invitation_row["email"]
        invited_role = MembershipRole(invitation_row["role"])

        member_cur = conn.execute(
            """
            INSERT INTO organization_members (
                member_id, organization_id, email, display_name, status, token_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 0, ?, ?)
            ON CONFLICT(organization_id, email) DO UPDATE SET
                status = ?,
                display_name = excluded.display_name,
                token_version = organization_members.token_version + 1,
                updated_at = excluded.updated_at;
            """,
            (
                uuid.uuid4().hex,
                scope,
                invited_email,
                normalized_display_name,
                MembershipStatus.ACTIVE.value,
                now_iso,
                now_iso,
                MembershipStatus.ACTIVE.value,
            ),
        )
        if member_cur.rowcount != 1:
            raise AuditLedgerIntegrityError(
                f"Failed to upsert organization_members row for '{invited_email}' in '{scope}'"
            )

        member_row = conn.execute(
            """
            SELECT member_id, token_version FROM organization_members
            WHERE organization_id = ? AND email = ?;
            """,
            (scope, invited_email),
        ).fetchone()
        if member_row is None:
            raise AuditLedgerIntegrityError(
                f"Failed to resolve member row for '{invited_email}' in '{scope}'"
            )
        member_id = member_row["member_id"]
        token_version = int(member_row["token_version"])

        conn.execute(
            """
            INSERT INTO member_roles (organization_id, member_id, role, granted_by, granted_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(member_id, role) DO NOTHING;
            """,
            (scope, member_id, invited_role.value, member_id, now_iso),
        )

        self._append_membership_audit_tx(
            conn,
            organization_id=scope,
            event_type=MembershipAuditEventType.MEMBER_ADDED,
            summary=f"Member added: {invited_email}",
            actor=member_id,
            details={
                "invitation_id": normalized_invitation_id,
                "email": invited_email,
                "initial_roles": [invited_role.value],
            },
            timestamp=now_iso,
        )

        expires_dt = now_dt + timedelta(seconds=session_ttl_seconds)
        bearer_token = self._mint_membership_token(
            membership_secret=str(membership_secret),
            member_id=member_id,
            organization_id=scope,
            token_version=token_version,
            issued_at=now_iso,
            expires_at=expires_dt.isoformat(),
        )
        return {
            "member_id": member_id,
            "organization_id": scope,
            "email": invited_email,
            "roles": [invited_role],
            "bearer_token": bearer_token,
            "expires_at": expires_dt.isoformat(),
        }

    def accept_invitation(
        self,
        *,
        organization_id: str,
        invitation_id: str,
        invitation_secret: str,
        display_name: str,
        membership_secret: str,
        session_ttl_seconds: int = 3600,
        now: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Accept an invitation within a BEGIN IMMEDIATE transaction."""
        scope = self._require_membership_scope(organization_id)
        with self.get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                result = self.accept_invitation_tx(
                    conn,
                    organization_id=scope,
                    invitation_id=invitation_id,
                    invitation_secret=invitation_secret,
                    display_name=display_name,
                    membership_secret=membership_secret,
                    session_ttl_seconds=session_ttl_seconds,
                    now=now,
                )
                conn.commit()
                return result
            except Exception:
                conn.rollback()
                raise

    def revoke_invitation_tx(
        self,
        conn: sqlite3.Connection,
        *,
        organization_id: str,
        invitation_id: str,
        actor_member_id: str,
    ) -> None:
        """Conditionally flip PENDING -> REVOKED inside the caller's transaction.

        rowcount == 1 is required: an unknown, accepted, expired, revoked, or
        cross-org invitation raises MembershipNotFoundError (R5).
        """
        scope = self._require_membership_scope(organization_id)
        if not invitation_id or not str(invitation_id).strip():
            raise MembershipNotFoundError("invitation_id is required")
        if not actor_member_id or not str(actor_member_id).strip():
            raise MembershipConflictError("actor_member_id must be the verified administrator member_id")

        normalized_invitation_id = str(invitation_id).strip()
        actor = str(actor_member_id).strip()
        now_iso = datetime.now(timezone.utc).isoformat()

        invitation_row = conn.execute(
            """
            SELECT email FROM membership_invitations
            WHERE invitation_id = ? AND organization_id = ? AND status = ?;
            """,
            (normalized_invitation_id, scope, InvitationStatus.PENDING.value),
        ).fetchone()
        if invitation_row is None:
            raise MembershipNotFoundError(
                f"Invitation '{normalized_invitation_id}' not found in organization '{scope}'"
            )

        cur = conn.execute(
            """
            UPDATE membership_invitations
            SET status = ?
            WHERE invitation_id = ? AND organization_id = ? AND status = ?;
            """,
            (
                InvitationStatus.REVOKED.value,
                normalized_invitation_id,
                scope,
                InvitationStatus.PENDING.value,
            ),
        )
        if cur.rowcount != 1:
            raise MembershipNotFoundError(
                f"Invitation '{normalized_invitation_id}' not found in organization '{scope}'"
            )

        self._append_membership_audit_tx(
            conn,
            organization_id=scope,
            event_type=MembershipAuditEventType.INVITATION_REVOKED,
            summary=f"Membership invitation revoked for {invitation_row['email']}",
            actor=actor,
            details={
                "invitation_id": normalized_invitation_id,
                "target_email": invitation_row["email"],
            },
            timestamp=now_iso,
        )

    def revoke_invitation(
        self,
        *,
        organization_id: str,
        invitation_id: str,
        actor_member_id: str,
    ) -> None:
        """Revoke an invitation within a BEGIN IMMEDIATE transaction."""
        scope = self._require_membership_scope(organization_id)
        with self.get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                self.revoke_invitation_tx(
                    conn,
                    organization_id=scope,
                    invitation_id=invitation_id,
                    actor_member_id=actor_member_id,
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def set_member_roles_tx(
        self,
        conn: sqlite3.Connection,
        *,
        organization_id: str,
        target_member_id: str,
        new_roles: List[MembershipRole],
        actor_member_id: str,
    ) -> None:
        """Atomically rewrite the member's role rows inside the caller's transaction.

        Guards (R1, R3) are re-checked inside the write transaction:
        self-mutation is forbidden, and dropping the last ACTIVE Tenant
        Administrator is refused. Roles come only from the closed enum
        vocabulary (R4).
        """
        scope = self._require_membership_scope(organization_id)
        if not target_member_id or not str(target_member_id).strip():
            raise MembershipNotFoundError("target_member_id is required")
        if not actor_member_id or not str(actor_member_id).strip():
            raise MembershipConflictError("actor_member_id must be the verified administrator member_id")

        target_id = str(target_member_id).strip()
        actor = str(actor_member_id).strip()
        normalized_roles = self._validate_membership_roles(new_roles)
        now_iso = datetime.now(timezone.utc).isoformat()

        target_row = conn.execute(
            """
            SELECT member_id FROM organization_members
            WHERE member_id = ? AND organization_id = ? AND status = ?;
            """,
            (target_id, scope, MembershipStatus.ACTIVE.value),
        ).fetchone()
        if target_row is None:
            raise MembershipNotFoundError(
                f"Member '{target_id}' not found in organization '{scope}'"
            )

        if actor == target_id:
            raise SelfMutationError(
                "Administrators cannot change their own roles (R1)"
            )

        old_role_rows = conn.execute(
            """
            SELECT role FROM member_roles
            WHERE member_id = ? AND organization_id = ?
            ORDER BY role ASC;
            """,
            (target_id, scope),
        ).fetchall()
        old_roles = [MembershipRole(r["role"]) for r in old_role_rows]

        currently_admin = MembershipRole.TENANT_ADMINISTRATOR in old_roles
        will_be_admin = MembershipRole.TENANT_ADMINISTRATOR in normalized_roles
        if currently_admin and not will_be_admin:
            remaining_admins = self._count_other_active_administrators_tx(
                conn, organization_id=scope, excluding_member_id=target_id
            )
            if remaining_admins == 0:
                raise LastAdministratorError(
                    f"Cannot drop the last ACTIVE Tenant Administrator of '{scope}' (R3)"
                )

        conn.execute(
            "DELETE FROM member_roles WHERE member_id = ? AND organization_id = ?;",
            (target_id, scope),
        )
        for role in normalized_roles:
            cur = conn.execute(
                """
                INSERT INTO member_roles (organization_id, member_id, role, granted_by, granted_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (scope, target_id, role.value, actor, now_iso),
            )
            if cur.rowcount != 1:
                raise AuditLedgerIntegrityError(
                    f"Failed to insert role '{role.value}' for member '{target_id}' in '{scope}'"
                )

        touch = conn.execute(
            """
            UPDATE organization_members SET updated_at = ?
            WHERE member_id = ? AND organization_id = ? AND status = ?;
            """,
            (now_iso, target_id, scope, MembershipStatus.ACTIVE.value),
        )
        if touch.rowcount != 1:
            raise AuditLedgerIntegrityError(
                f"Failed to update organization_members row for '{target_id}' in '{scope}'"
            )

        self._append_membership_audit_tx(
            conn,
            organization_id=scope,
            event_type=MembershipAuditEventType.MEMBER_ROLE_CHANGED,
            summary=f"Member roles changed for {target_id}",
            actor=actor,
            details={
                "target_member_id": target_id,
                "old_roles": [r.value for r in old_roles],
                "new_roles": [r.value for r in normalized_roles],
            },
            timestamp=now_iso,
        )

    def set_member_roles(
        self,
        *,
        organization_id: str,
        target_member_id: str,
        new_roles: List[MembershipRole],
        actor_member_id: str,
    ) -> None:
        """Rewrite a member's role set within a BEGIN IMMEDIATE transaction."""
        scope = self._require_membership_scope(organization_id)
        with self.get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                self.set_member_roles_tx(
                    conn,
                    organization_id=scope,
                    target_member_id=target_member_id,
                    new_roles=new_roles,
                    actor_member_id=actor_member_id,
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def remove_member_tx(
        self,
        conn: sqlite3.Connection,
        *,
        organization_id: str,
        target_member_id: str,
        actor_member_id: str,
    ) -> Dict[str, Any]:
        """Mark a member REMOVED with immediate session revocation inside the caller's transaction.

        Flipping status and bumping token_version in one transaction
        invalidates every outstanding membership token at its next
        validation (per-request fresh read, no cache). member_roles rows
        are deliberately retained but inert: every authorization check
        requires status = ACTIVE first. This method touches NOTHING else —
        never handoff_grants, pending_approval_items, adapter_attempts,
        risk_cases, or case_audit_checkpoints.
        """
        scope = self._require_membership_scope(organization_id)
        if not target_member_id or not str(target_member_id).strip():
            raise MembershipNotFoundError("target_member_id is required")
        if not actor_member_id or not str(actor_member_id).strip():
            raise MembershipConflictError("actor_member_id must be the verified administrator member_id")

        target_id = str(target_member_id).strip()
        actor = str(actor_member_id).strip()
        now_iso = datetime.now(timezone.utc).isoformat()

        target_row = conn.execute(
            """
            SELECT email FROM organization_members
            WHERE member_id = ? AND organization_id = ? AND status = ?;
            """,
            (target_id, scope, MembershipStatus.ACTIVE.value),
        ).fetchone()
        if target_row is None:
            raise MembershipNotFoundError(
                f"Member '{target_id}' not found in organization '{scope}'"
            )

        if actor == target_id:
            raise SelfMutationError("Administrators cannot remove themselves (R2)")

        admin_row = conn.execute(
            """
            SELECT 1 FROM member_roles
            WHERE member_id = ? AND organization_id = ? AND role = ?;
            """,
            (target_id, scope, MembershipRole.TENANT_ADMINISTRATOR.value),
        ).fetchone()
        if admin_row is not None:
            remaining_admins = self._count_other_active_administrators_tx(
                conn, organization_id=scope, excluding_member_id=target_id
            )
            if remaining_admins == 0:
                raise LastAdministratorError(
                    f"Cannot remove the last ACTIVE Tenant Administrator of '{scope}' (R3)"
                )

        cur = conn.execute(
            """
            UPDATE organization_members
            SET status = ?,
                token_version = token_version + 1,
                updated_at = ?
            WHERE member_id = ? AND organization_id = ? AND status = ?;
            """,
            (
                MembershipStatus.REMOVED.value,
                now_iso,
                target_id,
                scope,
                MembershipStatus.ACTIVE.value,
            ),
        )
        if cur.rowcount != 1:
            raise MembershipNotFoundError(
                f"Member '{target_id}' not found in organization '{scope}'"
            )

        new_version_row = conn.execute(
            "SELECT token_version FROM organization_members WHERE member_id = ? AND organization_id = ?;",
            (target_id, scope),
        ).fetchone()
        new_token_version = int(new_version_row["token_version"])

        conn.execute(
            """
            UPDATE membership_invitations
            SET status = ?
            WHERE organization_id = ? AND email = ? AND status = ?;
            """,
            (
                InvitationStatus.REVOKED.value,
                scope,
                target_row["email"],
                InvitationStatus.PENDING.value,
            ),
        )

        self._append_membership_audit_tx(
            conn,
            organization_id=scope,
            event_type=MembershipAuditEventType.MEMBER_REMOVED,
            summary=f"Member removed: {target_row['email']}",
            actor=actor,
            details={
                "target_member_id": target_id,
                "email": target_row["email"],
                "token_version": new_token_version,
            },
            timestamp=now_iso,
        )
        return {
            "target_member_id": target_id,
            "email": target_row["email"],
            "token_version": new_token_version,
        }

    def remove_member(
        self,
        *,
        organization_id: str,
        target_member_id: str,
        actor_member_id: str,
    ) -> Dict[str, Any]:
        """Remove a member within a BEGIN IMMEDIATE transaction."""
        scope = self._require_membership_scope(organization_id)
        with self.get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            try:
                result = self.remove_member_tx(
                    conn,
                    organization_id=scope,
                    target_member_id=target_member_id,
                    actor_member_id=actor_member_id,
                )
                conn.commit()
                return result
            except Exception:
                conn.rollback()
                raise

    def list_members(self, *, organization_id: str) -> List[Dict[str, Any]]:
        """List ACTIVE members with their role sets strictly within one organization.

        There is deliberately NO organization_id=None mode and no UNSCOPED
        sentinel: membership is always organization-scoped.
        """
        scope = self._require_membership_scope(organization_id)
        with self.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT member_id, email, display_name, status, created_at, updated_at
                FROM organization_members
                WHERE organization_id = ? AND status = ?
                ORDER BY created_at ASC, member_id ASC;
                """,
                (scope, MembershipStatus.ACTIVE.value),
            ).fetchall()
            role_rows = conn.execute(
                """
                SELECT member_id, role FROM member_roles
                WHERE organization_id = ?
                ORDER BY role ASC;
                """,
                (scope,),
            ).fetchall()
            roles_by_member: Dict[str, List[str]] = {}
            for r in role_rows:
                roles_by_member.setdefault(r["member_id"], []).append(r["role"])
            return [
                {
                    "member_id": r["member_id"],
                    "email": r["email"],
                    "display_name": r["display_name"],
                    "status": r["status"],
                    "roles": roles_by_member.get(r["member_id"], []),
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
                for r in rows
            ]

    def verify_membership_audit(self, *, organization_id: str) -> Optional[Dict[str, Any]]:
        """Verify the org-keyed membership audit chain and checkpoint MAC (read-only).

        Returns None when the organization has no membership activity at
        all (no checkpoint row), mirroring verify_case_audit's shape with
        organization_id in place of case_id.
        """
        scope = self._require_membership_scope(organization_id)
        with self.get_connection() as conn:
            return self.verify_membership_audit_tx(conn, organization_id=scope)

    def verify_membership_audit_tx(
        self,
        conn: sqlite3.Connection,
        *,
        organization_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Verify the org-keyed membership audit chain within a connection (read-only)."""
        scope = self._require_membership_scope(organization_id)

        cp_row = conn.execute(
            "SELECT * FROM membership_audit_checkpoints WHERE organization_id = ?;",
            (scope,),
        ).fetchone()
        if cp_row is None:
            rows_count = conn.execute(
                "SELECT COUNT(*) FROM membership_audit_events WHERE organization_id = ?;",
                (scope,),
            ).fetchone()[0]
            if rows_count == 0:
                return None
            return {
                "organization_id": scope,
                "is_valid": False,
                "trust_state": "CORRUPTED",
                "event_count": int(rows_count),
                "broken_at_seq": None,
                "reason": "Missing membership audit checkpoint with events present",
            }

        if not isinstance(cp_row["event_count"], int) or isinstance(cp_row["event_count"], bool):
            return {
                "organization_id": scope,
                "is_valid": False,
                "trust_state": "CORRUPTED",
                "event_count": 0,
                "broken_at_seq": None,
                "reason": "Checkpoint event_count is not an integer",
            }

        if not verify_checkpoint_mac(
            secret=self.audit_checkpoint_secret,
            case_id=scope,
            event_count=cp_row["event_count"],
            tip_hash=cp_row["tip_hash"],
            trust_state=cp_row["trust_state"],
            checkpoint_mac=cp_row["checkpoint_mac"],
        ):
            return {
                "organization_id": scope,
                "is_valid": False,
                "trust_state": "CORRUPTED",
                "event_count": cp_row["event_count"],
                "broken_at_seq": None,
                "reason": "Membership audit checkpoint MAC verification failed",
            }

        rows = conn.execute(
            "SELECT * FROM membership_audit_events WHERE organization_id = ? ORDER BY seq ASC;",
            (scope,),
        ).fetchall()
        if len(rows) != cp_row["event_count"]:
            return {
                "organization_id": scope,
                "is_valid": False,
                "trust_state": "CORRUPTED",
                "event_count": len(rows),
                "broken_at_seq": None,
                "reason": (
                    f"Event count mismatch: checkpoint records {cp_row['event_count']} events, "
                    f"found {len(rows)}"
                ),
            }

        expected_tip = rows[-1]["current_hash"] if rows else GENESIS_HASH
        if cp_row["tip_hash"] != expected_tip:
            return {
                "organization_id": scope,
                "is_valid": False,
                "trust_state": "CORRUPTED",
                "event_count": len(rows),
                "broken_at_seq": None,
                "reason": "Audit tip hash mismatch with checkpoint",
            }

        seen_seqs: set[int] = set()
        for idx, r in enumerate(rows):
            if r["seq"] in seen_seqs:
                return {
                    "organization_id": scope,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Duplicate audit sequence at seq {r['seq']}",
                }
            seen_seqs.add(r["seq"])
            expected_seq = idx + 1
            if r["seq"] != expected_seq:
                return {
                    "organization_id": scope,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Sequence gap: expected seq {expected_seq}, found {r['seq']}",
                }
            if r["organization_id"] != scope:
                return {
                    "organization_id": scope,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Cross-organization audit ownership violation: {r['organization_id']}",
                }
            expected_prev = rows[idx - 1]["current_hash"] if idx > 0 else GENESIS_HASH
            if r["prev_hash"] != expected_prev:
                return {
                    "organization_id": scope,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Broken prev_hash chain at seq {r['seq']}",
                }
            try:
                details = json.loads(r["details_json"])
            except Exception:
                return {
                    "organization_id": scope,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Malformed details_json at seq {r['seq']}",
                }
            recomputed = compute_audit_hash(
                prev_hash=r["prev_hash"],
                seq=r["seq"],
                event_type=r["event_type"],
                summary=r["summary"],
                actor=r["actor"],
                timestamp=r["timestamp"],
                details=details,
            )
            if recomputed != r["current_hash"]:
                return {
                    "organization_id": scope,
                    "is_valid": False,
                    "trust_state": "CORRUPTED",
                    "event_count": len(rows),
                    "broken_at_seq": r["seq"],
                    "reason": f"Tampered event payload at seq {r['seq']}: current_hash mismatch",
                }

        return {
            "organization_id": scope,
            "is_valid": True,
            "trust_state": AuditTrustState.TRUSTED.value,
            "event_count": cp_row["event_count"],
            "tip_hash": cp_row["tip_hash"],
            "broken_at_seq": None,
            "reason": None,
        }

    # ==========================================================================
    # Tenant operating limits: quotas, settings, and settings audit (Issue #10)
    #
    # "Tenant" is the issue's vocabulary for the enforcement scope of an
    # organization: every counter, settings row, and audit row keys on
    # organization_id — the session-owned scope used by every existing seam.
    # Every *_tx method must be called inside the caller's BEGIN IMMEDIATE
    # transaction so a quota decision and the mutation it guards commit (or
    # roll back) atomically; the read-only *_tx counters (count_open_cases_tx,
    # count_processing_backlog_tx, load_tenant_limits_tx) also accept a
    # connection but never write, so they can be used pre-transaction for
    # fail-fast checks and inside the transaction for race-free ones.
    # ==========================================================================

    @staticmethod
    def _require_quota_scope(organization_id: Optional[str]) -> str:
        """Return the stripped quota scope or raise UnscopedMembershipError.

        Reuses the membership blank-scope guard deliberately: quota and
        settings rows have exactly the same no-default-organization posture.
        A caller-supplied scope starting with the reserved '__' prefix (the
        '__PLATFORM__' backstop bucket and window sentinels) is rejected —
        only this module's platform constants may address the backstop.
        """
        if organization_id is None or not isinstance(organization_id, str) or not organization_id.strip():
            raise UnscopedMembershipError(
                "Tenant operating-limit operations require an explicit non-blank organization_id; "
                "there is no un-scoped quota mode."
            )
        scope = organization_id.strip()
        if scope.startswith("__") and scope != "__PLATFORM__":
            raise UnscopedMembershipError(
                f"Organization scope '{scope}' uses the reserved '__' prefix; "
                "the platform backstop bucket cannot be addressed by callers."
            )
        return scope

    def consume_quota_tx(
        self,
        conn: sqlite3.Connection,
        organization_id: str,
        quota_kind: str,
        window_key: str,
        max_allowed: int,
        now: Optional[datetime] = None,
    ) -> Tuple[bool, int, int]:
        """Atomically consume one unit from a windowed quota counter inside the caller's transaction.

        Uses a single conditional UPDATE ... WHERE counter < max_allowed so the
        check-and-increment is one statement under BEGIN IMMEDIATE: two racing
        admissions cannot both consume the last slot. Returns
        ``(allowed, new_count, remaining)``; a refused call leaves the counter
        untouched (the failure is durable for Retry-After math but costs nothing).

        ``quota_kind`` must be a non-blank string without the reserved '__'
        prefix; ``window_key`` must be a non-blank string (the fixed UTC window
        derivation or the 'CUMULATIVE' sentinel).
        """
        scope = self._require_quota_scope(organization_id)
        kind = (quota_kind or "").strip()
        if not kind or kind.startswith("__"):
            raise UnscopedMembershipError(
                f"quota_kind '{kind}' must be a non-blank string without the reserved '__' prefix"
            )
        win = (window_key or "").strip()
        if not win:
            raise UnscopedMembershipError("window_key must be a non-blank window or 'CUMULATIVE' sentinel")
        if not isinstance(max_allowed, int) or isinstance(max_allowed, bool) or max_allowed < 1:
            raise UnscopedMembershipError("max_allowed must be a positive integer")

        moment = now if now is not None else datetime.now(timezone.utc)
        now_iso = moment if isinstance(moment, str) else moment.isoformat()

        row = conn.execute(
            "SELECT counter FROM tenant_quota_counters WHERE organization_id = ? AND quota_kind = ? AND window_key = ?",
            (scope, kind, win),
        ).fetchone()
        if row is None:
            conn.execute(
                """
                INSERT INTO tenant_quota_counters (organization_id, quota_kind, window_key, counter, updated_at)
                VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(organization_id, quota_kind, window_key) DO NOTHING;
                """,
                (scope, kind, win, now_iso),
            )
            return (True, 1, max_allowed - 1)

        counter = int(row["counter"])
        if counter < max_allowed:
            cur = conn.execute(
                """
                UPDATE tenant_quota_counters
                SET counter = counter + 1, updated_at = ?
                WHERE organization_id = ? AND quota_kind = ? AND window_key = ? AND counter < ?;
                """,
                (now_iso, scope, kind, win, max_allowed),
            )
            if cur.rowcount == 1:
                new_count = counter + 1
                return (True, new_count, max_allowed - new_count)
            # Lost the race inside the transaction (should not happen under
            # BEGIN IMMEDIATE): re-read and refuse on the durable value.
            raced = conn.execute(
                "SELECT counter FROM tenant_quota_counters WHERE organization_id = ? AND quota_kind = ? AND window_key = ?",
                (scope, kind, win),
            ).fetchone()
            raced_count = int(raced["counter"]) if raced is not None else max_allowed
            return (False, raced_count, max(0, max_allowed - raced_count))
        return (False, counter, max(0, max_allowed - counter))

    def consume_cumulative_bytes_tx(
        self,
        conn: sqlite3.Connection,
        organization_id: str,
        delta_bytes: int,
        max_allowed: int,
        now: Optional[datetime] = None,
    ) -> Tuple[bool, int, int]:
        """Atomically add ``delta_bytes`` to the monotonic cumulative evidence-byte budget.

        The cumulative counter never resets: its window_key is the fixed
        'CUMULATIVE' sentinel, so the only way to raise the budget again is an
        explicit platform operator decision — quota exhaustion is durable by
        design. Returns ``(allowed, new_total, remaining)``; a refused call
        leaves the counter unchanged. A zero/negative delta is a no-op allow
        (nothing is added, existing total reported) because callers pass
        computed evidence sizes, which are always >= 0 for admitted content.
        """
        scope = self._require_quota_scope(organization_id)
        if not isinstance(delta_bytes, int) or isinstance(delta_bytes, bool) or delta_bytes < 0:
            raise UnscopedMembershipError("delta_bytes must be a non-negative integer")
        if not isinstance(max_allowed, int) or isinstance(max_allowed, bool) or max_allowed < 1:
            raise UnscopedMembershipError("max_allowed must be a positive integer")

        moment = now if now is not None else datetime.now(timezone.utc)
        now_iso = moment if isinstance(moment, str) else moment.isoformat()

        row = conn.execute(
            "SELECT counter FROM tenant_quota_counters WHERE organization_id = ? AND quota_kind = 'evidence_bytes' AND window_key = ?",
            (scope, CUMULATIVE_WINDOW_KEY),
        ).fetchone()
        current = int(row["counter"]) if row is not None else 0

        if delta_bytes == 0:
            return (True, current, max(0, max_allowed - current))

        if current + delta_bytes > max_allowed:
            return (False, current, max(0, max_allowed - current))

        if row is None:
            conn.execute(
                """
                INSERT INTO tenant_quota_counters (organization_id, quota_kind, window_key, counter, updated_at)
                VALUES (?, 'evidence_bytes', ?, ?, ?)
                ON CONFLICT(organization_id, quota_kind, window_key) DO NOTHING;
                """,
                (scope, CUMULATIVE_WINDOW_KEY, delta_bytes, now_iso),
            )
            return (True, delta_bytes, max_allowed - delta_bytes)

        cur = conn.execute(
            """
            UPDATE tenant_quota_counters
            SET counter = counter + ?, updated_at = ?
            WHERE organization_id = ? AND quota_kind = 'evidence_bytes' AND window_key = ? AND counter + ? <= ?;
            """,
            (delta_bytes, now_iso, scope, CUMULATIVE_WINDOW_KEY, delta_bytes, max_allowed),
        )
        if cur.rowcount == 1:
            new_total = current + delta_bytes
            return (True, new_total, max_allowed - new_total)
        raced = conn.execute(
            "SELECT counter FROM tenant_quota_counters WHERE organization_id = ? AND quota_kind = 'evidence_bytes' AND window_key = ?",
            (scope, CUMULATIVE_WINDOW_KEY),
        ).fetchone()
        raced_total = int(raced["counter"]) if raced is not None else max_allowed
        return (False, raced_total, max(0, max_allowed - raced_total))

    def load_tenant_limits_tx(
        self,
        conn: sqlite3.Connection,
        organization_id: str,
    ) -> TenantOperatingLimits:
        """Load the effective (defensively clamped) tenant operating limits for an organization.

        A missing row resolves to ``DEFAULT_TENANT_LIMITS``; a corrupt row
        (malformed JSON, wrong types, unknown fields) also resolves to the
        fail-closed defaults — a stored row can never widen a limit, and a
        corrupt row cannot break enforcement.
        """
        scope = self._require_quota_scope(organization_id)
        row = conn.execute(
            "SELECT limits_json FROM tenant_operating_limits WHERE organization_id = ?",
            (scope,),
        ).fetchone()
        if row is None:
            return effective_limits(None)
        try:
            parsed = json.loads(row["limits_json"])
            stored = TenantOperatingLimits.from_json_dict(parsed)
        except (ValueError, TypeError, json.JSONDecodeError):
            return effective_limits(None)
        return effective_limits(stored)

    def save_tenant_limits_tx(
        self,
        conn: sqlite3.Connection,
        organization_id: str,
        limits: TenantOperatingLimits,
        actor: str,
        reason_code: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> TenantOperatingLimits:
        """Persist a validated tenant-limits row and append the settings audit event atomically.

        ``limits`` must already be validated (``validate_settings_write``);
        the stored row is written verbatim from it — never clamped, so the
        tenant sees exactly what was accepted. The audit event ('ACCEPTED' or,
        with ``reason_code``, 'REJECTED') rides the same transaction as the
        upsert, so a committed settings change always has its audit row and
        vice versa. Returns the effective (clamped) limits the org will run
        under, computed the same way the read path computes them.
        """
        scope = self._require_quota_scope(organization_id)
        if not isinstance(limits, TenantOperatingLimits):
            raise UnscopedMembershipError("limits must be a TenantOperatingLimits instance")
        actor_norm = (actor or "").strip()
        if not actor_norm:
            raise UnscopedMembershipError("actor is required for tenant settings writes")

        moment = now if now is not None else datetime.now(timezone.utc)
        now_iso = moment if isinstance(moment, str) else moment.isoformat()

        action = "REJECTED" if reason_code else "ACCEPTED"
        limits_payload = limits.to_json_dict()

        conn.execute(
            """
            INSERT INTO tenant_operating_limits (organization_id, limits_json, updated_at, updated_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(organization_id) DO UPDATE SET
                limits_json = excluded.limits_json,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by;
            """,
            (scope, json.dumps(limits_payload), now_iso, actor_norm),
        )
        conn.execute(
            """
            INSERT INTO tenant_settings_audit_events (
                organization_id, actor, action, changes_json, reason_code, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?);
            """,
            (
                scope,
                actor_norm,
                action,
                json.dumps(limits_payload),
                reason_code,
                now_iso,
            ),
        )
        return effective_limits(limits)

    def record_settings_rejection_tx(
        self,
        conn: sqlite3.Connection,
        organization_id: str,
        actor: str,
        attempted_limits_json: Dict[str, Any],
        reason_code: str,
        now: Optional[datetime] = None,
    ) -> None:
        """Audit a refused settings write (malformed or above-ceiling) without persisting any of it.

        The rejected body is recorded so the audit trail shows what was
        attempted, but nothing is written to tenant_operating_limits: a refused
        write never partially applies. The attempted mapping is stored as
        provided (it already failed validation — it is evidence of the attempt,
        not a source of truth).
        """
        scope = self._require_quota_scope(organization_id)
        actor_norm = (actor or "").strip()
        if not actor_norm:
            raise UnscopedMembershipError("actor is required for tenant settings audit")
        reason_norm = (reason_code or "").strip()
        if not reason_norm:
            raise UnscopedMembershipError("reason_code is required for a rejected settings write")

        moment = now if now is not None else datetime.now(timezone.utc)
        now_iso = moment if isinstance(moment, str) else moment.isoformat()

        conn.execute(
            """
            INSERT INTO tenant_settings_audit_events (
                organization_id, actor, action, changes_json, reason_code, recorded_at
            ) VALUES (?, ?, 'REJECTED', ?, ?, ?);
            """,
            (
                scope,
                actor_norm,
                json.dumps(attempted_limits_json),
                reason_norm,
                now_iso,
            ),
        )

    def list_tenant_settings_audit_tx(
        self,
        conn: sqlite3.Connection,
        organization_id: str,
    ) -> List[Dict[str, Any]]:
        """List the org-scoped settings audit events (newest last) for tests and diagnostics."""
        scope = self._require_quota_scope(organization_id)
        rows = conn.execute(
            "SELECT * FROM tenant_settings_audit_events WHERE organization_id = ? ORDER BY id ASC",
            (scope,),
        ).fetchall()
        return [dict(r) for r in rows]

    def count_open_cases_tx(self, conn: sqlite3.Connection, organization_id: str) -> int:
        """Count the organization's open Risk Cases (every phase except terminal/rejected).

        'Open' means the case still occupies tenant capacity: it is not
        COMPLETE (terminal success), not RECONCILIATION_REQUIRED (terminal
        failure), and not ADMISSION_REJECTED (never opened — it consumed no
        admission slot and no evidence budget).
        """
        scope = self._require_quota_scope(organization_id)
        row = conn.execute(
            """
            SELECT COUNT(*) FROM risk_cases
            WHERE organization_id = ?
              AND phase NOT IN (?, ?, ?);
            """,
            (
                scope,
                CasePhase.COMPLETE.value,
                CasePhase.RECONCILIATION_REQUIRED.value,
                CasePhase.ADMISSION_REJECTED.value,
            ),
        ).fetchone()
        return int(row[0])

    def count_processing_backlog_tx(self, conn: sqlite3.Connection, organization_id: str) -> int:
        """Gauge admitted-but-unprocessed cases: the processing-concurrency backlog.

        The gauge is derived from the durable phase, not a mutable counter:
        a case is 'in backlog' from admission (INVESTIGATION) through
        investigation completion (OPERATOR_INTERVENTION, READY_FOR_HUMAN_HANDOFF).
        Terminal phases and pre-admission phases are excluded: an unadmitted
        case has consumed no processing capacity, and a completed or reconciled
        case has released it.
        """
        scope = self._require_quota_scope(organization_id)
        row = conn.execute(
            """
            SELECT COUNT(*) FROM risk_cases
            WHERE organization_id = ?
              AND phase IN (?, ?, ?);
            """,
            (
                scope,
                CasePhase.INVESTIGATION.value,
                CasePhase.OPERATOR_INTERVENTION.value,
                CasePhase.READY_FOR_HUMAN_HANDOFF.value,
            ),
        ).fetchone()
        return int(row[0])

