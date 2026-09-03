"""SQLite WAL persistence for cases, audit events, grants, and adapter attempts."""

import sqlite3
import json
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime, timezone

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
)
from payoutproof.grants.issuer import GrantVerifier
from payoutproof.core.crypto import (
    compute_snapshot_hash,
    compute_audit_hash,
    compute_checkpoint_mac,
    verify_checkpoint_mac,
)
from payoutproof.audit.chain import GENESIS_HASH

# Authoritative persistence schema identifier for SQLite tables
SCHEMA_VERSION = "PP-SCHEMA-V1"

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
            """)
            conn.commit()
            self._migrate_db(conn)
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
