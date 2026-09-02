"""SQLite WAL persistence for cases, audit events, grants, and adapter attempts."""

import sqlite3
import json
from typing import Optional, List, Dict, Any
from pathlib import Path

from payoutproof.core.models import RiskCaseState, AuditEvent, HandoffGrant


class Database:
    """SQLite WAL storage engine for PayoutProof."""

    def __init__(self, db_path: str | Path = "payoutproof.db"):
        self.db_path = str(db_path)
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Get connection with WAL mode enabled and Row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize database tables."""
        with self.get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS risk_cases (
                    case_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    case_version INTEGER NOT NULL,
                    phase TEXT NOT NULL,
                    state_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
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

                CREATE TABLE IF NOT EXISTS adapter_attempts (
                    idempotency_key TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL,
                    last_decision TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

    def save_case(self, state: RiskCaseState):
        """Save or update a Risk Case."""
        if not state.case_id:
            raise ValueError("Cannot persist case without case_id")

        state_dict = state.model_dump()
        state_json = json.dumps(state_dict)

        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO risk_cases (case_id, tenant_id, case_version, phase, state_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                ON CONFLICT(case_id) DO UPDATE SET
                    case_version = excluded.case_version,
                    phase = excluded.phase,
                    state_json = excluded.state_json,
                    updated_at = datetime('now');
            """, (state.case_id, state.tenant_id, state.case_version, state.phase.value, state_json))

            # Also persist any new audit events
            for ev in state.audit:
                ev_details = json.dumps(ev.details)
                conn.execute("""
                    INSERT OR IGNORE INTO audit_events (case_id, seq, event_type, summary, actor, prev_hash, current_hash, timestamp, details_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (state.case_id, ev.seq, ev.event_type, ev.summary, ev.actor, ev.prev_hash, ev.current_hash, ev.timestamp, ev_details))

            # If grant exists, persist grant
            if state.grant:
                g = state.grant
                conn.execute("""
                    INSERT INTO handoff_grants (grant_id, tenant_id, case_id, bound_intent_hash, bound_snapshot_hash, policy_version, outcome, nonce, issued_at, expires_at, signature, status, used)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(grant_id) DO UPDATE SET
                        status = excluded.status,
                        used = excluded.used;
                """, (g.grant_id, g.tenant_id, g.case_id, g.bound_intent_hash, g.bound_snapshot_hash, g.policy_version, g.outcome.value, g.nonce, g.issued_at, g.expires_at, g.signature, g.status.value, 1 if g.used else 0))

    def load_case(self, case_id: str) -> Optional[RiskCaseState]:
        """Load a Risk Case by ID."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT state_json FROM risk_cases WHERE case_id = ?", (case_id,)).fetchone()
            if not row:
                return None
            data = json.loads(row["state_json"])
            return RiskCaseState.model_validate(data)

    def list_cases(self) -> List[Dict[str, Any]]:
        """List all cases with summary metadata."""
        with self.get_connection() as conn:
            rows = conn.execute("SELECT case_id, tenant_id, case_version, phase, updated_at FROM risk_cases ORDER BY updated_at DESC").fetchall()
            return [dict(row) for row in rows]
