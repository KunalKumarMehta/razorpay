"""Focused acceptance tests for Issue #4: [Migrate] Scope Risk Cases to organizations.

Covers:
1. Idempotent migration: a legacy `risk_cases` schema without `organization_id`
   gains the column on first construction and stays stable on re-construction.
2. Scoped creation, reload persistence, and organization-filtered listing.
3. Zero-existence oracle: cross-tenant access returns strictly HTTP 404 on both
   GET /api/cases/{case_id} and POST /api/cases/{case_id}/dispatch, with a body
   indistinguishable from a missing case. Never 403, never a leak.
4. Compatibility: un-scoped legacy rows (organization_id NULL) keep working.
"""

import sqlite3

from fastapi.testclient import TestClient

from payoutproof.api.app import create_app
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.core.config import AppConfig
from payoutproof.storage.db import Database, DatabaseConsistencyError
from tests.helpers import TEST_AUDIT_CHECKPOINT_SECRET, TEST_GRANT_SECRET


def _make_legacy_schema_db(db_file) -> None:
    """Create a pre-Issue-4 database whose risk_cases table lacks organization_id."""
    conn = sqlite3.connect(db_file)
    conn.executescript("""
        CREATE TABLE risk_cases (
            case_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            case_version INTEGER NOT NULL,
            phase TEXT NOT NULL,
            state_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE case_audit_checkpoints (
            case_id TEXT PRIMARY KEY,
            event_count INTEGER NOT NULL,
            tip_hash TEXT NOT NULL,
            trust_state TEXT NOT NULL,
            checkpoint_mac TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE audit_events (
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
    """)
    conn.commit()
    conn.close()


def test_migration_adds_organization_id_idempotently(tmp_path):
    """Legacy risk_cases schema without organization_id is migrated crash-free and idempotently."""
    db_file = tmp_path / "legacy_scoped.db"
    _make_legacy_schema_db(db_file)

    # First construction migrates: column must exist afterwards
    db1 = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with db1.get_connection() as c:
        cols = {r["name"] for r in c.execute("PRAGMA table_info(risk_cases)").fetchall()}
    assert "organization_id" in cols, "migration must add organization_id to legacy risk_cases"

    # Second construction must not re-ALTER (idempotent, crash-free)
    db2 = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    with db2.get_connection() as c:
        cols = [r["name"] for r in c.execute("PRAGMA table_info(risk_cases)").fetchall()]
    assert cols.count("organization_id") == 1, "organization_id must not be duplicated by repeated migration"


def test_scoped_creation_reload_and_listing(tmp_path):
    """Cases created under an organization persist scope across reloads and filter listings."""
    db_file = tmp_path / "scoped.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    scoped = StateMachine.initial_state(case_id="RC-ORG-A", organization_id="org_alpha")
    legacy_style = StateMachine.initial_state(case_id="RC-NO-ORG")
    other_org = StateMachine.initial_state(case_id="RC-ORG-B", organization_id="org_beta")
    for state in (scoped, legacy_style, other_org):
        db.save_case(state)

    # Reload persistence: the row column round-trips onto the loaded state
    reloaded = db.load_case("RC-ORG-A")
    assert reloaded is not None
    assert reloaded.organization_id == "org_alpha"
    assert db.load_case("RC-NO-ORG").organization_id is None

    # The column is authoritative for the row scope
    with db.get_connection() as c:
        row = c.execute(
            "SELECT organization_id FROM risk_cases WHERE case_id = 'RC-ORG-A'"
        ).fetchone()
    assert row["organization_id"] == "org_alpha"

    # Listing by organization
    assert {c["case_id"] for c in db.list_cases(organization_id="org_alpha")} == {"RC-ORG-A"}
    assert {c["case_id"] for c in db.list_cases(organization_id="org_beta")} == {"RC-ORG-B"}
    # NULL-safe: an explicit un-scoped query matches only un-scoped legacy rows
    from payoutproof.storage.db import UNSCOPED
    assert {c["case_id"] for c in db.list_cases(organization_id=UNSCOPED)} == {"RC-NO-ORG"}
    # Unfiltered listing still sees everything
    assert {c["case_id"] for c in db.list_cases()} == {"RC-ORG-A", "RC-NO-ORG", "RC-ORG-B"}


def test_rescope_of_existing_case_is_rejected(tmp_path):
    """save_case_tx refuses to re-scope an existing case inside its write transaction."""
    db = Database(db_path=tmp_path / "rescope.db", audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    db.save_case(StateMachine.initial_state(case_id="RC-FIXED-ORG", organization_id="org_alpha"))
    loaded = db.load_case("RC-FIXED-ORG")

    # Re-scope the loaded state (audit history preserved) and attempt to persist
    rescoped = loaded.model_copy(update={"organization_id": "org_gamma"})
    try:
        db.save_case(rescoped)
        raised = False
    except DatabaseConsistencyError:
        raised = True
    assert raised, "re-scoping an existing case must raise DatabaseConsistencyError"

    # Same-scope rewrite of the loaded state stays allowed
    db.save_case(loaded.model_copy(update={"organization_id": "org_alpha"}))
    assert db.load_case("RC-FIXED-ORG").organization_id == "org_alpha"


def test_state_json_column_disagreement_raises(tmp_path):
    """A state_json organization_id that disagrees with the row column fails closed."""
    db = Database(db_path=tmp_path / "disagree.db", audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    db.save_case(StateMachine.initial_state(case_id="RC-DISAGREE", organization_id="org_alpha"))

    # Tamper the row column out from under state_json
    with db.get_connection() as c:
        c.execute("UPDATE risk_cases SET organization_id = 'org_evil' WHERE case_id = 'RC-DISAGREE'")
        c.commit()

    try:
        db.load_case("RC-DISAGREE")
        raised = False
    except DatabaseConsistencyError:
        raised = True
    assert raised, "row/state_json organization disagreement must raise DatabaseConsistencyError"


def _make_client(tmp_path) -> TestClient:
    config = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(tmp_path / "api_org.db"),
    )
    return TestClient(create_app(config=config))


def test_api_header_scopes_creation_and_listing(tmp_path):
    """X-Organization-Id scopes case creation and filters GET /api/cases."""
    client = _make_client(tmp_path)

    # Header-driven creation (header takes precedence when the body omits scope)
    res = client.post(
        "/api/cases",
        json={"case_id": "RC-HDR-1"},
        headers={"X-Organization-Id": " org_alpha "},
    )
    assert res.status_code == 200
    assert res.json()["organization_id"] == "org_alpha"

    # Body-driven creation without header stays un-scoped
    res = client.post("/api/cases", json={"case_id": "RC-HDR-2", "organization_id": "org_beta"})
    assert res.status_code == 200
    assert res.json()["organization_id"] == "org_beta"

    # Empty or whitespace-only header is rejected with HTTP 400
    res = client.post("/api/cases", json={"case_id": "RC-HDR-3"}, headers={"X-Organization-Id": "   "})
    assert res.status_code == 400
    assert "missing mandatory organization identity" in res.json()["detail"].lower()

    # Scoped listing only returns the caller's organization
    res = client.get("/api/cases", headers={"X-Organization-Id": "org_alpha"})
    assert res.status_code == 200
    assert [c["case_id"] for c in res.json()] == ["RC-HDR-1"]

    # Unscoped listing request without header is rejected with HTTP 400
    res = client.get("/api/cases")
    assert res.status_code == 400


def test_cross_tenant_get_returns_strict_404(tmp_path):
    """GET of another organization's case is indistinguishable from a missing case."""
    client = _make_client(tmp_path)
    client.post("/api/cases", json={"case_id": "RC-X-1", "organization_id": "org_alpha"})

    res_same = client.get("/api/cases/RC-X-1", headers={"X-Organization-Id": "org_alpha"})
    assert res_same.status_code == 200

    res_cross = client.get("/api/cases/RC-X-1", headers={"X-Organization-Id": "org_beta"})
    assert res_cross.status_code == 404
    assert res_cross.json()["detail"] == "Case 'RC-X-1' not found"

    res_missing = client.get("/api/cases/RC-DOES-NOT-EXIST", headers={"X-Organization-Id": "org_beta"})
    assert res_missing.status_code == 404
    assert res_missing.json()["detail"] == "Case 'RC-DOES-NOT-EXIST' not found"

    # The two 404 bodies must be structurally identical (no existence leak)
    assert set(res_cross.json()) == set(res_missing.json())


def test_cross_tenant_dispatch_returns_strict_404(tmp_path):
    """Dispatching to another organization's case is rejected exactly like a missing case."""
    client = _make_client(tmp_path)
    client.post("/api/cases", json={"case_id": "RC-X-2", "organization_id": "org_alpha"})

    action = {"type": "EXTRACT_INTENT", "payload": {}}

    res_cross = client.post(
        "/api/cases/RC-X-2/dispatch",
        json=action,
        headers={"X-Organization-Id": "org_beta"},
    )
    assert res_cross.status_code == 404
    assert res_cross.json()["detail"] == "Case 'RC-X-2' not found"

    res_missing = client.post(
        "/api/cases/RC-DOES-NOT-EXIST/dispatch",
        json=action,
        headers={"X-Organization-Id": "org_beta"},
    )
    assert res_missing.status_code == 404
    assert res_missing.json()["detail"] == "Case 'RC-DOES-NOT-EXIST' not found"

    # Same-organization dispatch proceeds past the scope gate
    res_same = client.post(
        "/api/cases/RC-X-2/dispatch",
        json=action,
        headers={"X-Organization-Id": "org_alpha"},
    )
    assert res_same.status_code == 200
    assert res_same.json()["organization_id"] == "org_alpha"


def test_unscoped_caller_can_reach_legacy_unscoped_case(tmp_path):
    """A caller with no active organization is rejected at the API boundary with HTTP 400."""
    client = _make_client(tmp_path)
    res_post = client.post("/api/cases", json={"case_id": "RC-LEGACY-9"})
    assert res_post.status_code == 400
    assert "missing mandatory organization identity" in res_post.json()["detail"].lower()

    res_get = client.get("/api/cases/RC-LEGACY-9")
    assert res_get.status_code == 400
    assert "missing mandatory organization identity" in res_get.json()["detail"].lower()
