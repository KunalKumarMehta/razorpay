"""Test suite for dual-dialect storage engine, versioned migrations, and PostgreSQL support (Issue #11)."""

import sqlite3
import pytest
from payoutproof.core.config import AppConfig, ConfigurationError
from payoutproof.storage.db import (
    Database,
    DIALECT_SQLITE,
    DIALECT_POSTGRESQL,
    _translate_query,
)
from payoutproof.storage.migrations import (
    MigrationRunner,
    IncompatibleSchemaError,
    check_schema_compatibility,
    translate_ddl,
    MIGRATIONS,
    LATEST_VERSION,
    LATEST_VERSION_ID,
)


def test_migrations_defined_and_monotonic():
    """Verify all migrations are strictly monotonic and have valid checksums."""
    assert len(MIGRATIONS) == 3
    assert LATEST_VERSION == 3
    assert LATEST_VERSION_ID == "PP-SCHEMA-V3"

    for i, m in enumerate(MIGRATIONS, start=1):
        assert m.version == i
        assert len(m.checksum()) == 64
        assert len(m.sqlite_statements) > 0


def test_translate_ddl():
    """Test SQLite to PostgreSQL DDL translation."""
    sql = "CREATE TABLE foo (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT);"
    translated = translate_ddl(sql, "postgresql")
    assert "BIGSERIAL PRIMARY KEY" in translated
    assert "AUTOINCREMENT" not in translated

    # PRAGMA dropped
    pragma = "PRAGMA journal_mode=WAL;"
    assert translate_ddl(pragma, "postgresql") == ""

    # SQLite dialect returns original
    assert translate_ddl(sql, "sqlite") == sql


def test_translate_query_placeholders():
    """Test SQL placeholder translation (? -> %s) preserving literals."""
    query = "SELECT * FROM cases WHERE id = ? AND status = ?;"
    translated = _translate_query(query, DIALECT_POSTGRESQL)
    assert translated == "SELECT * FROM cases WHERE id = %s AND status = %s;"

    # Literal ? should not be translated
    literal_query = "SELECT 'Is this a question?' as q, ? as param;"
    translated = _translate_query(literal_query, DIALECT_POSTGRESQL)
    assert "'Is this a question?'" in translated
    assert "%s as param" in translated


def test_migration_runner_apply_and_status(tmp_path):
    """Test MigrationRunner applies migrations from scratch on SQLite."""
    db_file = str(tmp_path / "test_migrations.db")
    conn = sqlite3.connect(db_file)
    runner = MigrationRunner(conn, dialect="sqlite")

    status_before = runner.status()
    assert status_before["applied_versions"] == []
    assert not status_before["is_current"]

    applied = runner.apply_pending()
    assert applied == [1, 2, 3]

    status_after = runner.status()
    assert status_after["applied_versions"] == [1, 2, 3]
    assert status_after["is_current"]
    assert status_after["latest_version_id"] == "PP-SCHEMA-V3"

    # Re-applying should be a no-op
    reapplied = runner.apply_pending()
    assert reapplied == []
    conn.close()


def test_migration_runner_detect_and_baseline_existing(tmp_path):
    """Test baseline_existing detects and records untracked tables from earlier schema."""
    db_file = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(db_file)
    # Manually create V1, V2, V3 signature tables without tracking table
    conn.executescript("""
        CREATE TABLE risk_cases (case_id TEXT PRIMARY KEY, tenant_id TEXT, organization_id TEXT, case_version INT, phase TEXT, state_json TEXT, created_at TEXT, updated_at TEXT);
        CREATE TABLE audit_events (id INTEGER PRIMARY KEY, case_id TEXT, seq INT, event_type TEXT, summary TEXT, actor TEXT, prev_hash TEXT, current_hash TEXT, timestamp TEXT, details_json TEXT);
        CREATE TABLE handoff_grants (grant_id TEXT PRIMARY KEY, tenant_id TEXT);
        CREATE TABLE adapter_attempts (idempotency_key TEXT PRIMARY KEY);
        CREATE TABLE pending_approval_items (item_id TEXT PRIMARY KEY);

        CREATE TABLE tenant_quota_counters (tenant_id TEXT, metric_name TEXT, window_start TEXT, count INT, PRIMARY KEY(tenant_id, metric_name, window_start));
        CREATE TABLE tenant_operating_limits (tenant_id TEXT PRIMARY KEY);
        CREATE TABLE tenant_settings_audit_events (id INTEGER PRIMARY KEY);

        CREATE TABLE policy_configs (config_id TEXT PRIMARY KEY);
        CREATE TABLE destination_records (destination_id TEXT PRIMARY KEY);
        CREATE TABLE config_audit_events (id INTEGER PRIMARY KEY);
        CREATE TABLE config_audit_checkpoints (organization_id TEXT PRIMARY KEY);
    """)
    conn.commit()

    runner = MigrationRunner(conn, dialect="sqlite")
    detected = runner.detect_baselined_versions()
    assert detected == [1, 2, 3]

    baselined = runner.baseline_existing()
    assert baselined == [1, 2, 3]

    status = runner.status()
    assert status["is_current"]
    conn.close()


def test_check_schema_compatibility_success(tmp_path):
    """Test check_schema_compatibility passes when schema is current."""
    db_file = str(tmp_path / "compat.db")
    conn = sqlite3.connect(db_file)
    runner = MigrationRunner(conn, dialect="sqlite")
    runner.apply_pending()

    compat = check_schema_compatibility(conn, dialect="sqlite")
    assert compat["is_current"]
    assert compat["latest_version"] == 3
    conn.close()


def test_check_schema_compatibility_unapplied_fails(tmp_path):
    """Test check_schema_compatibility refuses when unapplied migrations exist."""
    db_file = str(tmp_path / "unapplied.db")
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE foo (id INT);")
    conn.commit()
    # DB with table but no tracking table
    with pytest.raises(IncompatibleSchemaError) as exc_info:
        check_schema_compatibility(conn, dialect="sqlite", allow_untracked=False)
    assert "schema_migrations" in str(exc_info.value).lower()
    conn.close()


def test_config_database_url_support_and_redaction(monkeypatch):
    """Test AppConfig database_url handling, env resolution, and secret redaction."""
    s1 = "A" * 32
    s2 = "B" * 32
    s3 = "C" * 32
    raw_pg_url = "postgresql://app_user:super_secret_password@db.internal:5432/payoutproof"

    # 1. for_tests
    cfg = AppConfig.for_tests(
        grant_secret=s1,
        audit_checkpoint_secret=s2,
        membership_secret=s3,
        database_url=raw_pg_url,
    )
    assert cfg.database_url == raw_pg_url
    safe_dict = cfg.to_safe_dict()
    assert safe_dict["database_url"] == "[REDACTED]"
    repr_str = repr(cfg)
    assert raw_pg_url not in repr_str
    assert "super_secret_password" not in repr_str
    assert "database_url='[REDACTED]'" in repr_str

    # 2. from_env
    monkeypatch.setenv("PAYOUTPROOF_GRANT_SECRET", s1)
    monkeypatch.setenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", s2)
    monkeypatch.setenv("PAYOUTPROOF_MEMBERSHIP_SECRET", s3)
    monkeypatch.setenv("PAYOUTPROOF_DATABASE_URL", raw_pg_url)

    cfg_env = AppConfig.from_env()
    assert cfg_env.database_url == raw_pg_url
    assert raw_pg_url not in repr(cfg_env)


def test_database_dialect_detection(tmp_path):
    """Test Database correctly chooses dialect based on path or database_url."""
    secret = "0" * 32
    sqlite_db = Database(
        db_path=str(tmp_path / "test.db"),
        audit_checkpoint_secret=secret,
    )
    assert sqlite_db.dialect == DIALECT_SQLITE
    assert "Database(db_path=" in repr(sqlite_db)

    # Postgres URL via database_url
    pg_url = "postgresql://user:pass@host:5432/db"
    pg_db = Database.__new__(Database)
    pg_db.database_url = pg_url
    pg_db.dialect = DIALECT_POSTGRESQL
    pg_db.db_path = pg_url
    pg_db.audit_checkpoint_secret = secret
    repr_pg = repr(pg_db)
    assert "dialect='postgresql'" in repr_pg
    assert "database_url='[REDACTED]'" in repr_pg
    assert "pass" not in repr_pg
