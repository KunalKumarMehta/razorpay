"""Tests for P0-3B: Strict secret and configuration composition."""

import os
import io
import sys
import dataclasses
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from payoutproof.core.config import AppConfig, ConfigurationError
from payoutproof.core.models import RiskCaseState, PolicyEvaluationResult
from payoutproof.core.enums import PolicyOutcome, GrantStatus
from payoutproof.grants.issuer import GrantIssuer, GrantVerifier
from payoutproof.api.app import create_app
from tests.helpers import (
    make_admitted_case_state,
    make_confirmed_intent,
    TEST_GRANT_SECRET,
    TEST_AUDIT_CHECKPOINT_SECRET,
)


SECRET_A = "a" * 32
SECRET_B = "b" * 32
WEAK_SECRET = "too-short-secret"


def test_missing_secrets_in_production_fails_closed(monkeypatch):
    """Missing required secrets in non-development fails closed with safe ConfigurationError."""
    # 1. Missing both
    monkeypatch.delenv("PAYOUTPROOF_GRANT_SECRET", raising=False)
    monkeypatch.delenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", raising=False)
    monkeypatch.setenv("PAYOUTPROOF_ENV", "production")

    with pytest.raises(ConfigurationError) as exc:
        AppConfig.from_env()
    assert "PAYOUTPROOF_GRANT_SECRET" in str(exc.value)
    assert SECRET_A not in str(exc.value)

    # 2. Missing audit checkpoint secret
    monkeypatch.setenv("PAYOUTPROOF_GRANT_SECRET", SECRET_A)
    with pytest.raises(ConfigurationError) as exc2:
        AppConfig.from_env()
    assert "PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET" in str(exc2.value)
    assert SECRET_A not in str(exc2.value)


def test_weak_secrets_fail_closed(monkeypatch):
    """Secrets shorter than 32 characters fail closed with safe actionable error message."""
    monkeypatch.setenv("PAYOUTPROOF_ENV", "production")
    monkeypatch.setenv("PAYOUTPROOF_GRANT_SECRET", WEAK_SECRET)
    monkeypatch.setenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", SECRET_B)

    with pytest.raises(ConfigurationError) as exc:
        AppConfig.from_env()
    err_str = str(exc.value)
    assert "grant_secret" in err_str
    assert "at least 32 characters" in err_str
    assert WEAK_SECRET not in err_str

    monkeypatch.setenv("PAYOUTPROOF_GRANT_SECRET", SECRET_A)
    monkeypatch.setenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", WEAK_SECRET)
    with pytest.raises(ConfigurationError) as exc2:
        AppConfig.from_env()
    err_str2 = str(exc2.value)
    assert "audit_checkpoint_secret" in err_str2
    assert "at least 32 characters" in err_str2
    assert WEAK_SECRET not in err_str2


def test_equal_secrets_fail_closed(monkeypatch):
    """Grant secret and audit checkpoint secret must be distinct; equality fails closed."""
    monkeypatch.setenv("PAYOUTPROOF_ENV", "production")
    monkeypatch.setenv("PAYOUTPROOF_GRANT_SECRET", SECRET_A)
    monkeypatch.setenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", SECRET_A)

    with pytest.raises(ConfigurationError) as exc:
        AppConfig.from_env()
    err_str = str(exc.value)
    assert "must be distinct" in err_str
    assert SECRET_A not in err_str


def test_valid_env_composition(monkeypatch):
    """Supplying distinct valid secrets >= 32 chars successfully constructs AppConfig."""
    monkeypatch.setenv("PAYOUTPROOF_ENV", "staging")
    monkeypatch.setenv("PAYOUTPROOF_GRANT_SECRET", SECRET_A)
    monkeypatch.setenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", SECRET_B)
    monkeypatch.setenv("PAYOUTPROOF_DB_PATH", "/tmp/staging.db")
    monkeypatch.setenv("PAYOUTPROOF_ENABLE_DEMO_ADAPTER_MODES", "1")

    config = AppConfig.from_env()
    assert config.environment == "staging"
    assert config.grant_secret == SECRET_A
    assert config.audit_checkpoint_secret == SECRET_B
    assert config.db_path == "/tmp/staging.db"
    assert config.enable_demo_adapter_modes is True


def test_development_mode_generates_ephemeral_secrets_and_warns_stderr_once(monkeypatch, capsys):
    """PAYOUTPROOF_ENV=development generates missing secrets, emits warning to stderr once, never printing secret values."""
    monkeypatch.setenv("PAYOUTPROOF_ENV", "development")
    monkeypatch.delenv("PAYOUTPROOF_GRANT_SECRET", raising=False)
    monkeypatch.delenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", raising=False)

    # Reset warning flag for this test
    import payoutproof.core.config as config_mod
    config_mod._DEV_SECRETS_WARNED = False

    config1 = AppConfig.from_env()
    assert len(config1.grant_secret) >= 32
    assert len(config1.audit_checkpoint_secret) >= 32
    assert config1.grant_secret != config1.audit_checkpoint_secret

    captured1 = capsys.readouterr()
    assert "WARNING: PAYOUTPROOF_ENV=development generated process-ephemeral secrets" in captured1.err
    assert "restarting the process will invalidate" in captured1.err
    # Never print actual secret values
    assert config1.grant_secret not in captured1.err
    assert config1.audit_checkpoint_secret not in captured1.err
    assert config1.grant_secret not in captured1.out
    assert config1.audit_checkpoint_secret not in captured1.out

    # Calling again in the same process does not duplicate the warning
    config2 = AppConfig.from_env()
    captured2 = capsys.readouterr()
    assert "WARNING: PAYOUTPROOF_ENV=development generated process-ephemeral secrets" not in captured2.err


def test_development_mode_rejects_weak_or_equal_supplied_secrets(monkeypatch):
    """Even in development mode, explicitly supplied secrets must be >=32 chars and distinct."""
    monkeypatch.setenv("PAYOUTPROOF_ENV", "development")
    monkeypatch.setenv("PAYOUTPROOF_GRANT_SECRET", WEAK_SECRET)

    with pytest.raises(ConfigurationError, match="at least 32 characters"):
        AppConfig.from_env()

    monkeypatch.setenv("PAYOUTPROOF_GRANT_SECRET", SECRET_A)
    monkeypatch.setenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", SECRET_A)
    with pytest.raises(ConfigurationError, match="must be distinct"):
        AppConfig.from_env()


def test_app_config_for_tests_requires_explicit_secrets_and_validates():
    """AppConfig.for_tests requires explicit caller secrets and refuses empty/weak/equal."""
    # Valid
    cfg = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )
    assert cfg.grant_secret == TEST_GRANT_SECRET
    assert cfg.audit_checkpoint_secret == TEST_AUDIT_CHECKPOINT_SECRET
    assert cfg.environment == "test"

    # Refuse empty
    with pytest.raises(ConfigurationError):
        AppConfig.for_tests(grant_secret="", audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    # Refuse weak (< 32 chars)
    with pytest.raises(ConfigurationError):
        AppConfig.for_tests(grant_secret=WEAK_SECRET, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)

    # Refuse equal
    with pytest.raises(ConfigurationError):
        AppConfig.for_tests(grant_secret=TEST_GRANT_SECRET, audit_checkpoint_secret=TEST_GRANT_SECRET)


def test_config_redaction_in_repr_and_str():
    """AppConfig repr and str always redact secrets."""
    config = AppConfig.for_tests(
        grant_secret="sensitive-grant-secret-12345678901234567890",
        audit_checkpoint_secret="sensitive-audit-secret-12345678901234567890",
    )
    repr_str = repr(config)
    str_str = str(config)

    assert "[REDACTED]" in repr_str
    assert "[REDACTED]" in str_str
    assert "sensitive-grant-secret" not in repr_str
    assert "sensitive-grant-secret" not in str_str
    assert "sensitive-audit-secret" not in repr_str
    assert "sensitive-audit-secret" not in str_str


def test_secrets_never_leak_in_api_or_logs(client):
    """Ensure secrets never appear in public health check, case endpoints, or error responses."""
    # 1. Health check
    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    health_text = res_health.text
    assert TEST_GRANT_SECRET not in health_text
    assert TEST_AUDIT_CHECKPOINT_SECRET not in health_text

    # 2. Case creation and get
    res_create = client.post("/api/cases", json={"case_id": "RC-LEAK-TEST", "tenant_id": "tenant_01"})
    assert res_create.status_code == 200
    create_text = res_create.text
    assert TEST_GRANT_SECRET not in create_text
    assert TEST_AUDIT_CHECKPOINT_SECRET not in create_text

    res_get = client.get("/api/cases/RC-LEAK-TEST")
    assert res_get.status_code == 200
    assert TEST_GRANT_SECRET not in res_get.text

    # 3. Action dispatch error
    res_bad_action = client.post("/api/cases/RC-LEAK-TEST/dispatch", json={"type": "INVALID_ACTION"})
    assert res_bad_action.status_code == 400
    assert TEST_GRANT_SECRET not in res_bad_action.text
    assert TEST_AUDIT_CHECKPOINT_SECRET not in res_bad_action.text

    # 4. Audit verification endpoint
    res_audit = client.get("/api/audit/verify/RC-LEAK-TEST")
    assert res_audit.status_code == 200
    assert TEST_GRANT_SECRET not in res_audit.text
    assert TEST_AUDIT_CHECKPOINT_SECRET not in res_audit.text


def test_source_and_docs_scan_for_deleted_symbols_and_hardcoded_secrets():
    """Scan all files under src/ and docs/ to assert DEFAULT_GRANT_SECRET and hardcoded secret are absent."""
    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "src"
    docs_dir = repo_root / "docs"

    target_dirs = [d for d in [src_dir, docs_dir] if d.exists()]
    forbidden_tokens = [
        "DEFAULT_GRANT_SECRET",
        "payoutproof-local-grant-signing-secret-2026",
    ]

    violations = []
    for d in target_dirs:
        for p in d.rglob("*"):
            if p.is_file() and p.suffix in (".py", ".md", ".json", ".yaml", ".yml", ".txt"):
                text = p.read_text(encoding="utf-8", errors="ignore")
                for token in forbidden_tokens:
                    if token in text:
                        violations.append((str(p.relative_to(repo_root)), token))

    assert not violations, f"Forbidden tokens found in source or docs: {violations}"


def test_wrong_grant_secret_fails_verification_and_correct_secret_verifies():
    """Grant verification fails with wrong secret and succeeds with correct secret."""
    intent = make_confirmed_intent(
        counterparty="Kaveri Components",
        destination="HDFC ••4821",
        amount="425000",
    )
    state = make_admitted_case_state(
        case_id="RC-VERIF-TEST",
        intent=intent,
        policy=PolicyEvaluationResult(
            outcome=PolicyOutcome.ELIGIBLE_FOR_HANDOFF,
            evaluated_intent_hash=intent.intent_hash,
            policy_version="PP-POLICY-V1",
        ),
    )

    grant = GrantIssuer.issue_grant(state, secret=SECRET_A)

    # Correct secret verifies
    valid, err = GrantVerifier.verify(grant, intent.intent_hash, secret=SECRET_A)
    assert valid is True
    assert err is None

    # Wrong secret fails verification
    valid_bad, err_bad = GrantVerifier.verify(grant, intent.intent_hash, secret=SECRET_B)
    assert valid_bad is False
    assert "signature verification failed" in err_bad.lower()


def test_importing_pure_modules_does_not_require_secrets(monkeypatch):
    """Importing pure domain, policy, or core modules outside development does not require secrets."""
    monkeypatch.delenv("PAYOUTPROOF_GRANT_SECRET", raising=False)
    monkeypatch.delenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", raising=False)
    monkeypatch.delenv("PAYOUTPROOF_ENV", raising=False)

    # Pure domain/policy imports must succeed cleanly without secrets
    import payoutproof.core.models
    import payoutproof.policy.evaluator
    import payoutproof.core.crypto
    import payoutproof.grants.issuer
    import payoutproof.api

    assert payoutproof.core.models is not None
    assert payoutproof.policy.evaluator is not None
    assert payoutproof.core.crypto is not None
    assert payoutproof.grants.issuer is not None
    assert payoutproof.api is not None


def test_api_serve_composition_without_config_fails_safely(monkeypatch):
    """create_app without explicit config fails closed with ConfigurationError outside development."""
    monkeypatch.delenv("PAYOUTPROOF_GRANT_SECRET", raising=False)
    monkeypatch.delenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", raising=False)
    monkeypatch.setenv("PAYOUTPROOF_ENV", "production")

    with pytest.raises(ConfigurationError):
        create_app()


def test_cli_serve_handles_configuration_error_with_guidance(monkeypatch, capsys):
    """CLI serve command catches ConfigurationError and exits 1 with setup guidance."""
    from payoutproof.cli.main import main

    monkeypatch.delenv("PAYOUTPROOF_GRANT_SECRET", raising=False)
    monkeypatch.delenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", raising=False)
    monkeypatch.setenv("PAYOUTPROOF_ENV", "production")
    monkeypatch.setattr(sys, "argv", ["payoutproof", "serve"])

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Configuration error" in captured.out or "Configuration error" in captured.err
    assert "Setup guidance" in captured.out or "Setup guidance" in captured.err


def test_env_mutation_after_app_construction_cannot_enable_demo_mode(tmp_path, monkeypatch):
    """Mutating os.environ after app construction cannot enable demo adapter modes."""
    db_file = tmp_path / "demo_mutation.db"
    config = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(db_file),
        enable_demo_adapter_modes=False,
    )
    app = create_app(config=config)
    client = TestClient(app)

    # Initialize a case
    res = client.post("/api/cases", json={"case_id": "RC-DEMO-MUT"})
    assert res.status_code == 200

    # Mutate os.environ after app construction
    monkeypatch.setenv("PAYOUTPROOF_ENABLE_DEMO_ADAPTER_MODES", "1")

    # INITIATE_HANDOFF with fake_adapter_mode must be rejected
    res_dispatch = client.post(
        "/api/cases/RC-DEMO-MUT/dispatch",
        json={"type": "INITIATE_HANDOFF", "payload": {"fake_adapter_mode": "SIMULATE_AMBIGUITY"}},
    )
    assert res_dispatch.status_code == 400
    assert "fake_adapter_mode simulation is disabled" in res_dispatch.json()["detail"]


def test_multi_app_isolation_with_conflicting_legacy_globals(tmp_path, monkeypatch):
    """App instance dependencies (app.state db/adapter) win over module-level legacy globals."""
    from payoutproof.storage.db import Database
    from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
    import payoutproof.api.app as app_mod

    db1_path = str(tmp_path / "app1.db")
    db1 = Database(db_path=db1_path, audit_checkpoint_secret=SECRET_B)
    adapter1 = FakeApprovalRailAdapter(
        db=db1,
        grant_secret=SECRET_A,
        audit_checkpoint_secret=SECRET_B,
    )
    cfg1 = AppConfig.for_tests(
        grant_secret=SECRET_A,
        audit_checkpoint_secret=SECRET_B,
        db_path=db1_path,
    )
    app1 = create_app(config=cfg1, db=db1)

    db2_path = str(tmp_path / "app2.db")
    db2 = Database(db_path=db2_path, audit_checkpoint_secret=SECRET_A)
    adapter2 = FakeApprovalRailAdapter(
        db=db2,
        grant_secret=SECRET_B,
        audit_checkpoint_secret=SECRET_A,
    )
    cfg2 = AppConfig.for_tests(
        grant_secret=SECRET_B,
        audit_checkpoint_secret=SECRET_A,
        db_path=db2_path,
    )
    app2 = create_app(config=cfg2, db=db2)

    # Inject conflicting module-level legacy globals
    legacy_db_path = str(tmp_path / "legacy.db")
    legacy_db = Database(db_path=legacy_db_path, audit_checkpoint_secret="d" * 32)
    legacy_adapter = FakeApprovalRailAdapter(
        db=legacy_db,
        grant_secret="c" * 32,
        audit_checkpoint_secret="d" * 32,
    )
    monkeypatch.setattr(app_mod, "db", legacy_db)
    monkeypatch.setattr(app_mod, "adapter", legacy_adapter)

    client1 = TestClient(app1)
    client2 = TestClient(app2)

    # App 1 creates case
    r1 = client1.post("/api/cases", json={"case_id": "RC-APP1-CASE"})
    assert r1.status_code == 200

    # App 2 creates case
    r2 = client2.post("/api/cases", json={"case_id": "RC-APP2-CASE"})
    assert r2.status_code == 200

    # Verify db1 only has App 1's case
    assert db1.load_case("RC-APP1-CASE") is not None
    assert db1.load_case("RC-APP2-CASE") is None

    # Verify db2 only has App 2's case
    assert db2.load_case("RC-APP2-CASE") is not None
    assert db2.load_case("RC-APP1-CASE") is None

    # Verify legacy_db is empty and was never touched
    assert len(legacy_db.list_cases()) == 0
    assert legacy_db.load_case("RC-APP1-CASE") is None
    assert legacy_db.load_case("RC-APP2-CASE") is None


def test_dataclass_fields_have_repr_false_and_safe_dict():
    """Secret fields declare field(repr=False) and to_safe_dict redacts secrets."""
    fields = {f.name: f for f in dataclasses.fields(AppConfig)}
    assert fields["grant_secret"].repr is False
    assert fields["audit_checkpoint_secret"].repr is False

    config = AppConfig.for_tests(
        grant_secret=SECRET_A,
        audit_checkpoint_secret=SECRET_B,
    )
    safe_dict = config.to_safe_dict()
    assert safe_dict["grant_secret"] == "[REDACTED]"
    assert safe_dict["audit_checkpoint_secret"] == "[REDACTED]"
    assert SECRET_A not in str(safe_dict)
    assert SECRET_B not in str(safe_dict)


def test_secrets_never_leak_in_openapi_schema():
    """OpenAPI schema generation does not reveal secrets or sensitive configuration values."""
    config = AppConfig.for_tests(
        grant_secret=SECRET_A,
        audit_checkpoint_secret=SECRET_B,
    )
    app = create_app(config=config)
    openapi_schema = app.openapi()
    schema_str = str(openapi_schema)
    assert SECRET_A not in schema_str
    assert SECRET_B not in schema_str


def test_cli_verify_audit_handles_configuration_error_with_guidance(monkeypatch, capsys):
    """CLI verify-audit catches ConfigurationError and exits 1 with setup guidance."""
    from payoutproof.cli.main import main

    monkeypatch.delenv("PAYOUTPROOF_GRANT_SECRET", raising=False)
    monkeypatch.delenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", raising=False)
    monkeypatch.setenv("PAYOUTPROOF_ENV", "production")
    monkeypatch.setattr(sys, "argv", ["payoutproof", "verify-audit", "--case-id", "RC-TEST"])

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Configuration error" in captured.out or "Configuration error" in captured.err
    assert "Setup guidance" in captured.out or "Setup guidance" in captured.err


def test_cli_verify_audit_uses_configured_db_path(tmp_path, monkeypatch, capsys):
    """CLI verify-audit uses db_path from AppConfig and reports structural validity without false claims."""
    from payoutproof.cli.main import main
    from payoutproof.storage.db import Database
    from tests.helpers import make_admitted_case_state

    db_file = tmp_path / "custom_audit.db"
    db = Database(db_path=db_file, audit_checkpoint_secret=SECRET_B)
    case_state = make_admitted_case_state(case_id="RC-AUDIT-CLI")
    db.save_case(case_state)

    monkeypatch.setenv("PAYOUTPROOF_GRANT_SECRET", SECRET_A)
    monkeypatch.setenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", SECRET_B)
    monkeypatch.setenv("PAYOUTPROOF_ENV", "test")
    monkeypatch.setenv("PAYOUTPROOF_DB_PATH", str(db_file))
    monkeypatch.setattr(sys, "argv", ["payoutproof", "verify-audit", "--case-id", "RC-AUDIT-CLI"])

    # Must succeed cleanly
    main()

    captured = capsys.readouterr()
    assert "structurally valid" in captured.out
    # Must not falsely claim authenticated verification
    assert "authenticated verification" not in captured.out.lower()


def test_pure_import_has_no_app_side_effect():
    """Importing payoutproof.api.app does not eagerly instantiate app or mutate globals."""
    import payoutproof.api.app as app_mod

    # create_app returns an isolated instance and does not overwrite app_mod._legacy_app
    cfg = AppConfig.for_tests(grant_secret=SECRET_A, audit_checkpoint_secret=SECRET_B)
    app1 = create_app(config=cfg)
    assert app_mod._legacy_app is not app1
