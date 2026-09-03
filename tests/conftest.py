"""Pytest fixtures for PayoutProof tests."""

import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

import pytest
from fastapi.testclient import TestClient

from payoutproof.core.config import AppConfig
from payoutproof.api.app import create_app
from tests.helpers import (
    make_valid_authority_record,
    make_valid_evidence_payload,
    make_authorized_bundle_action,
    make_admitted_case_state,
    TEST_GRANT_SECRET,
    TEST_AUDIT_CHECKPOINT_SECRET,
)


@pytest.fixture
def valid_authority():
    return make_valid_authority_record()


@pytest.fixture
def valid_evidence():
    return make_valid_evidence_payload()


@pytest.fixture
def authorized_admission_action():
    return make_authorized_bundle_action


@pytest.fixture
def admitted_case_state():
    return make_admitted_case_state


@pytest.fixture
def test_config(tmp_path):
    test_db_path = str(tmp_path / "payoutproof_test.db")
    return AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=test_db_path,
        enable_demo_adapter_modes=False,
    )


@pytest.fixture
def app(test_config, isolate_test_database):
    test_db = isolate_test_database
    return create_app(config=test_config, db=test_db)


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture(autouse=True)
def isolate_test_database(tmp_path, monkeypatch):
    """Ensure every test runs against a clean, isolated SQLite database and test config."""
    test_db_path = str(tmp_path / "payoutproof_test.db")
    monkeypatch.setenv("PAYOUTPROOF_DB_PATH", test_db_path)
    monkeypatch.setenv("PAYOUTPROOF_GRANT_SECRET", TEST_GRANT_SECRET)
    monkeypatch.setenv("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET", TEST_AUDIT_CHECKPOINT_SECRET)
    from payoutproof.storage.db import Database
    from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter

    test_db = Database(db_path=test_db_path, audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET)
    test_adapter = FakeApprovalRailAdapter(
        db=test_db,
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
    )

    test_config_obj = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=test_db_path,
        enable_demo_adapter_modes=False,
    )

    app_module = sys.modules.get("payoutproof.api.app")
    if app_module is not None:
        monkeypatch.setattr(app_module, "db", test_db)
        monkeypatch.setattr(app_module, "adapter", test_adapter)
        monkeypatch.setattr(app_module, "_legacy_app", None)

    yield test_db
