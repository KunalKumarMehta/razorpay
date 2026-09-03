"""Focused tests for secret-free release metadata at public boundaries.

Covers:
1. ReleaseMetadata is immutable, complete, and secret-free.
2. /api/health and /api/release publish the stable identifier set.
3. Suite execution reports carry the Evaluation Version binding.
4. Identifiers stay consistent with pyproject, PolicyGate, and checkpoint MAC constants.
5. No secrets leak into release payloads.
"""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from payoutproof.core.release import (
    ReleaseMetadata,
    RELEASE_METADATA,
    get_release_metadata,
    APPLICATION_VERSION,
    POLICY_VERSION,
    SCHEMA_VERSION,
    AUDIT_CHECKPOINT_VERSION,
    MODEL_CONFIGURATION_VERSION,
    EVALUATION_VERSION,
    EVIDENCE_SCOPE,
)
from payoutproof.core.config import AppConfig
from payoutproof.api.app import create_app
from payoutproof.scorer.service import EvaluationExecutionService, SYNTHETIC_SCOPE_DECLARATION
from tests.helpers import TEST_GRANT_SECRET, TEST_AUDIT_CHECKPOINT_SECRET

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_release_metadata_is_complete_and_stable():
    """ReleaseMetadata exposes every stable identifier with no empty values."""
    meta = get_release_metadata()

    expected_fields = {
        "application_version": APPLICATION_VERSION,
        "policy_version": POLICY_VERSION,
        "schema_version": SCHEMA_VERSION,
        "audit_checkpoint_version": AUDIT_CHECKPOINT_VERSION,
        "model_configuration_version": MODEL_CONFIGURATION_VERSION,
        "evaluation_version": EVALUATION_VERSION,
        "evidence_scope": EVIDENCE_SCOPE,
        "maturity": "IN_DEVELOPMENT",
    }
    public = meta.to_public_dict()
    assert public == expected_fields
    # Singleton accessor returns the frozen process-wide identity
    assert get_release_metadata() is RELEASE_METADATA


def test_release_metadata_is_immutable():
    """The frozen dataclass rejects field mutation and construction with empty identifiers."""
    meta = get_release_metadata()
    with pytest.raises(Exception):
        meta.application_version = "9.9.9"  # type: ignore

    with pytest.raises(ValueError, match="non-empty string"):
        ReleaseMetadata(application_version="   ")
    with pytest.raises(ValueError, match="non-empty string"):
        ReleaseMetadata(evaluation_version="")


def test_release_metadata_consistent_with_source_and_project_constants():
    """Identifiers mirror pyproject version, PolicyGate version, and checkpoint MAC domain."""
    # 1. Application version matches pyproject.toml [project].version
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert m is not None, "pyproject.toml must declare a project version"
    assert m.group(1) == APPLICATION_VERSION

    # 2. Policy version mirrors the Policy Gate constant
    from payoutproof.policy.evaluator import POLICY_VERSION as GATE_POLICY_VERSION
    assert POLICY_VERSION == GATE_POLICY_VERSION

    # 3. Schema version mirrors storage database constant
    from payoutproof.storage.db import SCHEMA_VERSION as DB_SCHEMA_VERSION
    assert SCHEMA_VERSION == DB_SCHEMA_VERSION

    # 4. Audit checkpoint version mirrors the checkpoint MAC domain separator
    checkpoint_src = (REPO_ROOT / "src" / "payoutproof" / "core" / "crypto.py").read_text(encoding="utf-8")
    assert AUDIT_CHECKPOINT_VERSION in checkpoint_src

    # 5. Evidence scope mirrors the evaluation scope declaration
    assert EVIDENCE_SCOPE == SYNTHETIC_SCOPE_DECLARATION


def test_health_endpoint_publishes_release_metadata(tmp_path):
    """/api/health exposes the exact release identifier set under a `release` block."""
    config = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(tmp_path / "health_release.db"),
    )
    client = TestClient(create_app(config=config))
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()

    release = data["release"]
    assert release == RELEASE_METADATA.to_public_dict()
    # Top-level version stays aligned with the release identity
    assert data["version"] == release["application_version"]
    assert data["maturity"] == release["maturity"]


def test_release_endpoint_is_secret_free(tmp_path):
    """/api/release publishes identifiers and never carries secrets or environment data."""
    config = AppConfig.for_tests(
        grant_secret=TEST_GRANT_SECRET,
        audit_checkpoint_secret=TEST_AUDIT_CHECKPOINT_SECRET,
        db_path=str(tmp_path / "release.db"),
    )
    client = TestClient(create_app(config=config))
    res = client.get("/api/release")
    assert res.status_code == 200
    payload_text = res.text

    # Exact identifier set, no extras
    assert res.json() == RELEASE_METADATA.to_public_dict()

    # Never leaks configured secrets
    assert TEST_GRANT_SECRET not in payload_text
    assert TEST_AUDIT_CHECKPOINT_SECRET not in payload_text
    # Never exposes environment, paths, or redaction markers
    assert "[REDACTED]" not in payload_text
    assert "db_path" not in payload_text
    assert "environment" not in payload_text


def test_health_release_payload_is_secret_free_against_config(tmp_path):
    """Health release block never reflects AppConfig secret material."""
    config = AppConfig.for_tests(
        grant_secret="distinct-grant-secret-for-release-check-123",
        audit_checkpoint_secret="distinct-checkpoint-secret-for-release-456",
        db_path=str(tmp_path / "health_secret_free.db"),
    )
    client = TestClient(create_app(config=config))
    res = client.get("/api/health")
    assert res.status_code == 200
    assert "distinct-grant-secret-for-release-check-123" not in res.text
    assert "distinct-checkpoint-secret-for-release-456" not in res.text


def test_evaluation_reports_carry_release_identity():
    """Every synthetic suite report is bound to its Evaluation Version, policy, and model config."""
    for suite in ("dev", "sealed", "safety"):
        report = EvaluationExecutionService.run_suite(suite)
        assert report.evaluation_version == EVALUATION_VERSION
        assert report.policy_version == POLICY_VERSION
        assert report.model_configuration_version == MODEL_CONFIGURATION_VERSION
        # Scope declaration stays honest and tied to the release identity
        assert report.scope_declaration == EVIDENCE_SCOPE


def test_evaluation_version_identifier_declares_synthetic_scope():
    """The Evaluation Version identifier and scope must state synthetic evidence honestly."""
    assert "SYNTHETIC" in EVALUATION_VERSION
    assert "NOT_HELD_OUT" in EVIDENCE_SCOPE
    # Model configuration identifier must not claim real model execution
    assert "SYNTHETIC" in MODEL_CONFIGURATION_VERSION
    assert "ASR" not in MODEL_CONFIGURATION_VERSION
    assert "AASIST" not in MODEL_CONFIGURATION_VERSION


def test_release_metadata_module_scans_clean_of_secret_patterns():
    """The release module text itself contains no secret-like material."""
    release_src = (REPO_ROOT / "src" / "payoutproof" / "core" / "release.py").read_text(encoding="utf-8")
    for token in ("grant_secret", "audit_checkpoint_secret", "password", "token_urlsafe"):
        assert token not in release_src, f"release.py must not reference secret material: {token}"
