"""Focused tests for offline SBOM generation and supply chain integrity.

Covers:
1. CycloneDX 1.5 JSON generation from uv.lock and web/package-lock.json.
2. SPDX 2.3 JSON generation with proper package and relationship declarations.
3. Component coverage includes backend (fastapi, pydantic) and frontend (react, vite) packages.
4. Serial numbers and package URLs are well-formed.
5. Generated SBOM is secret-free and contains no absolute user paths.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_cyclonedx_sbom_generation(tmp_path):
    """CycloneDX 1.5 JSON generation succeeds and contains expected package metadata."""
    out_file = tmp_path / "sbom.cdx.json"
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "generate_sbom.py"),
        "--root",
        str(REPO_ROOT),
        "--output",
        str(out_file),
        "--format",
        "cyclonedx",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    assert out_file.is_file()

    doc = json.loads(out_file.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["component"]["name"] == "payoutproof"

    components = doc["components"]
    assert len(components) > 100

    purls = {c["purl"] for c in components}
    # Backend dependencies
    assert any(p.startswith("pkg:pypi/fastapi@") for p in purls)
    assert any(p.startswith("pkg:pypi/pydantic@") for p in purls)
    assert any(p.startswith("pkg:pypi/uvicorn@") for p in purls)
    assert any(p.startswith("pkg:pypi/cryptography@") for p in purls)

    # Frontend dependencies
    assert any(p.startswith("pkg:npm/react@") for p in purls)
    assert any(p.startswith("pkg:npm/vite@") for p in purls)
    assert any(p.startswith("pkg:npm/typescript@") for p in purls)

    # Verify checksums exist
    fastapi_comp = next(c for c in components if c["name"] == "fastapi")
    assert "hashes" in fastapi_comp
    assert len(fastapi_comp["hashes"]) > 0
    assert fastapi_comp["hashes"][0]["alg"] == "SHA-256"


def test_spdx_sbom_generation(tmp_path):
    """SPDX 2.3 JSON generation succeeds and contains expected packages and relationships."""
    out_file = tmp_path / "sbom.spdx.json"
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "generate_sbom.py"),
        "--root",
        str(REPO_ROOT),
        "--output",
        str(out_file),
        "--format",
        "spdx",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    assert out_file.is_file()

    doc = json.loads(out_file.read_text(encoding="utf-8"))
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["name"].startswith("payoutproof-")

    packages = doc["packages"]
    assert len(packages) > 100

    root_pkg = next(p for p in packages if p["SPDXID"] == "SPDXRef-Application")
    assert root_pkg["name"] == "payoutproof"

    relationships = doc["relationships"]
    assert len(relationships) == len(packages) - 1


def test_sbom_is_secret_free(tmp_path):
    """SBOM JSON output contains no secret tokens, private keys, or personal paths."""
    out_file = tmp_path / "sbom.cdx.json"
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "generate_sbom.py"),
        "--root",
        str(REPO_ROOT),
        "--output",
        str(out_file),
    ]
    subprocess.run(cmd, capture_output=True, text=True, check=True)
    content = out_file.read_text(encoding="utf-8")

    for forbidden in ("/Users/", "/home/", "grant_secret", "audit_checkpoint_secret", "password", "PRIVATE KEY"):
        assert forbidden not in content, f"Forbidden string '{forbidden}' leaked into SBOM!"
