#!/usr/bin/env python3
"""Offline, reproducible Software Bill of Materials (SBOM) generator for PayoutProof.

Parses python dependencies from `uv.lock` and frontend dependencies from
`web/package-lock.json` to generate an authoritative, standards-compliant
CycloneDX 1.5 JSON or SPDX 2.3 JSON SBOM.

Runs completely offline from a clean checkout without network dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import tomllib


def parse_uv_lock(lock_path: Path) -> List[Dict[str, Any]]:
    """Parse python package metadata and checksums from uv.lock."""
    if not lock_path.is_file():
        return []

    data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = data.get("package", [])
    components: List[Dict[str, Any]] = []

    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue

        purl = f"pkg:pypi/{name.lower()}@{version}"
        hashes: List[Dict[str, str]] = []

        sdist = pkg.get("sdist", {})
        if "hash" in sdist and sdist["hash"].startswith("sha256:"):
            hashes.append({
                "alg": "SHA-256",
                "content": sdist["hash"].split("sha256:", 1)[1],
            })

        for wheel in pkg.get("wheels", []):
            if "hash" in wheel and wheel["hash"].startswith("sha256:"):
                h_val = wheel["hash"].split("sha256:", 1)[1]
                if not any(h["content"] == h_val for h in hashes):
                    hashes.append({
                        "alg": "SHA-256",
                        "content": h_val,
                    })

        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "ecosystem": "pypi",
            "hashes": hashes,
        })

    return sorted(components, key=lambda c: c["purl"])


def parse_npm_lock(lock_path: Path) -> List[Dict[str, Any]]:
    """Parse node package metadata and checksums from web/package-lock.json."""
    if not lock_path.is_file():
        return []

    data = json.loads(lock_path.read_text(encoding="utf-8"))
    packages = data.get("packages", {})
    components: List[Dict[str, Any]] = []
    seen_purls = set()

    for pkg_path, info in packages.items():
        if not pkg_path or not pkg_path.startswith("node_modules/"):
            continue

        name = pkg_path.replace("node_modules/", "")
        version = info.get("version")
        if not name or not version:
            continue

        purl = f"pkg:npm/{name}@{version}"
        if purl in seen_purls:
            continue
        seen_purls.add(purl)

        hashes: List[Dict[str, str]] = []
        integrity = info.get("integrity", "")
        if integrity.startswith("sha512-"):
            hashes.append({
                "alg": "SHA-512",
                "content": integrity.split("sha512-", 1)[1],
            })

        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "ecosystem": "npm",
            "hashes": hashes,
            "license": info.get("license"),
        })

    return sorted(components, key=lambda c: c["purl"])


def generate_cyclonedx_sbom(
    app_version: str,
    py_components: List[Dict[str, Any]],
    npm_components: List[Dict[str, Any]],
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate CycloneDX 1.5 JSON SBOM document."""
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    all_components = py_components + npm_components

    cdx_components = []
    for comp in all_components:
        c_entry: Dict[str, Any] = {
            "type": comp["type"],
            "name": comp["name"],
            "version": comp["version"],
            "purl": comp["purl"],
        }
        if comp.get("hashes"):
            c_entry["hashes"] = comp["hashes"]
        if comp.get("license"):
            c_entry["licenses"] = [{"license": {"id": comp["license"]}}]
        cdx_components.append(c_entry)

    purl_stream = "\n".join(c["purl"] for c in cdx_components)
    serial_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"urn:payoutproof:{app_version}:{purl_stream}")

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial_uuid}",
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [
                {
                    "vendor": "PayoutProof",
                    "name": "generate_sbom",
                    "version": app_version,
                }
            ],
            "component": {
                "type": "application",
                "name": "payoutproof",
                "version": app_version,
                "description": "PayoutProof: Trust Agent and Deterministic Policy Gate for Payment Risk",
            },
        },
        "components": cdx_components,
    }


def generate_spdx_sbom(
    app_version: str,
    py_components: List[Dict[str, Any]],
    npm_components: List[Dict[str, Any]],
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate SPDX 2.3 JSON SBOM document."""
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    all_components = py_components + npm_components

    spdx_packages = [
        {
            "SPDXID": "SPDXRef-Application",
            "name": "payoutproof",
            "versionInfo": app_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        }
    ]
    relationships = []

    for idx, comp in enumerate(all_components):
        spdx_id = f"SPDXRef-Package-{comp['ecosystem']}-{idx+1}"
        pkg_entry: Dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": comp["name"],
            "versionInfo": comp["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp["purl"],
                }
            ],
        }
        if comp.get("hashes"):
            pkg_entry["checksums"] = [
                {"algorithm": h["alg"].replace("-", ""), "checksumValue": h["content"]}
                for h in comp["hashes"]
            ]
        spdx_packages.append(pkg_entry)
        relationships.append({
            "spdxElementId": "SPDXRef-Application",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": spdx_id,
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"payoutproof-{app_version}",
        "documentNamespace": f"https://payoutproof.internal/spdx/{app_version}/{uuid.uuid4()}",
        "creationInfo": {
            "creators": ["Tool: PayoutProof-generate_sbom-0.1.0"],
            "created": ts,
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate PayoutProof Software Bill of Materials")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root directory",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Path to write SBOM JSON (default: stdout or build/sbom.cdx.json)",
    )
    parser.add_argument(
        "--format",
        choices=["cyclonedx", "spdx"],
        default="cyclonedx",
        help="SBOM specification format",
    )
    parser.add_argument(
        "--app-version",
        default="0.1.0",
        help="Application version string",
    )

    args = parser.parse_args()
    root = args.root

    uv_lock = root / "uv.lock"
    npm_lock = root / "web" / "package-lock.json"

    py_components = parse_uv_lock(uv_lock)
    npm_components = parse_npm_lock(npm_lock)

    if args.format == "cyclonedx":
        sbom_doc = generate_cyclonedx_sbom(args.app_version, py_components, npm_components)
    else:
        sbom_doc = generate_spdx_sbom(args.app_version, py_components, npm_components)

    out_json = json.dumps(sbom_doc, indent=2) + "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(out_json, encoding="utf-8")
        print(f"Generated {args.format.upper()} SBOM at {args.output} ({len(py_components)} Python + {len(npm_components)} npm components)")
    else:
        print(out_json)


if __name__ == "__main__":
    main()
