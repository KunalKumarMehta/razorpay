"""Focused tests for truthful evidence reset and explicit deferral enforcement."""

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_handoff_ledger_structure_and_truthful_status():
    """Verify handoff_ledger.json is valid JSON with truthful development statuses."""
    ledger_path = REPO_ROOT / "handoff_ledger.json"
    assert ledger_path.exists(), "handoff_ledger.json must exist"

    with open(ledger_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Core status and branch verification
    assert data["status"] == "IN_DEVELOPMENT"
    assert data["branch"] == "antigravity/mvp-implementation"
    assert "verified_commands" in data
    assert "planned_acceptance_commands" in data

    # No unearned PASS or GREEN claims across top-level, modules, or gates
    raw_text = json.dumps(data)
    assert not re.search(r"\b(PASS|GREEN)\b", raw_text, re.IGNORECASE)

    # Module statuses must be honest (IN_DEVELOPMENT or UNIT_TESTED)
    for mod_name, mod_info in data["modules"].items():
        assert mod_info["status"] in ("IN_DEVELOPMENT", "UNIT_TESTED"), (
            f"Module {mod_name} has invalid status {mod_info.get('status')}"
        )

    # Modules with known reproducible gaps must be marked IN_DEVELOPMENT with gap documented
    known_incomplete_modules = [
        "admission",
        "deterministic_policy_gate",
        "grants_and_hmac",
        "audit_hash_chain",
        "fake_action_adapter",
        "persistence",
        "api_control_plane",
        "simulator_oracle_scorer",
        "web_presentation",
    ]
    for mod_name in known_incomplete_modules:
        assert data["modules"][mod_name]["status"] == "IN_DEVELOPMENT", (
            f"Module {mod_name} must be marked IN_DEVELOPMENT"
        )
        has_gap_info = "known_gap" in data["modules"][mod_name] or "description" in data["modules"][mod_name]
        assert has_gap_info, f"Module {mod_name} must describe known gap or development status"

    # Acceptance gate statuses must not be PASSED and have no unearned percentages
    for gate_name, gate_info in data["acceptance_gates"].items():
        assert gate_info["status"] in ("NOT_RUN", "IN_DEVELOPMENT"), (
            f"Gate {gate_name} has invalid status {gate_info.get('status')}"
        )
        assert "observed" not in gate_info or gate_info.get("observed") == "NOT_RUN"
        assert "observed_dev" not in gate_info
        assert "observed_sealed" not in gate_info

    # Tamper and replay gates must be marked IN_DEVELOPMENT acknowledging known gaps
    assert data["acceptance_gates"]["tamper_detection_gate"]["status"] == "IN_DEVELOPMENT"
    assert data["acceptance_gates"]["replay_prevention_gate"]["status"] == "IN_DEVELOPMENT"
    assert "known gap" in data["acceptance_gates"]["tamper_detection_gate"]["notes"].lower()
    assert "known gap" in data["acceptance_gates"]["replay_prevention_gate"]["notes"].lower()

    # Safety gate must state held-out target is NOT_RUN and only 81 repeated synthetic executions were verified
    safety_notes = data["acceptance_gates"]["zero_tolerance_safety_gate"]["notes"]
    assert "NOT_RUN" in safety_notes
    assert "81 repeated synthetic safety executions (27 base cases × 3 repetitions)" in safety_notes


def test_readme_truthful_presentation():
    """Verify README.md contains no static PASS claims, no repeated 3x current claims, and truthful rows."""
    readme_path = REPO_ROOT / "README.md"
    content = readme_path.read_text(encoding="utf-8")

    # Relative link to ledger, no absolute file URL
    assert "./handoff_ledger.json" in content
    assert "file:///" not in content

    # Predeclared gates must be marked NOT RUN / NOT YET EVIDENCED
    assert "NOT RUN" in content
    assert "NOT YET EVIDENCED" in content

    # No unqualified static PASS or GREEN in table status columns
    assert not re.search(r"\|\s*PASS\s*\|", content)
    assert not re.search(r"\|\s*GREEN\s*\|", content)

    # README documents the centralized 81-execution repeated synthetic safety invariant harness (27x3)
    assert "81-execution critical safety invariant harness (27 synthetic base cases × 3 repetitions)" in content
    assert "deterministic synthetic structured policy-plumbing harnesses—not held-out data" in content.lower()
    assert "future target" not in content
    assert "single pass" not in content


    # Audit and replay rows must report partial unit checks with known gaps, not Verified
    assert "Verified in unit tests only" not in content
    assert "Partial unit checks with known gaps" in content


def test_no_razorpayx_adapter_runtime_references():
    """Verify RazorpayXTestAdapter and razorpayx_adapter are not referenced in runtime code."""
    src_dir = REPO_ROOT / "src" / "payoutproof"
    for py_file in src_dir.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        assert "RazorpayXTestAdapter" not in text, f"Found RazorpayXTestAdapter in {py_file}"
        assert "razorpayx_adapter" not in text, f"Found razorpayx_adapter in {py_file}"


def test_cli_contains_truthful_harness_banner():
    """Verify CLI eval output includes truthful development harness notice."""
    cli_path = REPO_ROOT / "src" / "payoutproof" / "cli" / "main.py"
    cli_text = cli_path.read_text(encoding="utf-8")
    assert "DEVELOPMENT POLICY HARNESS / SYNTHETIC STRUCTURED CASES / NOT A SEALED EVALUATION" in cli_text
    assert "[green]MEETS_TARGET[/green]" in cli_text
