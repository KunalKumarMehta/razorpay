"""Command-line interface for PayoutProof."""

import sys
import argparse
from typing import Optional, Any
import uvicorn
from rich.console import Console
from rich.table import Table

from payoutproof.scorer.service import EvaluationExecutionService
from payoutproof.storage.db import Database
from payoutproof.audit.chain import AuditChain

console = Console()


def run_benchmark(suite: str):
    """Run development policy harness and print rich report."""
    console.print("\n[bold yellow]DEVELOPMENT POLICY HARNESS / SYNTHETIC STRUCTURED CASES / NOT A SEALED EVALUATION[/bold yellow]")
    console.print("[dim]Exercises deterministic policy plumbing with synthetic cases. Not held-out product performance or proof.[/dim]\n")

    report = EvaluationExecutionService.run_suite(suite)

    rep_info = f", {report.base_case_count}×{report.repetition_count}" if report.repetition_count > 1 else ""
    title_text = (
        "DEVELOPMENT POLICY HARNESS / SYNTHETIC STRUCTURED CASES / NOT A SEALED EVALUATION\n"
        f"Suite: {report.suite.upper()} ({report.total_executions} synthetic executions{rep_info})"
    )

    table = Table(title=title_text)
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Harness Result", style="magenta")
    table.add_column("Predeclared Target Gate", style="yellow")
    table.add_column("Harness Status", style="bold")

    # Hard Safety Gate
    unsafe_display = f"{report.unsafe_handoffs_count} (zero unsafe)" if report.unsafe_handoffs_count == 0 else str(report.unsafe_handoffs_count)
    table.add_row(
        "Unsafe Handoffs",
        unsafe_display,
        "0 (Zero Tolerance)",
        "[green]MEETS_TARGET[/green]" if report.passed_safety_gate else "[red]FAILS_TARGET[/red]",
    )

    # Exact Match Gate
    mismatch_display = (
        f"{report.total_executions - report.exact_mismatches_count}/{report.total_executions} (zero exact mismatches)"
        if report.exact_mismatches_count == 0
        else f"{report.total_executions - report.exact_mismatches_count}/{report.total_executions} ({report.exact_mismatches_count} mismatches)"
    )
    table.add_row(
        "Exact Match Invariance",
        mismatch_display,
        "0 Mismatches",
        "[green]MEETS_TARGET[/green]" if report.exact_mismatches_count == 0 else "[red]FAILS_TARGET[/red]",
    )

    # 3-Action Accuracy
    table.add_row(
        "3-Action Correctness (Harness)",
        f"{report.three_action_accuracy*100:.1f}% (CI: {report.three_action_wilson[0]*100:.1f}%–{report.three_action_wilson[1]*100:.1f}%)",
        "≥ 90.0%",
        "[green]MEETS_TARGET[/green]" if report.three_action_accuracy >= 0.90 else "[red]FAILS_TARGET[/red]",
    )

    # Protective Recall
    table.add_row(
        "Protective Intervention Recall (Harness)",
        f"{report.protective_recall*100:.1f}% (CI: {report.protective_recall_wilson[0]*100:.1f}%–{report.protective_recall_wilson[1]*100:.1f}%)",
        "≥ 95.0%",
        "[green]MEETS_TARGET[/green]" if report.protective_recall >= 0.95 else "[red]FAILS_TARGET[/red]",
    )

    # Intent Binding
    table.add_row(
        "Intent Binding Correctness (Harness)",
        f"{report.intent_binding_accuracy*100:.1f}%",
        "≥ 95.0%",
        "[green]MEETS_TARGET[/green]" if report.intent_binding_accuracy >= 0.95 else "[red]FAILS_TARGET[/red]",
    )

    # Interaction Reduction
    table.add_row(
        "Operator Interaction Reduction (Simulated)",
        f"{report.interaction_reduction_pct:.1f}% ({report.total_no_tool_interactions} vs {report.total_tool_interactions} gestures)",
        "≥ 30.0%",
        "[green]MEETS_TARGET[/green]" if report.passed_interaction_gate else "[red]FAILS_TARGET[/red]",
    )

    console.print(table)
    console.print(
        f"[dim]Harness scope: {report.scope_declaration}. "
        "Deterministic synthetic structured policy-plumbing harness—NOT held-out data, "
        "real media/models, human validation, real-world performance, or product proof.[/dim]\n"
    )


def verify_case_audit(case_id: str, config: Any = None):
    """Verify authenticated audit chain for a case using configured database and audit secret."""
    if config is None:
        from payoutproof.core.config import AppConfig, ConfigurationError

        try:
            config = AppConfig.from_env()
        except ConfigurationError as e:
            console.print(f"[bold red]Configuration error:[/bold red] {e}")
            console.print(
                "[yellow]Setup guidance:[/yellow] Provide required secrets:\n"
                "  export PAYOUTPROOF_GRANT_SECRET='<32+ character secret>'\n"
                "  export PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET='<32+ character secret>'\n"
                "Or set PAYOUTPROOF_ENV=development for local ephemeral development."
            )
            sys.exit(1)

    db = Database(db_path=config.db_path, audit_checkpoint_secret=config.audit_checkpoint_secret)
    result = db.verify_case_audit(case_id)
    if result is None:
        console.print(f"[red]Case {case_id} not found.[/red]")
        sys.exit(1)

    if result["is_valid"]:
        console.print(
            f"[bold green]Audit Chain for {case_id} is structurally valid, authenticated, and TRUSTED across all {result['event_count']} events (checkpoint MAC verified).[/bold green]"
        )
    else:
        trust_st = result.get("trust_state", "UNTRUSTED")
        reason = result.get("reason", "Integrity check failed")
        broken_seq = result.get("broken_at_seq")
        seq_str = f" at sequence {broken_seq}" if broken_seq is not None else ""
        console.print(f"[bold red]Audit Chain {trust_st}{seq_str}: {reason}[/bold red]")
        sys.exit(1)



def main():
    parser = argparse.ArgumentParser(prog="payoutproof", description="PayoutProof CLI")
    subparsers = parser.add_subparsers(dest="command")

    # serve command
    serve_parser = subparsers.add_parser("serve", help="Start FastAPI control plane server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host address")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port number")

    # eval command
    eval_parser = subparsers.add_parser("eval", help="Run development policy harness")
    eval_parser.add_argument("--suite", choices=["dev", "sealed", "safety"], default="dev", help="Suite to run")

    # verify-audit command
    audit_parser = subparsers.add_parser("verify-audit", help="Verify case audit chain")
    audit_parser.add_argument("--case-id", required=True, help="Risk Case ID")

    args = parser.parse_args()

    if args.command == "serve":
        from payoutproof.core.config import AppConfig, ConfigurationError
        from payoutproof.api.app import create_app

        try:
            config = AppConfig.from_env()
        except ConfigurationError as e:
            console.print(f"[bold red]Configuration error:[/bold red] {e}")
            console.print(
                "[yellow]Setup guidance:[/yellow] Provide required secrets:\n"
                "  export PAYOUTPROOF_GRANT_SECRET='<32+ character secret>'\n"
                "  export PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET='<32+ character secret>'\n"
                "Or set PAYOUTPROOF_ENV=development for local ephemeral development."
            )
            sys.exit(1)

        app_instance = create_app(config)
        uvicorn.run(app_instance, host=args.host, port=args.port)
    elif args.command == "eval":
        run_benchmark(args.suite)
    elif args.command == "verify-audit":
        from payoutproof.core.config import AppConfig, ConfigurationError

        try:
            config = AppConfig.from_env()
        except ConfigurationError as e:
            console.print(f"[bold red]Configuration error:[/bold red] {e}")
            console.print(
                "[yellow]Setup guidance:[/yellow] Provide required secrets:\n"
                "  export PAYOUTPROOF_GRANT_SECRET='<32+ character secret>'\n"
                "  export PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET='<32+ character secret>'\n"
                "Or set PAYOUTPROOF_ENV=development for local ephemeral development."
            )
            sys.exit(1)

        verify_case_audit(args.case_id, config=config)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
