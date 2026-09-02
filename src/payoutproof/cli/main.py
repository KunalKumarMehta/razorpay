"""Command-line interface for PayoutProof."""

import sys
import argparse
import uvicorn
from rich.console import Console
from rich.table import Table

from payoutproof.simulator.generator import Simulator
from payoutproof.scorer.scorer import EvaluationScorer
from payoutproof.scorer.runner import execute_case_under_test
from payoutproof.storage.db import Database
from payoutproof.audit.chain import AuditChain

console = Console()


def run_benchmark(suite: str):
    """Run benchmark evaluation suite and print rich report."""
    console.print(f"[bold green]Running PayoutProof Benchmark: {suite.upper()} Suite[/bold green]")

    if suite == "sealed":
        cases = Simulator.generate_sealed_corpus()
    elif suite == "safety":
        cases = Simulator.generate_safety_corpus()
    else:
        cases = Simulator.generate_dev_corpus()

    results = [execute_case_under_test(c) for c in cases]
    report = EvaluationScorer.score_results(results)

    table = Table(title=f"PayoutProof Evaluation Results ({suite.upper()} - {report.total_cases} Cases)")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Observed Value", style="magenta")
    table.add_column("Acceptance Gate", style="yellow")
    table.add_column("Status", style="bold green")

    # Hard Safety Gate
    table.add_row(
        "Unsafe Handoffs",
        str(report.unsafe_handoffs_count),
        "0 (Zero Tolerance)",
        "[green]PASS[/green]" if report.passed_safety_gate else "[red]FAIL[/red]"
    )

    # 3-Action Accuracy
    table.add_row(
        "3-Action Correctness",
        f"{report.three_action_accuracy*100:.1f}% (CI: {report.three_action_wilson[0]*100:.1f}%–{report.three_action_wilson[1]*100:.1f}%)",
        "≥ 90.0%",
        "[green]PASS[/green]" if report.three_action_accuracy >= 0.90 else "[red]FAIL[/red]"
    )

    # Protective Recall
    table.add_row(
        "Protective Intervention Recall",
        f"{report.protective_recall*100:.1f}% (CI: {report.protective_recall_wilson[0]*100:.1f}%–{report.protective_recall_wilson[1]*100:.1f}%)",
        "≥ 95.0%",
        "[green]PASS[/green]" if report.protective_recall >= 0.95 else "[red]FAIL[/red]"
    )

    # Intent Binding
    table.add_row(
        "Intent Binding Correctness",
        f"{report.intent_binding_accuracy*100:.1f}%",
        "≥ 95.0%",
        "[green]PASS[/green]" if report.intent_binding_accuracy >= 0.95 else "[red]FAIL[/red]"
    )

    # Interaction Reduction
    table.add_row(
        "Operator Interaction Reduction",
        f"{report.interaction_reduction_pct:.1f}% ({report.total_no_tool_interactions} vs {report.total_tool_interactions} gestures)",
        "≥ 30.0%",
        "[green]PASS[/green]" if report.passed_interaction_gate else "[red]FAIL[/red]"
    )

    console.print(table)


def verify_case_audit(case_id: str):
    """Verify audit chain for a case."""
    db = Database()
    state = db.load_case(case_id)
    if not state:
        console.print(f"[red]Case {case_id} not found.[/red]")
        sys.exit(1)

    is_valid, broken_seq, reason = AuditChain.verify_chain(state.audit)
    if is_valid:
        console.print(f"[bold green]Audit Chain for {case_id} is cryptographically VALID across all {len(state.audit)} events.[/bold green]")
    else:
        console.print(f"[bold red]Audit Chain CORRUPTED at sequence {broken_seq}: {reason}[/bold red]")


def main():
    parser = argparse.ArgumentParser(prog="payoutproof", description="PayoutProof CLI")
    subparsers = parser.add_subparsers(dest="command")

    # serve command
    serve_parser = subparsers.add_parser("serve", help="Start FastAPI control plane server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host address")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port number")

    # eval command
    eval_parser = subparsers.add_parser("eval", help="Run benchmark evaluation")
    eval_parser.add_argument("--suite", choices=["dev", "sealed", "safety"], default="dev", help="Suite to run")

    # verify-audit command
    audit_parser = subparsers.add_parser("verify-audit", help="Verify case audit chain")
    audit_parser.add_argument("--case-id", required=True, help="Risk Case ID")

    args = parser.parse_args()

    if args.command == "serve":
        uvicorn.run("payoutproof.api.app:app", host=args.host, port=args.port, reload=True)
    elif args.command == "eval":
        run_benchmark(args.suite)
    elif args.command == "verify-audit":
        verify_case_audit(args.case_id)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
