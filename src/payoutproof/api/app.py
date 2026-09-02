"""FastAPI control plane API for PayoutProof."""

from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from payoutproof.core.models import RiskCaseState, AuditEvent
from payoutproof.core.enums import PolicyOutcome, CasePhase, IntentStatus
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.storage.db import Database
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.audit.chain import AuditChain
from payoutproof.simulator.generator import Simulator
from payoutproof.scorer.scorer import EvaluationScorer
from payoutproof.grants.issuer import DEFAULT_GRANT_SECRET

app = FastAPI(
    title="PayoutProof API",
    version="0.1.0",
    description="Trust Agent and Deterministic Policy Gate for Payment Risk",
)

# Enable CORS for local Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory / SQLite singletons
db = Database()
adapter = FakeApprovalRailAdapter(grant_secret=DEFAULT_GRANT_SECRET)


class ActionRequest(BaseModel):
    type: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class CreateCaseRequest(BaseModel):
    case_id: Optional[str] = None
    tenant_id: str = "tenant_default"


@app.get("/api/health")
def get_health() -> Dict[str, Any]:
    """Liveness, readiness, and capability status."""
    return {
        "status": "HEALTHY",
        "service": "PayoutProof Control Plane",
        "version": "0.1.0",
        "database": "SQLite WAL active",
        "capabilities": {
            "admission": "READY",
            "policy_gate": "READY",
            "grant_issuer": "READY",
            "fake_adapter": "READY",
            "audit_chain": "READY",
        }
    }


@app.get("/api/cases")
def list_cases() -> List[Dict[str, Any]]:
    """List existing Risk Cases."""
    return db.list_cases()


@app.post("/api/cases")
def create_case(req: CreateCaseRequest) -> RiskCaseState:
    """Initialize a new Risk Case."""
    case_id = req.case_id or f"RC-DEMO-{Simulator.generate_dev_corpus()[0].case_id.split('-')[-1]}"
    state = StateMachine.initial_state(case_id=case_id, tenant_id=req.tenant_id)
    db.save_case(state)
    return state


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> RiskCaseState:
    """Get full state of a Risk Case."""
    state = db.load_case(case_id)
    if not state:
        # If not found, initialize a fresh demo case
        state = StateMachine.initial_state(case_id=case_id)
        db.save_case(state)
    return state


@app.post("/api/cases/{case_id}/dispatch")
def dispatch_action(case_id: str, req: ActionRequest) -> RiskCaseState:
    """Dispatch a lifecycle transition action to a Risk Case."""
    current_state = db.load_case(case_id)
    if not current_state:
        current_state = StateMachine.initial_state(case_id=case_id)

    # Apply pure state transition
    next_state = StateMachine.reduce(
        state=current_state,
        action={"type": req.type, "payload": req.payload},
        adapter=adapter,
        grant_secret=DEFAULT_GRANT_SECRET,
    )

    # Persist updated state and audit events
    db.save_case(next_state)
    return next_state


@app.get("/api/audit/verify/{case_id}")
def verify_audit(case_id: str) -> Dict[str, Any]:
    """Verify cryptographic integrity of the audit chain for a case."""
    state = db.load_case(case_id)
    if not state:
        raise HTTPException(status_code=404, detail="Case not found")

    is_valid, broken_seq, reason = AuditChain.verify_chain(state.audit)
    return {
        "case_id": case_id,
        "total_events": len(state.audit),
        "is_valid": is_valid,
        "broken_at_seq": broken_seq,
        "reason": reason,
    }


@app.post("/api/evaluate/run")
def run_evaluation(suite: str = "dev") -> Dict[str, Any]:
    """Run an evaluation benchmark suite and return aggregate statistical report."""
    from payoutproof.scorer.runner import execute_case_under_test

    if suite.lower() == "sealed":
        cases = Simulator.generate_sealed_corpus()
    elif suite.lower() == "safety":
        cases = Simulator.generate_safety_corpus()
    else:
        cases = Simulator.generate_dev_corpus()

    results = [execute_case_under_test(c) for c in cases]
    report = EvaluationScorer.score_results(results)
    return report.model_dump()
