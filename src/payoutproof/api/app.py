"""FastAPI control plane API for PayoutProof.

Organization scope is mandatory: every case, policy, grant, handoff, and audit
route requires a non-blank X-Organization-Id header. There is no default
organization and no un-scoped legacy access path. Only /api/health and
/api/release (secret-free release metadata) are exempt.
"""

import hmac
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from payoutproof.core.models import RiskCaseState
from payoutproof.core.enums import PolicyOutcome, CasePhase, IntentStatus, DemoFakeAdapterMode
from payoutproof.core.config import AppConfig, ConfigurationError
from payoutproof.core.release import get_release_metadata, APPLICATION_VERSION
from payoutproof.core.providers import ClockProvider, NonceProvider
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.case_workflow.handoff_service import HandoffService
from payoutproof.storage.db import (
    Database,
    StaleCaseStateError,
    GrantTransitionError,
    AuditLedgerIntegrityError,
)
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.audit.chain import AuditChain
from payoutproof.scorer.service import EvaluationExecutionService


ALLOWED_ACTIONS = {
    "RESET",
    "ADMIT_AUTHORIZED_BUNDLE",
    "SUBMIT_UNAUTHORIZED_BUNDLE",
    "EXTRACT_INTENT",
    "FAIL_MODEL",
    "CONFIRM_INTENT",
    "ADD_CALLBACK_EVIDENCE",
    "ADD_DESTINATION_APPROVAL",
    "ADD_CONTRADICTION",
    "SUBMIT_TAMPERED_SNAPSHOT",
    "EVALUATE_POLICY",
    "ISSUE_GRANT",
    "EDIT_AMOUNT",
    "MODIFY_INTENT",
    "INITIATE_HANDOFF",
}

REMOVED_OUTCOME_COMMANDS = {
    "HANDOFF_ACCEPTED",
    "HANDOFF_AMBIGUOUS",
    "REPLAY_GRANT",
}

DISALLOWED_PAYLOAD_FIELDS = {
    "pending_item_id",
    "adapter_decision",
    "outcome",
    "grant_status",
    "used",
    "state",
    "phase",
    "case_version",
    "status",
    "last_adapter_decision",
    "policy_outcome",
    "idempotency_key",
}


class ActionRequest(BaseModel):
    type: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class CreateCaseRequest(BaseModel):
    case_id: Optional[str] = None
    tenant_id: str = "tenant_default"
    organization_id: Optional[str] = None


ORGANIZATION_HEADER = "X-Organization-Id"


def _require_organization_id(request: Request) -> str:
    """Resolve the caller's mandatory active organization from X-Organization-Id.

    There is no default organization: an absent, empty, or whitespace-only
    header is rejected with HTTP 400. The resolved value is stripped and used
    verbatim as the exclusive scope for every subsequent read and write.
    """
    raw = request.headers.get(ORGANIZATION_HEADER)
    if raw is None:
        raise HTTPException(status_code=400, detail="Missing mandatory organization identity")
    organization_id = raw.strip()
    if not organization_id:
        raise HTTPException(status_code=400, detail="Missing mandatory organization identity")
    return organization_id


def _resolve_db(request: Request) -> Database:
    """Resolve database instance from app.state (sole owner of dependencies)."""
    db_instance = getattr(request.app.state, "db", None)
    if db_instance is None:
        raise HTTPException(status_code=500, detail="Database dependency not configured")
    return db_instance


def _resolve_adapter(request: Request) -> FakeApprovalRailAdapter:
    """Resolve action adapter from app.state (sole owner of dependencies)."""
    adapter_instance = getattr(request.app.state, "adapter", None)
    if adapter_instance is None:
        raise HTTPException(status_code=500, detail="Adapter dependency not configured")
    return adapter_instance


def _resolve_config(request: Request) -> AppConfig:
    """Resolve immutable AppConfig attached to app.state."""
    config = getattr(request.app.state, "config", None)
    if config is None:
        raise HTTPException(status_code=500, detail="Configuration dependency not configured")
    return config


router = APIRouter()


@router.get("/api/health")
def get_health() -> Dict[str, Any]:
    """Liveness, readiness, capability status, and secret-free release identity.

    The `release` block pins the exact application, policy, schema, model
    configuration, and Evaluation Version identifiers for this build. It is
    safe by construction: ReleaseMetadata contains no secrets, no paths, and
    no environment data (unlike AppConfig, whose secrets must stay redacted).
    """
    release = get_release_metadata()
    return {
        "status": "HEALTHY",
        "service": "PayoutProof Control Plane",
        "version": release.application_version,
        "database": "SQLite WAL active",
        "maturity": release.maturity,
        "release": release.to_public_dict(),
        "capabilities": {
            "admission": "IN_DEVELOPMENT",
            "policy_gate": "IN_DEVELOPMENT",
            "grant_issuer": "IN_DEVELOPMENT",
            "fake_adapter": "IN_DEVELOPMENT",
            "audit_chain": "IN_DEVELOPMENT",
            "durable_replay_protection": "UNIT_TESTED",
        },
    }


@router.get("/api/release")
def get_release() -> Dict[str, Any]:
    """Secret-free release identity: application, policy, schema, model config, Evaluation Version.

    Publishes exactly the stable identifiers carried by ReleaseMetadata.
    Evidence scope is declared honestly: the bound Evaluation Version covers
    the synthetic structured harnesses only, not held-out or pilot proof.
    """
    release = get_release_metadata()
    return release.to_public_dict()


@router.get("/api/cases")
def list_cases(request: Request) -> List[Dict[str, Any]]:
    """List existing Risk Cases strictly within the caller's active organization."""
    active_db = _resolve_db(request)
    organization_id = _require_organization_id(request)
    return active_db.list_cases(organization_id=organization_id)


@router.post("/api/cases")
def create_case(req: CreateCaseRequest, request: Request) -> RiskCaseState:
    """Initialize a new Risk Case (unadmitted) serialized in a transaction.

    Organization scope is mandatory: provided via X-Organization-Id header
    or request body. If both are provided, they must agree. Creation without
    an explicit organization is rejected with HTTP 400.
    """
    import uuid
    active_db = _resolve_db(request)
    raw_header = request.headers.get(ORGANIZATION_HEADER)
    header_org = raw_header.strip() if raw_header else None
    organization_id = header_org or req.organization_id
    if not organization_id or not str(organization_id).strip():
        raise HTTPException(
            status_code=400,
            detail="Missing mandatory organization identity",
        )
    organization_id = str(organization_id).strip()
    if req.organization_id is not None and header_org is not None and req.organization_id.strip() != header_org:
        raise HTTPException(
            status_code=400,
            detail=f"Request body organization_id '{req.organization_id}' conflicts with active organization '{header_org}'",
        )
    case_id = req.case_id or f"RC-{uuid.uuid4().hex[:8].upper()}"
    with active_db.get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        try:
            existing = active_db.load_case_tx(conn, case_id)
            if existing is not None:
                raise HTTPException(status_code=409, detail=f"Case '{case_id}' already exists")
            state = StateMachine.initial_state(
                case_id=case_id,
                tenant_id=req.tenant_id,
                organization_id=organization_id,
            )
            active_db.save_case_tx(conn, state)
            conn.commit()
            return state
        except AuditLedgerIntegrityError as e:
            conn.rollback()
            raise HTTPException(status_code=409, detail=f"Audit ledger integrity failure: {e}")
        except HTTPException:
            conn.rollback()
            raise
        except Exception:
            conn.rollback()
            raise


@router.get("/api/cases/{case_id}")
def get_case(case_id: str, request: Request) -> RiskCaseState:
    """Get full state of a Risk Case (read-only; returns 404 if absent or out of scope).

    Zero-existence oracle: a case that does not exist and a case belonging to a
    different organization are indistinguishable — both return strictly 404.
    Cross-tenant access never yields 403 or any hint the case exists.
    """
    active_db = _resolve_db(request)
    organization_id = _require_organization_id(request)

    scope = active_db.get_case_scope(case_id)
    if scope is None or scope["organization_id"] != organization_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    try:
        state = active_db.load_case(case_id)
    except AuditLedgerIntegrityError as e:
        raise HTTPException(status_code=409, detail=f"Audit ledger integrity failure: {e}")
    if not state:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return state


@router.post("/api/cases/{case_id}/dispatch")
def dispatch_action(case_id: str, req: ActionRequest, request: Request) -> RiskCaseState:
    """Dispatch a lifecycle transition action to a Risk Case.

    All mutations are serialized through SQLite BEGIN IMMEDIATE transactions.
    """
    # 0. Organization identity is mandatory before any case or action handling
    request_organization_id = _require_organization_id(request)

    action_type = (req.type or "").strip()

    # 1. Reject direct internal outcome command names with HTTP 400
    if action_type in REMOVED_OUTCOME_COMMANDS:
        raise HTTPException(
            status_code=400,
            detail=f"Direct outcome command '{action_type}' has been removed from API. Outcomes are server-owned.",
        )

    # 2. Reject unsupported actions with HTTP 400
    if action_type not in ALLOWED_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Malformed or unsupported action command type: '{req.type}'",
        )

    # 3. Reject client payload fields such as pending_item_id, adapter_decision, outcome, grant_status, used, or state overrides
    payload = req.payload or {}
    disallowed_found = [k for k in payload.keys() if k in DISALLOWED_PAYLOAD_FIELDS]
    if disallowed_found:
        raise HTTPException(
            status_code=400,
            detail=f"Disallowed client payload fields: {disallowed_found}. Clients cannot author adapter outcomes or state overrides.",
        )

    active_db = _resolve_db(request)
    active_adapter = _resolve_adapter(request)
    config = _resolve_config(request)
    clock = getattr(request.app.state, "clock", None)
    nonce_provider = getattr(request.app.state, "nonce_provider", None)

    # 4. Missing or out-of-scope case returns 404 for all actions (zero-existence oracle:
    #    a cross-organization case is reported exactly like a missing one)
    scope = active_db.get_case_scope(case_id)
    if scope is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    if scope["organization_id"] != request_organization_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    try:
        persisted_case = active_db.load_case(case_id)
    except AuditLedgerIntegrityError as e:
        raise HTTPException(
            status_code=409,
            detail=f"Audit ledger integrity failure: {e}",
        )
    if not persisted_case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    # 5. Reject fake_adapter_mode for non-handoff actions or when disabled
    fake_adapter_mode = payload.get("fake_adapter_mode")
    if fake_adapter_mode is not None:
        if action_type != "INITIATE_HANDOFF":
            raise HTTPException(
                status_code=400,
                detail="fake_adapter_mode is only permitted for INITIATE_HANDOFF",
            )
        if not config.enable_demo_adapter_modes:
            raise HTTPException(
                status_code=400,
                detail="fake_adapter_mode simulation is disabled. Demo simulation modes are only permitted in local demo mode.",
            )

    # 6. Handle INITIATE_HANDOFF via server-owned HandoffService (which opens its own BEGIN IMMEDIATE)
    if action_type == "INITIATE_HANDOFF":
        simulate_ambiguity = False
        if fake_adapter_mode is not None:
            try:
                mode_enum = DemoFakeAdapterMode(fake_adapter_mode)
                simulate_ambiguity = (mode_enum == DemoFakeAdapterMode.SIMULATE_AMBIGUITY)
            except (ValueError, KeyError):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid fake_adapter_mode '{fake_adapter_mode}'. Only {[m.value for m in DemoFakeAdapterMode]} is permitted.",
                )

        try:
            next_state = HandoffService.execute_handoff(
                state=persisted_case,
                adapter=active_adapter,
                grant_secret=config.grant_secret,
                simulate_ambiguity=simulate_ambiguity,
            )
            return next_state
        except AuditLedgerIntegrityError as e:
            raise HTTPException(
                status_code=409,
                detail=f"Audit ledger integrity failure: {e}",
            )
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="Internal error during handoff processing; operation aborted safely fail-closed.",
            )

    # 7. For all other mutating actions, serialize in an explicit BEGIN IMMEDIATE transaction
    with active_db.get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        try:
            current_state = active_db.load_case_tx(conn, case_id)
            if not current_state:
                raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

            # Scope is re-checked inside the write transaction so a concurrent
            # re-scope or deletion cannot slip an out-of-scope mutation through.
            if current_state.organization_id != request_organization_id:
                raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

            next_state = StateMachine.reduce(
                state=current_state,
                action={"type": action_type, "payload": payload},
                grant_secret=config.grant_secret,
                clock=clock,
                nonce_provider=nonce_provider,
            )

            # Persist updated state and audit events
            active_db.save_case_tx(conn, next_state)
            conn.commit()
            return next_state
        except AuditLedgerIntegrityError as e:
            conn.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"Audit ledger integrity failure: {e}",
            )
        except (StaleCaseStateError, GrantTransitionError) as e:
            conn.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"State conflict: {e}",
            )
        except HTTPException:
            conn.rollback()
            raise
        except Exception as e:
            conn.rollback()
            raise HTTPException(
                status_code=500,
                detail=f"Internal error during action dispatch: {e}",
            )


@router.get("/api/audit/verify/{case_id}")
def verify_audit(case_id: str, request: Request) -> Dict[str, Any]:
    """Verify cryptographic integrity of the audit chain for a case in the caller's organization.

    Zero-existence oracle: an absent case and another organization's case are
    indistinguishable — both return strictly 404.
    """
    active_db = _resolve_db(request)
    organization_id = _require_organization_id(request)

    scope = active_db.get_case_scope(case_id)
    if scope is None or scope["organization_id"] != organization_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    result = active_db.verify_case_audit(case_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    return {
        "case_id": case_id,
        "total_events": result["event_count"],
        "event_count": result["event_count"],
        "is_valid": result["is_valid"],
        "trust_state": result["trust_state"],
        "broken_at_seq": result.get("broken_at_seq"),
        "reason": result.get("reason"),
    }


@router.post("/api/evaluate/run")
def run_evaluation(suite: str = "dev") -> Dict[str, Any]:
    """Run an evaluation benchmark suite and return aggregate statistical report."""
    try:
        report = EvaluationExecutionService.run_suite(suite)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return report.model_dump(mode="json")



def create_app(
    config: Optional[AppConfig] = None,
    db: Optional[Database] = None,
    clock: Optional[ClockProvider] = None,
    nonce_provider: Optional[NonceProvider] = None,
) -> FastAPI:
    """Factory creating FastAPI application configured with AppConfig.

    Owns Database, adapter, and dependencies attached via app.state.
    Strict default composition from AppConfig.from_env; no silent secret fallback.
    """
    if config is None:
        config = AppConfig.from_env()

    app_instance = FastAPI(
        title="PayoutProof API",
        version=APPLICATION_VERSION,
        description="Trust Agent and Deterministic Policy Gate for Payment Risk",
    )

    app_instance.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if db is not None:
        db_secret = getattr(db, "audit_checkpoint_secret", None)
        if db_secret is None or not hmac.compare_digest(str(db_secret), config.audit_checkpoint_secret):
            raise ConfigurationError(
                "Injected Database audit_checkpoint_secret does not match AppConfig audit_checkpoint_secret"
            )
        resolved_db = db
    else:
        resolved_db = Database(
            db_path=config.db_path,
            audit_checkpoint_secret=config.audit_checkpoint_secret,
        )

    resolved_adapter = FakeApprovalRailAdapter(
        db=resolved_db,
        grant_secret=config.grant_secret,
        audit_checkpoint_secret=config.audit_checkpoint_secret,
    )

    app_instance.state.config = config
    app_instance.state.db = resolved_db
    app_instance.state.adapter = resolved_adapter
    app_instance.state.clock = clock
    app_instance.state.nonce_provider = nonce_provider

    app_instance.include_router(router)
    return app_instance
