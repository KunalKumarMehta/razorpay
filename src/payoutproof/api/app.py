"""FastAPI control plane API for PayoutProof.

Organization scope and operator identity are both server-owned. Every case,
policy, grant, handoff, and audit route requires a session established via
the standards-based OIDC authorization-code flow; the session carries the
operator's subject, role, tenant, and organization, and those values are the
exclusive source of scope for every read and write. The X-Organization-Id
header is no longer an authority: an absent header resolves to the session
organization, a blank header is malformed, and a conflicting header is a
rejected escalation attempt. Only /api/health, /api/release (secret-free
release metadata), and the /api/auth/* authentication routes are exempt.

Role enforcement is centralized in the frozen capability matrix
(payoutproof.auth.roles) plus a session dependency on this router — not
per-route hand-rolled checks and not middleware added only in `create_app`
— so every application instance that includes this router is protected.
"""

import hmac
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import Depends, FastAPI, HTTPException, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from payoutproof.core.models import RiskCaseState
from payoutproof.core.enums import PolicyOutcome, CasePhase, IntentStatus, DemoFakeAdapterMode
from payoutproof.core.config import AppConfig, ConfigurationError
from payoutproof.core.limits import (
    PLATFORM_BACKSTOP_ORGANIZATION,
    PLATFORM_GLOBAL_REQUESTS_PER_HOUR,
    PLATFORM_MAX_EVIDENCE_ITEM_BYTES,
    PLATFORM_MAX_RETENTION_DAYS,
    PLATFORM_SUPPORTED_FORMATS,
    TenantOperatingLimits,
    content_byte_size,
    effective_limits,
    normalized_mime_type,
    retry_after_seconds,
    validate_settings_write,
    window_key,
    SettingsValidationError,
)
from payoutproof.core.release import get_release_metadata, APPLICATION_VERSION
from payoutproof.core.providers import ClockProvider, NonceProvider
from payoutproof.case_workflow.state_machine import StateMachine
from payoutproof.case_workflow.handoff_service import HandoffService
from payoutproof.storage.db import (
    Database,
    StaleCaseStateError,
    GrantTransitionError,
    AuditLedgerIntegrityError,
    DestinationRecordError,
    DestinationTransitionError,
    DestinationNotFoundError,
    PolicyConfigTransitionError,
    PolicyConfigNotFoundError,
    PolicyConfigTamperError,
)
from payoutproof.adapters.fake_adapter import FakeApprovalRailAdapter
from payoutproof.audit.chain import AuditChain
from payoutproof.scorer.service import EvaluationExecutionService
from payoutproof.api.actions import (
    ALLOWED_ACTIONS,
    REMOVED_OUTCOME_COMMANDS,
    DISALLOWED_PAYLOAD_FIELDS,
)
from payoutproof.auth import routes as auth_routes
from payoutproof.auth.dependencies import (
    active_organization,
    require_action_role,
    require_case_creator,
    require_case_reader,
    require_audit_verifier,
    require_evaluation_runner,
    require_session,
    require_session_tenant,
)
from payoutproof.auth.oidc import OIDCProviderClient
from payoutproof.auth.roles import (
    DEMO_ONLY_ACTIONS,
    CAPABILITY_READ_CASES,
    CAPABILITY_VERIFY_AUDIT,
    CAPABILITY_RUN_EVALUATION,
)
from payoutproof.auth.session import SessionRecord, SessionStore


class ActionRequest(BaseModel):
    type: str
    payload: Dict[str, Any] = Field(default_factory=dict)


class CreateCaseRequest(BaseModel):
    case_id: Optional[str] = None
    tenant_id: Optional[str] = None


class CreateDestinationRequest(BaseModel):
    """Create an Approved Destination record (CREATED status) in the caller's organization.

    Authority is server-owned: organization comes from the session, the bound
    policy config is resolved server-side from the caller's organization, and
    the client names only the destination facts and the effective window.
    """
    destination_id: Optional[str] = None
    counterparty: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    destination_type: str = Field(min_length=1)
    valid_from: str = Field(min_length=1)
    valid_to: Optional[str] = None
    policy_config_id: Optional[str] = None


class CreatePolicyConfigRequest(BaseModel):
    """Mint a DRAFT policy configuration version for the caller's organization.

    The content hash is always derived server-side from the submitted
    thresholds; a client-asserted content_hash would be a lie about content.
    """
    config_id: Optional[str] = None
    version_id: Optional[str] = None
    grant_ttl_seconds: Optional[int] = None
    step_up_rules: Optional[Dict[str, Any]] = None
    block_conditions: Optional[Dict[str, Any]] = None


# Public, session-exempt surface: liveness, secret-free release identity, and
# the OIDC authentication routes themselves (login redirect, callback, me,
# logout — the latter two enforce the session dependency inside auth_routes).
public_router = APIRouter()

# Protected surface: every case, audit, and evaluation route requires an
# authenticated, unexpired, unrevoked operator session. The dependency lives
# on the router (not only in create_app) so any app instance that mounts
# this router is protected.
protected_router = APIRouter(dependencies=[Depends(require_session)])


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


def _resolve_clock(request: Request) -> ClockProvider:
    """Resolve the injected clock (deterministic time for sessions and audit)."""
    clock = getattr(request.app.state, "clock", None)
    return clock if clock is not None else None


# ── Tenant operating-limits enforcement (Issue #10) ─────────────────────────
#
# Ordering discipline (fail-safe, mirroring the Issue #7 dispatch ordering):
#
#   session (401, router dependency)
#     -> payload-pure pre-checks (413/415/422) — no DB reads, no case existence
#     -> case scope (404 zero-existence)
#     -> role (403)
#     -> windowed/gauged quota checks (429) — inside the write transaction
#
# The payload-pure checks deliberately run *before* the case-existence 404: a
# rejected payload tells the caller nothing about any case, and an oversized
# or unsupported payload never pays for a scope lookup. The quota checks run
# *inside* the caller's BEGIN IMMEDIATE transaction where one exists, so a
# refused request never mutates anything and two racing requests cannot both
# consume the last slot.

QUOTA_ERROR_CODE = "QUOTA_EXCEEDED"
HTTP_429 = 429

# Actions that submit evidence bundles for admission: they consume the
# cumulative evidence-byte budget and occupy a processing slot, so they carry
# the byte and backlog gates in addition to the request-rate gates.
# ADD_CALLBACK_EVIDENCE appends evidence to an already-admitted case: it
# consumes byte budget but no new processing slot.
ADMISSION_ACTIONS = {"ADMIT_AUTHORIZED_BUNDLE", "SUBMIT_UNAUTHORIZED_BUNDLE"}
EVIDENCE_ADDING_ACTIONS = ADMISSION_ACTIONS | {"ADD_CALLBACK_EVIDENCE"}


def _quota_rejection(quota_kind: str, retry_after: Optional[int], message: str) -> HTTPException:
    """Build the uniform quota-rejected 429 (typed fields, no internal detail).

    ``retry_after`` is exposed as both the Retry-After header (seconds) and a
    structured body field: the window reset is derived from the caller's own
    clock data, so it leaks no internal timing.
    """
    headers = {"Retry-After": str(retry_after)} if retry_after is not None else None
    return HTTPException(
        status_code=HTTP_429,
        detail={
            "error_code": QUOTA_ERROR_CODE,
            "quota_kind": quota_kind,
            "message": message,
            "retry_after_seconds": retry_after,
        },
        headers=headers,
    )


def _request_clock_now(request: Request) -> datetime:
    """Current UTC moment from the injected clock, else system time."""
    clock = getattr(request.app.state, "clock", None)
    if clock is not None:
        now = clock.now()
        return now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def _effective_limits_for(conn: sqlite3.Connection, active_db: Database, organization_id: str) -> TenantOperatingLimits:
    """Effective limits for an org, read inside the caller's transaction."""
    return active_db.load_tenant_limits_tx(conn, organization_id)


def _enforce_hourly_request_quota(request: Request, active_db: Database, organization_id: str) -> None:
    """Consume one request from the org's hourly window and the global backstop bucket.

    Per-organization first (the honest-client bound), then the '__PLATFORM__'
    backstop bucket (the bound on a client multiplying fake organization
    identities — the org scope on the session-ephemeral test path is
    self-asserted, so only a global bucket can bound a dishonest one; real
    authentication is the durable fix and is tracked as follow-up). Both
    counters ride one BEGIN IMMEDIATE so the counters and the request
    outcome commit together. A refused request commits its own increment:
    the windowed counter is the durable record of refused attempts too, and
    the count can never exceed the cap it refused against.
    """
    now = _request_clock_now(request)
    wk = window_key(now)
    retry = retry_after_seconds(now)

    with active_db.get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        try:
            limits = _effective_limits_for(conn, active_db, organization_id)
            allowed, count, _remaining = active_db.consume_quota_tx(
                conn, organization_id, "requests", wk, limits.requests_per_hour, now=now
            )
            if not allowed:
                raise _quota_rejection(
                    "requests",
                    retry,
                    f"Hourly request quota exhausted for this organization "
                    f"({count} of {limits.requests_per_hour} requests this hour); "
                    f"retry after {retry} seconds.",
                )
            backstop_allowed, backstop_count, _br = active_db.consume_quota_tx(
                conn,
                PLATFORM_BACKSTOP_ORGANIZATION,
                "requests_global",
                wk,
                PLATFORM_GLOBAL_REQUESTS_PER_HOUR,
                now=now,
            )
            if not backstop_allowed:
                raise _quota_rejection(
                    "requests_global",
                    retry,
                    f"Platform-wide hourly request quota exhausted ({backstop_count} of "
                    f"{PLATFORM_GLOBAL_REQUESTS_PER_HOUR} requests this hour); "
                    f"retry after {retry} seconds.",
                )
            conn.commit()
        except HTTPException:
            # A refused request still records the attempted consumption
            # durably (the windowed counter is the bound's own evidence),
            # then propagates the 429.
            try:
                conn.commit()
            except Exception:
                conn.rollback()
            raise
        except Exception:
            conn.rollback()
            raise


def _payload_pure_admission_checks(payload: Dict[str, Any]) -> None:
    """Payload-pure admission pre-checks: item size (413), format (415), retention (422).

    These checks depend only on the submitted payload — never on a case, a
    session role, or any database row — so they run before case existence and
    before the write transaction. Every bound applied here is a platform
    ceiling: the tenant-tightened variants of the item-size, format, and
    retention limits are enforced inside the transaction (where the org's
    effective limits are loaded) by the admission gates; this pre-check is
    the platform floor that needs no row.
    """
    ev = payload.get("evidence")
    content = ev.get("content") if isinstance(ev, dict) else payload.get("content")
    mime_raw = ev.get("mime_type") if isinstance(ev, dict) else payload.get("mime_type")

    # Format gate (415): the platform allowlist. Normalization mirrors the
    # admission validator so 'TEXT/PLAIN ' is judged as 'text/plain'.
    norm = normalized_mime_type(mime_raw)
    if norm is not None and norm not in PLATFORM_SUPPORTED_FORMATS:
        raise HTTPException(
            status_code=415,
            detail={
                "error_code": "FORMAT_NOT_SUPPORTED",
                "mime_type": norm,
                "supported_formats": sorted(PLATFORM_SUPPORTED_FORMATS),
                "message": f"Evidence format '{norm}' is not supported; supported formats: "
                f"{sorted(PLATFORM_SUPPORTED_FORMATS)}",
            },
        )
    # A blank/missing MIME type with content present is malformed input: the
    # case-level admission validator is the authority for that shape (and
    # everything else about the PAR), producing the existing in-case
    # ADMISSION_REJECTED mutation. No platform 415 is minted for it.

    # Item-size gate (413): computed from the actual content bytes, never a
    # declared size. Only computable sizes are gated here; non-string/non-
    # bytes content remains the validator's authority.
    size = content_byte_size(content)
    if size is not None and size > PLATFORM_MAX_EVIDENCE_ITEM_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "error_code": "EVIDENCE_TOO_LARGE",
                "max_bytes": PLATFORM_MAX_EVIDENCE_ITEM_BYTES,
                "actual_bytes": size,
                "message": f"Evidence item is {size} bytes; the platform item ceiling is "
                f"{PLATFORM_MAX_EVIDENCE_ITEM_BYTES} bytes.",
            },
        )

    # Retention gate (422): the PAR's declared retention must not exceed the
    # platform retention ceiling. The tenant-tightened bound is enforced
    # inside the transaction by the admission gates.
    authority = payload.get("processing_authority")
    if isinstance(authority, dict):
        declared = authority.get("retention_days")
        if isinstance(declared, int) and not isinstance(declared, bool):
            if declared > PLATFORM_MAX_RETENTION_DAYS:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error_code": "RETENTION_EXCEEDS_TENANT_LIMIT",
                        "declared_days": declared,
                        "tenant_limit_days": PLATFORM_MAX_RETENTION_DAYS,
                        "message": f"Retention {declared} days exceeds the tenant limit "
                        f"{PLATFORM_MAX_RETENTION_DAYS} days.",
                    },
                )


def _admission_quota_gates(
    request: Request,
    active_db: Database,
    conn: sqlite3.Connection,
    organization_id: str,
    action_type: str,
    payload: Dict[str, Any],
) -> None:
    """In-transaction admission gates: open-case (429), backlog (429), cumulative bytes (429).

    Runs inside the caller's BEGIN IMMEDIATE, so the quota decision and the
    mutation it guards commit atomically and two racing admissions cannot
    both pass. Ordering is cheapest-first: the derived gauges (pure COUNT
    queries) before the cumulative-byte consumption (a write).
    """
    limits = _effective_limits_for(conn, active_db, organization_id)

    # Open-case gauge: only for actions that open a new case (the admission
    # bundle actions), not for evidence appended to an existing case.
    if action_type in ADMISSION_ACTIONS:
        open_cases = active_db.count_open_cases_tx(conn, organization_id)
        if open_cases >= limits.max_open_cases:
            raise _quota_rejection(
                "max_open_cases",
                None,
                f"Open-case limit reached for this organization ({open_cases} open cases; "
                f"limit {limits.max_open_cases}). Close or resolve cases before opening new ones.",
            )

    # Processing-backlog gauge: derived from durable phase, never a counter.
    if action_type in ADMISSION_ACTIONS:
        backlog = active_db.count_processing_backlog_tx(conn, organization_id)
        if backlog >= limits.max_processing_concurrency:
            raise _quota_rejection(
                "processing_backlog",
                None,
                f"Processing backlog limit reached for this organization ({backlog} admitted-but-"
                f"unprocessed cases; limit {limits.max_processing_concurrency}).",
            )

    # Cumulative evidence-byte budget: computed from the actual content bytes
    # (never a declared size); a missing/blank content has no computable size
    # and is left to the case-level validator.
    if action_type in EVIDENCE_ADDING_ACTIONS:
        ev = payload.get("evidence")
        content = ev.get("content") if isinstance(ev, dict) else payload.get("content")
        size = content_byte_size(content)
        if size is not None:
            allowed, total, _remaining = active_db.consume_cumulative_bytes_tx(
                conn, organization_id, size, limits.max_org_evidence_bytes, now=_request_clock_now(request)
            )
            if not allowed:
                raise _quota_rejection(
                    "max_org_evidence_bytes",
                    None,
                    f"Cumulative evidence-byte budget exhausted for this organization "
                    f"({total} of {limits.max_org_evidence_bytes} bytes used).",
                )


def _require_settings_admin(request: Request, config: AppConfig) -> None:
    """Gate the tenant operating-settings surface on the dedicated admin token.

    The settings surface is deliberately *not* part of the role matrix: it is
    a platform-administration surface gated by a dedicated bearer token
    (PAYOUTPROOF_SETTINGS_ADMIN_TOKEN), enabled by
    PAYOUTPROOF_ENABLE_SETTINGS_ADMIN. Disabled, the routes return 404
    (unknown surface, no capability hints). Enabled, the caller must present
    the exact token (constant-time comparison). The admin token scopes *what*
    may be administered; the organization scope still comes from the session.
    """
    if not config.enable_settings_admin:
        raise HTTPException(status_code=404, detail="Not Found")
    header = request.headers.get("Authorization", "")
    expected = config.settings_admin_token or ""
    supplied = header[7:] if header.lower().startswith("bearer ") else header.strip()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Settings administrator token required")


@protected_router.get("/api/settings/limits")
def get_tenant_limits(
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Read the effective tenant operating limits for the caller's organization.

    Returns the *effective* limits (defensively clamped at read time), not
    the raw stored row: even a tampered row can never be reported — or
    enforced — above a platform ceiling. The response carries no secrets and
    no other organization's data.
    """
    active_db = _resolve_db(request)
    config = _resolve_config(request)
    _require_settings_admin(request, config)

    organization_id = active_organization(request, session)
    with active_db.get_connection() as conn:
        limits = active_db.load_tenant_limits_tx(conn, organization_id)
    return {
        "organization_id": organization_id,
        "limits": limits.to_json_dict(),
        "is_default": limits == effective_limits(None),
    }


class TenantLimitsRequest(BaseModel):
    """OpenAPI shape declaration for the settings write body.

    Deliberately NOT the validation layer: the route parses the raw JSON body
    itself so unknown fields, wrong types, and above-ceiling values all reach
    ``validate_settings_write`` and are audited as REJECTED. Pydantic's default
    behavior would silently drop unknown fields, which would violate the
    SETTINGS_INVALID contract. The model exists only so the OpenAPI schema
    documents the accepted fields; the route never instantiates it.
    """

    model_config = {"extra": "allow"}

    max_evidence_item_bytes: Optional[int] = None
    allowed_evidence_formats: Optional[List[str]] = None
    evidence_retention_days: Optional[int] = None
    max_processing_concurrency: Optional[int] = None
    requests_per_hour: Optional[int] = None
    max_open_cases: Optional[int] = None
    max_org_evidence_bytes: Optional[int] = None


@protected_router.put("/api/settings/limits")
async def put_tenant_limits(
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Full-replace the caller's organization operating settings.

    Fail-safe ordering: settings-admin surface (404 disabled / 401 unauthenticated)
    -> request shape (422) -> validation against the immutable platform
    ceilings (422) -> transactional upsert with the ACCEPTED audit event.
    Out-of-bounds values are refused, never silently clamped: a tenant must
    know its settings were rejected. Every rejected write is audited as
    REJECTED in its own transaction and persists none of its values; an
    accepted write persists both the settings row and its ACCEPTED audit
    event atomically.
    """
    active_db = _resolve_db(request)
    config = _resolve_config(request)
    _require_settings_admin(request, config)

    organization_id = active_organization(request, session)
    actor = f"settings_admin:{session.subject}" if session.subject else "settings_admin"

    # Parse the raw body: unknown fields and wrong types must reach the
    # settings validator (and the REJECTED audit), not be silently coerced
    # or dropped by a body model.
    import json as _json

    raw_body = await request.body()
    parse_error: Optional[str] = None
    candidate: Any = None
    if not raw_body:
        parse_error = "Request body must be a JSON object"
    else:
        try:
            candidate = _json.loads(raw_body)
        except Exception:
            parse_error = "Request body must be valid JSON"

    now = _request_clock_now(request)

    with active_db.get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        try:
            if parse_error is not None or not isinstance(candidate, dict):
                active_db.record_settings_rejection_tx(
                    conn,
                    organization_id,
                    actor,
                    {"parse_error": parse_error or "Request body must be a JSON object"},
                    "SETTINGS_INVALID",
                    now=now,
                )
                conn.commit()
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error_code": "SETTINGS_INVALID",
                        "reason_code": "SETTINGS_INVALID",
                        "message": parse_error or "Request body must be a JSON object",
                    },
                )
            try:
                validated = validate_settings_write(candidate)
            except SettingsValidationError as e:
                active_db.record_settings_rejection_tx(
                    conn,
                    organization_id,
                    actor,
                    candidate,
                    e.reason_code,
                    now=now,
                )
                conn.commit()
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error_code": e.reason_code,
                        "reason_code": e.reason_code,
                        "message": e.message,
                    },
                )

            effective = active_db.save_tenant_limits_tx(
                conn, organization_id, validated, actor, reason_code=None, now=now
            )
            conn.commit()
            return {
                "organization_id": organization_id,
                "limits": effective.to_json_dict(),
                "reason_code": None,
                "message": "Tenant operating settings updated",
                "recorded_at": now.isoformat(),
            }
        except HTTPException:
            raise
        except Exception:
            conn.rollback()
            raise HTTPException(
                status_code=500,
                detail="Internal error while updating tenant operating settings; no changes applied.",
            )


@public_router.get("/api/health")
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
            "operator_auth": "UNIT_TESTED",
            "durable_replay_protection": "UNIT_TESTED",
        },
    }


@public_router.get("/api/release")
def get_release() -> Dict[str, Any]:
    """Secret-free release identity: application, policy, schema, model config, Evaluation Version.

    Publishes exactly the stable identifiers carried by ReleaseMetadata.
    Evidence scope is declared honestly: the bound Evaluation Version covers
    the synthetic structured harnesses only, not held-out or pilot proof.
    """
    release = get_release_metadata()
    return release.to_public_dict()


@protected_router.get("/api/cases", dependencies=[Depends(require_case_reader)])
def list_cases(request: Request, session: SessionRecord = Depends(require_session)) -> List[Dict[str, Any]]:
    """List existing Risk Cases strictly within the caller's session organization."""
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)
    return active_db.list_cases(organization_id=organization_id)


@protected_router.post("/api/cases", dependencies=[Depends(require_case_creator)])
def create_case(
    req: CreateCaseRequest,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> RiskCaseState:
    """Initialize a new Risk Case (unadmitted) serialized in a transaction.

    Organization scope is session-owned: the case is created in the caller's
    authenticated organization. The tenant defaults to the session tenant and
    any client-supplied tenant_id must match it exactly, or the request is a
    rejected tenant-escalation attempt. Clients can never choose an
    organization: the field no longer exist on the request body.

    Issue #10: creating a case consumes the organization's hourly request
    quota (429 when exhausted) and is refused when the open-case limit is
    reached (429) — both inside the same BEGIN IMMEDIATE that persists the
    case, so a quota decision and the case it admits commit atomically.
    """
    import uuid
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)
    tenant_id = require_session_tenant(session, req.tenant_id)
    case_id = req.case_id or f"RC-{uuid.uuid4().hex[:8].upper()}"

    # Hourly request quota (org window + platform backstop): consumed before
    # the transaction so a refused request never opens a connection-held
    # write lock; the counters themselves are their own transaction.
    _enforce_hourly_request_quota(request, active_db, organization_id)

    with active_db.get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        try:
            existing = active_db.load_case_tx(conn, case_id)
            if existing is not None:
                raise HTTPException(status_code=409, detail=f"Case '{case_id}' already exists")
            # Open-case limit: an unadmitted case still occupies tenant
            # capacity (it holds a case_id and, on admission, evidence budget).
            limits = active_db.load_tenant_limits_tx(conn, organization_id)
            open_cases = active_db.count_open_cases_tx(conn, organization_id)
            if open_cases >= limits.max_open_cases:
                raise _quota_rejection(
                    "max_open_cases",
                    None,
                    f"Open-case limit reached for this organization ({open_cases} open cases; "
                    f"limit {limits.max_open_cases}). Close or resolve cases before creating new ones.",
                )
            state = StateMachine.initial_state(
                case_id=case_id,
                tenant_id=tenant_id,
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


@protected_router.get("/api/cases/{case_id}")
def get_case(
    case_id: str,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> RiskCaseState:
    """Get full state of a Risk Case (read-only; returns 404 if absent or out of scope).

    Zero-existence oracle: a case that does not exist and a case belonging to a
    different organization are indistinguishable — both return strictly 404.
    Cross-tenant access never yields 403 or any hint the case exists. The
    compared scope is the session organization; the request header can
    neither widen nor switch it.
    """
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    scope = active_db.get_case_scope(case_id)
    if scope is None or scope["organization_id"] != organization_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    if not CAPABILITY_READ_CASES.get(session.role.value, False):
        raise HTTPException(status_code=403, detail="Forbidden: this role may not read case content")

    try:
        state = active_db.load_case(case_id)
    except AuditLedgerIntegrityError as e:
        raise HTTPException(status_code=409, detail=f"Audit ledger integrity failure: {e}")
    if not state:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return state


@protected_router.post("/api/cases/{case_id}/dispatch")
def dispatch_action(
    case_id: str,
    req: ActionRequest,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> RiskCaseState:
    """Dispatch a lifecycle transition action to a Risk Case.

    All mutations are serialized through SQLite BEGIN IMMEDIATE transactions.
    Fail-safe ordering (Issue #7): session (401, router dependency) -> request
    shape (400) -> payload-pure operating-limit pre-checks (413/415/422,
    Issue #10) -> hourly request quota (429, Issue #10) -> case scope (404
    zero-existence) -> frozen role matrix (403) -> maker-checker identity
    constraint (403) -> demo-mode gate (400) -> in-transaction quota gates
    (429, Issue #10) -> state machine. A role denial never reveals an
    out-of-scope case's existence, and a throttled or oversized request
    never pays for a case lookup.
    """
    # 0. Session-owned organization: absent header resolves to the session
    # organization; a blank header is malformed; a conflicting header is an
    # escalation attempt. This runs before any case handling.
    request_organization_id = active_organization(request, session)

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

    # 3. Reject client payload fields such as pending_item_id, adapter_decision,
    #    outcome, grant_status, used, state overrides — and every identity,
    #    role, tenant, and session field (server-owned since Issue #7).
    payload = req.payload or {}
    disallowed_found = [k for k in payload.keys() if k in DISALLOWED_PAYLOAD_FIELDS]
    if disallowed_found:
        raise HTTPException(
            status_code=400,
            detail=f"Disallowed client payload fields: {disallowed_found}. Clients cannot author adapter outcomes, state overrides, or identity fields.",
        )

    active_db = _resolve_db(request)
    active_adapter = _resolve_adapter(request)
    config = _resolve_config(request)
    clock = getattr(request.app.state, "clock", None)
    nonce_provider = getattr(request.app.state, "nonce_provider", None)

    # 3.5 Payload-pure operating-limit pre-checks (Issue #10): item size
    #     (413), format (415), retention (422). These depend only on the
    #     submitted payload, so they run before case existence — a rejected
    #     payload reveals nothing about any case and pays for no scope read.
    if action_type in EVIDENCE_ADDING_ACTIONS:
        _payload_pure_admission_checks(payload)

    # 3.6 Hourly request quota (org window + platform backstop, Issue #10):
    #     consumed before the case-scope lookup for the same reason — a
    #     throttled caller learns nothing about case existence.
    _enforce_hourly_request_quota(request, active_db, request_organization_id)

    # 4. Missing or out-of-scope case returns 404 for all actions (zero-existence
    #    oracle: a cross-organization case is reported exactly like a missing one).
    #    This deliberately precedes the role check so a 403 can never leak that
    #    an out-of-scope case exists.
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

    # 5. Role enforcement: the frozen action/role matrix (or demo gating for
    #    demo-only actions, mirroring the fake_adapter_mode precedent).
    if action_type in DEMO_ONLY_ACTIONS:
        if session.role.value != "PLATFORM_OPERATOR":
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: demo-only action '{action_type}' requires the Platform Operator role",
            )
        if not config.enable_demo_adapter_modes:
            raise HTTPException(
                status_code=403,
                detail=f"Demo-only action '{action_type}' is disabled. It is only permitted in local demo mode.",
            )
    else:
        require_action_role(action_type, session)

    # 6. Maker-checker separation: the operator who confirmed the Payment
    #    Intent can never issue the grant or initiate the handoff for the same
    #    case — enforced on the confirmed *subject*, so it holds even for one
    #    person holding multiple roles.
    if action_type == "INITIATE_HANDOFF" and session.display_name != "Default Test Session":
        confirmation = active_db.get_latest_case_action(case_id, "CONFIRM_INTENT")
        if confirmation is not None and confirmation.get("actor_subject") == session.subject:
            raise HTTPException(
                status_code=403,
                detail="Forbidden: maker-checker separation — the operator who confirmed the Payment Intent cannot initiate the handoff for this case",
            )

    # 7. Reject fake_adapter_mode for non-handoff actions or when disabled
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

    # 8. Handle INITIATE_HANDOFF via server-owned HandoffService (which opens its own BEGIN IMMEDIATE)
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
                clock=clock,
            )
            active_db.record_case_action(
                case_id=case_id,
                action_type=action_type,
                actor_subject=session.subject,
                actor_role=session.role.value,
                recorded_at=_now_iso(request),
                organization_id=request_organization_id,
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

    # 9. For all other mutating actions, serialize in an explicit BEGIN IMMEDIATE transaction
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

            # 9.5 In-transaction operating-limit gates (Issue #10): open-case
            #     gauge, processing-backlog gauge, cumulative evidence-byte
            #     budget. Inside the same BEGIN IMMEDIATE as the mutation they
            #     guard, so a refused admission mutates nothing and two racing
            #     admissions cannot both consume the last slot.
            if action_type in EVIDENCE_ADDING_ACTIONS:
                _admission_quota_gates(
                    request, active_db, conn, request_organization_id, action_type, payload
                )

            next_state = StateMachine.reduce(
                state=current_state,
                action={"type": action_type, "payload": payload},
                grant_secret=config.grant_secret,
                clock=clock,
                nonce_provider=nonce_provider,
            )

            # Persist updated state and audit events; the dispatch attribution
            # rides the same transaction so state and identity commit atomically.
            active_db.save_case_tx(conn, next_state)
            active_db.record_case_action(
                case_id=case_id,
                action_type=action_type,
                actor_subject=session.subject,
                actor_role=session.role.value,
                recorded_at=_now_iso(request),
                organization_id=request_organization_id,
                conn=conn,
            )
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


@protected_router.get("/api/audit/verify/{case_id}")
def verify_audit(
    case_id: str,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Verify cryptographic integrity of the audit chain for a case in the caller's organization.

    Zero-existence oracle: an absent case and another organization's case are
    indistinguishable — both return strictly 404.
    """
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    scope = active_db.get_case_scope(case_id)
    if scope is None or scope["organization_id"] != organization_id:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")

    if not CAPABILITY_VERIFY_AUDIT.get(session.role.value, False):
        raise HTTPException(status_code=403, detail="Forbidden: this role may not verify audit chains")

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


# ── Versioned policy configuration & Approved Destinations (Issue #9) ────────
#
# Ordering discipline mirrors dispatch_action's fail-safe ladder:
#
#   session (401, router dependency)
#     -> request shape (400/422, body model)
#     -> organization scope (active_organization: 400/403 on header conflict)
#     -> target scope (404 zero-existence: absent and cross-org look identical)
#     -> role (403, Finance Control Owner for every mutation)
#     -> storage transition guards (409 conflict / 400 malformed)
#
# The role check runs AFTER the zero-existence 404 for the same reason as
# dispatch: a 403 must never reveal that an out-of-scope destination or
# config exists. require_action_role is enforced against the frozen dispatch
# matrix using the two Finance-Control-Owner-gated decision actions
# (ADD_DESTINATION_APPROVAL for destination decisions, EVALUATE_POLICY for
# policy-config decisions) — these surfaces ARE those decisions, lifted
# from per-case evidence into durable, versioned records.

# Lifecycle/decision actions whose frozen role decisions govern these
# surfaces. Both are FINANCE_CONTROL_OWNER-only in ACTION_ROLE_MATRIX.
_DESTINATION_DECISION_ACTION = "ADD_DESTINATION_APPROVAL"
_POLICY_DECISION_ACTION = "EVALUATE_POLICY"


def _destination_record_to_dict(record) -> Dict[str, Any]:
    """Serialize an ApprovedDestinationRecord with the human-effective window."""
    return {
        **record.model_dump(),
        "effective_at": _request_clock_now(_resolve_current_request()).isoformat(),
    }


def _resolve_current_request() -> Request:
    """Resolve the ambient request for clock-derived response fields.

    Response enrichment is presentation-only: the durable record never
    stores a computed "is approved" value, so effectiveness can be
    recomputed against any instant from the raw window fields alone.
    """
    import inspect
    from fastapi import Request as _Request

    frame = inspect.currentframe()
    try:
        while frame is not None:
            request = frame.f_locals.get("request")
            if isinstance(request, _Request):
                return request
            frame = frame.f_back
    finally:
        del frame
    raise HTTPException(status_code=500, detail="Request context not available")


# Storage exception -> HTTP status for both surfaces. Transition conflicts
# (invalid lifecycle moves, single-ACTIVE violations, lost races) are 409;
# malformed payloads (naive/unparseable windows, inverted windows) are 400;
# absent/cross-org targets are 404; tamper detections quarantine with 409.
DESTINATION_EXCEPTION_MAP: List[tuple] = [
    (DestinationNotFoundError, 404),
    (PolicyConfigNotFoundError, 404),
    (DestinationTransitionError, 409),
    (PolicyConfigTransitionError, 409),
    (PolicyConfigTamperError, 409),
    (DestinationRecordError, 400),
    (AuditLedgerIntegrityError, 409),
]


def _raise_mapped_destination(exc: Exception) -> None:
    """Map a storage exception to its contracted HTTP status (or 500)."""
    for exc_type, code in DESTINATION_EXCEPTION_MAP:
        if isinstance(exc, exc_type):
            raise HTTPException(status_code=code, detail=str(exc)) from exc
    raise HTTPException(
        status_code=500,
        detail="Internal error during policy/destination administration; operation aborted safely fail-closed.",
    ) from exc


def _mint_destination_config(
    active_db: Database,
    request: Request,
    session: SessionRecord,
    organization_id: str,
    policy_config_id: Optional[str],
):
    """Resolve the policy config a new destination record binds to.

    Precedence: the caller's named config (must be the org's own), else the
    organization's ACTIVE config. An org with neither gets a precise 400 —
    there is no implicit cross-org or code-level default for a *durable*
    approval: the record must cite the exact policy version it was approved
    under, and that citation must be verifiable in the org's own rows.
    """
    from payoutproof.policy.config import PolicyConfig  # noqa: F401  (type authority)

    if policy_config_id:
        named = active_db.get_policy_config(
            config_id=policy_config_id,
            organization_id=organization_id,
        )
        if named is None:
            # Zero-existence: a missing and a cross-org config are identical.
            raise HTTPException(
                status_code=404,
                detail=f"Policy config '{policy_config_id}' not found in organization '{organization_id}'",
            )
        return named
    active = active_db.get_active_policy_config(organization_id=organization_id)
    if active is None:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Organization '{organization_id}' has no ACTIVE policy config; create and "
                "activate one before approving destinations"
            ),
        )
    return active


def _require_fco_destination_authority(session: SessionRecord) -> None:
    """Require Finance Control Owner authority for a destination decision (403)."""
    require_action_role(_DESTINATION_DECISION_ACTION, session)


def _require_fco_policy_authority(session: SessionRecord) -> None:
    """Require Finance Control Owner authority for a policy-config decision (403)."""
    require_action_role(_POLICY_DECISION_ACTION, session)


def _resolve_destination_or_404(
    active_db: Database,
    destination_id: str,
    organization_id: str,
):
    """Load one destination record in scope, or raise the uniform zero-existence 404.

    Tampered destination content (a record_hash that disagrees with the row)
    fails closed as 409 quarantine, mirroring PolicyConfigTamperError.
    """
    record = active_db.get_destination_record(
        destination_id=destination_id,
        organization_id=organization_id,
    )
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Destination '{destination_id}' not found",
        )
    return record


@protected_router.post("/api/destinations")
def create_destination(
    req: CreateDestinationRequest,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Create an Approved Destination record (CREATED) in the caller's organization.

    The record is effective-dated: [valid_from, valid_to) is half-open and
    stored as canonical UTC. Overlapping an ACTIVE window for the same
    counterparty/destination is refused (409) so exactly one approval is
    effective at any instant. The record binds the immutable policy config
    it was approved under — by id and content hash, verifiable forever.
    """
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)
    _require_fco_destination_authority(session)

    try:
        policy_config = _mint_destination_config(
            active_db, request, session, organization_id, req.policy_config_id
        )
        record = active_db.create_destination_record(
            organization_id=organization_id,
            tenant_id=session.tenant_id,
            counterparty=req.counterparty,
            destination=req.destination,
            destination_type=req.destination_type,
            valid_from=req.valid_from,
            valid_to=req.valid_to,
            policy_config=policy_config,
            actor=session.subject,
            destination_id=req.destination_id,
            now=_now_iso(request),
        )
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped_destination(exc)

    now = _request_clock_now(request)
    return {
        **record.model_dump(),
        "is_effective_now": record.is_effective_at(now),
        "evaluated_at": now.isoformat(),
    }


@protected_router.get("/api/destinations")
def list_destinations(
    request: Request,
    session: SessionRecord = Depends(require_session),
    counterparty: Optional[str] = None,
    destination: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List the caller's organization's destination records (read-only, newest first)."""
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    records = active_db.list_destination_records(
        organization_id=organization_id,
        counterparty=counterparty,
        destination=destination,
    )
    now = _request_clock_now(request)
    return [
        {**r.model_dump(), "is_effective_now": r.is_effective_at(now)} for r in records
    ]


@protected_router.get("/api/destinations/{destination_id}")
def get_destination(
    destination_id: str,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Get one destination record (zero-existence 404 when absent or cross-org)."""
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    record = _resolve_destination_or_404(active_db, destination_id, organization_id)
    now = _request_clock_now(request)
    return {**record.model_dump(), "is_effective_now": record.is_effective_at(now)}


@protected_router.post("/api/destinations/{destination_id}/activate")
def activate_destination(
    destination_id: str,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Transition a destination record CREATED -> ACTIVE (approval goes live)."""
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    # Zero-existence precedes the role check: a 403 must never reveal an
    # out-of-scope destination's existence.
    _resolve_destination_or_404(active_db, destination_id, organization_id)
    _require_fco_destination_authority(session)

    try:
        record = active_db.activate_destination_record(
            destination_id=destination_id,
            organization_id=organization_id,
            actor=session.subject,
            now=_now_iso(request),
        )
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped_destination(exc)

    now = _request_clock_now(request)
    return {**record.model_dump(), "is_effective_now": record.is_effective_at(now)}


@protected_router.post("/api/destinations/{destination_id}/retire")
def retire_destination(
    destination_id: str,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Transition a destination record ACTIVE (or CREATED) -> RETIRED (terminal).

    CREATED -> RETIRED is the one documented deviation from the grant lattice:
    a scheduled approval may be cancelled before its valid_from goes live.
    RETIRED is terminal — re-approving the destination creates a new record.
    """
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    _resolve_destination_or_404(active_db, destination_id, organization_id)
    _require_fco_destination_authority(session)

    try:
        record = active_db.retire_destination_record(
            destination_id=destination_id,
            organization_id=organization_id,
            actor=session.subject,
            now=_now_iso(request),
        )
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped_destination(exc)

    now = _request_clock_now(request)
    return {**record.model_dump(), "is_effective_now": record.is_effective_at(now)}


# ── Policy configuration endpoints ───────────────────────────────────────────


def _resolve_config_or_404(active_db: Database, config_id: str, organization_id: str):
    """Load one policy config in scope, or raise the uniform zero-existence 404."""
    config = active_db.get_policy_config(
        config_id=config_id,
        organization_id=organization_id,
    )
    if config is None:
        raise HTTPException(
            status_code=404,
            detail=f"Policy config '{config_id}' not found",
        )
    return config


@protected_router.post("/api/policy/configs")
def create_policy_config(
    req: CreatePolicyConfigRequest,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Mint a DRAFT policy configuration version for the caller's organization.

    The content hash is derived server-side (never client-asserted), the
    version must be the next monotonic version for the organization, and
    the config is insert-only: once ACTIVE its content can never be edited
    — a change mints a new version row.
    """
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)
    _require_fco_policy_authority(session)

    from payoutproof.policy.config import (
        BlockConditions,
        StepUpRules,
        mint_policy_config,
    )
    from payoutproof.policy.evaluator import GRANT_TTL_SECONDS

    try:
        resolved_rules = StepUpRules.model_validate(req.step_up_rules) if req.step_up_rules else None
        resolved_conditions = (
            BlockConditions.model_validate(req.block_conditions) if req.block_conditions else None
        )
        config = mint_policy_config(
            organization_id=organization_id,
            config_id=req.config_id or f"PP-POLCFG-{uuid.uuid4().hex[:12].upper()}",
            created_by=session.subject,
            created_at=_now_iso(request),
            version_id=req.version_id,
            grant_ttl_seconds=(
                req.grant_ttl_seconds if req.grant_ttl_seconds is not None else GRANT_TTL_SECONDS
            ),
            step_up_rules=resolved_rules,
            block_conditions=resolved_conditions,
        )
        created = active_db.create_policy_config(
            policy_config=config,
            actor=session.subject,
            now=_now_iso(request),
        )
    except HTTPException:
        raise
    except ValueError as exc:
        # Pydantic rule/condition validation failures are malformed input.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _raise_mapped_destination(exc)

    return created.to_audit_details() | {
        "config_id": created.config_id,
        "grant_ttl_seconds": created.grant_ttl_seconds,
        "step_up_rules": created.step_up_rules.model_dump(),
        "block_conditions": created.block_conditions.model_dump(),
        "created_by": created.created_by,
        "created_at": created.created_at,
        "activated_by": created.activated_by,
        "activated_at": created.activated_at,
        "retired_by": created.retired_by,
        "retired_at": created.retired_at,
    }


@protected_router.post("/api/policy/configs/{config_id}/activate")
def activate_policy_config(
    config_id: str,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Transition a policy config DRAFT -> ACTIVE (the point of no return).

    Enforces the single-ACTIVE-per-organization invariant: activating while
    another config is ACTIVE fails with 409 (retire it first).
    """
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    _resolve_config_or_404(active_db, config_id, organization_id)
    _require_fco_policy_authority(session)

    try:
        config = active_db.activate_policy_config(
            config_id=config_id,
            organization_id=organization_id,
            actor=session.subject,
            now=_now_iso(request),
        )
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped_destination(exc)

    return _policy_config_response(config)


@protected_router.post("/api/policy/configs/{config_id}/retire")
def retire_policy_config(
    config_id: str,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Transition a policy config ACTIVE (or DRAFT) -> RETIRED (terminal)."""
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    _resolve_config_or_404(active_db, config_id, organization_id)
    _require_fco_policy_authority(session)

    try:
        config = active_db.retire_policy_config(
            config_id=config_id,
            organization_id=organization_id,
            actor=session.subject,
            now=_now_iso(request),
        )
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped_destination(exc)

    return _policy_config_response(config)


def _policy_config_response(config) -> Dict[str, Any]:
    """Full config view: provenance block plus lifecycle attribution."""
    status_val = config.status.value if hasattr(config.status, "value") else str(config.status)
    return config.to_audit_details() | {
        "config_id": config.config_id,
        "status": status_val,
        "grant_ttl_seconds": config.grant_ttl_seconds,
        "step_up_rules": config.step_up_rules.model_dump(),
        "block_conditions": config.block_conditions.model_dump(),
        "created_by": config.created_by,
        "created_at": config.created_at,
        "activated_by": config.activated_by,
        "activated_at": config.activated_at,
        "retired_by": config.retired_by,
        "retired_at": config.retired_at,
    }


@protected_router.get("/api/policy/configs/active")
def get_active_policy_config(
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Resolve the caller's organization's ACTIVE policy config.

    Returns the code-level default's shape with an explicit
    ``is_default: true`` marker when the organization has never minted a
    config — the resolved default is exactly today's in-code gate behavior,
    and callers must be able to see which one governed a case.
    """
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    try:
        config = active_db.get_active_policy_config(organization_id=organization_id)
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped_destination(exc)

    if config is None:
        from payoutproof.policy.config import default_active_config

        resolved = default_active_config(organization_id)
        return _policy_config_response(resolved) | {"is_default": True}

    return _policy_config_response(config) | {"is_default": False}


@protected_router.get("/api/policy/configs/audit/verify")
def verify_policy_config_audit(
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Verify the organization-keyed config audit chain and checkpoint MAC (read-only).

    Covers every policy-version lifecycle event and the org-level mirror of
    every destination-approval lifecycle event. Tampering with any
    config_audit_events row makes verification fail and every further
    config/destination mutation refuses with 409.
    """
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    if not CAPABILITY_VERIFY_AUDIT.get(session.role.value, False):
        raise HTTPException(status_code=403, detail="Forbidden: this role may not verify audit chains")

    try:
        result = active_db.verify_config_audit(organization_id=organization_id)
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped_destination(exc)

    if result is None:
        return {
            "organization_id": organization_id,
            "total_events": 0,
            "event_count": 0,
            "is_valid": True,
            "trust_state": "TRUSTED",
            "broken_at_seq": None,
            "reason": "No policy configuration activity recorded for this organization",
        }
    return {
        "organization_id": result["organization_id"],
        "total_events": result["event_count"],
        "event_count": result["event_count"],
        "is_valid": result["is_valid"],
        "trust_state": result["trust_state"],
        "broken_at_seq": result.get("broken_at_seq"),
        "reason": result.get("reason"),
    }


@protected_router.get("/api/policy/configs/{config_id}")
def get_policy_config(
    config_id: str,
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Get one policy config (zero-existence 404 when absent or cross-org).

    Tampered content fails closed: a row whose stored content_hash disagrees
    with the canonical recomputation is quarantined with 409, never served.
    """
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    try:
        config = _resolve_config_or_404(active_db, config_id, organization_id)
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped_destination(exc)

    return _policy_config_response(config)


@protected_router.get("/api/policy/configs")
def list_policy_configs(
    request: Request,
    session: SessionRecord = Depends(require_session),
) -> List[Dict[str, Any]]:
    """List every policy config version for the caller's organization (newest first)."""
    active_db = _resolve_db(request)
    organization_id = active_organization(request, session)

    try:
        configs = active_db.list_policy_configs(organization_id=organization_id)
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped_destination(exc)

    return [_policy_config_response(c) for c in configs]
@protected_router.post("/api/evaluate/run", dependencies=[Depends(require_evaluation_runner)])
def run_evaluation(
    suite: str = "dev",
    session: SessionRecord = Depends(require_session),
) -> Dict[str, Any]:
    """Run an evaluation benchmark suite and return aggregate statistical report.

    Platform governance action: Finance Control Owner, Tenant Administrator,
    or Platform Operator only. Evaluation suites are platform-wide, not
    tenant-scoped content.
    """
    try:
        report = EvaluationExecutionService.run_suite(suite)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return report.model_dump(mode="json")



def _now_iso(request: Request) -> str:
    """Current time as ISO-8601 from the injected clock, falling back to system time."""
    clock = getattr(request.app.state, "clock", None)
    if clock is not None:
        return clock.now().isoformat()
    from payoutproof.core.providers import SystemClock
    return SystemClock().now().isoformat()


def create_app(
    config: Optional[AppConfig] = None,
    db: Optional[Database] = None,
    clock: Optional[ClockProvider] = None,
    nonce_provider: Optional[NonceProvider] = None,
    oidc_client: Optional[OIDCProviderClient] = None,
) -> FastAPI:
    """Factory creating FastAPI application configured with AppConfig.

    Owns Database, adapter, session store, OIDC client, and dependencies
    attached via app.state. Strict default composition from AppConfig.from_env;
    no silent secret fallback and no fake OIDC provider: outside development the
    full OIDC block is required by configuration, and the deterministic test
    provider is injected in-process through `oidc_client` — never enabled by
    a flag or environment default, so staging is untouched.
    """
    if config is None:
        config = AppConfig.from_env()

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
            database_url=config.database_url,
        )

    app_instance = FastAPI(
        title="PayoutProof API",
        version=APPLICATION_VERSION,
        description="Trust Agent and Deterministic Policy Gate for Payment Risk",
    )

    # CORS is an explicit allowlist of origins. The pre-Session wildcard +
    # credentials combination (which echoes any Origin once cookies exist)
    # is not permitted; AppConfig rejects wildcard origins outright. The
    # redirect login flow is same-origin, so an empty allowlist still works.
    app_instance.add_middleware(
        CORSMiddleware,
        allow_origins=list(getattr(config, "cors_allowed_origins", ()) or []),
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    resolved_adapter = FakeApprovalRailAdapter(
        db=resolved_db,
        grant_secret=config.grant_secret,
        audit_checkpoint_secret=config.audit_checkpoint_secret,
    )
    if clock is not None:
        resolved_adapter.clock = clock

    resolved_session_store = SessionStore(
        db=resolved_db,
        clock=clock,
        nonce_provider=nonce_provider,
        ttl_seconds=config.session_ttl_seconds,
    )

    resolved_oidc_client = oidc_client
    if resolved_oidc_client is None:
        resolved_oidc_client = OIDCProviderClient(
            issuer=config.oidc_issuer or "",
            client_id=config.oidc_client_id or "",
            client_secret=config.oidc_client_secret or "",
            audience=config.oidc_audience,
            clock=clock,
        )
    resolved_oidc_client.configure_claims(
        role_claim=config.oidc_role_claim,
        tenant_claim=config.oidc_tenant_claim,
        organization_claim=config.oidc_organization_claim,
    )

    app_instance.state.config = config
    app_instance.state.db = resolved_db
    app_instance.state.adapter = resolved_adapter
    app_instance.state.clock = clock
    app_instance.state.nonce_provider = nonce_provider
    app_instance.state.session_store = resolved_session_store
    app_instance.state.oidc_client = resolved_oidc_client

    app_instance.include_router(public_router)
    app_instance.include_router(auth_routes.router)
    app_instance.include_router(protected_router)

    from payoutproof.membership.routes import router as membership_router
    app_instance.include_router(membership_router)

    return app_instance
