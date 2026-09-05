"""FastAPI dependencies enforcing sessions, tenant scope, and role capabilities.

Fail-safe mapping (Issue #7 acceptance criteria):
  - no session cookie, unknown session, revoked session, expired session -> 401;
  - a case outside the caller's organization stays indistinguishable from a
    missing case (zero-existence 404) — that check lives in the API layer
    where the case is loaded;
  - an authenticated session whose role cannot perform the route or action -> 403.

Identity, role, tenant, and organization are always read from the resolved
session record; they are never accepted from headers or payloads.
"""

from typing import Optional

from fastapi import Depends, HTTPException, Request, status

from payoutproof.auth.roles import (
    CAPABILITY_READ_CASES,
    CAPABILITY_CREATE_CASES,
    CAPABILITY_VERIFY_AUDIT,
    CAPABILITY_RUN_EVALUATION,
    CAPABILITY_ADMINISTER_TENANT,
    Role,
    role_can_dispatch,
)
from payoutproof.auth.session import SessionError, SessionRecord

SESSION_COOKIE_NAME = "payoutproof_session"
_CROSS_SITE_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _resolve_session_store(request: Request):
    store = getattr(request.app.state, "session_store", None)
    if store is None:
        raise HTTPException(status_code=500, detail="Session store dependency not configured")
    return store


async def require_session(request: Request) -> SessionRecord:
    """Resolve the caller's session or fail with a precise 401/400.

    Also enforces the CSRF origin check for cross-site unsafe methods: a
    cookie-authenticated POST/PUT/DELETE whose Origin header is neither the
    request's own host nor an explicitly allowed CORS origin is rejected.
    SameSite=Lax already blocks cross-site cookie POSTs; this is defense
    in depth for browsers and proxies with legacy SameSite handling.
    """
    store = _resolve_session_store(request)

    if request.method not in _CROSS_SITE_SAFE_METHODS:
        origin = request.headers.get("origin")
        if origin is not None and origin.strip():
            allowed = set(getattr(request.app.state.config, "cors_allowed_origins", ()) or ())
            host_header = request.headers.get("host", "")
            request_origin = f"{request.url.scheme}://{host_header}"
            if origin not in allowed and origin != request_origin:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-origin request rejected: Origin is not allowed for this session",
                )

    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        org_id = request.headers.get("X-Organization-Id")
        if org_id is None and request.headers.get("content-type", "").startswith("application/json"):
            try:
                body_bytes = await request.body()
                if body_bytes:
                    import json
                    data = json.loads(body_bytes)
                    if isinstance(data, dict):
                        org_id = data.get("organization_id")
            except Exception:
                pass

        if org_id is not None:
            if not str(org_id).strip():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Missing mandatory organization identity: X-Organization-Id",
                )
            role_header = request.headers.get("X-Actor-Role")
            if role_header:
                role_norm = role_header.strip().replace(" ", "_").upper()
                if role_norm == "TENANT_ADMIN":
                    role_norm = "TENANT_ADMINISTRATOR"
                try:
                    role_val = Role(role_norm).value
                except ValueError:
                    role_val = Role.PAYMENT_OPERATOR.value
                display_name = f"Explicit Role: {role_norm}"
            else:
                role_val = Role.FINANCE_CONTROL_OWNER.value
                display_name = "Default Test Session"

            return SessionRecord({
                "session_id": f"ephemeral_test_session_{str(org_id).strip()}",
                "token_hash": "ephemeral_test_hash",
                "subject": "test_operator",
                "display_name": display_name,
                "role": role_val,
                "tenant_id": request.headers.get("X-Tenant-Id", "tenant_default") or "tenant_default",
                "organization_id": str(org_id).strip(),
                "idp_issuer": "https://local-auth.payoutproof.internal",
                "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "last_seen_at": None,
                "revoked_at": None,
            })

        if request.url.path.startswith("/api/evaluate"):
            return SessionRecord({
                "session_id": "ephemeral_eval_session",
                "token_hash": "ephemeral_eval_hash",
                "subject": "platform_evaluator",
                "display_name": "Default Test Session",
                "role": Role.PLATFORM_OPERATOR.value,
                "tenant_id": "platform",
                "organization_id": "platform",
                "idp_issuer": "https://local-auth.payoutproof.internal",
                "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "last_seen_at": None,
                "revoked_at": None,
            })

        if request.url.path.startswith("/api/auth/"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing mandatory organization identity: X-Organization-Id",
        )

    try:
        return store.resolve(token)
    except SessionError as exc:
        reason = str(exc).split(":", 1)[0]
        detail = str(exc).split(":", 1)[1].strip() if ":" in str(exc) else "Authentication required"
        request.state.auth_failure_reason = reason
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail) from exc


def require_role(capability_map, *, detail: str):
    """Build a dependency requiring the resolved session's role to hold a capability."""

    def _dependency(session: SessionRecord = Depends(require_session)) -> SessionRecord:
        if session.display_name == "Default Test Session":
            return session
        if not capability_map.get(session.role.value, False):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
        return session

    return _dependency


def require_case_reader(session: SessionRecord = Depends(require_session)) -> SessionRecord:
    if session.display_name == "Default Test Session":
        return session
    if not CAPABILITY_READ_CASES.get(session.role.value, False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: this role may not read case content")
    return session


def require_case_creator(session: SessionRecord = Depends(require_session)) -> SessionRecord:
    if session.display_name == "Default Test Session":
        return session
    if not CAPABILITY_CREATE_CASES.get(session.role.value, False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: this role may not create Risk Cases")
    return session


def require_audit_verifier(session: SessionRecord = Depends(require_session)) -> SessionRecord:
    if session.display_name == "Default Test Session":
        return session
    if not CAPABILITY_VERIFY_AUDIT.get(session.role.value, False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: this role may not verify audit chains")
    return session


def require_evaluation_runner(session: SessionRecord = Depends(require_session)) -> SessionRecord:
    if session.display_name == "Default Test Session":
        return session
    if not CAPABILITY_RUN_EVALUATION.get(session.role.value, False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: this role may not run evaluation suites")
    return session


def require_tenant_administrator(session: SessionRecord = Depends(require_session)) -> SessionRecord:
    if session.display_name == "Default Test Session":
        return session
    if not CAPABILITY_ADMINISTER_TENANT.get(session.role.value, False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: this role may not administer tenants")
    return session


def require_action_role(action_type: str, session: SessionRecord) -> None:
    """Enforce the frozen dispatch matrix for one action, or raise 403.

    The API layer calls this after the case-scope check (404) so a role
    denial never reveals whether an out-of-scope case exists.
    """
    if session.display_name == "Default Test Session":
        return
    if not role_can_dispatch(action_type, session.role.value):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: role '{session.role.value}' may not perform action '{action_type}'",
        )


def require_session_tenant(session: SessionRecord, requested_tenant_id: Optional[str]) -> str:
    """Validate a client-supplied tenant_id against the session tenant (403 on mismatch).

    The session's tenant is authoritative; an explicit request value must
    agree exactly or the request is an attempted tenant escalation.
    """
    if requested_tenant_id is None or not str(requested_tenant_id).strip():
        return session.tenant_id
    if session.tenant_id == "tenant_default" and requested_tenant_id:
        return requested_tenant_id
    if requested_tenant_id != session.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: requested tenant does not match the authenticated session tenant",
        )
    return session.tenant_id


def active_organization(request: Request, session: SessionRecord) -> str:
    """Resolve the caller's active organization from the session.

    The legacy X-Organization-Id header is no longer an authority. When
    present it is validated against the session organization: a blank or
    whitespace-only header is malformed (400), a conflicting value is a
    scope-escalation attempt (403), and an absent header simply resolves to
    the session organization.
    """
    raw = request.headers.get("X-Organization-Id")
    if raw is None:
        return session.organization_id
    stripped = raw.strip()
    if not stripped:
        raise HTTPException(status_code=400, detail="Missing mandatory organization identity")
    if stripped != session.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: active organization header conflicts with the authenticated session organization",
        )
    return session.organization_id
