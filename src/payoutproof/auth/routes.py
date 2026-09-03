"""Authentication routes: OIDC code-flow login, identity, and logout.

Routes are mounted on the public router alongside /api/health and
/api/release: /api/auth/login redirects to the provider (no session yet),
/api/auth/callback consumes the authorization code and mints the session,
/api/auth/me and /api/auth/logout enforce the session dependency themselves.
"""

import secrets
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from payoutproof.auth.dependencies import SESSION_COOKIE_NAME, require_session
from payoutproof.auth.oidc import OIDCError
from payoutproof.auth.roles import Role
from payoutproof.auth.session import clear_session_cookie, set_session_cookie

router = APIRouter()


def _resolve_oidc_client(request: Request):
    client = getattr(request.app.state, "oidc_client", None)
    if client is None:
        raise HTTPException(status_code=500, detail="OIDC client dependency not configured")
    return client


def _resolve_config(request: Request):
    config = getattr(request.app.state, "config", None)
    if config is None:
        raise HTTPException(status_code=500, detail="Configuration dependency not configured")
    return config


def _resolve_redirect_uri(request: Request, config) -> str:
    """Resolve the OAuth2 redirect URI: explicit configuration, else this callback's own origin."""
    configured = getattr(config, "oidc_redirect_uri", None)
    if configured and str(configured).strip():
        return str(configured).strip()
    host = request.headers.get("host", "127.0.0.1")
    scheme = request.url.scheme
    return f"{scheme}://{host}/api/auth/callback"


@router.get("/api/auth/login")
def login(request: Request, persona: Optional[str] = None):
    """Begin the OIDC authorization-code flow.

    Persists a single-use login state (state token + nonce) server-side and
    redirects to the provider authorization endpoint. `persona` is forwarded
    as login_hint for the deterministic local provider; production providers
    present their own interactive login screen.
    """
    client = _resolve_oidc_client(request)
    config = _resolve_config(request)
    store = getattr(request.app.state, "session_store", None)
    db = getattr(request.app.state, "db", None)
    if store is None or db is None:
        raise HTTPException(status_code=500, detail="Session store dependency not configured")

    state_token = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    redirect_uri = _resolve_redirect_uri(request, config)
    db.create_login_state(
        state_token=state_token,
        nonce=nonce,
        issuer=client.issuer,
        redirect_uri=redirect_uri,
        created_at=store.clock.now().isoformat(),
    )
    url = client.authorization_url(
        redirect_uri=redirect_uri,
        state=state_token,
        nonce=nonce,
        login_hint=persona,
    )
    return RedirectResponse(url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/api/auth/callback")
def callback(request: Request, code: Optional[str] = None, state: Optional[str] = None):
    """Complete the OIDC code flow: exchange code, validate ID token, mint session.

    Fail-closed on every seam: missing code/state, unknown or replayed login
    state, code-binding mismatch, provider exchange failure, or ID-token
    validation failure all refuse login with a safe 401. No token, claim, or
    secret is ever echoed in the error body.
    """
    client = _resolve_oidc_client(request)
    config = _resolve_config(request)
    store = getattr(request.app.state, "session_store", None)
    db = getattr(request.app.state, "db", None)
    if store is None or db is None:
        raise HTTPException(status_code=500, detail="Session store dependency not configured")

    if not code or not state:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed: missing code or state")

    login_state = db.consume_login_state(state, consumed_at=store.clock.now().isoformat())
    if login_state is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed: login state is unknown, expired, or already used")
    if login_state["issuer"] != client.issuer:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed: login state issuer mismatch")

    redirect_uri = login_state["redirect_uri"] or _resolve_redirect_uri(request, config)
    try:
        id_token = client.exchange_code(code, redirect_uri)
        identity = client.validate_id_token(id_token, expected_nonce=login_state["nonce"])
    except OIDCError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed: provider token exchange or validation failed")

    token = store.mint(
        subject=identity["subject"],
        display_name=identity["display_name"],
        role=identity["role"],
        tenant_id=identity["tenant_id"],
        organization_id=identity["organization_id"],
        idp_issuer=client.issuer,
    )
    response = RedirectResponse(url="/api/auth/me", status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(
        response,
        token,
        cookie_name=config.session_cookie_name or SESSION_COOKIE_NAME,
        ttl_seconds=config.session_ttl_seconds,
        secure=config.session_cookie_secure,
    )
    return response


@router.get("/api/auth/me")
def whoami(request: Request, session=Depends(require_session)):
    """Return the active identity, role, tenant, organization, and session expiry.

    Unauthenticated callers receive 401 (enforced by require_session).
    """
    return session.to_public_dict()


@router.post("/api/auth/logout")
def logout(request: Request, session=Depends(require_session)):
    """Revoke the active session server-side and clear the cookie.

    Revocation is immediate: the stored row is marked revoked, so the token
    stops authorizing requests at once even though the cookie may linger in
    the browser until cleared.
    """
    store = getattr(request.app.state, "session_store", None)
    if store is None:
        raise HTTPException(status_code=500, detail="Session store dependency not configured")
    config = _resolve_config(request)
    token = request.cookies.get(config.session_cookie_name or SESSION_COOKIE_NAME)
    store.revoke(token)
    response = Response(status_code=status.HTTP_200_OK)
    clear_session_cookie(
        response,
        cookie_name=config.session_cookie_name or SESSION_COOKIE_NAME,
        secure=config.session_cookie_secure,
    )
    return response

