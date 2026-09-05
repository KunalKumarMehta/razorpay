"""Deterministic in-process OIDC provider for local and automated tests.

This is a test double, not a configuration path: it is injected in-process
via `create_app` (never enabled by a config flag or env default), so staging
and production configuration are untouched. The production OIDC client's
validation code (issuer, audience, JWKS signature, expiry) runs unchanged
against this provider — only the key material and endpoints differ.

Determinism guarantees:
  - one ephemeral RSA signing key per process, clearly non-secret, generated
    at first use and never written to disk;
  - fixed issuer URL, client id, redirect URI, and claim names;
  - deterministic personas (subject, name, role, tenant, organization);
  - `iat`/`exp` derived only from the injected `ClockProvider`, never the
    wall clock, so expiry tests are reproducible;
  - authorization codes are single-use, bound to the exact redirect URI,
    and expire via the injected clock;
  - first-class negative-control knobs (expired token, wrong audience,
    wrong issuer, bad signature, replayed code) because the API's rejection
    paths are acceptance criteria in disguise.
"""

import hmac
import secrets
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from payoutproof.auth.jwt_util import generate_signing_key, public_jwk, sign_jwt
from payoutproof.core.providers import ClockProvider, SystemClock

TEST_ISSUER = "https://idp.payoutproof.test"
TEST_CLIENT_ID = "payoutproof-test-client"
TEST_CLIENT_SECRET = "test-client-secret-clearly-not-production-32ch"  # test fixture only
TEST_REDIRECT_URI = "http://127.0.0.1:9413/api/auth/callback"
TEST_KID = "payoutproof-test-signing-key"
TEST_ROLE_CLAIM = "payoutproof_role"
TEST_TENANT_CLAIM = "payoutproof_tenant"
TEST_ORGANIZATION_CLAIM = "payoutproof_organization"

DEFAULT_SESSION_TTL_SECONDS = 28800
CODE_TTL_SECONDS = 60

# Deterministic personas: (subject, display name, role, tenant, organization).
# Each persona maps 1:1 onto a Role; combined roles are minted on demand via
# `register_persona` so maker-checker separation can be tested against a
# single operator holding both Payment Operator and Finance Control Owner.
DEFAULT_PERSONAS: Dict[str, Dict[str, str]] = {
    "payment_operator": {
        "sub": "test-sub-payment-operator",
        "name": "Priya Operator",
        "role": "PAYMENT_OPERATOR",
        "tenant_id": "tenant_test",
        "organization_id": "org_test",
    },
    "finance_control_owner": {
        "sub": "test-sub-finance-control-owner",
        "name": "Farida Control Owner",
        "role": "FINANCE_CONTROL_OWNER",
        "tenant_id": "tenant_test",
        "organization_id": "org_test",
    },
    "auditor": {
        "sub": "test-sub-auditor",
        "name": "Arun Auditor",
        "role": "AUDITOR",
        "tenant_id": "tenant_test",
        "organization_id": "org_test",
    },
    "tenant_administrator": {
        "sub": "test-sub-tenant-administrator",
        "name": "Tanvi Tenant Admin",
        "role": "TENANT_ADMINISTRATOR",
        "tenant_id": "tenant_test",
        "organization_id": "org_test",
    },
    "platform_operator": {
        "sub": "test-sub-platform-operator",
        "name": "Pooja Platform Operator",
        "role": "PLATFORM_OPERATOR",
        "tenant_id": "tenant_platform",
        "organization_id": "org_platform",
    },
    "payment_operator_org_beta": {
        "sub": "test-sub-payment-operator-beta",
        "name": "Bilal Operator (Beta)",
        "role": "PAYMENT_OPERATOR",
        "tenant_id": "tenant_test",
        "organization_id": "org_beta",
    },
    "finance_control_owner_org_beta": {
        "sub": "test-sub-finance-control-owner-beta",
        "name": "Beena Control Owner (Beta)",
        "role": "FINANCE_CONTROL_OWNER",
        "tenant_id": "tenant_test",
        "organization_id": "org_beta",
    },
}


class FakeOIDCProvider:
    """In-process OIDC provider with a real, verifiable signing key."""

    def __init__(
        self,
        clock: Optional[ClockProvider] = None,
        session_ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
        code_ttl_seconds: int = CODE_TTL_SECONDS,
    ) -> None:
        self.clock = clock if clock is not None else SystemClock()
        self.session_ttl_seconds = session_ttl_seconds
        self.code_ttl_seconds = code_ttl_seconds
        # Ephemeral, process-local, test-only key. Generated lazily so merely
        # importing this module never performs key generation work.
        self._signing_key = None
        # Pending authorization grants: code -> persona/claims snapshot.
        # Codes are single-use and removed on exchange.
        self._pending_codes: Dict[str, Dict[str, Any]] = {}
        # Negative-control overrides for the *next* minted token.
        self._token_overrides: Dict[str, Any] = {}
        self.personas: Dict[str, Dict[str, str]] = dict(DEFAULT_PERSONAS)

    # -- key management ------------------------------------------------------

    @property
    def signing_key(self):
        if self._signing_key is None:
            self._signing_key = generate_signing_key()
        return self._signing_key

    def jwks(self) -> Dict[str, Any]:
        return {"keys": [public_jwk(self.signing_key, TEST_KID)]}

    # -- persona management ---------------------------------------------------

    def register_persona(
        self,
        persona: str,
        sub: str,
        name: str,
        role: str,
        tenant_id: str,
        organization_id: str,
    ) -> None:
        """Register a persona (e.g. a dual-role operator for maker-checker tests)."""
        self.personas[persona] = {
            "sub": sub,
            "name": name,
            "role": role,
            "tenant_id": tenant_id,
            "organization_id": organization_id,
        }

    # -- negative controls ----------------------------------------------------

    def next_token_expired(self) -> None:
        """Mint the next token already expired (exp in the past)."""
        self._token_overrides["expired"] = True

    def next_token_wrong_audience(self) -> None:
        """Mint the next token for a different audience."""
        self._token_overrides["wrong_audience"] = True

    def next_token_wrong_issuer(self) -> None:
        """Mint the next token under a foreign issuer claim."""
        self._token_overrides["wrong_issuer"] = True

    def next_token_bad_signature(self) -> None:
        """Mint the next token signed by a throwaway key (JWKS mismatch)."""
        self._token_overrides["bad_signature"] = True

    def next_token_invalid_role(self, invalid_role: str = "SUPERUSER") -> None:
        """Mint the next token carrying a role outside the frozen Role vocabulary."""
        self._token_overrides["invalid_role"] = invalid_role

    def next_token_missing_tenant(self) -> None:
        """Mint the next token without tenant/organization claims."""
        self._token_overrides["missing_tenant"] = True

    def _consume_token_overrides(self) -> Dict[str, Any]:
        overrides = dict(self._token_overrides)
        self._token_overrides.clear()
        return overrides

    # -- token minting --------------------------------------------------------

    def mint_id_token(
        self,
        persona: str,
        nonce: Optional[str] = None,
        issued_at_epoch: Optional[float] = None,
        ttl_seconds: Optional[int] = None,
    ) -> str:
        """Mint a signed ID token for a persona, honoring pending negative controls.

        The direct-grant path automated tests use: request a token for a
        persona and receive a validly signed ID token without a browser.
        """
        if persona not in self.personas:
            raise ValueError(f"Unknown test persona '{persona}'")
        p = self.personas[persona]
        now = self.clock.now()
        iat = issued_at_epoch if issued_at_epoch is not None else now.timestamp()
        ttl = ttl_seconds if ttl_seconds is not None else self.session_ttl_seconds
        overrides = self._consume_token_overrides()

        exp = iat + ttl
        if overrides.get("expired"):
            exp = iat - 3600

        claims: Dict[str, Any] = {
            "iss": "https://evil.example/idp" if overrides.get("wrong_issuer") else TEST_ISSUER,
            "sub": p["sub"],
            "aud": "some-other-client" if overrides.get("wrong_audience") else TEST_CLIENT_ID,
            "iat": int(iat),
            "exp": int(exp),
            "name": p["name"],
            TEST_ROLE_CLAIM: overrides.get("invalid_role", p["role"]) if overrides.get("invalid_role") else p["role"],
        }
        if not overrides.get("missing_tenant"):
            claims[TEST_TENANT_CLAIM] = p["tenant_id"]
            claims[TEST_ORGANIZATION_CLAIM] = p["organization_id"]
        if nonce is not None:
            claims["nonce"] = nonce

        signing_key = generate_signing_key() if overrides.get("bad_signature") else self.signing_key
        return sign_jwt(claims, signing_key, TEST_KID)

    def discovery_document(self) -> Dict[str, Any]:
        return {
            "issuer": TEST_ISSUER,
            "authorization_endpoint": f"{TEST_ISSUER}/authorize",
            "token_endpoint": f"{TEST_ISSUER}/token",
            "jwks_uri": f"{TEST_ISSUER}/.well-known/jwks.json",
            "userinfo_endpoint": f"{TEST_ISSUER}/userinfo",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["plain"],
        }

    # -- authorization-code flow ----------------------------------------------

    def issue_code(
        self,
        persona: str,
        redirect_uri: str = TEST_REDIRECT_URI,
        nonce: Optional[str] = None,
    ) -> str:
        """Issue a single-use authorization code bound to a persona and redirect URI."""
        if persona not in self.personas:
            raise ValueError(f"Unknown test persona '{persona}'")
        code = f"test-code-{secrets.token_urlsafe(16)}"
        expires_at = self.clock.now().timestamp() + self.code_ttl_seconds
        self._pending_codes[code] = {
            "persona": persona,
            "redirect_uri": redirect_uri,
            "expires_at": expires_at,
            "nonce": nonce,
        }
        return code

    def exchange_code(
        self,
        code: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ) -> Dict[str, Any]:
        """Exchange an authorization code for tokens (single-use, client-authenticated).

        This is the provider-side enforcement the production client relies on:
        exact client credentials, exact redirect URI match, unexpired code,
        and strict single use. Failures raise ValueError with a reason prefix.
        """
        grant = self._pending_codes.pop(code, None)
        if grant is None:
            raise ValueError("CODE_INVALID_OR_REPLAYED: authorization code is unknown or already used")
        if not hmac.compare_digest(client_id, TEST_CLIENT_ID) or not hmac.compare_digest(
            client_secret, TEST_CLIENT_SECRET
        ):
            raise ValueError("CLIENT_AUTH_FAILED: client_id/client_secret do not match")
        if grant["redirect_uri"] != redirect_uri:
            raise ValueError("REDIRECT_URI_MISMATCH: redirect_uri does not match the authorization request")
        if self.clock.now().timestamp() > grant["expires_at"]:
            raise ValueError("CODE_EXPIRED: authorization code has expired")

        id_token = self.mint_id_token(grant["persona"], nonce=grant.get("nonce"))
        return {
            "access_token": f"test-access-{secrets.token_urlsafe(12)}",
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": self.session_ttl_seconds,
        }


def build_fake_oidc_app(provider: FakeOIDCProvider) -> FastAPI:
    """Build the provider as a standalone ASGI app (discovery, authorize, token, JWKS, userinfo).

    `authorize` selects the persona via `login_hint` — the deterministic
    stand-in for the provider's interactive login screen.
    """
    app = FastAPI(title="PayoutProof Fake OIDC Provider (test-only)")

    @app.get("/.well-known/openid-configuration")
    def openid_configuration():
        return JSONResponse(provider.discovery_document())

    @app.get("/.well-known/jwks.json")
    def jwks():
        return JSONResponse(provider.jwks())

    @app.get("/authorize")
    async def authorize(request: Request):
        qp = parse_qs(request.url.query)
        client_id = (qp.get("client_id") or [""])[0]
        redirect_uri = (qp.get("redirect_uri") or [""])[0]
        login_hint = (qp.get("login_hint") or ["payment_operator"])[0]
        state = (qp.get("state") or [""])[0]
        nonce = (qp.get("nonce") or [None])[0]
        if client_id != TEST_CLIENT_ID:
            return JSONResponse({"error": "invalid_client"}, status_code=400)
        if not redirect_uri:
            return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri required"}, status_code=400)
        if login_hint not in provider.personas:
            return JSONResponse({"error": "invalid_request", "error_description": f"unknown persona '{login_hint}'"}, status_code=400)
        code = provider.issue_code(login_hint, redirect_uri, nonce=nonce)
        params = {"code": code}
        if state:
            params["state"] = state
        return RedirectResponse(f"{redirect_uri}{'&' if '?' in redirect_uri else '?'}{urlencode(params)}")

    @app.post("/token")
    async def token(request: Request):
        body_bytes = await request.body()
        parsed = parse_qs(body_bytes.decode("utf-8"))
        code = parsed.get("code", [""])[0]
        client_id = parsed.get("client_id", [""])[0]
        client_secret = parsed.get("client_secret", [""])[0]
        grant_type = parsed.get("grant_type", [""])[0]
        redirect_uri = parsed.get("redirect_uri", [""])[0]
        if grant_type and grant_type != "authorization_code":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        try:
            return JSONResponse(provider.exchange_code(code, client_id, client_secret, redirect_uri))
        except ValueError as exc:
            reason = str(exc).split(":", 1)[0]
            return JSONResponse({"error": "invalid_grant", "error_description": reason}, status_code=400)

    @app.get("/userinfo")
    async def userinfo(request: Request):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer test-access-"):
            return JSONResponse({"error": "invalid_token"}, status_code=401)
        # The access token is opaque to this fixture; the app consumes the ID
        # token only, so userinfo reports the canonical default persona.
        p = provider.personas["payment_operator"]
        return JSONResponse({
            "sub": p["sub"],
            "name": p["name"],
            TEST_ROLE_CLAIM: p["role"],
            TEST_TENANT_CLAIM: p["tenant_id"],
            TEST_ORGANIZATION_CLAIM: p["organization_id"],
        })

    return app
