"""OIDC authorization-code-flow client for PayoutProof.

The client speaks standard OIDC: discovery document, authorization endpoint
redirect, token exchange with client authentication, and JWKS-based RS256
ID-token verification. The deterministic test provider implements the same
protocol in-process (its ASGI app is reachable through an injected httpx
transport), so the validation code here is exercised unchanged against
test key material — the fake swaps only key material and endpoints via
`create_app` dependency injection, never a config flag or env default.
"""

import time
from typing import Any, Dict, Optional, Protocol
from urllib.parse import urlencode

import httpx

from payoutproof.auth.jwt_util import decode_and_verify_jwt
from payoutproof.auth.roles import ROLE_CLAIM_VALUES, Role
from payoutproof.core.providers import ClockProvider, SystemClock


class OIDCError(Exception):
    """Raised when the provider exchange or ID-token validation fails (reason prefixed)."""


class TransportProvider(Protocol):
    """Minimal httpx-compatible client surface this module needs."""

    def get(self, url: str, **kwargs) -> Any: ...

    def post(self, url: str, data: Optional[Dict[str, str]] = None, **kwargs) -> Any: ...

class OIDCProviderClient:
    """Standard OIDC client bound to a configured issuer.

    `transport` must expose httpx-like `get`/`post`. Production passes a real
    `httpx.Client`; tests pass a transport backed by the in-process fake
    provider, so no network call ever occurs.
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str,
        audience: Optional[str] = None,
        transport: Optional[TransportProvider] = None,
        clock: Optional[ClockProvider] = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience or client_id
        self.clock = clock if clock is not None else SystemClock()
        self._transport = transport if transport is not None else httpx.Client(timeout=timeout_seconds)
        self._discovery: Optional[Dict[str, Any]] = None
        self._jwks: Optional[Dict[str, Any]] = None
        self._oidc_config = None
        self._role_claim = None
        self._tenant_claim = None
        self._organization_claim = None

    def configure_claims(
        self,
        role_claim: str,
        tenant_claim: str,
        organization_claim: str,
    ) -> None:
        self._role_claim = role_claim
        self._tenant_claim = tenant_claim
        self._organization_claim = organization_claim

    def discovery(self) -> Dict[str, Any]:
        """Fetch and cache the discovery document for the configured issuer."""
        if self._discovery is None:
            try:
                resp = self._transport.get(f"{self.issuer}/.well-known/openid-configuration")
            except httpx.HTTPError as exc:
                raise OIDCError(f"DISCOVERY_UNAVAILABLE: {exc}") from exc
            if resp.status_code != 200:
                raise OIDCError(f"DISCOVERY_HTTP_{resp.status_code}")
            try:
                doc = resp.json()
            except ValueError as exc:
                raise OIDCError(f"DISCOVERY_MALFORMED: {exc}") from exc
            if doc.get("issuer") != self.issuer:
                raise OIDCError(
                    f"DISCOVERY_ISSUER_MISMATCH: discovery issuer {doc.get('issuer')!r} != configured {self.issuer!r}"
                )
            for required in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not doc.get(required):
                    raise OIDCError(f"DISCOVERY_MISSING_{required.upper()}")
            self._discovery = doc
        return self._discovery

    def jwks(self) -> Dict[str, Any]:
        """Fetch and cache the provider JWKS used to verify ID tokens."""
        if self._jwks is None:
            doc = self.discovery()
            try:
                resp = self._transport.get(doc["jwks_uri"])
            except httpx.HTTPError as exc:
                raise OIDCError(f"JWKS_UNAVAILABLE: {exc}") from exc
            if resp.status_code != 200:
                raise OIDCError(f"JWKS_HTTP_{resp.status_code}")
            try:
                self._jwks = resp.json()
            except ValueError as exc:
                raise OIDCError(f"JWKS_MALFORMED: {exc}") from exc
        return self._jwks

    def authorization_url(
        self,
        redirect_uri: str,
        state: str,
        nonce: str,
        login_hint: Optional[str] = None,
    ) -> str:
        """Build the provider authorization endpoint URL for the code flow."""
        doc = self.discovery()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid",
            "state": state,
            "nonce": nonce,
        }
        if login_hint:
            params["login_hint"] = login_hint
        return f"{doc['authorization_endpoint']}?{urlencode(params)}"

    def exchange_code(self, code: str, redirect_uri: str) -> str:
        """Exchange an authorization code for an ID token (client-authenticated)."""
        doc = self.discovery()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": redirect_uri,
        }
        try:
            resp = self._transport.post(doc["token_endpoint"], data=data)
        except httpx.HTTPError as exc:
            raise OIDCError(f"TOKEN_EXCHANGE_UNAVAILABLE: {exc}") from exc
        if resp.status_code != 200:
            raise OIDCError(f"TOKEN_EXCHANGE_REJECTED: provider returned HTTP {resp.status_code}")
        try:
            body = resp.json()
        except ValueError as exc:
            raise OIDCError(f"TOKEN_RESPONSE_MALFORMED: {exc}") from exc
        id_token = body.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise OIDCError("TOKEN_RESPONSE_MISSING_ID_TOKEN")
        return id_token

    def validate_id_token(
        self,
        id_token: str,
        *,
        expected_nonce: Optional[str] = None,
        now_epoch: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Verify signature and envelope claims, then map identity claims to a session identity.

        Returns {"subject", "display_name", "role", "tenant_id", "organization_id"}.
        Raises OIDCError (reason-prefixed) for any validation failure, so the
        API layer can map every failure to a precise, safe 401.
        """
        from payoutproof.auth.jwt_util import JwtValidationError

        now = now_epoch if now_epoch is not None else self.clock.now().timestamp()
        try:
            _, claims = decode_and_verify_jwt(
                id_token,
                self.jwks(),
                expected_issuer=self.issuer,
                expected_audience=self.audience,
                now_epoch=now,
            )
        except JwtValidationError as exc:
            raise OIDCError(str(exc)) from exc

        if expected_nonce is not None:
            token_nonce = claims.get("nonce")
            if not isinstance(token_nonce, str) or token_nonce != expected_nonce:
                raise OIDCError("NONCE_MISMATCH: ID-token nonce does not match the login request")

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise OIDCError("SUBJECT_MISSING: ID token carries no usable subject")

        role_claim = claims.get(self._role_claim or "payoutproof_role")
        if not isinstance(role_claim, str) or role_claim not in ROLE_CLAIM_VALUES:
            raise OIDCError(
                f"ROLE_CLAIM_INVALID: role claim {role_claim!r} is not a recognized operator role"
            )
        role = Role(role_claim)

        tenant_claim_name = self._tenant_claim or "payoutproof_tenant"
        organization_claim_name = self._organization_claim or "payoutproof_organization"
        tenant_id = claims.get(tenant_claim_name)
        organization_id = claims.get(organization_claim_name)
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise OIDCError(f"TENANT_CLAIM_MISSING: {tenant_claim_name} claim is absent or empty")
        if not isinstance(organization_id, str) or not organization_id.strip():
            raise OIDCError(f"ORGANIZATION_CLAIM_MISSING: {organization_claim_name} claim is absent or empty")

        display_name = claims.get("name")
        if not isinstance(display_name, str) or not display_name.strip():
            display_name = subject

        return {
            "subject": subject,
            "display_name": display_name,
            "role": role,
            "tenant_id": tenant_id,
            "organization_id": organization_id,
        }
