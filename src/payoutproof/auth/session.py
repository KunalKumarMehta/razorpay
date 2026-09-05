"""Server-side operator sessions: opaque tokens, hashed at rest, revocable.

The cookie carries only an opaque high-entropy token; the authoritative
session record (subject, role, tenant, organization, expiry, revocation)
lives in the `operator_sessions` table keyed by `sha256(token)`. A DB read
therefore never leaks a usable bearer token, revocation is immediate and
global (DELETE-equivalent: the row is marked revoked), and roles stay
server-truth for the session's lifetime instead of living in a client-held
claim.

Expiry is evaluated on every request against the ClockProvider, never
only at mint time. In-memory process lifetime is the stated MVP limitation:
sessions do not survive a restart, which is acceptable for the MVP and is
documented in the Issue #7 ADR rather than silently surprising anyone.
"""

import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import Response

from payoutproof.auth.roles import Role
from payoutproof.core.crypto import sha256_hex
from payoutproof.core.providers import ClockProvider, SystemClock, NonceProvider, SystemNonce
from payoutproof.storage.db import Database

COOKIE_SAMESITE = "lax"
COOKIE_PATH = "/"


class SessionError(Exception):
    """Raised when a session token cannot be resolved to an active session (reason prefixed)."""


class SessionRecord:
    """Immutable view of one operator session as resolved from storage."""

    def __init__(self, row: Dict[str, Any]) -> None:
        self.session_id: str = row["session_id"]
        self.token_hash: str = row["token_hash"]
        self.subject: str = row["subject"]
        self.display_name: str = row["display_name"]
        self.role: Role = Role(row["role"])
        self.tenant_id: str = row["tenant_id"]
        self.organization_id: str = row["organization_id"]
        self.idp_issuer: str = row["idp_issuer"]
        self.issued_at: str = row["issued_at"]
        self.expires_at: str = row["expires_at"]
        self.last_seen_at: Optional[str] = row["last_seen_at"]
        self.revoked_at: Optional[str] = row["revoked_at"]

    @property
    def actor(self) -> str:
        """Attribution string stamped into audit events: subject plus role."""
        return f"{self.subject}|{self.role.value}"

    def to_public_dict(self) -> Dict[str, Any]:
        """Safe identity summary for /api/auth/me. Never exposes the token or its hash."""
        return {
            "session_id": self.session_id,
            "subject": self.subject,
            "display_name": self.display_name,
            "role": self.role.value,
            "tenant_id": self.tenant_id,
            "organization_id": self.organization_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


class SessionStore:
    """Issue, resolve, and revoke operator sessions against SQLite storage."""

    def __init__(
        self,
        db: Database,
        clock: Optional[ClockProvider] = None,
        nonce_provider: Optional[NonceProvider] = None,
        ttl_seconds: int = 28800,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.db = db
        self.clock = clock if clock is not None else SystemClock()
        self.nonce_provider = nonce_provider if nonce_provider is not None else SystemNonce()
        self.ttl_seconds = ttl_seconds

    def mint(
        self,
        *,
        subject: str,
        display_name: str,
        role: Role,
        tenant_id: str,
        organization_id: str,
        idp_issuer: str,
    ) -> str:
        """Mint a new session; returns the opaque cookie token (stored hashed)."""
        token = secrets.token_urlsafe(32)
        session_id = f"SESS-{self.nonce_provider.generate_nonce(16).upper()}"
        now = self.clock.now()
        issued_at = now.isoformat()
        expires_at = (now + timedelta(seconds=self.ttl_seconds)).isoformat()
        self.db.create_operator_session(
            session_id=session_id,
            token_hash=sha256_hex(token),
            subject=subject,
            display_name=display_name,
            role=role.value,
            tenant_id=tenant_id,
            organization_id=organization_id,
            idp_issuer=idp_issuer,
            issued_at=issued_at,
            expires_at=expires_at,
            last_seen_at=issued_at,
        )
        return token

    def resolve(self, token: Optional[str], *, touch: bool = True) -> SessionRecord:
        """Resolve a cookie token to an active session record.

        Raises SessionError (reason-prefixed) for a missing token, unknown
        session, revoked session, or expired session. Expiry uses the
        injected clock, so tests time-travel deterministically.
        """
        if not token or not token.strip():
            raise SessionError("SESSION_ABSENT: no session cookie presented")
        row = self.db.get_operator_session(sha256_hex(token))
        if row is None:
            raise SessionError("SESSION_UNKNOWN: session does not exist")
        if row["revoked_at"] is not None:
            raise SessionError("SESSION_REVOKED: session was revoked; sign in again")
        now = self.clock.now()
        try:
            exp_dt = datetime.fromisoformat(row["expires_at"])
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=now.tzinfo)
        except (ValueError, TypeError):
            raise SessionError("SESSION_CORRUPT: stored expiry is malformed")
        if exp_dt <= now:
            raise SessionError("SESSION_EXPIRED: session has expired; sign in again")
        record = SessionRecord(row)
        if touch:
            self.db.touch_operator_session(sha256_hex(token), now.isoformat())
        return record

    def revoke(self, token: Optional[str]) -> bool:
        """Revoke the session for a token; returns False when it does not exist."""
        if not token or not token.strip():
            return False
        return self.db.revoke_operator_session(
            sha256_hex(token), revoked_at=self.clock.now().isoformat()
        )


def set_session_cookie(
    response: Response,
    token: str,
    *,
    cookie_name: str,
    ttl_seconds: int,
    secure: bool,
) -> None:
    """Attach the opaque session token as an HttpOnly cookie.

    `Secure` is driven by configuration (true in production/staging via
    from_env; the ASGI test transport is plain HTTP, so tests pass False).
    `SameSite=Lax` blocks cross-site POST cookie attachment while keeping
    top-level navigation flows workable.
    """
    response.set_cookie(
        key=cookie_name,
        value=token,
        max_age=ttl_seconds,
        httponly=True,
        secure=secure,
        samesite=COOKIE_SAMESITE,
        path=COOKIE_PATH,
    )


def clear_session_cookie(response: Response, *, cookie_name: str, secure: bool) -> None:
    """Expire the session cookie on logout (the session row is revoked separately)."""
    response.delete_cookie(
        key=cookie_name,
        path=COOKIE_PATH,
        secure=secure,
        samesite=COOKIE_SAMESITE,
        httponly=True,
    )
