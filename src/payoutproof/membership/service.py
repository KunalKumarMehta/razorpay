"""Membership administration service: guard, scope, and audit discipline.

Zero Autonomous Money Actions: this service administers organization
membership only. It never grants authority to approve, release, or
initiate money actions, and it dispatches nothing through the case action
surface (ALLOWED_ACTIONS is untouched). Membership roles govern the
membership surface alone; case-surface authority comes exclusively from the
frozen role matrix in payoutproof.auth.roles.

Documented revocation bound (criterion 3):

    Membership revocation takes effect at the member's **next authenticated
    request**: any authorization check that begins after the removal
    transaction commits is denied, because every check re-reads the member
    row (status, token_version, organization_id) from SQLite with no cache.
    An in-flight request whose authorization check already completed may
    finish. There is no time-based staleness window.

Bearer tokens are stateless HMAC-signed envelopes verified with the
membership secret (never the grant secret), so administration and the
Money Action surface are cryptographically separated. The member row is
the session-revocation authority: removal flips status and bumps
token_version in one transaction, invalidating every outstanding token at
its next validation.
"""

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from payoutproof.core.config import AppConfig
from payoutproof.core.enums import MembershipRole, MembershipStatus
from payoutproof.storage.db import (
    AuditLedgerIntegrityError,
    Database,
    InvitationNotFoundError,
    LastAdministratorError,
    MembershipConflictError,
    MembershipNotFoundError,
    SelfMutationError,
    UnscopedMembershipError,
)

DEFAULT_INVITATION_TTL_DAYS = 7
DEFAULT_SESSION_TTL_SECONDS = 3600


@dataclass(frozen=True)
class MembershipAdminService:
    """Thin service binding Database membership storage to AppConfig secrets.

    Statelessness is deliberate: the Database owns every transaction and the
    audit chain; this service only resolves secrets, defaults, and guards,
    so it can be constructed freely per request with no shared mutable
    state. The membership audit checkpoint MAC continues to use
    audit_checkpoint_secret (audit domain); only bearer tokens use the
    membership secret.
    """

    db: Database
    config: AppConfig

    @property
    def membership_secret(self) -> str:
        """The stateless-token signing key; distinct from grant and audit secrets by construction."""
        return self.config.membership_secret

    def resolve_principal(
        self,
        *,
        organization_id: str,
        bearer_token: Optional[str],
        now: Optional[str] = None,
    ) -> Optional[Any]:
        """Resolve and verify a membership bearer token within the organization scope.

        Returns the principal dict or None on any failure (bad signature,
        expired, removed member, version mismatch, cross-org token) —
        callers must map None to 401/404 without distinguishing which check
        failed.
        """
        if bearer_token is None:
            return None
        return self.db.resolve_membership_principal(
            organization_id=organization_id,
            bearer_token=bearer_token,
            membership_secret=self.membership_secret,
            now=now,
        )

    def require_administrator(
        self,
        *,
        organization_id: str,
        bearer_token: Optional[str],
    ) -> Any:
        """Resolve the principal and require ACTIVE Tenant Administrator membership.

        Fail-closed ordering: an unauthenticated or invalid caller is
        rejected before any existence check (401), a caller outside the
        organization is indistinguishable from absent (404), and a valid
        principal without administration authority gets 403.
        """
        principal = self.resolve_principal(
            organization_id=organization_id,
            bearer_token=bearer_token,
        )
        if principal is None:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=401,
                detail="Membership authentication required",
            )
        if principal["organization_id"] != organization_id:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="Not found")
        if MembershipRole.TENANT_ADMINISTRATOR not in principal["roles"]:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=403,
                detail="Forbidden: only Tenant Administrators may administer membership",
            )
        return principal

    def require_any_member_or_404(
        self,
        *,
        organization_id: str,
        bearer_token: Optional[str],
    ) -> Any:
        """Resolve the principal and require only ACTIVE membership (read paths).

        Any authenticated ACTIVE member of the organization may read the
        member list and verify the membership audit chain; administration
        mutations separately require the Tenant Administrator role.
        """
        principal = self.resolve_principal(
            organization_id=organization_id,
            bearer_token=bearer_token,
        )
        if principal is None:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=401,
                detail="Membership authentication required",
            )
        if principal["organization_id"] != organization_id:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="Not found")
        return principal

    def default_invitation_expiry(self, now: Optional[datetime] = None) -> str:
        """The default invitation expiry: 7 days from now, ISO-8601 UTC."""
        base = now or datetime.now(timezone.utc)
        return (base + timedelta(days=DEFAULT_INVITATION_TTL_DAYS)).isoformat()

    def invite(
        self,
        *,
        organization_id: str,
        email: str,
        role: MembershipRole,
        invited_by: str,
        expires_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a single-use PENDING invitation and append MEMBER_INVITED."""
        resolved_expiry = (expires_at or "").strip() or self.default_invitation_expiry()
        invitation_id, invitation_secret = self.db.invite_member(
            organization_id=organization_id,
            email=email,
            role=role,
            invited_by=invited_by,
            expires_at=resolved_expiry,
        )
        return {
            "invitation_id": invitation_id,
            "invitation_secret": invitation_secret,
            "email": email,
            "role": role,
            "expires_at": resolved_expiry,
            "status": "PENDING",
        }

    def accept(
        self,
        *,
        organization_id: str,
        invitation_id: str,
        invitation_secret: str,
        display_name: str,
        session_ttl_seconds: Optional[int] = None,
        now: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Claim an invitation, create/reactivate the member, and mint the bearer token once."""
        ttl = session_ttl_seconds if session_ttl_seconds is not None else DEFAULT_SESSION_TTL_SECONDS
        return self.db.accept_invitation(
            organization_id=organization_id,
            invitation_id=invitation_id,
            invitation_secret=invitation_secret,
            display_name=display_name,
            membership_secret=self.membership_secret,
            session_ttl_seconds=ttl,
            now=now,
        )

    def revoke_invitation(
        self,
        *,
        organization_id: str,
        invitation_id: str,
        actor_member_id: str,
    ) -> None:
        """Revoke a PENDING invitation and append INVITATION_REVOKED."""
        self.db.revoke_invitation(
            organization_id=organization_id,
            invitation_id=invitation_id,
            actor_member_id=actor_member_id,
        )

    def set_roles(
        self,
        *,
        organization_id: str,
        target_member_id: str,
        new_roles: List[MembershipRole],
        actor_member_id: str,
    ) -> None:
        """Rewrite the member's role set and append MEMBER_ROLE_CHANGED."""
        self.db.set_member_roles(
            organization_id=organization_id,
            target_member_id=target_member_id,
            new_roles=new_roles,
            actor_member_id=actor_member_id,
        )

    def remove(
        self,
        *,
        organization_id: str,
        target_member_id: str,
        actor_member_id: str,
    ) -> Dict[str, Any]:
        """Remove the member with immediate session revocation and append MEMBER_REMOVED."""
        return self.db.remove_member(
            organization_id=organization_id,
            target_member_id=target_member_id,
            actor_member_id=actor_member_id,
        )

    def list_members(self, *, organization_id: str) -> List[Dict[str, Any]]:
        """List ACTIVE members with roles, strictly within one organization."""
        return self.db.list_members(organization_id=organization_id)

    def verify_audit(self, *, organization_id: str) -> Optional[Dict[str, Any]]:
        """Verify the org-keyed membership audit chain and checkpoint MAC (read-only)."""
        return self.db.verify_membership_audit(organization_id=organization_id)

    def generate_invitation_secret(self) -> str:
        """Server-side single-use invitation secret generation (never client-supplied in production)."""
        return secrets.token_urlsafe(32)


MEMBERSHIP_EXCEPTION_MAP: List[tuple] = [
    (InvitationNotFoundError, 404),
    (MembershipNotFoundError, 404),
    (UnscopedMembershipError, 400),
    (SelfMutationError, 403),
    (LastAdministratorError, 409),
    (MembershipConflictError, 409),
    (AuditLedgerIntegrityError, 409),
]

__all__ = [
    "MembershipAdminService",
    "MEMBERSHIP_EXCEPTION_MAP",
    "DEFAULT_INVITATION_TTL_DAYS",
    "DEFAULT_SESSION_TTL_SECONDS",
    "MembershipStatus",
]
