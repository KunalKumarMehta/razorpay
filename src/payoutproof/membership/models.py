"""Pydantic models and the frozen membership principal for organization administration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from payoutproof.core.enums import MembershipRole


@dataclass(frozen=True)
class MembershipPrincipal:
    """Verified membership principal resolved from the stateless bearer token.

    Every field is server-derived: the token signature is verified with the
    membership secret and the member row is re-read fresh from SQLite on
    every request, so a removed member stops resolving immediately at their
    next authenticated request.
    """

    member_id: str
    organization_id: str
    email: str
    roles: FrozenSet[MembershipRole]


class InviteMemberRequest(BaseModel):
    """Invite one email to the organization with a single role.

    The client never asserts authority: organization, inviter, and audit
    identity are all server-derived. The invitation secret is generated
    server-side and returned exactly once in the response.
    """

    model_config = ConfigDict(frozen=True)

    email: str = Field(..., min_length=3, max_length=320, description="Invitee email address")
    role: MembershipRole = Field(..., description="The single MembershipRole granted on acceptance")
    expires_at: Optional[str] = Field(
        default=None,
        description="ISO-8601 UTC expiry enforced on every claim; defaults to 7 days from now",
    )


class AcceptInvitationRequest(BaseModel):
    """Claim a single-use invitation and mint the member's bearer token.

    Acceptance is the ONLY session-issuance path. The bearer token is
    returned exactly once and never persisted.
    """

    model_config = ConfigDict(frozen=True)

    invitation_id: str = Field(..., min_length=8, description="Opaque invitation identifier")
    invitation_secret: str = Field(..., min_length=16, description="Single-use invitation secret")
    display_name: str = Field(..., min_length=1, max_length=120, description="Member display name")


class SetMemberRolesRequest(BaseModel):
    """Rewrite a member's full role set.

    Roles come only from the closed MembershipRole vocabulary. Self-mutation
    and dropping the last ACTIVE Tenant Administrator are refused by the
    service inside the write transaction.
    """

    model_config = ConfigDict(frozen=True)

    roles: List[MembershipRole] = Field(..., description="The complete new role set")


class RemoveMemberRequest(BaseModel):
    """Marker body for member removal.

    Every parameter of removal is server-owned (target path, actor from the
    authenticated principal); the body exists only so clients cannot assert
    identity or status fields.
    """

    model_config = ConfigDict(frozen=True)
