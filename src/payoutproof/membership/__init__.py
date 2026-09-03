"""Organization membership administration domain (Issue #8).

Tenant administration operates strictly within the organization boundary and
grants no authority over Money Actions. Administration and the Money Action
surface share zero tables and zero code paths; T-BARRIER-1 in
tests/test_membership_barrier.py proves mechanically that dropping every
membership table leaves the full Money Action lifecycle — case creation,
policy gate, grant issuance, handoff — 100% operational.
"""

from payoutproof.membership.models import (
    MembershipPrincipal,
    InviteMemberRequest,
    AcceptInvitationRequest,
    SetMemberRolesRequest,
    RemoveMemberRequest,
)
from payoutproof.membership.service import MembershipAdminService

__all__ = [
    "MembershipPrincipal",
    "InviteMemberRequest",
    "AcceptInvitationRequest",
    "SetMemberRolesRequest",
    "RemoveMemberRequest",
    "MembershipAdminService",
]
