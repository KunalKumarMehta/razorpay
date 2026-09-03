"""Membership administration API routes (Issue #8).

Routes live under their own /api/memberships/... namespace and never
dispatch through dispatch_action; ALLOWED_ACTIONS is untouched (binding
constraint 1). Bearer tokens travel in the Authorization header, never
cookies — the session-cookie path stays strictly with the OIDC operator
surface. Payloads never assert authority: bodies carrying identity, role,
organization, status, or member fields are rejected with 400 before any
transaction opens, mirroring DISALLOWED_PAYLOAD_FIELDS.

Error mapping (binding constraint 3):
  - missing/invalid/expired/revoked token -> 401
  - token-org != header-org -> 404 (zero-existence oracle)
  - valid principal, insufficient role -> 403
  - target absent/cross-org -> 404
  - body/header org conflict -> 400
  - unknown role -> 400
  - duplicate member / last-admin conflict -> 409
  - audit chain tampered -> 409 and further mutations refused
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request, status

from payoutproof.core.enums import MembershipRole
from payoutproof.membership.models import (
    AcceptInvitationRequest,
    InviteMemberRequest,
    RemoveMemberRequest,
    SetMemberRolesRequest,
)
from payoutproof.membership.service import MEMBERSHIP_EXCEPTION_MAP, MembershipAdminService
from payoutproof.storage.db import AuditLedgerIntegrityError

# Identity, scope, and authority fields a membership client can never author.
MEMBERSHIP_DISALLOWED_PAYLOAD_FIELDS = {
    "actor",
    "actor_member_id",
    "role",
    "roles",
    "organization_id",
    "organization",
    "status",
    "member_id",
    "target_member_id",
    "token",
    "bearer_token",
    "token_version",
    "secret",
    "invitation_secret",
    "granted_by",
    "display_name_of_actor",
}

# Accepted case route prefix mapping for org header (kept explicit, no reuse
# of the session dependency: the membership surface has its own principal).
router = APIRouter()


def _resolve_service(request: Request) -> MembershipAdminService:
    db = getattr(request.app.state, "db", None)
    config = getattr(request.app.state, "config", None)
    if db is None or config is None:
        raise HTTPException(status_code=500, detail="Membership dependencies not configured")
    return MembershipAdminService(db=db, config=config)


def _require_org_header(request: Request) -> str:
    """The mandatory X-Organization-Id header for the membership surface.

    Unlike the case surface (where the session owns the organization), the
    membership surface is itself the authority on scope: the header is
    mandatory and must match the token's organization exactly. A mismatch
    is a zero-existence 404, never a 403 that leaks the org's existence.
    """
    raw = request.headers.get("X-Organization-Id")
    if raw is None or not raw.strip():
        raise HTTPException(
            status_code=400,
            detail="Missing mandatory organization identity: X-Organization-Id",
        )
    return raw.strip()


def _bearer_token(request: Request) -> Optional[str]:
    """Extract the membership bearer token from the Authorization header (never cookies)."""
    raw = request.headers.get("Authorization")
    if raw is None or not raw.strip():
        return None
    value = raw.strip()
    if value.lower().startswith("bearer "):
        return value[7:].strip() or None
    return None


def _reject_disallowed_fields(payload_keys) -> None:
    disallowed = [k for k in payload_keys if k in MEMBERSHIP_DISALLOWED_PAYLOAD_FIELDS]
    if disallowed:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Disallowed client fields: {disallowed}. Membership clients cannot assert "
                "identity, roles, scope, or authority; those are server-owned."
            ),
        )


@router.post("/api/memberships/invitations")
def invite_member(
    req: InviteMemberRequest,
    request: Request,
) -> Dict[str, Any]:
    """Create a single-use invitation for one email (Tenant Administrator only).

    The raw invitation secret is returned exactly once; only its SHA-256 is
    persisted, and neither the secret nor its hash ever enters the audit
    chain or any log.
    """
    organization_id = _require_org_header(request)
    service = _resolve_service(request)
    extra = req.model_dump(exclude={"email", "role", "expires_at"})
    _reject_disallowed_fields(extra.keys())
    principal = service.require_administrator(
        organization_id=organization_id,
        bearer_token=_bearer_token(request),
    )
    try:
        return service.invite(
            organization_id=organization_id,
            email=req.email,
            role=req.role,
            invited_by=principal["member_id"],
            expires_at=req.expires_at,
        )
    except HTTPException:
        raise
    except AuditLedgerIntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Membership audit integrity failure: {exc}",
        )
    except Exception as exc:
        _raise_mapped(exc)


@router.post("/api/memberships/invitations/accept")
def accept_invitation(
    req: AcceptInvitationRequest,
    request: Request,
) -> Dict[str, Any]:
    """Claim a single-use invitation; the only session-issuance path.

    The bearer token is returned exactly once, never persisted, never
    logged. An unknown, expired, revoked, cross-org, or already-used
    invitation is indistinguishable from absent (404).
    """
    organization_id = _require_org_header(request)
    service = _resolve_service(request)
    try:
        result = service.accept(
            organization_id=organization_id,
            invitation_id=req.invitation_id,
            invitation_secret=req.invitation_secret,
            display_name=req.display_name,
        )
    except HTTPException:
        raise
    except AuditLedgerIntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Membership audit integrity failure: {exc}",
        )
    except Exception as exc:
        _raise_mapped(exc)
    # roles are enum values; serialize to their string vocabulary
    result = dict(result)
    result["roles"] = [r.value if hasattr(r, "value") else str(r) for r in result["roles"]]
    return result


@router.post("/api/memberships/invitations/{invitation_id}/revoke")
def revoke_invitation(
    invitation_id: str,
    request: Request,
) -> Dict[str, Any]:
    """Revoke a PENDING invitation (Tenant Administrator only)."""
    organization_id = _require_org_header(request)
    service = _resolve_service(request)
    principal = service.require_administrator(
        organization_id=organization_id,
        bearer_token=_bearer_token(request),
    )
    try:
        service.revoke_invitation(
            organization_id=organization_id,
            invitation_id=invitation_id,
            actor_member_id=principal["member_id"],
        )
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped(exc)
    return {"invitation_id": invitation_id, "status": "REVOKED"}


@router.get("/api/memberships/members")
def list_members(request: Request) -> List[Dict[str, Any]]:
    """List ACTIVE members with their role sets (Tenant Administrator only)."""
    organization_id = _require_org_header(request)
    service = _resolve_service(request)
    service.require_administrator(
        organization_id=organization_id,
        bearer_token=_bearer_token(request),
    )
    return service.list_members(organization_id=organization_id)


@router.get("/api/memberships/members/{member_id}/roles")
def get_member_roles(member_id: str, request: Request) -> Dict[str, Any]:
    """Read one member's role set (any authenticated member of the organization)."""
    organization_id = _require_org_header(request)
    service = _resolve_service(request)
    principal = service.require_any_member_or_404(
        organization_id=organization_id,
        bearer_token=_bearer_token(request),
    )
    del principal
    members = service.list_members(organization_id=organization_id)
    for m in members:
        if m["member_id"] == member_id:
            return {"member_id": member_id, "roles": m["roles"], "status": m["status"]}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")


@router.post("/api/memberships/members/{member_id}/roles")
def set_member_roles(
    member_id: str,
    req: SetMemberRolesRequest,
    request: Request,
) -> Dict[str, Any]:
    """Rewrite a member's full role set (Tenant Administrator only).

    Self-mutation is refused (403) and dropping the last ACTIVE Tenant
    Administrator is refused (409); both guards run inside the write
    transaction so concurrent administrators cannot race past them.
    """
    organization_id = _require_org_header(request)
    service = _resolve_service(request)
    principal = service.require_administrator(
        organization_id=organization_id,
        bearer_token=_bearer_token(request),
    )
    try:
        service.set_roles(
            organization_id=organization_id,
            target_member_id=member_id,
            new_roles=list(req.roles),
            actor_member_id=principal["member_id"],
        )
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped(exc)
    return {"member_id": member_id, "roles": [r.value for r in req.roles]}


@router.post("/api/memberships/members/{member_id}/remove")
def remove_member(
    member_id: str,
    req: RemoveMemberRequest,
    request: Request,
) -> Dict[str, Any]:
    """Remove a member with immediate session revocation (Tenant Administrator only).

    Removal flips status to REMOVED and bumps token_version in one
    transaction: the member's token fails at its very next authenticated
    request. Money Action tables are never touched.
    """
    organization_id = _require_org_header(request)
    service = _resolve_service(request)
    principal = service.require_administrator(
        organization_id=organization_id,
        bearer_token=_bearer_token(request),
    )
    try:
        result = service.remove(
            organization_id=organization_id,
            target_member_id=member_id,
            actor_member_id=principal["member_id"],
        )
    except HTTPException:
        raise
    except Exception as exc:
        _raise_mapped(exc)
    return {
        "member_id": result["target_member_id"],
        "email": result["email"],
        "status": "REMOVED",
        "token_version": result["token_version"],
    }


@router.get("/api/memberships/audit/verify")
def verify_membership_audit(request: Request) -> Dict[str, Any]:
    """Verify the org-keyed membership audit chain and checkpoint MAC (read-only).

    Any authenticated member of the organization may verify; tampering with
    any membership_audit_events row makes verification fail and every
    further membership mutation refuse with 409.
    """
    organization_id = _require_org_header(request)
    service = _resolve_service(request)
    principal = service.require_any_member_or_404(
        organization_id=organization_id,
        bearer_token=_bearer_token(request),
    )
    del principal
    result = service.verify_audit(organization_id=organization_id)
    if result is None:
        return {
            "organization_id": organization_id,
            "total_events": 0,
            "event_count": 0,
            "is_valid": True,
            "trust_state": "TRUSTED",
            "broken_at_seq": None,
            "reason": "No membership activity recorded for this organization",
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


def _raise_mapped(exc: Exception) -> None:
    """Map a storage/service exception to its contracted HTTP status (or re-raise 500)."""
    for exc_type, code in MEMBERSHIP_EXCEPTION_MAP:
        if isinstance(exc, exc_type):
            raise HTTPException(status_code=code, detail=str(exc)) from exc
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Internal error during membership administration; operation aborted safely fail-closed.",
    ) from exc
