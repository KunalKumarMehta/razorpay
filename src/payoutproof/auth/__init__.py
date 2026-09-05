"""Operator authentication and role-bound sessions for PayoutProof.

This package owns the OIDC client, ID-token validation, the server-side
session store, and the role/capability matrix enforced by the API. Identity,
role, tenant, and organization are always server-derived: clients can never
assert them. No role in this package holds Money Action authority.
"""

from payoutproof.auth.roles import (
    Role,
    CAPABILITY_READ_CASES,
    CAPABILITY_CREATE_CASES,
    CAPABILITY_VERIFY_AUDIT,
    CAPABILITY_RUN_EVALUATION,
    CAPABILITY_ADMINISTER_TENANT,
    ACTION_ROLE_MATRIX,
    DEMO_ONLY_ACTIONS,
    role_can_dispatch,
)
from payoutproof.auth.session import SessionRecord, SessionStore, SessionError
from payoutproof.auth.oidc import OIDCProviderClient, OIDCError
from payoutproof.auth.dependencies import (
    SESSION_COOKIE_NAME,
    require_session,
    require_role,
    require_case_reader,
    require_case_creator,
    require_audit_verifier,
    require_evaluation_runner,
    require_tenant_administrator,
    require_action_role,
    require_session_tenant,
    active_organization,
)
from payoutproof.auth import routes

__all__ = [
    "Role",
    "CAPABILITY_READ_CASES",
    "CAPABILITY_CREATE_CASES",
    "CAPABILITY_VERIFY_AUDIT",
    "CAPABILITY_RUN_EVALUATION",
    "CAPABILITY_ADMINISTER_TENANT",
    "ACTION_ROLE_MATRIX",
    "DEMO_ONLY_ACTIONS",
    "role_can_dispatch",
    "SessionRecord",
    "SessionStore",
    "SessionError",
    "OIDCProviderClient",
    "OIDCError",
    "SESSION_COOKIE_NAME",
    "require_session",
    "require_role",
    "require_case_reader",
    "require_case_creator",
    "require_audit_verifier",
    "require_evaluation_runner",
    "require_tenant_administrator",
    "require_action_role",
    "require_session_tenant",
    "active_organization",
    "routes",
]
