"""Frozen role vocabulary and the dispatch-action capability matrix.

The matrix below is a code-level constant: no database table, configuration
file, or API can add a capability to a role. Escalating a role therefore
requires a code change and review, never a data change. In particular, no
role carries Money Action authority — PayoutProof only inserts a
PENDING_FINANCE_APPROVAL item into the downstream approval rail, and a
Handoff Grant is explicitly not a payment approval.

Role names follow CONTEXT.md where the glossary defines them (Payment
Operator, Finance Control Owner). Auditor, Tenant Administrator, and
Platform Operator extend the vocabulary for Issue #7 and are recorded in
the Issue #7 ADR for domain ratification.
"""

from enum import Enum
from typing import Dict, FrozenSet


class Role(str, Enum):
    """Operator roles bound to OIDC-authenticated sessions."""

    PAYMENT_OPERATOR = "PAYMENT_OPERATOR"
    FINANCE_CONTROL_OWNER = "FINANCE_CONTROL_OWNER"
    AUDITOR = "AUDITOR"
    TENANT_ADMINISTRATOR = "TENANT_ADMINISTRATOR"
    PLATFORM_OPERATOR = "PLATFORM_OPERATOR"


# Well-known role claim values as issued by the identity provider. The
# human-readable display names above stay stable even if an IdP renames.
ROLE_CLAIM_VALUES: Dict[str, Role] = {role.value: role for role in Role}

ALL_ROLES: FrozenSet[str] = frozenset(role.value for role in Role)

# Session capability toggles consumed by the API layer. Read-heavy
# capabilities are granted broadly; every mutating capability stays
# narrow. Auditor is strictly read-only: it holds no True entry below.
CAPABILITY_READ_CASES: Dict[str, bool] = {
    Role.PAYMENT_OPERATOR.value: True,
    Role.FINANCE_CONTROL_OWNER.value: True,
    Role.AUDITOR.value: True,
    Role.TENANT_ADMINISTRATOR.value: True,
    Role.PLATFORM_OPERATOR.value: False,
}
CAPABILITY_CREATE_CASES: Dict[str, bool] = {
    Role.PAYMENT_OPERATOR.value: True,
    Role.FINANCE_CONTROL_OWNER.value: True,
    Role.AUDITOR.value: False,
    Role.TENANT_ADMINISTRATOR.value: False,
    Role.PLATFORM_OPERATOR.value: False,
}
CAPABILITY_VERIFY_AUDIT: Dict[str, bool] = {
    Role.PAYMENT_OPERATOR.value: False,
    Role.FINANCE_CONTROL_OWNER.value: True,
    Role.AUDITOR.value: True,
    Role.TENANT_ADMINISTRATOR.value: True,
    Role.PLATFORM_OPERATOR.value: False,
}
CAPABILITY_RUN_EVALUATION: Dict[str, bool] = {
    Role.PAYMENT_OPERATOR.value: False,
    Role.FINANCE_CONTROL_OWNER.value: True,
    Role.AUDITOR.value: False,
    Role.TENANT_ADMINISTRATOR.value: True,
    Role.PLATFORM_OPERATOR.value: True,
}
CAPABILITY_ADMINISTER_TENANT: Dict[str, bool] = {
    Role.PAYMENT_OPERATOR.value: False,
    Role.FINANCE_CONTROL_OWNER.value: False,
    Role.AUDITOR.value: False,
    Role.TENANT_ADMINISTRATOR.value: True,
    Role.PLATFORM_OPERATOR.value: False,
}

# Demo-only and adversarial actions. They stay outside the role matrix and
# are additionally gated by config.enable_demo_adapter_modes at dispatch,
# mirroring the fake_adapter_mode precedent. No business role gets them
# through role checks alone.
DEMO_ONLY_ACTIONS: FrozenSet[str] = frozenset({
    "RESET",
    "FAIL_MODEL",
    "SUBMIT_UNAUTHORIZED_BUNDLE",
    "SUBMIT_TAMPERED_SNAPSHOT",
})

# The frozen dispatch matrix: action -> roles that may dispatch it.
# Rationale:
# - Payment Operator is the maker: it receives the instruction, admits the
#   evidence bundle, extracts/edits/confirm the Payment Intent.
# - Finance Control Owner is the checker: destination approval under finance
#   policy, Policy Gate execution, Handoff Grant issuance, handoff initiation.
#   The maker-checker identity constraint in the API layer additionally
#   forbids the confirming subject from issuing/handing off the same case.
# - Auditor is strictly read-only and appears in no row.
# - Tenant Administrator administers identities, not case workflows, and
#   appears in no row.
# - Platform Operator owns cross-tenant platform operations (health/release
#   via the public router, evaluation runs) and no case content.
ACTION_ROLE_MATRIX: Dict[str, FrozenSet[str]] = {
    "ADMIT_AUTHORIZED_BUNDLE": frozenset({Role.PAYMENT_OPERATOR.value}),
    "ADD_CALLBACK_EVIDENCE": frozenset({Role.PAYMENT_OPERATOR.value}),
    "ADD_CONTRADICTION": frozenset({Role.PAYMENT_OPERATOR.value, Role.FINANCE_CONTROL_OWNER.value}),
    "EXTRACT_INTENT": frozenset({Role.PAYMENT_OPERATOR.value}),
    "EDIT_AMOUNT": frozenset({Role.PAYMENT_OPERATOR.value}),
    "MODIFY_INTENT": frozenset({Role.PAYMENT_OPERATOR.value}),
    "CONFIRM_INTENT": frozenset({Role.PAYMENT_OPERATOR.value}),
    "ADD_DESTINATION_APPROVAL": frozenset({Role.FINANCE_CONTROL_OWNER.value}),
    "EVALUATE_POLICY": frozenset({Role.FINANCE_CONTROL_OWNER.value}),
    "ISSUE_GRANT": frozenset({Role.FINANCE_CONTROL_OWNER.value}),
    "INITIATE_HANDOFF": frozenset({Role.FINANCE_CONTROL_OWNER.value}),
}


def build_action_role_matrix() -> Dict[str, FrozenSet[str]]:
    """Return a deep copy of the frozen action/role matrix for callers that index it.

    The module-level ACTION_ROLE_MATRIX stays the sole enforcement source;
    this helper only serves read-only inspection (e.g. completeness tests).
    """
    return {action: frozenset(roles) for action, roles in ACTION_ROLE_MATRIX.items()}


def role_can_dispatch(action_type: str, role: str) -> bool:
    """Return True only when the frozen matrix explicitly grants the role the action.

    Default-deny: any action absent from the matrix (including demo-only
    actions) is denied to every role. Unknown actions are additionally
    rejected as HTTP 400 by the API layer before this check runs.
    """
    if action_type in DEMO_ONLY_ACTIONS:
        return False
    allowed = ACTION_ROLE_MATRIX.get(action_type)
    if allowed is None:
        return False
    return role in allowed


def validate_matrix_covers_allowed_actions() -> None:
    """Fail loudly when a new ALLOWED_ACTION lacks a role decision.

    Every dispatchable action must either be explicitly role-mapped or be a
    declared demo-only action. A new action added to ALLOWED_ACTIONS without
    a matrix entry would otherwise be silently default-denied, which is
    safe but hides the decision; this check makes the omission visible in
    tests instead.
    """
    from payoutproof.api.actions import ALLOWED_ACTIONS

    for action in ALLOWED_ACTIONS:
        if action in ACTION_ROLE_MATRIX and action in DEMO_ONLY_ACTIONS:
            raise ValueError(f"Action '{action}' is both role-mapped and demo-only; classify it exactly once")
        if action not in ACTION_ROLE_MATRIX and action not in DEMO_ONLY_ACTIONS:
            raise ValueError(
                f"Action '{action}' has no role mapping and is not declared demo-only; "
                "add it to ACTION_ROLE_MATRIX or DEMO_ONLY_ACTIONS"
            )
