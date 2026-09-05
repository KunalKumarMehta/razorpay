"""Client-dispatchable action vocabulary and server-authority payload rules.

This module is the single shared definition of dispatch action names and the
payload fields clients may never author. It exists so the auth package can
validate the role matrix against the authoritative action set without
importing the FastAPI application module (which would be circular).
"""

# All dispatchable lifecycle action names accepted by POST /api/cases/{case_id}/dispatch.
ALLOWED_ACTIONS = {
    "RESET",
    "ADMIT_AUTHORIZED_BUNDLE",
    "SUBMIT_UNAUTHORIZED_BUNDLE",
    "EXTRACT_INTENT",
    "FAIL_MODEL",
    "CONFIRM_INTENT",
    "ADD_CALLBACK_EVIDENCE",
    "ADD_DESTINATION_APPROVAL",
    "ADD_CONTRADICTION",
    "SUBMIT_TAMPERED_SNAPSHOT",
    "EVALUATE_POLICY",
    "ISSUE_GRANT",
    "EDIT_AMOUNT",
    "MODIFY_INTENT",
    "CORRECT_INTENT",
    "INVALIDATE_INTENT",
    "INITIATE_HANDOFF",
}

# Removed direct outcome commands: outcomes are strictly server-owned.
REMOVED_OUTCOME_COMMANDS = {
    "HANDOFF_ACCEPTED",
    "HANDOFF_AMBIGUOUS",
    "REPLAY_GRANT",
}

# Payload fields clients can never author: outcomes, state overrides, and —
# since Issue #7 — every identity, role, tenant, organization, actor, and
# session field. Identity is server-derived from the authenticated session
# only; a client-asserted value here is an escalation attempt and is
# rejected with HTTP 400 before any state machine code runs.
DISALLOWED_PAYLOAD_FIELDS = {
    "pending_item_id",
    "adapter_decision",
    "outcome",
    "grant_status",
    "used",
    "state",
    "phase",
    "case_version",
    "status",
    "last_adapter_decision",
    "policy_outcome",
    "idempotency_key",
    # Identity/session authority fields (Issue #7): server-owned.
    "actor",
    "actor_role",
    "role",
    "roles",
    "subject",
    "operator",
    "user",
    "user_id",
    "session",
    "session_id",
    "tenant_id",
    "organization_id",
    "organization",
}
