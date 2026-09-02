"""Handoff Grant issuance and verification."""

from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from payoutproof.core.models import RiskCaseState, HandoffGrant
from payoutproof.core.enums import PolicyOutcome, GrantStatus
from payoutproof.core.crypto import (
    generate_nonce,
    create_grant_signature,
    verify_grant_signature,
    compute_snapshot_hash,
)

DEFAULT_GRANT_SECRET = "payoutproof-local-grant-signing-secret-2026"
GRANT_VALIDITY_SECONDS = 300  # 5 minutes


class GrantIssuer:
    """Issues single-use HMAC-signed Handoff Grants for eligible cases."""

    @classmethod
    def issue_grant(
        cls,
        state: RiskCaseState,
        secret: str = DEFAULT_GRANT_SECRET,
        validity_seconds: int = GRANT_VALIDITY_SECONDS,
    ) -> HandoffGrant:
        """Issue a fresh Handoff Grant bound to case, intent hash, and snapshot hash."""
        if state.policy.outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF:
            raise ValueError(f"Cannot issue Handoff Grant for case with policy outcome {state.policy.outcome}")

        if not state.intent.intent_hash or state.policy.evaluated_intent_hash != state.intent.intent_hash:
            raise ValueError("Evaluated intent hash mismatch or intent not frozen")

        if not state.case_id:
            raise ValueError("Case ID is required to issue Handoff Grant")

        nonce = generate_nonce(16)
        grant_id = f"HG-{state.case_id}-{nonce[:8]}"
        now = datetime.now(timezone.utc)
        issued_at = now.isoformat()
        expires_at = (now + timedelta(seconds=validity_seconds)).isoformat()
        snapshot_hash = compute_snapshot_hash(state)

        signature = create_grant_signature(
            secret=secret,
            grant_id=grant_id,
            tenant_id=state.tenant_id,
            case_id=state.case_id,
            bound_intent_hash=state.intent.intent_hash,
            bound_snapshot_hash=snapshot_hash,
            policy_version=state.policy.policy_version,
            outcome=state.policy.outcome.value,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )

        return HandoffGrant(
            grant_id=grant_id,
            tenant_id=state.tenant_id,
            case_id=state.case_id,
            bound_intent_hash=state.intent.intent_hash,
            bound_snapshot_hash=snapshot_hash,
            policy_version=state.policy.policy_version,
            outcome=state.policy.outcome,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature,
            status=GrantStatus.ACTIVE,
            used=False,
        )


class GrantVerifier:
    """Verifies Handoff Grants against signatures, expiration, and bound hashes."""

    @classmethod
    def verify(
        cls,
        grant: HandoffGrant,
        current_intent_hash: str,
        secret: str = DEFAULT_GRANT_SECRET,
    ) -> Tuple[bool, Optional[str]]:
        """Verify validity of a Handoff Grant."""
        if grant.status != GrantStatus.ACTIVE:
            return False, f"Grant is not active (status: {grant.status})"

        if grant.used:
            return False, "Grant has already been consumed (single-use protection)"

        # Check expiration
        try:
            expires_dt = datetime.fromisoformat(grant.expires_at)
            if datetime.now(timezone.utc) > expires_dt:
                return False, "Grant has expired"
        except Exception as e:
            return False, f"Invalid expiration timestamp: {e}"

        # Verify HMAC signature
        is_sig_valid = verify_grant_signature(
            secret=secret,
            grant_id=grant.grant_id,
            tenant_id=grant.tenant_id,
            case_id=grant.case_id,
            bound_intent_hash=grant.bound_intent_hash,
            bound_snapshot_hash=grant.bound_snapshot_hash,
            policy_version=grant.policy_version,
            outcome=grant.outcome.value,
            nonce=grant.nonce,
            issued_at=grant.issued_at,
            expires_at=grant.expires_at,
            signature=grant.signature,
        )
        if not is_sig_valid:
            return False, "Cryptographic grant signature verification failed"

        # Verify bound intent hash matches current intent hash
        if grant.bound_intent_hash != current_intent_hash:
            return False, "Bound intent hash does not match current intent hash (material mutation detected)"

        return True, None
