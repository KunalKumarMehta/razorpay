"""Handoff Grant issuance and verification."""

from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from payoutproof.core.models import RiskCaseState, HandoffGrant
from payoutproof.core.enums import (
    PolicyOutcome,
    GrantStatus,
    CasePhase,
    ProcessingAuthorityStatus,
)
from payoutproof.core.crypto import (
    generate_nonce,
    create_grant_signature,
    verify_grant_signature,
    compute_snapshot_hash,
    compute_intent_hash,
)
from payoutproof.core.providers import (
    ClockProvider,
    NonceProvider,
    SystemClock,
    SystemNonce,
)
from payoutproof.core.keys import KeyRing

GRANT_VALIDITY_SECONDS = 300  # 5 minutes


class GrantVerificationError(ValueError):
    """Raised when a Handoff Grant fails verification against authoritative case scope.

    Carries a safe, stable reason string with no exception text so callers can
    surface it directly without leaking internals.
    """

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class GrantIssuer:
    """Issues single-use HMAC-signed Handoff Grants for eligible cases."""

    @classmethod
    def issue_grant(
        cls,
        state: RiskCaseState,
        *,
        secret: str | KeyRing,
        validity_seconds: int = GRANT_VALIDITY_SECONDS,
        clock: Optional[ClockProvider] = None,
        nonce_provider: Optional[NonceProvider] = None,
        key_id: Optional[str] = None,
    ) -> HandoffGrant:
        """Issue a fresh Handoff Grant bound to case, intent hash, and snapshot hash."""
        if isinstance(secret, KeyRing):
            signing_secret = secret.active_secret
            signing_key_id = secret.active_key_id
        else:
            if not secret or not str(secret).strip():
                raise ValueError("secret is required and cannot be empty to issue Handoff Grant")
            signing_secret = str(secret)
            signing_key_id = key_id

        resolved_clock = clock if clock is not None else SystemClock()
        resolved_nonce_provider = nonce_provider if nonce_provider is not None else SystemNonce()

        # 0. Check processing authority and admitted evidence
        is_admission_valid = (
            state.request_bundle_status == "ADMITTED"
            and state.phase != CasePhase.ADMISSION_REJECTED
            and state.processing_authority == ProcessingAuthorityStatus.VALID
            and state.authority_record is not None
            and state.authority_record.is_valid
            and len(state.evidence) > 0
        )
        if not is_admission_valid:
            raise ValueError("Cannot issue Handoff Grant without valid processing authority and admitted evidence")

        if state.policy.outcome != PolicyOutcome.ELIGIBLE_FOR_HANDOFF:
            raise ValueError(f"Cannot issue Handoff Grant for case with policy outcome {state.policy.outcome}")

        if not state.policy.policy_version or not str(state.policy.policy_version).strip():
            raise ValueError("Policy evaluation version is required to issue Handoff Grant")

        if not state.case_id:
            raise ValueError("Case ID is required to issue Handoff Grant")

        if not state.intent.intent_hash:
            raise ValueError("Payment Intent must be confirmed and hashed before issuing grant")

        recomputed_intent_hash = compute_intent_hash(state.intent)
        if recomputed_intent_hash != state.intent.intent_hash:
            raise ValueError("Recomputed intent hash mismatch; Payment Intent was mutated after confirmation")

        if state.policy.evaluated_intent_hash != state.intent.intent_hash:
            raise ValueError("Evaluated intent hash mismatch or intent not frozen")

        if not state.policy.evaluated_snapshot_hash:
            raise ValueError("Policy evaluation result is missing evaluated_snapshot_hash")

        recomputed_snapshot_hash = compute_snapshot_hash(state)
        if state.policy.evaluated_snapshot_hash != recomputed_snapshot_hash:
            raise ValueError("Evaluated snapshot hash mismatch: case state was mutated after policy evaluation")

        # Organization scope must agree between the case and its policy result so
        # the issued grant provably carries the case's organization identity.
        if state.policy.organization_id is not None and state.policy.organization_id != state.organization_id:
            raise ValueError(
                "Policy evaluation result organization scope does not match the case organization scope"
            )

        nonce = resolved_nonce_provider.generate_nonce(16)
        grant_id = f"HG-{state.case_id}-{nonce[:8]}"
        now = resolved_clock.now()
        issued_at = now.isoformat()
        expires_at = (now + timedelta(seconds=validity_seconds)).isoformat()
        snapshot_hash = recomputed_snapshot_hash

        signature = create_grant_signature(
            secret=signing_secret,
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
            organization_id=state.organization_id,
            key_id=signing_key_id,
        )

        return HandoffGrant(
            grant_id=grant_id,
            tenant_id=state.tenant_id,
            organization_id=state.organization_id,
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
            key_id=signing_key_id,
        )


class GrantVerifier:
    """Verifies Handoff Grants against signatures, expiration, and bound hashes."""

    @classmethod
    def verify(
        cls,
        grant: HandoffGrant,
        current_intent_hash: str,
        *,
        secret: str | KeyRing,
        clock: Optional[ClockProvider] = None,
        expected_organization_id: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Verify validity of a Handoff Grant.

        When expected_organization_id is supplied, the grant's own organization_id
        must match exactly; any substitution fails closed. Passing None means
        "no expected scope asserted" (legacy call sites); use verify_for_case to
        enforce the authoritative case scope.
        """
        if not secret:
            return False, "secret is required and cannot be empty to verify Handoff Grant"
        resolved_clock = clock if clock is not None else SystemClock()

        if grant.status != GrantStatus.ACTIVE:
            return False, f"Grant is not active (status: {grant.status})"

        if grant.used:
            return False, "Grant has already been consumed (single-use protection)"

        # Check expiration
        try:
            expires_dt = datetime.fromisoformat(grant.expires_at)
            if resolved_clock.now() > expires_dt:
                return False, "Grant has expired"
        except Exception:
            return False, "Invalid grant expiration timestamp"

        # Verify HMAC signature (binds organization scope when the grant carries one)
        if isinstance(secret, KeyRing):
            if grant.key_id:
                s = secret.get_secret(grant.key_id)
                if not s:
                    return False, f"Grant signed with unknown or retired key '{grant.key_id}'"
                is_sig_valid = verify_grant_signature(
                    secret=s,
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
                    organization_id=grant.organization_id,
                    key_id=grant.key_id,
                )
            else:
                is_sig_valid = False
                for s in secret.all_secrets:
                    if verify_grant_signature(
                        secret=s,
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
                        organization_id=grant.organization_id,
                        key_id=None,
                    ):
                        is_sig_valid = True
                        break
        else:
            is_sig_valid = verify_grant_signature(
                secret=str(secret),
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
                organization_id=grant.organization_id,
                key_id=grant.key_id,
            )
        if not is_sig_valid:
            return False, "Cryptographic grant signature verification failed"

        # Organization scope check: a grant issued for another organization can
        # never satisfy a case in a different organization (cross-tenant substitution).
        if expected_organization_id is not None and grant.organization_id != expected_organization_id:
            return False, (
                f"Grant organization scope mismatch: grant is bound to organization "
                f"'{grant.organization_id}' but the authoritative case scope is '{expected_organization_id}'"
            )

        # Verify bound intent hash matches current intent hash
        if grant.bound_intent_hash != current_intent_hash:
            return False, "Bound intent hash does not match current intent hash (material mutation detected)"

        return True, None

    @classmethod
    def verify_for_case(
        cls,
        grant: HandoffGrant,
        state: RiskCaseState,
        *,
        secret: str | KeyRing,
        clock: Optional[ClockProvider] = None,
    ) -> None:
        """Verify a grant against an authoritative RiskCaseState, raising on any failure.

        Fails closed with GrantVerificationError when the grant's tenant or
        organization identity does not match the case's authoritative scope, so a
        grant issued for one organization can never be replayed against another.
        """
        if grant.tenant_id != state.tenant_id:
            raise GrantVerificationError(
                f"Grant tenant mismatch: grant is bound to tenant '{grant.tenant_id}' "
                f"but the authoritative case tenant is '{state.tenant_id}'"
            )
        if grant.organization_id != state.organization_id:
            raise GrantVerificationError(
                f"Grant organization scope mismatch: grant is bound to organization "
                f"'{grant.organization_id}' but the authoritative case scope is '{state.organization_id}'"
            )

        is_valid, err = cls.verify(
            grant,
            state.intent.intent_hash or "",
            secret=secret,
            clock=clock,
            expected_organization_id=state.organization_id,
        )
        if not is_valid:
            raise GrantVerificationError(err or "Grant verification failed")

