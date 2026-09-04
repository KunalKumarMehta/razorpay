"""Deterministic cryptography and hashing functions for PayoutProof."""

import hashlib
import hmac
import json
import secrets
from typing import Any, Dict, Optional
from datetime import datetime, timezone, timedelta

from payoutproof.core.models import PaymentIntent, RiskCaseState


def sha256_hex(data: bytes | str) -> str:
    """Compute SHA-256 hex digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_intent_hash(intent: PaymentIntent) -> str:
    """Compute deterministic SHA-256 hash for a Payment Intent."""
    canonical_repr = intent.canonical_string()
    return sha256_hex(canonical_repr)


def compute_snapshot_hash(state: RiskCaseState) -> str:
    """Compute deterministic SHA-256 hash of authoritative case snapshot.

    Includes all authorization and policy inputs that may affect safety:
    authority_record, processing_authority, request_bundle_status, admitted evidence items,
    findings, canonical payment intent, tenant_id, case_id, case_version, and investigation inputs.
    Excludes outputs/ephemera that change during handoff (grant, handoff, audit, last_change, phase).

    Note: Full evaluation-snapshot-at-issuance freshness verification belongs to P0-3;
    this hash provides deterministic case-state integrity binding for handoff safety.
    """
    canonical_dict = {
        "case_id": state.case_id,
        "case_version": state.case_version,
        "tenant_id": state.tenant_id,
        "request_bundle_status": state.request_bundle_status,
        "processing_authority": (
            state.processing_authority.value
            if hasattr(state.processing_authority, "value")
            else str(state.processing_authority)
        ),
        "authority_record": (
            state.authority_record.model_dump()
            if state.authority_record
            else None
        ),
        "intent": {
            "counterparty": state.intent.counterparty,
            "destination": state.intent.destination,
            "destination_status": (
                state.intent.destination_status.value
                if hasattr(state.intent.destination_status, "value")
                else str(state.intent.destination_status)
            ),
            "amount": state.intent.amount,
            "currency": state.intent.currency,
            "purpose": state.intent.purpose,
            "instruction_reference": state.intent.instruction_reference,
            "provenance": sorted(state.intent.provenance),
            "status": (
                state.intent.status.value
                if hasattr(state.intent.status, "value")
                else str(state.intent.status)
            ),
            "intent_hash": state.intent.intent_hash,
        },
        "evidence": sorted(
            [
                {
                    "id": e.id,
                    "item_type": e.item_type,
                    "title": e.title,
                    "content_hash": e.content_hash,
                    "finding": e.finding,
                    "truth_state": (
                        e.truth_state.value
                        if hasattr(e.truth_state, "value")
                        else str(e.truth_state)
                    ),
                    "admitted_at": e.admitted_at,
                    "metadata": e.metadata,
                }
                for e in state.evidence
            ],
            key=lambda x: x["id"],
        ),
        "findings": sorted(
            [
                {
                    "name": f.name,
                    "truth_state": (
                        f.truth_state.value
                        if hasattr(f.truth_state, "value")
                        else str(f.truth_state)
                    ),
                    "detail": f.detail,
                    "evidence_ref": f.evidence_ref,
                }
                for f in state.findings
            ],
            key=lambda x: (x["name"], x["truth_state"], x["detail"], str(x["evidence_ref"])),
        ),
        "investigation": {
            "model_status": state.investigation.model_status,
            "attempt": state.investigation.attempt,
            "asr_confidence": state.investigation.asr_confidence,
            "extraction_latency_ms": state.investigation.extraction_latency_ms,
            "language_stratum": state.investigation.language_stratum,
        },
    }
    # Tenancy expansion seam: include organization_id only when present to preserve
    # byte-identical hashes and active grants for legacy un-scoped records.
    if state.organization_id is not None:
        canonical_dict["organization_id"] = state.organization_id

    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    return sha256_hex(canonical_json)


def compute_audit_hash(prev_hash: str, seq: int, event_type: str, summary: str, actor: str, timestamp: str, details: Dict[str, Any]) -> str:
    """Compute tamper-evident append-only SHA-256 hash chain node."""
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
    payload = f"{prev_hash}|{seq}|{event_type}|{summary}|{actor}|{timestamp}|{details_json}"
    return sha256_hex(payload)


def generate_nonce(length: int = 16) -> str:
    """Generate cryptographically secure random hex nonce."""
    return secrets.token_hex(length)


def create_grant_signature(
    secret: str,
    grant_id: str,
    tenant_id: str,
    case_id: str,
    bound_intent_hash: str,
    bound_snapshot_hash: str,
    policy_version: str,
    outcome: str,
    nonce: str,
    issued_at: str,
    expires_at: str,
    organization_id: Optional[str] = None,
    key_id: Optional[str] = None,
) -> str:
    """Create HMAC-SHA256 signature for a Handoff Grant."""
    message = f"{grant_id}|{tenant_id}|{case_id}|{bound_intent_hash}|{bound_snapshot_hash}|{policy_version}|{outcome}|{nonce}|{issued_at}|{expires_at}"
    # Tenancy expansion seam: bind the organization scope into the signed payload
    # only when present so legacy un-scoped grants keep byte-identical signatures.
    if organization_id is not None:
        message = f"{message}|ORG[{organization_id}]"
    if key_id is not None:
        message = f"{message}|KID[{key_id}]"
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_grant_signature(
    secret: str,
    grant_id: str,
    tenant_id: str,
    case_id: str,
    bound_intent_hash: str,
    bound_snapshot_hash: str,
    policy_version: str,
    outcome: str,
    nonce: str,
    issued_at: str,
    expires_at: str,
    signature: str,
    organization_id: Optional[str] = None,
    key_id: Optional[str] = None,
) -> bool:
    """Verify HMAC-SHA256 signature of a Handoff Grant using constant-time comparison."""
    expected_sig = create_grant_signature(
        secret=secret,
        grant_id=grant_id,
        tenant_id=tenant_id,
        case_id=case_id,
        bound_intent_hash=bound_intent_hash,
        bound_snapshot_hash=bound_snapshot_hash,
        policy_version=policy_version,
        outcome=outcome,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        organization_id=organization_id,
        key_id=key_id,
    )
    if hmac.compare_digest(expected_sig, signature):
        return True
    if key_id is not None:
        expected_v1 = create_grant_signature(
            secret=secret,
            grant_id=grant_id,
            tenant_id=tenant_id,
            case_id=case_id,
            bound_intent_hash=bound_intent_hash,
            bound_snapshot_hash=bound_snapshot_hash,
            policy_version=policy_version,
            outcome=outcome,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            organization_id=organization_id,
            key_id=None,
        )
        return hmac.compare_digest(expected_v1, signature)
    else:
        expected_v2_v1 = create_grant_signature(
            secret=secret,
            grant_id=grant_id,
            tenant_id=tenant_id,
            case_id=case_id,
            bound_intent_hash=bound_intent_hash,
            bound_snapshot_hash=bound_snapshot_hash,
            policy_version=policy_version,
            outcome=outcome,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            organization_id=organization_id,
            key_id="v1",
        )
        return hmac.compare_digest(expected_v2_v1, signature)


def derive_idempotency_key(
    tenant_id: str,
    case_id: str,
    case_version: int,
    grant_id: str,
    organization_id: Optional[str] = None,
) -> str:
    """Deterministically derive server-owned idempotency key from authoritative fields.

    The organization scope is bound into the key only when present, preserving
    byte-identical legacy keys for un-scoped records while distinguishing
    organizations that share a tenant.
    """
    if organization_id is None:
        return f"IDEM::{tenant_id}::{case_id}::V{case_version}::{grant_id}"
    return f"IDEM::{tenant_id}::ORG[{organization_id}]::{case_id}::V{case_version}::{grant_id}"


AUDIT_CHECKPOINT_V1 = "PAYOUTPROOF_AUDIT_CHECKPOINT_V1"
AUDIT_CHECKPOINT_V2 = "PAYOUTPROOF_AUDIT_CHECKPOINT_V2"


def compute_checkpoint_mac(
    secret: str,
    case_id: str,
    event_count: int,
    tip_hash: str,
    trust_state: str,
    key_id: Optional[str] = None,
) -> str:
    """Compute HMAC-SHA256 MAC for a case audit checkpoint with explicit domain separation."""
    if key_id is not None:
        message = f"PAYOUTPROOF_AUDIT_CHECKPOINT_V2|{key_id}|{case_id}|{event_count}|{tip_hash}|{trust_state}"
    else:
        message = f"PAYOUTPROOF_AUDIT_CHECKPOINT_V1|{case_id}|{event_count}|{tip_hash}|{trust_state}"
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_checkpoint_mac(
    secret: Any,
    case_id: Any,
    event_count: Any,
    tip_hash: Any,
    trust_state: Any,
    checkpoint_mac: Any,
    key_id: Optional[str] = None,
) -> bool:
    """Verify HMAC-SHA256 MAC for a case audit checkpoint using constant-time comparison.

    Safely returns False for None, non-string, non-int, or malformed inputs, never raising TypeError.
    """
    try:
        if not isinstance(secret, str) or not secret:
            return False
        if not isinstance(case_id, str) or not case_id:
            return False
        if not isinstance(event_count, int) or isinstance(event_count, bool):
            return False
        if not isinstance(tip_hash, str) or not tip_hash:
            return False
        if not isinstance(trust_state, str) or not trust_state:
            return False
        if not isinstance(checkpoint_mac, str) or not checkpoint_mac:
            return False

        if key_id is not None:
            expected_mac = compute_checkpoint_mac(
                secret=secret,
                case_id=case_id,
                event_count=event_count,
                tip_hash=tip_hash,
                trust_state=trust_state,
                key_id=key_id,
            )
            if hmac.compare_digest(expected_mac, checkpoint_mac):
                return True
            # Fallback to V1 if stamped with key_id but MACed under legacy domain
            expected_v1 = compute_checkpoint_mac(
                secret=secret,
                case_id=case_id,
                event_count=event_count,
                tip_hash=tip_hash,
                trust_state=trust_state,
                key_id=None,
            )
            return hmac.compare_digest(expected_v1, checkpoint_mac)
        else:
            expected_v1 = compute_checkpoint_mac(
                secret=secret,
                case_id=case_id,
                event_count=event_count,
                tip_hash=tip_hash,
                trust_state=trust_state,
                key_id=None,
            )
            if hmac.compare_digest(expected_v1, checkpoint_mac):
                return True
            expected_v2_v1 = compute_checkpoint_mac(
                secret=secret,
                case_id=case_id,
                event_count=event_count,
                tip_hash=tip_hash,
                trust_state=trust_state,
                key_id="v1",
            )
            return hmac.compare_digest(expected_v2_v1, checkpoint_mac)
    except Exception:
        return False
