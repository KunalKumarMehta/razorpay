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
    """Compute deterministic SHA-256 hash of authoritative case snapshot."""
    canonical_dict = {
        "case_id": state.case_id,
        "case_version": state.case_version,
        "tenant_id": state.tenant_id,
        "intent": {
            "counterparty": state.intent.counterparty,
            "destination": state.intent.destination,
            "destination_status": state.intent.destination_status.value,
            "amount": state.intent.amount,
            "currency": state.intent.currency,
            "purpose": state.intent.purpose,
            "instruction_reference": state.intent.instruction_reference,
            "status": state.intent.status.value,
            "hash": state.intent.intent_hash,
        },
        "evidence_hashes": sorted([e.content_hash for e in state.evidence]),
        "findings": sorted([f"{f.name}:{f.truth_state.value}:{f.detail}" for f in state.findings]),
        "processing_authority": state.processing_authority.value,
    }
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
) -> str:
    """Create HMAC-SHA256 signature for a Handoff Grant."""
    message = f"{grant_id}|{tenant_id}|{case_id}|{bound_intent_hash}|{bound_snapshot_hash}|{policy_version}|{outcome}|{nonce}|{issued_at}|{expires_at}"
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
    )
    return hmac.compare_digest(expected_sig, signature)
