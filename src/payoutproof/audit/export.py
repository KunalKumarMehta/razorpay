"""Verifiable Risk Case audit export builder and pure offline verifier.

Zero network connectivity or database access required for offline verification.
Guarantees fail-closed rejection on event deletion, tampering, reordering,
sequence gaps, checkpoint forgery, or cross-tenant substitution.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from payoutproof.audit.chain import GENESIS_HASH
from payoutproof.core.crypto import (
    compute_audit_hash,
    compute_snapshot_hash,
    verify_checkpoint_mac,
)
from payoutproof.core.enums import AuditTrustState, CasePhase
from payoutproof.core.keys import KeyRing
from payoutproof.core.models import AuditEvent, HandoffGrant, RiskCaseState
from payoutproof.grants.issuer import GrantVerifier

EXPORT_VERSION = "PAYOUTPROOF_CASE_AUDIT_EXPORT_V1"


class CaseExportError(Exception):
    """Raised when building or parsing an audit export fails."""
    pass


def build_case_export(
    db: Any,
    case_id: str,
    organization_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a verifiable canonical JSON-serializable audit export envelope.

    Operates in a single read transaction to produce a consistent point-in-time snapshot.
    Restricted strictly to the organization scope.
    """
    with db.get_connection() as conn:
        # Zero-existence check
        row = conn.execute(
            "SELECT case_id, tenant_id, organization_id, case_version, phase, created_at FROM risk_cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if not row:
            raise CaseExportError(f"Case '{case_id}' not found.")

        row_org = row["organization_id"]
        if organization_id is not None and row_org != organization_id:
            raise CaseExportError(f"Case '{case_id}' not found.")

        # Load verified state
        state = db.load_case_tx(conn, case_id)
        if not state:
            raise CaseExportError(f"Case '{case_id}' not found.")

        # Fetch authoritative checkpoints
        cp_rows = conn.execute(
            "SELECT * FROM case_audit_checkpoints WHERE case_id = ?",
            (case_id,),
        ).fetchall()
        checkpoints: List[Dict[str, Any]] = []
        for cp in cp_rows:
            checkpoints.append({
                "case_id": cp["case_id"],
                "event_count": cp["event_count"],
                "tip_hash": cp["tip_hash"],
                "trust_state": cp["trust_state"],
                "checkpoint_mac": cp["checkpoint_mac"],
                "updated_at": cp["updated_at"],
                "key_id": cp["key_id"] if "key_id" in cp.keys() else None,
            })

        # Fetch authoritative handoff grants
        grant_rows = conn.execute(
            "SELECT * FROM handoff_grants WHERE case_id = ? ORDER BY issued_at ASC",
            (case_id,),
        ).fetchall()
        grants: List[Dict[str, Any]] = []
        for gr in grant_rows:
            grants.append({
                "grant_id": gr["grant_id"],
                "tenant_id": gr["tenant_id"],
                "organization_id": gr["organization_id"],
                "case_id": gr["case_id"],
                "bound_intent_hash": gr["bound_intent_hash"],
                "bound_snapshot_hash": gr["bound_snapshot_hash"],
                "policy_version": gr["policy_version"],
                "outcome": gr["outcome"],
                "nonce": gr["nonce"],
                "issued_at": gr["issued_at"],
                "expires_at": gr["expires_at"],
                "signature": gr["signature"],
                "status": gr["status"],
                "used": bool(gr["used"]),
                "key_id": gr["key_id"] if "key_id" in gr.keys() else None,
            })

        # Fetch attribution if table exists
        attribution: List[Dict[str, Any]] = []
        try:
            attr_rows = conn.execute(
                "SELECT * FROM case_action_actors WHERE case_id = ? ORDER BY id ASC",
                (case_id,),
            ).fetchall()
            for ar in attr_rows:
                attribution.append({
                    "action_type": ar["action_type"],
                    "actor_subject": ar["actor_subject"],
                    "actor_role": ar["actor_role"],
                    "recorded_at": ar["recorded_at"],
                })
        except Exception:
            pass

        return {
            "export_version": EXPORT_VERSION,
            "case_id": case_id,
            "organization_id": row_org,
            "tenant_id": row["tenant_id"],
            "case_version": row["case_version"],
            "phase": row["phase"],
            "created_at": row["created_at"],
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "state_snapshot": state.model_dump(mode="json"),
            "audit_events": [ev.model_dump(mode="json") for ev in state.audit],
            "checkpoints": checkpoints,
            "grants": grants,
            "dispatch_attribution": attribution,
        }


def verify_case_export(
    export_payload: Dict[str, Any],
    *,
    audit_ring: KeyRing,
    grant_ring: Optional[KeyRing] = None,
) -> Tuple[bool, str]:
    """Verify an exported Risk Case audit offline without network or database access.

    Returns (is_valid, reason).
    """
    if not isinstance(export_payload, dict):
        return False, "Export payload must be a JSON dictionary."

    if export_payload.get("export_version") != EXPORT_VERSION:
        return False, f"Unsupported export version '{export_payload.get('export_version')}'; expected '{EXPORT_VERSION}'."

    case_id = export_payload.get("case_id")
    tenant_id = export_payload.get("tenant_id")
    organization_id = export_payload.get("organization_id")
    if not case_id or not tenant_id:
        return False, "Export is missing required 'case_id' or 'tenant_id'."

    raw_events = export_payload.get("audit_events")
    if not isinstance(raw_events, list) or not raw_events:
        return False, "Export contains no audit events or malformed audit_events list."

    # Parse and verify event chain
    events: List[AuditEvent] = []
    for idx, raw_ev in enumerate(raw_events):
        try:
            ev = AuditEvent.model_validate(raw_ev)
            events.append(ev)
        except Exception as e:
            return False, f"Malformed audit event at index {idx}: {e}"

    seen_seqs = set()
    for idx, ev in enumerate(events):
        expected_seq = idx + 1
        if ev.seq in seen_seqs:
            return False, f"Duplicate sequence number {ev.seq} at index {idx}."
        seen_seqs.add(ev.seq)

        if ev.seq != expected_seq:
            return False, f"Sequence gap or reordering: expected seq {expected_seq}, found {ev.seq}."

        if ev.case_id and ev.case_id != case_id:
            return False, (
                f"Cross-case contamination at seq {ev.seq}: event case_id '{ev.case_id}' "
                f"does not match export case_id '{case_id}'."
            )

        expected_prev = events[idx - 1].current_hash if idx > 0 else GENESIS_HASH
        if ev.prev_hash != expected_prev:
            return False, (
                f"Broken prev_hash chain at seq {ev.seq}: expected prev_hash '{expected_prev}', "
                f"found '{ev.prev_hash}'."
            )

        recomputed = compute_audit_hash(
            prev_hash=ev.prev_hash,
            seq=ev.seq,
            event_type=ev.event_type,
            summary=ev.summary,
            actor=ev.actor,
            timestamp=ev.timestamp,
            details=ev.details,
        )
        if recomputed != ev.current_hash:
            return False, f"Tampered event payload at seq {ev.seq}: current_hash mismatch."

    # Verify checkpoints
    raw_checkpoints = export_payload.get("checkpoints")
    if not isinstance(raw_checkpoints, list) or not raw_checkpoints:
        return False, "Export is missing checkpoints."

    for cp in raw_checkpoints:
        cp_case_id = cp.get("case_id")
        if cp_case_id != case_id:
            return False, f"Checkpoint case_id '{cp_case_id}' does not match export case_id '{case_id}'."

        count = cp.get("event_count")
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            return False, f"Invalid checkpoint event_count: {count!r}."

        if count > len(events):
            return False, f"Checkpoint records {count} events but export only contains {len(events)}."

        expected_tip = events[count - 1].current_hash
        if cp.get("tip_hash") != expected_tip:
            return False, (
                f"Checkpoint tip_hash mismatch: expected '{expected_tip}', "
                f"found '{cp.get('tip_hash')}'."
            )

        trust_state = cp.get("trust_state")
        if trust_state != AuditTrustState.TRUSTED.value:
            return False, f"Untrusted checkpoint trust_state: '{trust_state}'."

        kid = cp.get("key_id")
        mac = cp.get("checkpoint_mac")
        if not mac:
            return False, "Checkpoint is missing checkpoint_mac."

        if kid:
            sec = audit_ring.get_secret(kid)
            if not sec:
                return False, f"Checkpoint references unknown or retired signing key '{kid}'."
            is_valid_mac = verify_checkpoint_mac(
                secret=sec,
                case_id=case_id,
                event_count=count,
                tip_hash=expected_tip,
                trust_state=trust_state,
                checkpoint_mac=mac,
                key_id=kid,
            )
            if not is_valid_mac:
                return False, f"Checkpoint MAC verification failed for key '{kid}'."
        else:
            is_valid_mac = False
            for s in audit_ring.all_secrets:
                if verify_checkpoint_mac(
                    secret=s,
                    case_id=case_id,
                    event_count=count,
                    tip_hash=expected_tip,
                    trust_state=trust_state,
                    checkpoint_mac=mac,
                    key_id=None,
                ):
                    is_valid_mac = True
                    break
            if not is_valid_mac:
                return False, "Checkpoint MAC verification failed across all available audit keys."

    # Verify Grants (and cross-tenant isolation)
    raw_grants = export_payload.get("grants", [])
    if isinstance(raw_grants, list):
        for gr in raw_grants:
            if gr.get("case_id") != case_id:
                return False, f"Grant '{gr.get('grant_id')}' bound to case '{gr.get('case_id')}' injected into export '{case_id}'."
            if gr.get("tenant_id") != tenant_id:
                return False, f"Cross-tenant grant substitution: grant tenant '{gr.get('tenant_id')}' != export tenant '{tenant_id}'."
            if gr.get("organization_id") != organization_id:
                return False, f"Cross-organization grant substitution: grant org '{gr.get('organization_id')}' != export org '{organization_id}'."

            if grant_ring is not None:
                try:
                    grant_model = HandoffGrant.model_validate(gr)
                    ok, g_err = GrantVerifier.verify(
                        grant_model,
                        grant_model.bound_intent_hash,
                        secret=grant_ring,
                        expected_organization_id=organization_id,
                    )
                    if not ok:
                        return False, f"Grant signature verification failed: {g_err}"
                except Exception as e:
                    return False, f"Grant verification error: {e}"

    # Verify state snapshot consistency
    raw_snapshot = export_payload.get("state_snapshot")
    if raw_snapshot and isinstance(raw_snapshot, dict):
        try:
            snapshot_state = RiskCaseState.model_validate(raw_snapshot)
            if snapshot_state.case_id != case_id:
                return False, "Snapshot state case_id mismatch."
            if snapshot_state.tenant_id != tenant_id:
                return False, "Snapshot state tenant_id mismatch."
            if snapshot_state.organization_id != organization_id:
                return False, "Snapshot state organization_id mismatch."
        except Exception as e:
            return False, f"Snapshot state model validation failed: {e}"

    return True, f"Audit export for case '{case_id}' verified offline successfully ({len(events)} events, trusted checkpoint)."
