"""Tamper-evident append-only SHA-256 audit hash chain."""

from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from payoutproof.core.models import AuditEvent
from payoutproof.core.crypto import compute_audit_hash
from payoutproof.core.providers import ClockProvider, SystemClock

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


class AuditChain:
    """Manages and verifies tamper-evident audit event chains."""

    @staticmethod
    def create_event(
        events: List[AuditEvent],
        event_type: str,
        summary: str,
        actor: str = "PayoutProof",
        case_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        clock: Optional[ClockProvider] = None,
    ) -> AuditEvent:
        """Append a new event linked to the previous event hash."""
        resolved_clock = clock if clock is not None else SystemClock()
        seq = len(events) + 1
        prev_hash = events[-1].current_hash if events else GENESIS_HASH
        timestamp = resolved_clock.now().isoformat()
        clean_details = details or {}

        current_hash = compute_audit_hash(
            prev_hash=prev_hash,
            seq=seq,
            event_type=event_type,
            summary=summary,
            actor=actor,
            timestamp=timestamp,
            details=clean_details,
        )

        return AuditEvent(
            seq=seq,
            case_id=case_id,
            event_type=event_type,
            summary=summary,
            actor=actor,
            prev_hash=prev_hash,
            current_hash=current_hash,
            timestamp=timestamp,
            details=clean_details,
        )

    @staticmethod
    def verify_chain(events: List[AuditEvent]) -> Tuple[bool, Optional[int], Optional[str]]:
        """Verify the cryptographic integrity of an audit event chain.

        Returns (is_valid, broken_at_seq, reason).
        """
        if not events:
            return True, None, None

        for idx, event in enumerate(events):
            expected_seq = idx + 1
            if event.seq != expected_seq:
                return False, event.seq, f"Sequence gap: expected seq {expected_seq}, found {event.seq}"

            expected_prev = events[idx - 1].current_hash if idx > 0 else GENESIS_HASH
            if event.prev_hash != expected_prev:
                return False, event.seq, f"Broken prev_hash chain at seq {event.seq}"

            recomputed_hash = compute_audit_hash(
                prev_hash=event.prev_hash,
                seq=event.seq,
                event_type=event.event_type,
                summary=event.summary,
                actor=event.actor,
                timestamp=event.timestamp,
                details=event.details,
            )
            if recomputed_hash != event.current_hash:
                return False, event.seq, f"Tampered event payload at seq {event.seq}: hash mismatch"

        return True, None, None
