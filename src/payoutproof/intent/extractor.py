"""Payment Intent extraction, normalization, and confirmation."""

import re
from typing import Optional, Dict, Any, List, Tuple
from payoutproof.core.models import PaymentIntent
from payoutproof.core.enums import IntentStatus, DestinationStatus
from payoutproof.core.crypto import compute_intent_hash


def normalize_inr_amount(raw_val: str | int | float | None) -> Optional[str]:
    """Normalize various INR amount formats to canonical integer string subunits.

    Examples:
    - "425000" -> "425000"
    - "₹4,25,000" -> "425000"
    - "4.25 lakh" -> "425000"
    - "4.25 Lakhs" -> "425000"
    - "4.25L" -> "425000"
    - "50,000" -> "50000"
    - "1.5 crore" -> "15000000"
    """
    if raw_val is None:
        return None

    s = str(raw_val).strip()
    if not s:
        return None

    # Check for lakh / crore expressions
    lakh_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:lakh|lakhs|l)\b", s, re.IGNORECASE)
    if lakh_match:
        val = float(lakh_match.group(1))
        return str(int(val * 100000))

    crore_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:crore|crores|cr)\b", s, re.IGNORECASE)
    if crore_match:
        val = float(crore_match.group(1))
        return str(int(val * 10000000))

    # Strip currency symbols, commas, spaces
    cleaned = re.sub(r"[^\d.]", "", s)
    if not cleaned:
        return None

    try:
        val = float(cleaned)
        return str(int(val))
    except ValueError:
        return None


def extract_intent_from_structured_data(data: Dict[str, Any]) -> PaymentIntent:
    """Extract unconfirmed Payment Intent from structured findings or text analysis."""
    counterparty = data.get("counterparty")
    destination = data.get("destination")
    raw_amount = data.get("amount")
    amount = normalize_inr_amount(raw_amount)
    currency = data.get("currency", "INR")
    purpose = data.get("purpose")
    instruction_ref = data.get("instruction_reference", data.get("instruction_ref"))
    provenance = data.get("provenance", [])

    return PaymentIntent(
        counterparty=counterparty,
        destination=destination,
        destination_status=DestinationStatus.UNAPPROVED,
        amount=amount,
        currency=currency,
        purpose=purpose,
        instruction_reference=instruction_ref,
        provenance=provenance,
        status=IntentStatus.EXTRACTED,
        intent_hash=None,
    )


def confirm_intent(intent: PaymentIntent) -> PaymentIntent:
    """Confirm extracted Payment Intent and compute immutable intent hash."""
    if intent.status not in (IntentStatus.EXTRACTED, IntentStatus.INVALIDATED):
        raise ValueError(f"Cannot confirm intent with status {intent.status}")

    # Ensure required fields are present for valid intent
    if not intent.counterparty or not intent.destination or not intent.amount:
        raise ValueError("Cannot confirm intent with missing required fields (counterparty, destination, amount)")

    hash_val = compute_intent_hash(intent)

    return PaymentIntent(
        counterparty=intent.counterparty,
        destination=intent.destination,
        destination_status=intent.destination_status,
        amount=intent.amount,
        currency=intent.currency,
        purpose=intent.purpose,
        instruction_reference=intent.instruction_reference,
        provenance=intent.provenance,
        status=IntentStatus.CONFIRMED,
        intent_hash=hash_val,
    )


def correct_intent(
    intent: PaymentIntent,
    counterparty: Optional[str] = None,
    destination: Optional[str] = None,
    amount: Optional[str] = None,
    currency: Optional[str] = None,
    purpose: Optional[str] = None,
    instruction_reference: Optional[str] = None,
    reason: Optional[str] = None,
) -> Tuple[PaymentIntent, bool]:
    """Correct extracted fields on a Payment Intent.

    If intent was already CONFIRMED and a material field changed, its status transitions
    to INVALIDATED and intent_hash is cleared.
    If intent was EXTRACTED or INVALIDATED, it updates fields and keeps status as EXTRACTED,
    ready for review and explicit confirmation.
    Returns (new_intent, was_material_change).
    """
    new_counterparty = counterparty if counterparty is not None else intent.counterparty
    new_destination = destination if destination is not None else intent.destination
    new_amount = normalize_inr_amount(amount) if amount is not None else intent.amount
    new_currency = currency if currency is not None else intent.currency
    new_purpose = purpose if purpose is not None else intent.purpose
    new_ref = instruction_reference if instruction_reference is not None else intent.instruction_reference

    is_material = (
        new_counterparty != intent.counterparty or
        new_destination != intent.destination or
        new_amount != intent.amount or
        new_currency != intent.currency or
        new_purpose != intent.purpose or
        new_ref != intent.instruction_reference
    )

    new_provenance = list(intent.provenance)
    if reason:
        new_provenance.append(f"operator_correction:{reason}")

    if intent.status == IntentStatus.CONFIRMED:
        new_status = IntentStatus.INVALIDATED if is_material else intent.status
        new_hash = None if is_material else intent.intent_hash
    else:
        new_status = IntentStatus.EXTRACTED
        new_hash = None

    new_intent = PaymentIntent(
        counterparty=new_counterparty,
        destination=new_destination,
        destination_status=intent.destination_status,
        amount=new_amount,
        currency=new_currency,
        purpose=new_purpose,
        instruction_reference=new_ref,
        provenance=new_provenance,
        status=new_status,
        intent_hash=new_hash,
    )
    return new_intent, is_material


def modify_intent(
    intent: PaymentIntent,
    counterparty: Optional[str] = None,
    destination: Optional[str] = None,
    amount: Optional[str] = None,
    purpose: Optional[str] = None,
    currency: Optional[str] = None,
    instruction_reference: Optional[str] = None,
    reason: Optional[str] = None,
) -> Tuple[PaymentIntent, bool]:
    """Apply an edit to a Payment Intent (backwards-compatible alias)."""
    return correct_intent(
        intent=intent,
        counterparty=counterparty,
        destination=destination,
        amount=amount,
        currency=currency,
        purpose=purpose,
        instruction_reference=instruction_reference,
        reason=reason,
    )


def invalidate_intent(
    intent: PaymentIntent,
    reason: str = "Operator manual invalidation",
) -> PaymentIntent:
    """Explicitly invalidate a Payment Intent and revoke frozen hash identity."""
    new_provenance = list(intent.provenance) + [f"invalidation:{reason}"]
    return PaymentIntent(
        counterparty=intent.counterparty,
        destination=intent.destination,
        destination_status=intent.destination_status,
        amount=intent.amount,
        currency=intent.currency,
        purpose=intent.purpose,
        instruction_reference=intent.instruction_reference,
        provenance=new_provenance,
        status=IntentStatus.INVALIDATED,
        intent_hash=None,
    )
