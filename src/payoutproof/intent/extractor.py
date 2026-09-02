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


def modify_intent(
    intent: PaymentIntent,
    counterparty: Optional[str] = None,
    destination: Optional[str] = None,
    amount: Optional[str] = None,
    purpose: Optional[str] = None,
) -> Tuple[PaymentIntent, bool]:
    """Apply an edit to a Payment Intent.

    If any material field changed, marks status as INVALIDATED and clears intent_hash.
    Returns (new_intent, was_material_change).
    """
    new_counterparty = counterparty if counterparty is not None else intent.counterparty
    new_destination = destination if destination is not None else intent.destination
    new_amount = normalize_inr_amount(amount) if amount is not None else intent.amount
    new_purpose = purpose if purpose is not None else intent.purpose

    is_material = (
        new_counterparty != intent.counterparty or
        new_destination != intent.destination or
        new_amount != intent.amount or
        new_purpose != intent.purpose
    )

    if is_material:
        new_status = IntentStatus.INVALIDATED
        new_hash = None
    else:
        new_status = intent.status
        new_hash = intent.intent_hash

    new_intent = PaymentIntent(
        counterparty=new_counterparty,
        destination=new_destination,
        destination_status=intent.destination_status,
        amount=new_amount,
        currency=intent.currency,
        purpose=new_purpose,
        instruction_reference=intent.instruction_reference,
        provenance=intent.provenance,
        status=new_status,
        intent_hash=new_hash,
    )
    return new_intent, is_material
