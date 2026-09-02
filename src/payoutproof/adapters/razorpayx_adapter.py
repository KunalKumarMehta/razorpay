"""RazorpayX Test Mode adapter stub and webhook verification."""

import hmac
import hashlib
from typing import Dict, Any, Tuple, Optional
from payoutproof.core.models import PaymentIntent, HandoffGrant
from payoutproof.core.enums import AdapterDecision


class RazorpayXTestAdapter:
    """Test-mode adapter demonstrating authenticated API/webhook boundaries with test money.

    Clearly labeled as test-mode dummy integration, not live payment or approval.
    """

    def __init__(self, key_id: str = "rzp_test_demo", key_secret: str = "rzp_secret_demo"):
        self.key_id = key_id
        self.key_secret = key_secret

    def create_test_payout(self, intent: PaymentIntent, grant: HandoffGrant) -> Dict[str, Any]:
        """Simulate creating a test payout in RazorpayX Test Mode."""
        return {
            "id": f"pout_test_{grant.case_id}",
            "entity": "payout",
            "amount": int(intent.amount or "0"),
            "currency": intent.currency or "INR",
            "status": "processing",
            "purpose": intent.purpose or "payout",
            "mode": "NEFT",
            "reference_id": grant.case_id,
            "mode_label": "TEST_MODE_ONLY",
        }

    @staticmethod
    def verify_webhook_signature(payload_bytes: bytes, signature: str, webhook_secret: str) -> bool:
        """Verify Razorpay webhook HMAC-SHA256 signature."""
        expected = hmac.new(webhook_secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
