"""Admission validation for Processing Authority Records and submitted evidence."""

from typing import Tuple, Optional, List, Any, Union
from payoutproof.core.models import ProcessingAuthorityRecord
from payoutproof.core.enums import ReasonCode
from payoutproof.core.crypto import sha256_hex

ALLOWED_MIME_TYPES = {
    "audio/wav",
    "audio/x-wav",
    "audio/mpeg",
    "audio/mp3",
    "audio/ogg",
    "text/plain",
    "application/json",
    "application/pdf",
    "image/png",
    "image/jpeg",
}

MAX_AUDIO_SIZE_BYTES = 10 * 1024 * 1024       # 10 MB
MAX_TEXT_SIZE_BYTES = 1 * 1024 * 1024          # 1 MB
MAX_DOCUMENT_SIZE_BYTES = 10 * 1024 * 1024     # 10 MB
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024        # 10 MB


class AdmissionValidator:
    """Validates submitted evidence and processing authority prior to case opening."""

    @staticmethod
    def validate_authority(authority: Optional[Union[ProcessingAuthorityRecord, dict]]) -> Tuple[bool, Optional[str]]:
        """Validate Processing Authority Record.

        If authority is missing or invalid, admission must be refused.
        No Risk Case is opened and no Policy Outcome exists.
        """
        if authority is None:
            return False, "Missing Processing Authority Record"

        if isinstance(authority, dict):
            try:
                authority = ProcessingAuthorityRecord(**authority)
            except Exception:
                return False, "Malformed or incomplete Processing Authority Record"
        elif not isinstance(authority, ProcessingAuthorityRecord):
            return False, "Invalid Processing Authority Record type"

        if not authority.is_valid:
            return False, "Processing Authority Record is marked invalid"

        if not authority.data_class or not authority.data_class.strip():
            return False, "Data classification is required"

        if not authority.source or not authority.source.strip():
            return False, "Source is required"

        if not authority.subject_category or not authority.subject_category.strip():
            return False, "Subject category is required"

        if not authority.submitter or not authority.submitter.strip():
            return False, "Submitter identity is required"

        if not authority.purpose or not authority.purpose.strip():
            return False, "Processing purpose is required"

        if not authority.asserted_authority_ref or not authority.asserted_authority_ref.strip():
            return False, "Asserted authority reference is required"

        if not authority.processing_route or not authority.processing_route.strip():
            return False, "Processing route is required"

        if not authority.redaction_declaration or not authority.redaction_declaration.strip():
            return False, "Redaction declaration is required"

        if not authority.permitted_uses or len(authority.permitted_uses) == 0 or not any(isinstance(u, str) and u.strip() for u in authority.permitted_uses):
            return False, "Non-empty permitted uses are required"

        if authority.retention_days is None or authority.retention_days <= 0:
            return False, "Retention must be a positive bounded number of days"

        if authority.retention_days > 365:
            return False, "Retention exceeds maximum bounded period (365 days)"

        if not isinstance(authority.restrictions, list):
            return False, "Restrictions must be a list"

        if not isinstance(authority.legal_hold, bool):
            return False, "Legal hold must be a boolean"

        return True, None

    @staticmethod
    def validate_payload(
        content: Optional[Union[bytes, str]],
        mime_type: Optional[str],
        filename: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate payload bytes/string and compute content hash.

        Returns (is_valid, content_hash, error_message).
        """
        if content is None:
            return False, None, "Payload content is required"

        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
        elif isinstance(content, (bytes, bytearray)):
            content_bytes = bytes(content)
        else:
            return False, None, "Payload content must be string or bytes"

        if len(content_bytes) == 0:
            return False, None, "Payload is empty"

        if not mime_type or not mime_type.strip():
            return False, None, "MIME type is required"

        normalized_mime = mime_type.strip().lower()
        if normalized_mime not in ALLOWED_MIME_TYPES:
            return False, None, "MIME type is not allowlisted"

        if "audio" in normalized_mime and len(content_bytes) > MAX_AUDIO_SIZE_BYTES:
            return False, None, f"Audio exceeds size limit ({MAX_AUDIO_SIZE_BYTES} bytes)"

        if "pdf" in normalized_mime and len(content_bytes) > MAX_DOCUMENT_SIZE_BYTES:
            return False, None, f"Document exceeds size limit ({MAX_DOCUMENT_SIZE_BYTES} bytes)"

        if "image" in normalized_mime and len(content_bytes) > MAX_IMAGE_SIZE_BYTES:
            return False, None, f"Image exceeds size limit ({MAX_IMAGE_SIZE_BYTES} bytes)"

        if ("text" in normalized_mime or "json" in normalized_mime) and len(content_bytes) > MAX_TEXT_SIZE_BYTES:
            return False, None, f"Payload exceeds size limit ({MAX_TEXT_SIZE_BYTES} bytes)"

        content_hash = sha256_hex(content_bytes)
        return True, content_hash, None

    @staticmethod
    def classify_rejection_reason(error_message: str) -> ReasonCode:
        """Map rejection error message to a frozen ReasonCode."""
        msg = error_message.lower()
        if "not allowlisted" in msg or "prohibited" in msg:
            return ReasonCode.PROHIBITED_INPUT
        if "empty" in msg or "size limit" in msg or "malformed" in msg or "must be a" in msg or "positive" in msg or "exceeds" in msg or "must be string" in msg or "identifier" in msg or "type" in msg:
            return ReasonCode.MALFORMED_INPUT
        return ReasonCode.ADMISSION_AUTHORITY_INCOMPLETE
