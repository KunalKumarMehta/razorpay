"""Admission validation for Processing Authority Records and submitted evidence."""

from typing import Tuple, Optional, List
from payoutproof.core.models import ProcessingAuthorityRecord
from payoutproof.core.crypto import sha256_hex

ALLOWED_MIME_TYPES = {
    "audio/wav",
    "audio/x-wav",
    "audio/mpeg",
    "audio/mp3",
    "audio/ogg",
    "text/plain",
    "application/json",
}

MAX_AUDIO_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_TEXT_SIZE_BYTES = 1 * 1024 * 1024    # 1 MB


class AdmissionValidator:
    """Validates submitted evidence and processing authority prior to case opening."""

    @staticmethod
    def validate_authority(authority: Optional[ProcessingAuthorityRecord]) -> Tuple[bool, Optional[str]]:
        """Validate Processing Authority Record.

        If authority is missing or invalid, admission must be refused.
        No Risk Case is opened and no Policy Outcome exists.
        """
        if authority is None:
            return False, "Missing Processing Authority Record"

        if not authority.is_valid:
            return False, "Processing Authority Record is marked invalid"

        if not authority.purpose or not authority.purpose.strip():
            return False, "Processing purpose is required"

        if not authority.asserted_authority_ref or not authority.asserted_authority_ref.strip():
            return False, "Asserted authority reference is required"

        if not authority.submitter or not authority.submitter.strip():
            return False, "Submitter identity is required"

        if not authority.data_class or not authority.data_class.strip():
            return False, "Data classification is required"

        return True, None

    @staticmethod
    def validate_payload(
        content: bytes | str,
        mime_type: str,
        filename: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate payload bytes/string and compute content hash.

        Returns (is_valid, content_hash, error_message).
        """
        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
        else:
            content_bytes = content

        if len(content_bytes) == 0:
            return False, None, "Payload is empty"

        if mime_type not in ALLOWED_MIME_TYPES:
            return False, None, f"MIME type '{mime_type}' is not allowlisted"

        if "audio" in mime_type and len(content_bytes) > MAX_AUDIO_SIZE_BYTES:
            return False, None, f"Audio exceeds size limit ({len(content_bytes)} > {MAX_AUDIO_SIZE_BYTES})"

        if "text" in mime_type and len(content_bytes) > MAX_TEXT_SIZE_BYTES:
            return False, None, f"Text exceeds size limit ({len(content_bytes)} > {MAX_TEXT_SIZE_BYTES})"

        content_hash = sha256_hex(content_bytes)
        return True, content_hash, None
