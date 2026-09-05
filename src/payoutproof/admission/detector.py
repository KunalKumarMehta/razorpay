"""Server-side content detection, allowlists, archive protection, and security scanning.

Controls evidence admission via deep inspection of raw bytes rather than relying
on client-declared MIME headers. Guarantees fail-closed rejection on spoofed types,
prohibited archive formats, and executable/malware signatures.
"""

from __future__ import annotations

import json
import re
from typing import Dict, Optional, Set, Tuple

from payoutproof.core.enums import ReasonCode

# Allowlists for payment-risk evidence
ALLOWED_EVIDENCE_MIME_TYPES: Set[str] = {
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

# Size limits per media category (bytes)
MAX_AUDIO_BYTES = 10 * 1024 * 1024       # 10 MB
MAX_TEXT_BYTES = 1 * 1024 * 1024          # 1 MB
MAX_DOCUMENT_BYTES = 10 * 1024 * 1024     # 10 MB
MAX_IMAGE_BYTES = 10 * 1024 * 1024        # 10 MB

# Prohibited archive headers (magic bytes)
ARCHIVE_SIGNATURES: Dict[str, bytes] = {
    "zip": b"PK\x03\x04",
    "zip_empty": b"PK\x05\x06",
    "zip_spanned": b"PK\x07\x08",
    "gzip": b"\x1f\x8b",
    "bzip2": b"BZh",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "rar": b"Rar!\x1a\x07",
}

# Executable / script binary headers
EXECUTABLE_SIGNATURES: Dict[str, bytes] = {
    "pe_dos": b"MZ",
    "elf": b"\x7fELF",
    "macho_32": b"\xfe\xed\xfa\xce",
    "macho_64": b"\xfe\xed\xfa\xcf",
    "macho_32_rev": b"\xce\xfa\xed\xfe",
    "macho_64_rev": b"\xcf\xfa\xed\xfe",
}

# Standard EICAR test string for anti-malware verification
EICAR_STANDARD_TEST_STRING = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_TEST_STRING = EICAR_STANDARD_TEST_STRING.decode("ascii")

# Suspicious script patterns
SCRIPT_INJECTION_PATTERNS = [
    re.compile(b"<\\s*script", re.IGNORECASE),
    re.compile(b"javascript\\s*:", re.IGNORECASE),
    re.compile(b"<\\s*iframe", re.IGNORECASE),
]


class SecurityScanError(Exception):
    """Raised when evidence fails security or quarantine inspection."""
    pass


class ArchiveProtectionError(SecurityScanError):
    """Raised when evidence contains prohibited compressed archives."""
    pass


def is_archive_payload(data: bytes) -> Tuple[bool, Optional[str]]:
    """Inspect raw bytes for archive magic headers."""
    if len(data) < 2:
        return False, None
    for name, sig in ARCHIVE_SIGNATURES.items():
        if data.startswith(sig):
            return True, f"Prohibited archive format detected: {name}"
    # TAR format check: 'ustar' at byte offset 257
    if len(data) >= 262 and data[257:262] == b"ustar":
        return True, "Prohibited archive format detected: tar"
    return False, None


def is_executable_or_malicious(data: bytes) -> Tuple[bool, Optional[str]]:
    """Scan raw bytes for executables, malware test patterns, or script injection."""
    # 1. EICAR test signature
    if EICAR_STANDARD_TEST_STRING in data:
        return True, "Malware test signature detected (EICAR)"

    # 2. Native executable headers
    if len(data) >= 4:
        for name, sig in EXECUTABLE_SIGNATURES.items():
            if data.startswith(sig):
                return True, f"Prohibited executable binary format detected: {name}"

    # 3. Shebang script headers
    if data.startswith(b"#!"):
        first_line = data.split(b"\n", 1)[0]
        if any(b in first_line for b in (b"/sh", b"/bash", b"/python", b"/perl", b"/ruby", b"/bin")):
            return True, "Prohibited executable shell script detected"

    # 4. Embedded active scripts in non-code files
    for pat in SCRIPT_INJECTION_PATTERNS:
        if pat.search(data):
            return True, "Prohibited active script injection detected"

    return False, None


def detect_content_type(data: bytes) -> Optional[str]:
    """Determine true media type from raw bytes using magic number analysis."""
    if not data:
        return None

    # 1. Audio WAV
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return "audio/wav"

    # 2. Audio OGG
    if data.startswith(b"OggS"):
        return "audio/ogg"

    # 3. Audio MP3 (ID3 tag or MPEG sync frame)
    if data.startswith(b"ID3"):
        return "audio/mpeg"
    if len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
        return "audio/mpeg"

    # 4. PDF
    if data.startswith(b"%PDF-"):
        return "application/pdf"

    # 5. Image PNG
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"

    # 6. Image JPEG
    if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"

    # 7. JSON
    try:
        decoded_text = data.decode("utf-8")
        parsed = json.loads(decoded_text)
        if isinstance(parsed, (dict, list)):
            return "application/json"
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass

    # 8. Text Plain (UTF-8 valid without binary null bytes or low control codes)
    try:
        decoded = data.decode("utf-8")
        # Reject if containing binary null bytes or non-whitespace control characters
        has_null = "\x00" in decoded
        has_binary_ctrl = any(
            ord(c) < 32 and c not in ("\t", "\n", "\r") for c in decoded[:2048]
        )
        if not has_null and not has_binary_ctrl:
            return "text/plain"
    except UnicodeDecodeError:
        pass

    return None


def inspect_evidence_bytes(
    data: bytes,
    declared_mime_type: Optional[str] = None,
) -> Tuple[bool, str, Optional[str], Optional[ReasonCode]]:
    """Deep inspection of evidence payload against allowlists and threat models.

    Returns:
        (is_valid, resolved_mime, error_detail, reason_code)
    """
    if not data or len(data) == 0:
        return False, "", "Payload content is empty", ReasonCode.MALFORMED_INPUT

    # 1. Archive Protection Gate
    is_arch, arch_detail = is_archive_payload(data)
    if is_arch:
        return False, "application/octet-stream", arch_detail, ReasonCode.PROHIBITED_INPUT

    # 2. Malware & Quarantine Gate
    is_threat, threat_detail = is_executable_or_malicious(data)
    if is_threat:
        return False, "application/octet-stream", f"Security quarantine: {threat_detail}", ReasonCode.PROHIBITED_INPUT

    # 3. True MIME detection
    detected = detect_content_type(data)
    if detected is None:
        return (
            False,
            "application/octet-stream",
            "Unrecognized or unsupported content structure; binary inspection failed",
            ReasonCode.PROHIBITED_INPUT,
        )

    # 4. Allowlist Verification
    if detected not in ALLOWED_EVIDENCE_MIME_TYPES:
        return (
            False,
            detected,
            f"Detected content type '{detected}' is not in the authorized evidence allowlist",
            ReasonCode.PROHIBITED_INPUT,
        )

    # 5. Client Spoofing Prevention
    if declared_mime_type:
        norm_declared = declared_mime_type.strip().lower()
        # Allow audio/mp3 and audio/mpeg equivalence, and audio/x-wav and audio/wav equivalence
        equivalents = {
            "audio/mp3": "audio/mpeg",
            "audio/x-wav": "audio/wav",
        }
        canonical_declared = equivalents.get(norm_declared, norm_declared)
        canonical_detected = equivalents.get(detected, detected)

        if canonical_declared != canonical_detected:
            # Special case: JSON is valid text/plain
            if canonical_declared == "text/plain" and canonical_detected == "application/json":
                pass
            else:
                return (
                    False,
                    detected,
                    f"MIME declaration spoofing detected: client declared '{declared_mime_type}' but server detected '{detected}'",
                    ReasonCode.MALFORMED_INPUT,
                )

    # 6. Size Limits per Category
    length = len(data)
    if "audio" in detected and length > MAX_AUDIO_BYTES:
        return False, detected, f"Audio exceeds size limit ({MAX_AUDIO_BYTES} bytes)", ReasonCode.MALFORMED_INPUT
    if detected in ("application/pdf",) and length > MAX_DOCUMENT_BYTES:
        return False, detected, f"Document exceeds size limit ({MAX_DOCUMENT_BYTES} bytes)", ReasonCode.MALFORMED_INPUT
    if detected in ("image/png", "image/jpeg") and length > MAX_IMAGE_BYTES:
        return False, detected, f"Image exceeds size limit ({MAX_IMAGE_BYTES} bytes)", ReasonCode.MALFORMED_INPUT
    if detected in ("text/plain", "application/json") and length > MAX_TEXT_BYTES:
        return False, detected, f"Text payload exceeds size limit ({MAX_TEXT_BYTES} bytes)", ReasonCode.MALFORMED_INPUT

    return True, detected, None, None
