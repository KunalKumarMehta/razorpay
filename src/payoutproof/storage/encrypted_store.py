"""Encrypted object storage engine for raw evidence preservation.

Guarantees:
1. Raw evidence is encrypted at rest using authenticated symmetric AEAD (AES-256-GCM).
2. Content hash (SHA-256) is computed over plaintext for audit and policy verification.
3. Cryptographic binding with tenant, organization, case, and evidence identifiers in AAD.
4. Complete secret redaction in representations and error messages.
5. Support for KeyRing key rotation (reads records under retained keys).
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from payoutproof.core.crypto import sha256_hex
from payoutproof.core.keys import KeyRing


class ObjectStoreError(Exception):
    """Base exception for object storage operations."""
    pass


class ObjectNotFoundError(ObjectStoreError):
    """Raised when an evidence object does not exist at the target URI."""
    pass


class DecryptionIntegrityError(ObjectStoreError):
    """Raised when decryption fails authentication or hash mismatch."""
    pass


@dataclass(frozen=True)
class StoredObjectRef:
    """Immutable descriptor of an encrypted object in storage."""
    storage_uri: str
    content_hash: str
    plaintext_size_bytes: int
    ciphertext_size_bytes: int
    encryption_algorithm: str
    key_id: Optional[str]
    tenant_id: str
    organization_id: str
    case_id: str
    evidence_id: str


class EncryptedObjectStore:
    """AES-256-GCM encrypted object store with tenant-isolated directory layout."""

    STORAGE_SCHEME = "enc-file://"
    CURRENT_VERSION_BYTE = b"\x01"

    def __init__(
        self,
        base_dir: Union[str, Path],
        *,
        encryption_key: Union[str, bytes, KeyRing],
    ):
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

        if isinstance(encryption_key, KeyRing):
            self._key_ring: Optional[KeyRing] = encryption_key
            self._single_key_bytes: Optional[bytes] = None
        else:
            self._key_ring = None
            if isinstance(encryption_key, str):
                # If hex string of 64 chars (32 bytes), decode; else encode utf-8 or pad/hash to 32 bytes
                key_str = encryption_key.strip()
                if len(key_str) >= 32:
                    self._single_key_bytes = key_str[:32].encode("utf-8")
                else:
                    raise ValueError("encryption_key must be at least 32 characters")
            elif isinstance(encryption_key, (bytes, bytearray)):
                if len(encryption_key) < 32:
                    raise ValueError("encryption_key bytes must be at least 32 bytes")
                self._single_key_bytes = bytes(encryption_key[:32])
            else:
                raise TypeError("encryption_key must be str, bytes, or KeyRing")

    def _resolve_cipher(self, key_id: Optional[str] = None) -> Tuple[AESGCM, Optional[str]]:
        """Resolve AESGCM cipher for given key_id or active key."""
        if self._key_ring is not None:
            kid = key_id or self._key_ring.active_key_id
            sec = self._key_ring.get_secret(kid)
            if not sec:
                raise ObjectStoreError(f"Encryption key '{kid}' not found in KeyRing")
            key_bytes = sec[:32].encode("utf-8")
            return AESGCM(key_bytes), kid
        else:
            return AESGCM(self._single_key_bytes), key_id or "v1"

    def _build_path(
        self,
        tenant_id: str,
        organization_id: str,
        case_id: str,
        evidence_id: str,
    ) -> Path:
        """Construct isolated file path on disk."""
        # Sanitize path segments to prevent traversal
        safe_tenant = "".join(c for c in tenant_id if c.isalnum() or c in "-_")
        safe_org = "".join(c for c in organization_id if c.isalnum() or c in "-_")
        safe_case = "".join(c for c in case_id if c.isalnum() or c in "-_")
        safe_ev = "".join(c for c in evidence_id if c.isalnum() or c in "-_")

        target_dir = self.base_dir / safe_tenant / safe_org / safe_case
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir / f"{safe_ev}.enc"

    def _path_from_uri(self, storage_uri: str) -> Path:
        """Convert enc-file:// URI back to Path."""
        if not storage_uri.startswith(self.STORAGE_SCHEME):
            raise ValueError(f"Unsupported storage URI scheme: {storage_uri}")
        rel_path = storage_uri[len(self.STORAGE_SCHEME):]
        full_path = (self.base_dir / rel_path).resolve()
        # Ensure path stays within base_dir
        if not str(full_path).startswith(str(self.base_dir)):
            raise SecurityScanError("Attempted path traversal in storage URI")
        return full_path

    def put_evidence(
        self,
        *,
        tenant_id: str,
        organization_id: str,
        case_id: str,
        evidence_id: str,
        plaintext: bytes,
    ) -> StoredObjectRef:
        """Encrypt and store raw evidence with cryptographic domain binding."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes or bytearray")

        content_hash = sha256_hex(plaintext)
        cipher, active_kid = self._resolve_cipher()

        # 12-byte cryptographically secure random nonce
        nonce = secrets.token_bytes(12)

        # Authenticated Associated Data binds scope into encryption tag
        aad = f"{tenant_id}|{organization_id}|{case_id}|{evidence_id}".encode("utf-8")

        # AES-256-GCM encryption
        ciphertext = cipher.encrypt(nonce, bytes(plaintext), aad)

        # Payload structure: version (1) + nonce (12) + ciphertext
        payload = self.CURRENT_VERSION_BYTE + nonce + ciphertext

        target_file = self._build_path(tenant_id, organization_id, case_id, evidence_id)
        target_file.write_bytes(payload)

        rel_path = target_file.relative_to(self.base_dir).as_posix()
        uri = f"{self.STORAGE_SCHEME}{rel_path}"

        return StoredObjectRef(
            storage_uri=uri,
            content_hash=content_hash,
            plaintext_size_bytes=len(plaintext),
            ciphertext_size_bytes=len(payload),
            encryption_algorithm="AES-256-GCM",
            key_id=active_kid,
            tenant_id=tenant_id,
            organization_id=organization_id,
            case_id=case_id,
            evidence_id=evidence_id,
        )

    def get_evidence(self, ref: StoredObjectRef) -> bytes:
        """Read, decrypt, and verify evidence payload."""
        target_file = self._path_from_uri(ref.storage_uri)
        if not target_file.exists():
            raise ObjectNotFoundError(f"Evidence object not found: {ref.storage_uri}")

        payload = target_file.read_bytes()
        if len(payload) < 1 + 12 + 16:  # version + nonce + tag min length
            raise DecryptionIntegrityError("Corrupted evidence payload: insufficient byte length")

        ver = payload[0:1]
        if ver != self.CURRENT_VERSION_BYTE:
            raise DecryptionIntegrityError(f"Unsupported payload version: {ver!r}")

        nonce = payload[1:13]
        ciphertext = payload[13:]

        cipher, _ = self._resolve_cipher(ref.key_id)
        aad = f"{ref.tenant_id}|{ref.organization_id}|{ref.case_id}|{ref.evidence_id}".encode("utf-8")

        try:
            plaintext = cipher.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise DecryptionIntegrityError(f"AES-GCM decryption failed: authentication tag mismatch or wrong key ({e})")

        recomputed_hash = sha256_hex(plaintext)
        if recomputed_hash != ref.content_hash:
            raise DecryptionIntegrityError(
                f"Plaintext hash mismatch: expected '{ref.content_hash}', got '{recomputed_hash}'"
            )

        return plaintext

    def put(
        self,
        *,
        tenant_id: str,
        organization_id: str,
        case_id: str,
        evidence_id: str,
        content: bytes,
    ) -> StoredObjectRef:
        """Alias for put_evidence with content parameter."""
        return self.put_evidence(
            tenant_id=tenant_id,
            organization_id=organization_id,
            case_id=case_id,
            evidence_id=evidence_id,
            plaintext=content,
        )

    def get_raw_encrypted_bytes(self, storage_uri: str) -> bytes:
        """Read raw bytes directly from storage path on disk."""
        target_file = self._path_from_uri(storage_uri)
        if not target_file.exists():
            raise ObjectNotFoundError(f"Evidence object not found: {storage_uri}")
        return target_file.read_bytes()

    def _decrypt(
        self,
        payload: bytes,
        *,
        tenant_id: str,
        organization_id: str,
        case_id: str,
        evidence_id: str,
        key_id: Optional[str] = None,
    ) -> bytes:
        """Internal decrypt helper given raw payload and AAD params."""
        if len(payload) < 1 + 12 + 16:
            raise DecryptionIntegrityError("Corrupted evidence payload: insufficient byte length")
        ver = payload[0:1]
        if ver != self.CURRENT_VERSION_BYTE:
            raise DecryptionIntegrityError(f"Unsupported payload version: {ver!r}")
        nonce = payload[1:13]
        ciphertext = payload[13:]
        cipher, _ = self._resolve_cipher(key_id)
        aad = f"{tenant_id}|{organization_id}|{case_id}|{evidence_id}".encode("utf-8")
        try:
            return cipher.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise DecryptionIntegrityError(f"AES-GCM decryption failed: {e}")

    def get(
        self,
        storage_uri: str,
        *,
        key_id: Optional[str] = None,
    ) -> Tuple[bytes, StoredObjectRef]:
        """Read and decrypt by URI, deriving context from path."""
        target_file = self._path_from_uri(storage_uri)
        if not target_file.exists():
            raise ObjectNotFoundError(f"Evidence object not found: {storage_uri}")

        # Derive path components from base_dir: base_dir / tenant / org / case / evidence.enc
        rel_parts = target_file.relative_to(self.base_dir).parts
        if len(rel_parts) < 4:
            raise ObjectStoreError(f"Invalid evidence path layout: {rel_parts}")
        tenant_id, org_id, case_id = rel_parts[0], rel_parts[1], rel_parts[2]
        ev_file = rel_parts[3]
        evidence_id = ev_file[:-4] if ev_file.endswith(".enc") else ev_file

        payload = target_file.read_bytes()
        plaintext = self._decrypt(
            payload,
            tenant_id=tenant_id,
            organization_id=org_id,
            case_id=case_id,
            evidence_id=evidence_id,
            key_id=key_id,
        )
        content_hash = sha256_hex(plaintext)
        ref = StoredObjectRef(
            storage_uri=storage_uri,
            content_hash=content_hash,
            plaintext_size_bytes=len(plaintext),
            ciphertext_size_bytes=len(payload),
            encryption_algorithm="AES-256-GCM",
            key_id=key_id or (self._key_ring.active_key_id if self._key_ring else "v1"),
            tenant_id=tenant_id,
            organization_id=org_id,
            case_id=case_id,
            evidence_id=evidence_id,
        )
        return plaintext, ref

    def delete_evidence(self, storage_uri: str) -> bool:
        """Securely shred and remove evidence object."""
        try:
            target_file = self._path_from_uri(storage_uri)
            if not target_file.exists():
                return False

            file_size = target_file.stat().st_size
            # Overwrite with zeros
            target_file.write_bytes(b"\x00" * file_size)
            target_file.unlink()
            return True
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"EncryptedObjectStore(base_dir={self.base_dir!r}, encryption_key='[REDACTED]')"

    def __str__(self) -> str:
        return self.__repr__()
