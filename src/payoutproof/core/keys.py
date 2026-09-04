"""Key Ring and key rotation management for PayoutProof.

Pure standard-library module to prevent circular imports.
Never stores mutable secret globals or reveals secret values in repr/str.
"""

from __future__ import annotations

import hmac
import os
import re
from typing import Dict, List, Mapping, Optional


class KeyRingError(Exception):
    """Raised when KeyRing configuration or parsing fails."""
    pass


class KeyRing:
    """Immutable collection of named cryptographic keys with an active key ID.

    Guarantees:
    1. Active key is always present in keys mapping.
    2. All secrets are at least 32 characters long.
    3. Secrets are never exposed in __repr__ or __str__.
    4. Provides constant-time MAC verification across active and retained keys.
    """

    def __init__(self, active_key_id: str, keys: Mapping[str, str]):
        self._active_key_id: str = ""
        self._keys: Dict[str, str] = {}

        if not active_key_id or not str(active_key_id).strip():
            raise KeyRingError("active_key_id must be a non-empty string.")

        cleaned_active_id = str(active_key_id).strip()
        cleaned_keys: Dict[str, str] = {}

        for k, v in keys.items():
            k_clean = str(k).strip()
            if not k_clean:
                raise KeyRingError("Key ID in KeyRing cannot be empty.")
            if not v or len(str(v).strip()) < 32:
                raise KeyRingError(
                    f"Secret for key '{k_clean}' is missing or too weak (must be at least 32 characters)."
                )
            cleaned_keys[k_clean] = str(v)

        if cleaned_active_id not in cleaned_keys:
            raise KeyRingError(
                f"Active key '{cleaned_active_id}' is not present in provided keys."
            )

        self._active_key_id = cleaned_active_id
        self._keys = cleaned_keys

    def has_key(self, key_id: Optional[str]) -> bool:
        """Check whether a key ID exists in the ring. None maps to active key."""
        if key_id is None:
            return True
        return str(key_id).strip() in self._keys

    @property
    def active_key_id(self) -> str:
        """Identifier of the current active signing key."""
        return self._active_key_id

    @property
    def keys(self) -> Dict[str, str]:
        """Mapping of all key identifiers to secrets (active and retained)."""
        return dict(self._keys)

    @property
    def active_secret(self) -> str:
        """Raw secret string of the active key."""
        return self._keys[self._active_key_id]

    @property
    def all_secrets(self) -> List[str]:
        """List of all secret values (active first, then retained)."""
        active = [self.active_secret]
        retained = [v for k, v in self._keys.items() if k != self._active_key_id]
        return active + retained

    @property
    def retained_keys(self) -> Dict[str, str]:
        """Mapping of retained (inactive) key identifiers to secrets."""
        return {k: v for k, v in self._keys.items() if k != self._active_key_id}

    def get_secret(self, key_id: Optional[str] = None) -> Optional[str]:
        """Get secret by key ID. If key_id is None, returns active secret."""
        if key_id is None:
            return self.active_secret
        return self._keys.get(str(key_id).strip())

    def contains_secret(self, secret: str) -> bool:
        """Check whether a secret string matches any key in the ring (constant-time)."""
        if not secret:
            return False
        for s in self._keys.values():
            if hmac.compare_digest(s, secret):
                return True
        return False

    def are_disjoint(self, other: KeyRing) -> bool:
        """Check that no secret in this ring matches any secret in the other ring."""
        for s1 in self._keys.values():
            for s2 in other._keys.values():
                if hmac.compare_digest(s1, s2):
                    return False
        return True

    @classmethod
    def from_single_key(cls, secret: str, key_id: str = "v1") -> KeyRing:
        """Create a KeyRing containing a single active key."""
        return cls(active_key_id=key_id, keys={key_id: secret})

    @classmethod
    def parse_retained_string(cls, raw: str) -> Dict[str, str]:
        """Parse comma-separated 'key_id:secret' or 'secret' retained keys string."""
        if not raw or not raw.strip():
            return {}
        result: Dict[str, str] = {}
        items = [item.strip() for item in raw.split(",") if item.strip()]
        for idx, item in enumerate(items, start=1):
            if ":" in item:
                kid, sec = item.split(":", 1)
                kid = kid.strip()
                sec = sec.strip()
                if not kid or not sec:
                    raise KeyRingError(f"Malformed retained key pair {item!r}; expected 'key_id:secret'")
                result[kid] = sec
            else:
                sec = item.strip()
                result[f"retained_{idx}"] = sec
        return result

    @classmethod
    def from_env(
        cls,
        *,
        active_secret_env: str,
        active_key_id_env: Optional[str] = None,
        retained_secrets_env: Optional[str] = None,
        default_key_id: str = "v1",
        environ: Optional[Mapping[str, str]] = None,
    ) -> Optional[KeyRing]:
        """Build KeyRing from environment mapping."""
        env = os.environ if environ is None else environ
        active_secret = env.get(active_secret_env)
        if not active_secret:
            return None

        active_kid = default_key_id
        if active_key_id_env:
            active_kid = env.get(active_key_id_env, "").strip() or default_key_id

        keys: Dict[str, str] = {active_kid: active_secret}

        if retained_secrets_env:
            raw_retained = env.get(retained_secrets_env, "").strip()
            if raw_retained:
                retained_map = cls.parse_retained_string(raw_retained)
                keys.update(retained_map)

        return cls(active_key_id=active_kid, keys=keys)

    def __repr__(self) -> str:
        keys_summary = ", ".join(f"{k!r}: '[REDACTED]'" for k in self._keys)
        return f"KeyRing(active_key_id={self._active_key_id!r}, keys={{{keys_summary}}})"

    def __str__(self) -> str:
        return self.__repr__()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KeyRing):
            return False
        if self._active_key_id != other._active_key_id:
            return False
        if set(self._keys.keys()) != set(other._keys.keys()):
            return False
        for k, v in self._keys.items():
            if not hmac.compare_digest(v, other._keys[k]):
                return False
        return True
