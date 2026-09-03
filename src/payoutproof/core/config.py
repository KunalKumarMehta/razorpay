"""Configuration and secret management for PayoutProof.

Pure standard-library module to prevent circular imports.
Never stores mutable secret globals or reveals secret values in repr/str.
"""

from __future__ import annotations

import os
import sys
import secrets
import hmac
from dataclasses import dataclass, field
from typing import Mapping, Optional, Dict, Any


_DEV_SECRETS_WARNED = False


class ConfigurationError(Exception):
    """Stable safe exception for configuration failures."""
    pass


@dataclass(frozen=True)
class AppConfig:
    """Immutable application configuration with redacted secrets representation.

    IMPORTANT SECURITY DIRECTIVE:
    AppConfig contains sensitive cryptographic secrets (`grant_secret`, `audit_checkpoint_secret`).
    These secret fields are declared with `field(repr=False)` and masked as `[REDACTED]` in `__repr__` and `__str__`.
    However, callers must recognize that generic Python introspection utilities such as `dataclasses.asdict()`
    or `dataclasses.astuple()` inspect dataclass fields directly and extract raw secret values.
    AppConfig must NEVER be generically serialized or converted via `asdict`/`astuple` without explicit filtering.
    For safe public representation, diagnostic telemetry, or debugging, use `.to_safe_dict()`.
    Secrets must never appear in API responses, logs, health checks, OpenAPI schemas, or exceptions.
    """

    grant_secret: str = field(repr=False)
    audit_checkpoint_secret: str = field(repr=False)
    environment: str = "production"
    db_path: str = "payoutproof.db"
    enable_demo_adapter_modes: bool = False

    def __post_init__(self) -> None:
        if not self.grant_secret or len(self.grant_secret.strip()) < 32:
            raise ConfigurationError(
                "grant_secret is missing or too weak (must be at least 32 characters)."
            )
        if not self.audit_checkpoint_secret or len(self.audit_checkpoint_secret.strip()) < 32:
            raise ConfigurationError(
                "audit_checkpoint_secret is missing or too weak (must be at least 32 characters)."
            )
        if hmac.compare_digest(self.grant_secret, self.audit_checkpoint_secret):
            raise ConfigurationError(
                "grant_secret and audit_checkpoint_secret must be distinct secrets."
            )

    def to_safe_dict(self) -> Dict[str, Any]:
        """Return safe, non-sensitive configuration mapping suitable for display or logging.

        Guarantees that sensitive secrets are replaced with '[REDACTED]'.
        """
        return {
            "environment": self.environment,
            "grant_secret": "[REDACTED]",
            "audit_checkpoint_secret": "[REDACTED]",
            "db_path": self.db_path,
            "enable_demo_adapter_modes": self.enable_demo_adapter_modes,
        }

    def __repr__(self) -> str:
        return (
            f"AppConfig("
            f"environment={self.environment!r}, "
            f"grant_secret='[REDACTED]', "
            f"audit_checkpoint_secret='[REDACTED]', "
            f"db_path={self.db_path!r}, "
            f"enable_demo_adapter_modes={self.enable_demo_adapter_modes!r}"
            f")"
        )

    def __str__(self) -> str:
        return self.__repr__()

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> AppConfig:
        """Compose configuration from environment variables.

        Outside explicit PAYOUTPROOF_ENV=development, requires PAYOUTPROOF_GRANT_SECRET
        and PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET (each >= 32 characters and distinct).
        In development mode, missing secrets are generated as process-ephemeral secrets
        with a one-time stderr warning; supplied secrets still validate strictly.
        """
        global _DEV_SECRETS_WARNED
        environ = os.environ if env is None else env

        raw_env = environ.get("PAYOUTPROOF_ENV", "").strip().lower()
        is_dev = raw_env == "development"
        environment = "development" if is_dev else (raw_env if raw_env else "production")

        grant_secret = environ.get("PAYOUTPROOF_GRANT_SECRET")
        audit_secret = environ.get("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET")

        if is_dev:
            missing_any = False
            if not grant_secret:
                grant_secret = secrets.token_urlsafe(32)
                missing_any = True
            if not audit_secret:
                audit_secret = secrets.token_urlsafe(32)
                missing_any = True

            if missing_any:
                while audit_secret == grant_secret:
                    audit_secret = secrets.token_urlsafe(32)

            if missing_any and not _DEV_SECRETS_WARNED:
                sys.stderr.write(
                    "WARNING: PAYOUTPROOF_ENV=development generated process-ephemeral secrets; "
                    "restarting the process will invalidate active grants and audit checkpoints.\n"
                )
                _DEV_SECRETS_WARNED = True
        else:
            if not grant_secret:
                raise ConfigurationError(
                    "Missing required environment variable PAYOUTPROOF_GRANT_SECRET "
                    "(must be at least 32 characters)."
                )
            if not audit_secret:
                raise ConfigurationError(
                    "Missing required environment variable PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET "
                    "(must be at least 32 characters)."
                )

        db_path = environ.get("PAYOUTPROOF_DB_PATH", "payoutproof.db")
        demo_modes_raw = environ.get("PAYOUTPROOF_ENABLE_DEMO_ADAPTER_MODES", "0").strip().lower()
        enable_demo = demo_modes_raw in ("1", "true", "yes", "enabled")

        return cls(
            grant_secret=grant_secret,
            audit_checkpoint_secret=audit_secret,
            environment=environment,
            db_path=db_path,
            enable_demo_adapter_modes=enable_demo,
        )

    @classmethod
    def for_tests(
        cls,
        grant_secret: str,
        audit_checkpoint_secret: str,
        environment: str = "test",
        db_path: str = ":memory:",
        enable_demo_adapter_modes: bool = False,
    ) -> AppConfig:
        """Compose configuration explicitly for tests.

        Requires explicit caller-provided distinct fixed secrets. No production defaults.
        """
        if not grant_secret:
            raise ConfigurationError("grant_secret is required for tests.")
        if not audit_checkpoint_secret:
            raise ConfigurationError("audit_checkpoint_secret is required for tests.")

        return cls(
            grant_secret=grant_secret,
            audit_checkpoint_secret=audit_checkpoint_secret,
            environment=environment,
            db_path=db_path,
            enable_demo_adapter_modes=enable_demo_adapter_modes,
        )
