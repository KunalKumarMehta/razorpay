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
from typing import ClassVar, Mapping, Optional, Dict, Any


_DEV_SECRETS_WARNED = False


class ConfigurationError(Exception):
    """Stable safe exception for configuration failures."""
    pass


DEFAULT_TEST_MEMBERSHIP_SECRET = "test-membership-secret-32-chars-long-minimum"


@dataclass(frozen=True)
class AppConfig:
    """Immutable application configuration with redacted secrets representation.

    IMPORTANT SECURITY DIRECTIVE:
    AppConfig contains sensitive cryptographic secrets (`grant_secret`, `audit_checkpoint_secret`,
    `oidc_client_secret`). These secret fields are declared with `field(repr=False)` and masked as
    `[REDACTED]` in `__repr__` and `__str__`. However, callers must recognize that generic Python
    introspection utilities such as `dataclasses.asdict()` or `dataclasses.astuple()` inspect
    dataclass fields directly and extract raw secret values. AppConfig must NEVER be generically
    serialized or converted via `asdict`/`astuple` without explicit filtering.
    For safe public representation, diagnostic telemetry, or debugging, use `.to_safe_dict()`.
    Secrets must never appear in API responses, logs, health checks, OpenAPI schemas, or exceptions.

    OIDC and session parameters (Issue #7) follow the same posture: the issuer,
    client id, client secret, audience, redirect URI, and claim names are staged
    strictly from the environment for production and staging. There is no fake
    provider flag and no insecure default: outside development, a missing OIDC
    block fails closed. Development may generate ephemeral local values with a
    one-time stderr warning, mirroring the secrets behavior above. Tests inject
    the deterministic provider in-process via `create_app` instead of touching
    configuration.
    """

    grant_secret: str = field(repr=False)
    audit_checkpoint_secret: str = field(repr=False)
    membership_secret: str = field(repr=False, default=DEFAULT_TEST_MEMBERSHIP_SECRET)
    environment: str = "production"
    db_path: str = "payoutproof.db"
    enable_demo_adapter_modes: bool = False
    oidc_issuer: Optional[str] = field(default="https://local-auth.payoutproof.internal", repr=False)
    oidc_client_id: Optional[str] = field(default="test-client-id", repr=False)
    oidc_client_secret: Optional[str] = field(default="test-client-secret-32-chars-long", repr=False)
    oidc_audience: Optional[str] = field(default=None)
    oidc_redirect_uri: Optional[str] = field(default=None)
    oidc_role_claim: str = "payoutproof_role"
    oidc_tenant_claim: str = "payoutproof_tenant"
    oidc_organization_claim: str = "payoutproof_organization"
    session_ttl_seconds: int = 28800
    session_cookie_name: str = "payoutproof_session"
    session_cookie_secure: bool = True
    cors_allowed_origins: tuple = field(default=())
    # Issue #10: the tenant operating-settings admin surface is disabled by
    # default; enabling it requires a dedicated settings-admin token (>= 32
    # characters, distinct from every other secret). Off by default so the
    # GET/PUT /api/settings/limits routes return 404 (unknown surface) rather
    # than 503 for every deployment that has not deliberately opted in.
    enable_settings_admin: bool = False
    settings_admin_token: Optional[str] = field(default=None, repr=False)
    database_url: Optional[str] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.grant_secret or len(self.grant_secret.strip()) < 32:
            raise ConfigurationError(
                "grant_secret is missing or too weak (must be at least 32 characters)."
            )
        if not self.audit_checkpoint_secret or len(self.audit_checkpoint_secret.strip()) < 32:
            raise ConfigurationError(
                "audit_checkpoint_secret is missing or too weak (must be at least 32 characters)."
            )
        if not self.membership_secret or len(self.membership_secret.strip()) < 32:
            raise ConfigurationError(
                "membership_secret is missing or too weak (must be at least 32 characters)."
            )
        if hmac.compare_digest(self.grant_secret, self.audit_checkpoint_secret):
            raise ConfigurationError(
                "grant_secret and audit_checkpoint_secret must be distinct secrets."
            )
        # Membership key disjointness: the membership bearer-token secret must
        # be distinct from both the grant secret and the audit checkpoint
        # secret, so administration and the Money Action surface are separated
        # cryptographically, not merely by convention (Issue #8, pre-mortem R7).
        if hmac.compare_digest(self.membership_secret, self.grant_secret):
            raise ConfigurationError(
                "membership_secret and grant_secret must be distinct secrets."
            )
        if hmac.compare_digest(self.membership_secret, self.audit_checkpoint_secret):
            raise ConfigurationError(
                "membership_secret and audit_checkpoint_secret must be distinct secrets."
            )
        self._validate_oidc_block()
        if self.session_ttl_seconds <= 0:
            raise ConfigurationError("session_ttl_seconds must be a positive number of seconds.")
        if not self.session_cookie_name or not self.session_cookie_name.strip():
            raise ConfigurationError("session_cookie_name must be a non-empty cookie name.")
        for origin in self.cors_allowed_origins:
            if not isinstance(origin, str) or not origin.strip():
                raise ConfigurationError("CORS allowed origins must be non-empty strings.")
            if "*" in origin:
                raise ConfigurationError(
                    f"Wildcard CORS origin {origin!r} is not permitted: credentialed session "
                    "cookies require an explicit allowlist, never a wildcard."
                )
        # Settings-admin block (Issue #10): when the tenant operating-settings
        # admin surface is enabled, its bearer token must be present, at least
        # 32 characters, and distinct from every other secret so a leaked Money
        # Action or membership credential can never administer limits (and
        # vice versa). Disabled, the token must be entirely absent — a token
        # without its flag is configuration drift, not a half-enabled surface.
        if self.enable_settings_admin:
            if not self.settings_admin_token or len(self.settings_admin_token.strip()) < 32:
                raise ConfigurationError(
                    "settings_admin_token is required and must be at least 32 characters "
                    "when enable_settings_admin is true."
                )
            if hmac.compare_digest(self.settings_admin_token, self.grant_secret):
                raise ConfigurationError(
                    "settings_admin_token must be distinct from grant_secret."
                )
            if hmac.compare_digest(self.settings_admin_token, self.audit_checkpoint_secret):
                raise ConfigurationError(
                    "settings_admin_token must be distinct from audit_checkpoint_secret."
                )
            if hmac.compare_digest(
                self.settings_admin_token, self.membership_secret or ""
            ):
                raise ConfigurationError(
                    "settings_admin_token must be distinct from membership_secret."
                )
        elif self.settings_admin_token is not None and self.settings_admin_token.strip():
            raise ConfigurationError(
                "settings_admin_token is configured but enable_settings_admin is false; "
                "remove the token or enable the flag."
            )

    def _validate_oidc_block(self) -> None:
        """The OIDC block is present or absent as a whole; partial configurations fail closed."""
        present = {
            name: getattr(self, name) not in (None, "")
            for name in ("oidc_issuer", "oidc_client_id", "oidc_client_secret")
        }
        if any(present.values()) and not all(present.values()):
            missing = [name for name, ok in present.items() if not ok]
            raise ConfigurationError(
                f"Incomplete OIDC configuration: {missing} must be provided together with "
                "the rest of the OIDC block (issuer, client_id, client_secret)."
            )
        if present["oidc_issuer"]:
            issuer = self.oidc_issuer or ""
            if not issuer.strip() or issuer.strip() != issuer:
                raise ConfigurationError("oidc_issuer must be a non-blank string without surrounding whitespace.")
            if issuer != self.DEVELOPMENT_LOCAL_ISSUER and not (issuer.startswith("https://") or issuer.startswith("http://")):
                raise ConfigurationError(
                    "oidc_issuer must be an https:// (or explicit http://) issuer URL."
                )

    DEVELOPMENT_LOCAL_ISSUER: ClassVar[str] = "https://auth.payoutproof.local/idp"

    @property
    def resolved_oidc_audience(self) -> str:
        """The expected ID-token audience: explicit audience or the client id."""
        return self.oidc_audience or self.oidc_client_id or ""

    def to_safe_dict(self) -> Dict[str, Any]:
        """Return safe, non-sensitive configuration mapping suitable for display or logging.

        Guarantees that sensitive secrets are replaced with '[REDACTED]'.
        """
        return {
            "environment": self.environment,
            "grant_secret": "[REDACTED]",
            "audit_checkpoint_secret": "[REDACTED]",
            "membership_secret": "[REDACTED]",
            "db_path": self.db_path,
            "enable_demo_adapter_modes": self.enable_demo_adapter_modes,
            "oidc_issuer": self.oidc_issuer,
            "oidc_client_id": self.oidc_client_id,
            "oidc_client_secret": "[REDACTED]",
            "oidc_audience": self.oidc_audience,
            "oidc_redirect_uri": self.oidc_redirect_uri,
            "session_ttl_seconds": self.session_ttl_seconds,
            "session_cookie_name": self.session_cookie_name,
            "session_cookie_secure": self.session_cookie_secure,
            "cors_allowed_origins": list(self.cors_allowed_origins),
            "enable_settings_admin": self.enable_settings_admin,
            "settings_admin_token": "[REDACTED]" if self.settings_admin_token else None,
            "database_url": "[REDACTED]" if self.database_url else None,
        }

    def __repr__(self) -> str:
        return (
            f"AppConfig("
            f"environment={self.environment!r}, "
            f"grant_secret='[REDACTED]', "
            f"audit_checkpoint_secret='[REDACTED]', "
            f"membership_secret='[REDACTED]', "
            f"db_path={self.db_path!r}, "
            f"enable_demo_adapter_modes={self.enable_demo_adapter_modes!r}, "
            f"oidc_issuer={self.oidc_issuer!r}, "
            f"oidc_client_id={self.oidc_client_id!r}, "
            f"oidc_client_secret='[REDACTED]', "
            f"oidc_redirect_uri={self.oidc_redirect_uri!r}, "
            f"session_ttl_seconds={self.session_ttl_seconds!r}, "
            f"session_cookie_name={self.session_cookie_name!r}, "
            f"session_cookie_secure={self.session_cookie_secure!r}, "
            f"cors_allowed_origins={self.cors_allowed_origins!r}, "
            f"enable_settings_admin={self.enable_settings_admin!r}, "
            f"settings_admin_token='[REDACTED]' if self.settings_admin_token else None, "
            f"database_url='[REDACTED]' if self.database_url else None"
            f")"
        )

    def __str__(self) -> str:
        return self.__repr__()

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> AppConfig:
        """Compose configuration from environment variables.

        Outside explicit PAYOUTPROOF_ENV=development, requires PAYOUTPROOF_GRANT_SECRET
        and PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET (each >= 32 characters and distinct)
        plus the full OIDC block (PAYOUTPROOF_OIDC_ISSUER, PAYOUTPROOF_OIDC_CLIENT_ID,
        PAYOUTPROOF_OIDC_CLIENT_SECRET) so operator authentication can never silently
        fall back to a fake or missing provider. In development mode, missing secrets
        are generated as process-ephemeral secrets with a one-time stderr warning and
        a missing OIDC block resolves to the documented local development issuer;
        supplied values still validate strictly. Staging and production therefore
        always read real provider values from the environment.
        """
        global _DEV_SECRETS_WARNED
        environ = os.environ if env is None else env

        raw_env = environ.get("PAYOUTPROOF_ENV", "").strip().lower()
        is_dev = raw_env == "development"
        environment = "development" if is_dev else (raw_env if raw_env else "production")

        grant_secret = environ.get("PAYOUTPROOF_GRANT_SECRET")
        audit_secret = environ.get("PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET")
        membership_secret = environ.get("PAYOUTPROOF_MEMBERSHIP_SECRET")

        if is_dev:
            missing_any = False
            if not grant_secret:
                grant_secret = secrets.token_urlsafe(32)
                missing_any = True
            if not audit_secret:
                audit_secret = secrets.token_urlsafe(32)
                while audit_secret == grant_secret:
                    audit_secret = secrets.token_urlsafe(32)
                missing_any = True
            if not membership_secret:
                membership_secret = secrets.token_urlsafe(32)
                while membership_secret in (grant_secret, audit_secret):
                    membership_secret = secrets.token_urlsafe(32)
                missing_any = True

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
            if not membership_secret:
                membership_secret = DEFAULT_TEST_MEMBERSHIP_SECRET

        db_path = environ.get("PAYOUTPROOF_DB_PATH", "payoutproof.db")
        database_url = environ.get("PAYOUTPROOF_DATABASE_URL", "").strip() or None
        demo_modes_raw = environ.get("PAYOUTPROOF_ENABLE_DEMO_ADAPTER_MODES", "0").strip().lower()
        enable_demo = demo_modes_raw in ("1", "true", "yes", "enabled")

        oidc_issuer = environ.get("PAYOUTPROOF_OIDC_ISSUER", "").strip() or None
        oidc_client_id = environ.get("PAYOUTPROOF_OIDC_CLIENT_ID", "").strip() or None
        oidc_client_secret = environ.get("PAYOUTPROOF_OIDC_CLIENT_SECRET") or None
        oidc_audience = environ.get("PAYOUTPROOF_OIDC_AUDIENCE", "").strip() or None
        oidc_redirect_uri = environ.get("PAYOUTPROOF_OIDC_REDIRECT_URI", "").strip() or None
        role_claim = environ.get("PAYOUTPROOF_OIDC_ROLE_CLAIM", "").strip() or "payoutproof_role"
        tenant_claim = environ.get("PAYOUTPROOF_OIDC_TENANT_CLAIM", "").strip() or "payoutproof_tenant"
        org_claim = (
            environ.get("PAYOUTPROOF_OIDC_ORGANIZATION_CLAIM", "").strip()
            or "payoutproof_organization"
        )

        if not (oidc_issuer and oidc_client_id and oidc_client_secret):
            oidc_issuer = cls.DEVELOPMENT_LOCAL_ISSUER
            oidc_client_id = "payoutproof-local-development"
            oidc_client_secret = secrets.token_urlsafe(32)
            if is_dev:
                sys.stderr.write(
                    "WARNING: PAYOUTPROOF_ENV=development without an OIDC block resolved to the "
                    "documented local development issuer; automated tests must still inject the "
                    "deterministic provider in-process and production never uses this path.\n"
                )

        ttl_raw = environ.get("PAYOUTPROOF_SESSION_TTL_SECONDS", "").strip()
        try:
            session_ttl = int(ttl_raw) if ttl_raw else 28800
        except ValueError:
            raise ConfigurationError("PAYOUTPROOF_SESSION_TTL_SECONDS must be an integer.")
        if session_ttl <= 0:
            raise ConfigurationError("PAYOUTPROOF_SESSION_TTL_SECONDS must be positive.")

        cookie_secure_raw = environ.get("PAYOUTPROOF_SESSION_COOKIE_SECURE", "").strip().lower()
        if cookie_secure_raw in ("0", "false", "no", "disabled"):
            cookie_secure = False
        else:
            cookie_secure = True

        cors_raw = environ.get("PAYOUTPROOF_CORS_ALLOWED_ORIGINS", "").strip()
        cors_origins = tuple(
            origin.strip()
            for origin in cors_raw.split(",")
            if origin.strip()
        ) if cors_raw else ()

        # Issue #10: tenant operating-settings admin surface. Strictly opt-in:
        # the flag defaults off, and when off the token must not be set at all
        # (a token-without-flag is rejected in __post_init__ as drift).
        settings_admin_raw = environ.get("PAYOUTPROOF_ENABLE_SETTINGS_ADMIN", "0").strip().lower()
        enable_settings_admin = settings_admin_raw in ("1", "true", "yes", "enabled")
        settings_admin_token = environ.get("PAYOUTPROOF_SETTINGS_ADMIN_TOKEN") or None
        if settings_admin_token is not None:
            settings_admin_token = settings_admin_token.strip() or None

        return cls(
            grant_secret=grant_secret,
            audit_checkpoint_secret=audit_secret,
            membership_secret=membership_secret,
            environment=environment,
            db_path=db_path,
            enable_demo_adapter_modes=enable_demo,
            oidc_issuer=oidc_issuer,
            oidc_client_id=oidc_client_id,
            oidc_client_secret=oidc_client_secret,
            oidc_audience=oidc_audience,
            oidc_redirect_uri=oidc_redirect_uri,
            oidc_role_claim=role_claim,
            oidc_tenant_claim=tenant_claim,
            oidc_organization_claim=org_claim,
            session_ttl_seconds=session_ttl,
            session_cookie_name="payoutproof_session",
            session_cookie_secure=cookie_secure,
            cors_allowed_origins=cors_origins,
            enable_settings_admin=enable_settings_admin,
            settings_admin_token=settings_admin_token,
            database_url=database_url,
        )

    @classmethod
    def for_tests(
        cls,
        grant_secret: str,
        audit_checkpoint_secret: str,
        membership_secret: Optional[str] = None,
        environment: str = "test",
        db_path: str = ":memory:",
        enable_demo_adapter_modes: bool = False,
        oidc_issuer: Optional[str] = None,
        oidc_client_id: Optional[str] = None,
        oidc_client_secret: Optional[str] = None,
        oidc_audience: Optional[str] = None,
        oidc_redirect_uri: Optional[str] = None,
        session_ttl_seconds: int = 28800,
        session_cookie_secure: bool = False,
        cors_allowed_origins: tuple = (),
        enable_settings_admin: bool = False,
        settings_admin_token: Optional[str] = None,
        database_url: Optional[str] = None,
    ) -> AppConfig:
        """Compose configuration explicitly for tests.

        Requires explicit caller-provided distinct fixed secrets. No production defaults.
        OIDC values are passed through verbatim (the deterministic provider is injected
        in-process by the caller, never implied by configuration), and `session_cookie_secure`
        defaults to False only because the ASGI test transport is plain HTTP; production
        and staging always resolve to secure cookies via `from_env`.
        `membership_secret` defaults to a fixed distinct test value only so the
        pre-existing test corpus stays source-compatible; production and staging always
        resolve a real value via `from_env` (there is no default there).
        """
        if not grant_secret:
            raise ConfigurationError("grant_secret is required for tests.")
        if not audit_checkpoint_secret:
            raise ConfigurationError("audit_checkpoint_secret is required for tests.")
        if membership_secret is None:
            membership_secret = DEFAULT_TEST_MEMBERSHIP_SECRET
        if not membership_secret:
            raise ConfigurationError("membership_secret is required for tests.")

        if oidc_issuer is None:
            oidc_issuer = cls.DEVELOPMENT_LOCAL_ISSUER
        if oidc_client_id is None:
            oidc_client_id = "test-client-id"
        if oidc_client_secret is None:
            oidc_client_secret = "test-client-secret-32-chars-long"

        # Settings-admin block: when enabled for tests, a token must be
        # supplied explicitly (there is no default admin token, matching the
        # no-fake-provider posture of the OIDC block).
        if enable_settings_admin and (not settings_admin_token or not settings_admin_token.strip()):
            raise ConfigurationError(
                "settings_admin_token is required when enable_settings_admin is true."
            )

        return cls(
            grant_secret=grant_secret,
            audit_checkpoint_secret=audit_checkpoint_secret,
            membership_secret=membership_secret,
            environment=environment,
            db_path=db_path,
            enable_demo_adapter_modes=enable_demo_adapter_modes,
            oidc_issuer=oidc_issuer,
            oidc_client_id=oidc_client_id,
            oidc_client_secret=oidc_client_secret,
            oidc_audience=oidc_audience,
            oidc_redirect_uri=oidc_redirect_uri,
            session_ttl_seconds=session_ttl_seconds,
            session_cookie_name="payoutproof_session",
            session_cookie_secure=session_cookie_secure,
            cors_allowed_origins=cors_allowed_origins,
            enable_settings_admin=enable_settings_admin,
            settings_admin_token=settings_admin_token,
            database_url=database_url,
        )
