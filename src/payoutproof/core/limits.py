"""Immutable platform ceilings and per-organization operating limits (Issue #10).

Two-tier limit model:

* ``PlatformCeilings`` are immutable source literals in this module. There is
  no ``from_env`` loader, no database representation, no admin write path, and
  no environment variable that can alter them. Changing a ceiling is a code
  change, peer-reviewed like any other. Nothing in ``AppConfig`` may hold or
  override a ceiling.
* ``TenantOperatingLimits`` are the per-organization operating settings,
  persisted as ``limits_json`` per organization, and validated against the
  ceilings at write time and defensively clamped at read time.

This module is pure standard library (no Pydantic, no FastAPI, no storage
imports) to prevent circular imports, mirroring ``core.config``.

Scope vocabulary: "tenant" is the issue's word for the enforcement scope of an
organization. Every limit, counter, and setting keys on ``organization_id`` —
the session-owned scope used by every existing enforcement seam.

Alignment invariants (pinned by tests, because ``admission.validator`` is
deliberately not edited by this issue):

* ``PLATFORM_SUPPORTED_FORMATS`` equals ``admission.validator.ALLOWED_MIME_TYPES``.
* ``PLATFORM_MAX_RETENTION_DAYS == 365`` equals the ``le=365`` bound on
  ``ProcessingAuthorityRecord.retention_days`` and the admission validator's
  retention check.
* ``PLATFORM_MAX_EVIDENCE_ITEM_BYTES`` is >= the admission validator's largest
  per-type cap (10 MB audio), so the API-layer gates are tighter-or-equal to
  the in-case admission validator. Anything the API admits but the validator
  refuses still produces the existing in-case ``ADMISSION_REJECTED`` mutation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Dict, FrozenSet, Mapping, Optional

# ── Immutable platform ceilings (the only place these values exist) ──────────

# Largest per-type admission cap today (admission/validator.py:18, 10 MB audio).
# The platform item ceiling is the outer bound; the per-type caps remain the
# admission-validator floor inside the state machine; a tenant value may only
# tighten both.
PLATFORM_MAX_EVIDENCE_ITEM_BYTES = 10 * 1024 * 1024

# Must equal the le=365 bound on ProcessingAuthorityRecord.retention_days and
# the admission validator's "Retention exceeds maximum bounded period" check.
PLATFORM_MAX_RETENTION_DAYS = 365

# Floor for tenant retention settings: retention is evidentiary duty, so a
# tenant may tighten the ceiling (shorter retention) but never set retention
# below one day (matches the validator's positive-days requirement, i.e. >= 1).
PLATFORM_MIN_RETENTION_DAYS = 1

# Cap for the derived processing-backlog gauge (admitted-but-unprocessed cases).
PLATFORM_MAX_PROCESSING_CONCURRENCY = 4

# Per-organization hourly request ceiling.
PLATFORM_MAX_REQUESTS_PER_HOUR = 10_000

# Platform-wide hourly backstop bucket. The organization scope is carried by
# a self-asserted header on the session-ephemeral test path, so per-organization
# quotas are enforceable against honest clients only; this global bucket bounds
# a client that multiplies fake organization identities. Real authentication
# is the durable fix.
PLATFORM_GLOBAL_REQUESTS_PER_HOUR = 1_000

# Pre-parse request-body ceiling (>= item ceiling + JSON-escape headroom).
PLATFORM_MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024

# Exactly mirrors admission.validator.ALLOWED_MIME_TYPES (7 formats).
PLATFORM_SUPPORTED_FORMATS: FrozenSet[str] = frozenset({
    "audio/wav",
    "audio/x-wav",
    "audio/mpeg",
    "audio/mp3",
    "audio/ogg",
    "text/plain",
    "application/json",
})

# Sentinel organization_id for the global platform backstop bucket, and the
# reserved window sentinel for monotonic cumulative counters. Both share the
# organization_id / window_key columns with caller-supplied values, so any
# caller-supplied scope beginning with "__" is rejected at the API seam.
PLATFORM_BACKSTOP_ORGANIZATION = "__PLATFORM__"
CUMULATIVE_WINDOW_KEY = "CUMULATIVE"
RESERVED_SCOPE_PREFIX = "__"

# Fixed UTC window duration (seconds) for hourly request quotas.
RATE_WINDOW_SECONDS = 3600


# ── Typed limit exceptions ──────────────────────────────────────────────────
#
# These carry exactly the fields the API layer needs to build the uniform
# error envelope — never raw exception text, SQL, or other organizations' data.


class QuotaExceededError(Exception):
    """A counted or gauged quota is exhausted (HTTP 429 QUOTA_EXCEEDED).

    ``quota_kind`` names the bound that fired ('requests' or
    'requests_global' for windowed kinds; 'max_open_cases',
    'max_org_evidence_bytes', or 'processing_backlog' for non-windowed ones).
    ``retry_after_seconds`` is None for non-windowed kinds: there is no window
    reset to wait for.
    """

    def __init__(self, quota_kind: str, retry_after_seconds: Optional[int] = None):
        self.quota_kind = quota_kind
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Quota exceeded: {quota_kind}")


class EvidenceTooLargeError(Exception):
    """One evidence item exceeds the effective per-item byte limit (HTTP 413)."""

    def __init__(self, max_bytes: int, actual_bytes: int):
        self.max_bytes = max_bytes
        self.actual_bytes = actual_bytes
        super().__init__(f"Evidence item exceeds effective limit: {actual_bytes} > {max_bytes} bytes")


class FormatNotSupportedError(Exception):
    """The submitted MIME type is outside the effective format allowlist (HTTP 415)."""

    def __init__(self, mime_type: str, allowed_formats):
        self.mime_type = mime_type
        self.allowed_formats = sorted(allowed_formats)
        super().__init__(f"Evidence format '{mime_type}' is not supported")


class RetentionExceedsTenantLimitError(Exception):
    """A Processing Authority Record declares retention beyond the tenant limit (HTTP 422)."""

    def __init__(self, declared_days: int, tenant_limit_days: int):
        self.declared_days = declared_days
        self.tenant_limit_days = tenant_limit_days
        super().__init__(f"Retention {declared_days} days exceeds tenant limit {tenant_limit_days} days")


class SettingsValidationError(Exception):
    """A tenant operating-settings write is malformed or above a ceiling (HTTP 422).

    ``reason_code`` is 'SETTINGS_ABOVE_CEILING' or 'SETTINGS_INVALID'; the
    rejection is audited in the same transaction that records it.
    """

    def __init__(self, reason_code: str, message: str):
        self.reason_code = reason_code
        self.message = message
        super().__init__(message)


# ── Tenant operating settings ───────────────────────────────────────────────


@dataclass(frozen=True)
class TenantOperatingLimits:
    """Per-organization operating settings, persisted as ``limits_json``.

    Deliberately a frozen stdlib dataclass (this module stays pure stdlib).
    All fields are optional so a partially-populated stored row still resolves
    to a complete, fail-closed effective value via ``effective_limits``.
    """

    max_evidence_item_bytes: Optional[int] = None
    allowed_evidence_formats: Optional[FrozenSet[str]] = None
    evidence_retention_days: Optional[int] = None
    max_processing_concurrency: Optional[int] = None
    requests_per_hour: Optional[int] = None
    max_open_cases: Optional[int] = None
    max_org_evidence_bytes: Optional[int] = None

    def to_json_dict(self) -> Dict[str, object]:
        """JSON-safe mapping (sorted format list; None fields stay None).

        Never used for enforcement — only for persistence and the settings
        read/write API surface.
        """
        return {
            "max_evidence_item_bytes": self.max_evidence_item_bytes,
            "allowed_evidence_formats": (
                sorted(self.allowed_evidence_formats)
                if self.allowed_evidence_formats is not None
                else None
            ),
            "evidence_retention_days": self.evidence_retention_days,
            "max_processing_concurrency": self.max_processing_concurrency,
            "requests_per_hour": self.requests_per_hour,
            "max_open_cases": self.max_open_cases,
            "max_org_evidence_bytes": self.max_org_evidence_bytes,
        }

    @classmethod
    def from_json_dict(cls, data: Optional[Mapping[str, object]]) -> "TenantOperatingLimits":
        """Rehydrate from a persisted ``limits_json`` mapping.

        Malformed input raises ValueError; callers treat that as a corrupt
        stored row and fall back to defaults fail-closed (a stored row can
        never widen a limit, and a corrupt row cannot break enforcement).
        """
        if not isinstance(data, Mapping):
            raise ValueError("limits_json must be a JSON object mapping")
        unknown = set(data.keys()) - {f.name for f in fields(cls)}
        if unknown:
            raise ValueError(f"Unknown tenant limit fields: {sorted(unknown)}")
        raw_formats = data.get("allowed_evidence_formats")
        if raw_formats is not None:
            if not isinstance(raw_formats, (list, tuple, set, frozenset)) or not all(
                isinstance(f, str) for f in raw_formats
            ):
                raise ValueError("allowed_evidence_formats must be a list of strings")
            return cls(
                max_evidence_item_bytes=_optional_int(data.get("max_evidence_item_bytes")),
                allowed_evidence_formats=frozenset(raw_formats),
                evidence_retention_days=_optional_int(data.get("evidence_retention_days")),
                max_processing_concurrency=_optional_int(data.get("max_processing_concurrency")),
                requests_per_hour=_optional_int(data.get("requests_per_hour")),
                max_open_cases=_optional_int(data.get("max_open_cases")),
                max_org_evidence_bytes=_optional_int(data.get("max_org_evidence_bytes")),
            )
        return cls(
            max_evidence_item_bytes=_optional_int(data.get("max_evidence_item_bytes")),
            allowed_evidence_formats=None,
            evidence_retention_days=_optional_int(data.get("evidence_retention_days")),
            max_processing_concurrency=_optional_int(data.get("max_processing_concurrency")),
            requests_per_hour=_optional_int(data.get("requests_per_hour")),
            max_open_cases=_optional_int(data.get("max_open_cases")),
            max_org_evidence_bytes=_optional_int(data.get("max_org_evidence_bytes")),
        )


def _optional_int(value) -> Optional[int]:
    """Coerce a stored value to int or None; reject bools and non-integers."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("Tenant limit values must be integers or null")
    return value


# Fail-closed defaults for organizations with no stored settings row.
# Conservative but generous enough that the development evaluation suites and
# the existing API test corpus run unthrottled: item bytes and formats at the
# platform ceilings, retention at the platform max, hourly requests and
# open-case count far above any single test's usage, and a cumulative-evidence
# byte budget of 10 GB. A too-tight default here would silently regress the
# baseline (pinned by the full-suite regression gate).
DEFAULT_TENANT_LIMITS = TenantOperatingLimits(
    max_evidence_item_bytes=PLATFORM_MAX_EVIDENCE_ITEM_BYTES,
    allowed_evidence_formats=PLATFORM_SUPPORTED_FORMATS,
    evidence_retention_days=PLATFORM_MAX_RETENTION_DAYS,
    max_processing_concurrency=PLATFORM_MAX_PROCESSING_CONCURRENCY,
    requests_per_hour=PLATFORM_MAX_REQUESTS_PER_HOUR,
    max_open_cases=1000,
    max_org_evidence_bytes=10 * 1024 * 1024 * 1024,
)


def effective_limits(tenant_limits: Optional[TenantOperatingLimits]) -> TenantOperatingLimits:
    """Read-time defensive clamp of stored tenant limits against the ceilings.

    Computed fresh at every enforcement point. Even a tampered
    ``tenant_operating_limits`` row can never *enlarge* a limit:

    * every numeric field is ``min(tenant_value, ceiling)`` (bounded below by
      its floor, 1);
    * formats are the set intersection with ``PLATFORM_SUPPORTED_FORMATS``;
    * retention is clamped into [floor, ceiling].

    A ``None`` field (stored row written before the field existed, or the
    default row) resolves to the fail-closed default for that field.
    """
    stored = tenant_limits if tenant_limits is not None else DEFAULT_TENANT_LIMITS
    defaults = DEFAULT_TENANT_LIMITS

    def clamp_int(value: Optional[int], ceiling: int) -> int:
        resolved = value if value is not None else ceiling
        # min first, then floor: a tampered zero/negative value degrades to the
        # floor (1), never to an unusable 0 and never above the ceiling.
        return max(1, min(resolved, ceiling))

    formats = stored.allowed_evidence_formats
    if formats is None:
        resolved_formats = defaults.allowed_evidence_formats
    else:
        resolved_formats = frozenset(formats) & PLATFORM_SUPPORTED_FORMATS
        if not resolved_formats:
            # An empty intersection (tampered or over-restrictive row) would
            # make every admission fail; degrade to the platform allowlist,
            # which is the widest honest value, still fail-closed against
            # unsupported formats.
            resolved_formats = PLATFORM_SUPPORTED_FORMATS

    return TenantOperatingLimits(
        max_evidence_item_bytes=clamp_int(
            stored.max_evidence_item_bytes, PLATFORM_MAX_EVIDENCE_ITEM_BYTES
        ),
        allowed_evidence_formats=resolved_formats,
        evidence_retention_days=max(
            PLATFORM_MIN_RETENTION_DAYS,
            min(
                stored.evidence_retention_days
                if stored.evidence_retention_days is not None
                else PLATFORM_MAX_RETENTION_DAYS,
                PLATFORM_MAX_RETENTION_DAYS,
            ),
        ),
        max_processing_concurrency=clamp_int(
            stored.max_processing_concurrency, PLATFORM_MAX_PROCESSING_CONCURRENCY
        ),
        requests_per_hour=clamp_int(stored.requests_per_hour, PLATFORM_MAX_REQUESTS_PER_HOUR),
        max_open_cases=clamp_int(stored.max_open_cases, PLATFORM_MAX_REQUESTS_PER_HOUR),
        max_org_evidence_bytes=clamp_int(
            stored.max_org_evidence_bytes,
            # No platform ceiling literal exists for the cumulative byte
            # budget; the platform-wide bound is the default row's 10 GB so a
            # tampered row can never exceed the default budget.
            DEFAULT_TENANT_LIMITS.max_org_evidence_bytes or 1,
        ),
    )


def validate_settings_write(candidate: Mapping[str, object]) -> TenantOperatingLimits:
    """Validate a full-replace tenant settings write against the ceilings.

    Returns the validated ``TenantOperatingLimits``, or raises
    ``SettingsValidationError`` with reason 'SETTINGS_ABOVE_CEILING' (value
    above its ceiling / below its floor / wrong type) or 'SETTINGS_INVALID'
    (unknown fields, malformed structure). Out-of-bounds values are rejected,
    never silently clamped — a tenant must know its settings were refused.
    """
    if not isinstance(candidate, Mapping):
        raise SettingsValidationError("SETTINGS_INVALID", "Request body must be a JSON object")
    known = {f.name for f in fields(TenantOperatingLimits)}
    unknown = set(candidate.keys()) - known
    if unknown:
        raise SettingsValidationError(
            "SETTINGS_INVALID", f"Unknown tenant limit fields: {sorted(unknown)}"
        )

    def require_int(name: str, ceiling: int, floor: int = 1) -> Optional[int]:
        raw = candidate.get(name)
        if raw is None:
            return None
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise SettingsValidationError(
                "SETTINGS_INVALID", f"Field '{name}' must be an integer or null"
            )
        if raw < floor or raw > ceiling:
            raise SettingsValidationError(
                "SETTINGS_ABOVE_CEILING",
                f"Field '{name}' value {raw} is outside the permitted range [{floor}, {ceiling}]",
            )
        return raw

    raw_formats = candidate.get("allowed_evidence_formats")
    if raw_formats is None:
        validated_formats: Optional[FrozenSet[str]] = None
    else:
        if not isinstance(raw_formats, (list, tuple, set, frozenset)) or not all(
            isinstance(f, str) and f.strip() for f in raw_formats
        ):
            raise SettingsValidationError(
                "SETTINGS_INVALID",
                "Field 'allowed_evidence_formats' must be a list of non-empty format strings",
            )
        format_set = frozenset(f.strip().lower() for f in raw_formats)
        unsupported = format_set - PLATFORM_SUPPORTED_FORMATS
        if unsupported:
            raise SettingsValidationError(
                "SETTINGS_ABOVE_CEILING",
                f"Field 'allowed_evidence_formats' contains formats outside the platform "
                f"allowlist: {sorted(unsupported)}",
            )
        if not format_set:
            raise SettingsValidationError(
                "SETTINGS_INVALID", "Field 'allowed_evidence_formats' must not be empty"
            )
        validated_formats = format_set

    retention = require_int(
        "evidence_retention_days", PLATFORM_MAX_RETENTION_DAYS, PLATFORM_MIN_RETENTION_DAYS
    )

    return TenantOperatingLimits(
        max_evidence_item_bytes=require_int(
            "max_evidence_item_bytes", PLATFORM_MAX_EVIDENCE_ITEM_BYTES
        ),
        allowed_evidence_formats=validated_formats,
        evidence_retention_days=retention,
        max_processing_concurrency=require_int(
            "max_processing_concurrency", PLATFORM_MAX_PROCESSING_CONCURRENCY
        ),
        requests_per_hour=require_int("requests_per_hour", PLATFORM_MAX_REQUESTS_PER_HOUR),
        max_open_cases=require_int("max_open_cases", PLATFORM_MAX_REQUESTS_PER_HOUR),
        max_org_evidence_bytes=require_int(
            "max_org_evidence_bytes", DEFAULT_TENANT_LIMITS.max_org_evidence_bytes or 1
        ),
    )


# ── Fixed UTC windows ────────────────────────────────────────────────────────


def window_key(now_utc: datetime, duration_seconds: int = RATE_WINDOW_SECONDS) -> str:
    """Derive the fixed UTC window key for a timestamp (never local time).

    Hourly windows truncate to the whole UTC hour, e.g. 2026-09-04T13:59:07Z
    and 2026-09-04T13:00:00Z both map to "2026-09-04T13". Purely derived from
    UTC, so there is no DST dependence and no per-process clock skew class
    beyond the injected clock's own accuracy.
    """
    if now_utc.tzinfo is None:
        raise ValueError("window_key requires a timezone-aware UTC datetime")
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be positive")
    if duration_seconds == RATE_WINDOW_SECONDS:
        return now_utc.strftime("%Y-%m-%dT%H")
    # General fallback for non-hourly durations: epoch bucketing, still fixed
    # and UTC-derived (DST-proof).
    epoch = int(now_utc.timestamp())
    bucket = epoch - (epoch % duration_seconds)
    return f"W{bucket}"


def retry_after_seconds(now_utc: datetime, duration_seconds: int = RATE_WINDOW_SECONDS) -> int:
    """Seconds until the current fixed window resets (always >= 1).

    The Retry-After value derives from the window reset, which is the caller's
    own clock data — no internal timing detail leaks through it.
    """
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be positive")
    epoch = int(now_utc.timestamp())
    elapsed_in_window = epoch % duration_seconds
    remaining = duration_seconds - elapsed_in_window
    # ceil to at least 1: at the exact boundary the next window has already
    # started and the honest answer is "wait the full next window".
    return max(1, math.ceil(remaining))


def normalized_mime_type(mime_type) -> Optional[str]:
    """Normalize a client-supplied MIME type the way the admission validator does."""
    if not isinstance(mime_type, str):
        return None
    stripped = mime_type.strip().lower()
    return stripped or None


def content_byte_size(content) -> Optional[int]:
    """Compute the byte size of a submitted evidence payload, never trusting a declared size.

    Mirrors the admission validator's type handling: str encodes as UTF-8,
    bytes/bytearray measure directly; every other type (including None) has
    no computable size and returns None (the case-level admission validator
    remains the authority for those malformed payloads).
    """
    if isinstance(content, str):
        return len(content.encode("utf-8"))
    if isinstance(content, (bytes, bytearray)):
        return len(content)
    return None
