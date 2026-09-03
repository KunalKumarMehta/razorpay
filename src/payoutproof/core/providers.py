"""Clock and Nonce provider protocols and implementations for PayoutProof."""

from datetime import datetime, timezone, timedelta
import secrets
from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class ClockProvider(Protocol):
    """Protocol for time providers."""

    def now(self) -> datetime:
        """Return current datetime (timezone-aware UTC)."""
        ...

    def now_iso(self) -> str:
        """Return ISO-8601 formatted string of current datetime."""
        ...


@runtime_checkable
class NonceProvider(Protocol):
    """Protocol for nonce providers."""

    def generate_nonce(self, length: int = 16) -> str:
        """Generate a random or sequential nonce."""
        ...


class SystemClock:
    """Secure system clock implementation using standard UTC time."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def now_iso(self) -> str:
        return self.now().isoformat()


class SystemNonce:
    """Cryptographically secure nonce provider using secrets."""

    def generate_nonce(self, length: int = 16) -> str:
        return secrets.token_hex(length)


class FixedClock:
    """Deterministic fixed clock for reproducible execution and tests."""

    def __init__(self, fixed_time: Optional[datetime | str] = None) -> None:
        if fixed_time is None:
            self._time = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)
        elif isinstance(fixed_time, str):
            dt = datetime.fromisoformat(fixed_time)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            self._time = dt
        else:
            dt = fixed_time
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            self._time = dt

    def now(self) -> datetime:
        return self._time

    def now_iso(self) -> str:
        return self._time.isoformat()

    def set_time(self, new_time: datetime | str) -> None:
        if isinstance(new_time, str):
            dt = datetime.fromisoformat(new_time)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            self._time = dt
        else:
            dt = new_time
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            self._time = dt

    def advance(self, seconds: float = 1.0) -> None:
        self._time = self._time + timedelta(seconds=seconds)


class SequentialNonce:
    """Deterministic sequential nonce provider for tests."""

    def __init__(self, start: int = 1, prefix: str = "") -> None:
        self.counter = start
        self.prefix = prefix

    def generate_nonce(self, length: int = 16) -> str:
        target_len = length * 2
        val = f"{self.prefix}{self.counter:08x}".ljust(target_len, "0")[:target_len]
        self.counter += 1
        return val
