"""Per-principal, per-tool token buckets."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from rawmcp.policy import RateLimit


@dataclass
class _Bucket:
    tokens: float
    updated: float


@dataclass(frozen=True)
class RateDecision:
    """Outcome of one rate-limit check."""

    allowed: bool
    retry_after_s: float = 0.0


class RateLimiter:
    """Token buckets keyed by ``(principal, tool)``.

    A bucket holds up to ``calls`` tokens and refills continuously at ``calls / period_s``
    tokens per second, so ``10/minute`` allows a burst of 10 and then one call every 6 s.
    The clock is injectable so tests do not sleep.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._buckets: dict[tuple[str, str, RateLimit], _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, principal: str, tool: str, limit: RateLimit | None) -> RateDecision:
        """Consume one token if available."""
        if limit is None:
            return RateDecision(True)
        rate = limit.calls / limit.period_s
        now = self._clock()
        key = (principal, tool, limit)
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = self._buckets[key] = _Bucket(float(limit.calls), now)
            bucket.tokens = min(float(limit.calls), bucket.tokens + (now - bucket.updated) * rate)
            bucket.updated = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return RateDecision(True)
            return RateDecision(False, retry_after_s=(1.0 - bucket.tokens) / rate)
