"""Deterministic fixed-window rate limiting (Step 31).

A small, in-process limiter for the operations that can consume
significant resources: correlation recompute, incident recalculation, risk
calculation, connector polling, controlled response governance writes and
scan starts.

Design constraints, chosen deliberately:

* **Deterministic.** A fixed window with an integer counter. No token
  bucket smoothing, no jitter, no randomness, so a given sequence of
  requests always produces the same verdicts and the behaviour is
  testable.
* **Bounded memory.** At most ``RATE_LIMIT_MAX_BUCKETS`` (window, key)
  pairs are remembered. When the ceiling is reached the least recently
  used bucket is evicted rather than growing without limit, so the
  limiter's own footprint is a fixed ceiling and cannot itself be used to
  exhaust memory.
* **No background work.** No threads, no timers, no scheduler, no
  external calls. Expiry is lazy: a stale window is simply overwritten
  when it is next seen.
* **In-process only.** This protects a single instance. A multi-replica
  deployment would need a shared store; that is documented as a known
  limitation rather than silently approximated here.
* **Configurable ceilings, never client input.** Every limit comes from
  ``Settings``; a caller cannot raise its own budget, and a limit of 0
  means "disabled" for that operation.

Callers are identified by the authenticated username when a token is
present, otherwise by the client host. That is a fairness heuristic, not
an authentication control: authorization remains server-side and
unchanged.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from app.core.config import Settings
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class _Bucket:
    window_start: float
    count: int


class RateLimitExceeded(Exception):
    """Raised when a caller exceeds the configured budget for an operation.

    Carries no caller-supplied data. The endpoint maps this to 429 with
    the standard error envelope.
    """

    def __init__(self, operation: str, limit: int, retry_after: int) -> None:
        super().__init__(f"Rate limit exceeded for {operation}.")
        self.operation = operation
        self.limit = limit
        self.retry_after = retry_after


class FixedWindowRateLimiter:
    """Thread-safe fixed-window counter with a bounded number of buckets."""

    def __init__(self, max_buckets: int = 10_000) -> None:
        self._buckets: OrderedDict[tuple[float, str], _Bucket] = OrderedDict()
        self._max_buckets = max(1, int(max_buckets))
        self._lock = threading.Lock()

    def reset(self) -> None:
        """Test helper: forget every window."""
        with self._lock:
            self._buckets.clear()

    def check(self, operation: str, key: str, limit: int, window_seconds: int) -> None:
        """Count one call, or raise :class:`RateLimitExceeded`.

        ``limit <= 0`` disables the check for that operation.
        """
        if limit <= 0:
            return
        if window_seconds <= 0:
            window_seconds = 1
        now = time.monotonic()
        window = int(now // window_seconds)
        bucket_key = (float(window), f"{operation}:{key}")
        with self._lock:
            bucket = self._buckets.get(bucket_key)
            if bucket is None or bucket.window_start != window:
                # A new window replaces this caller's previous bucket
                # rather than resetting the store, so many callers can
                # share one window without evicting each other.
                self._buckets[bucket_key] = _Bucket(window_start=window, count=1)
                self._buckets.move_to_end(bucket_key)
                self._evict_if_needed()
                return
            bucket.count += 1
            self._buckets.move_to_end(bucket_key)
            if bucket.count > limit:
                exceeded = bucket.count
            else:
                exceeded = 0
        if exceeded:
            retry_after = max(1, int(window_seconds - (now % window_seconds)))
            logger.warning("rate limit exceeded operation=%s limit=%d", operation, limit)
            raise RateLimitExceeded(operation, limit, retry_after)

    def _evict_if_needed(self) -> None:
        while len(self._buckets) > self._max_buckets:
            self._buckets.popitem(last=False)


_limiter = FixedWindowRateLimiter()


def get_limiter(request=None) -> FixedWindowRateLimiter:  # noqa: ANN001
    """Return the limiter for this application instance.

    The limiter lives on ``app.state`` rather than in a module global so
    that one process cannot accidentally share budgets between two
    independent applications (a real deployment has exactly one app, so
    the semantics are unchanged) and so an application can be created with
    a clean budget.
    """
    if request is not None:
        app = getattr(request, "app", None)
        state = getattr(app, "state", None)
        if state is not None and getattr(state, "limiter", None) is not None:
            return state.limiter
    return _limiter


def _caller_key(request) -> str:  # noqa: ANN001
    """Identify the caller for budgeting: username when known, else host."""
    auth_context = getattr(request.state, "auth", None)
    username = getattr(auth_context, "username", None)
    if username:
        return f"user:{username}"
    client = getattr(request, "client", None)
    host = getattr(client, "host", None) if client else None
    return f"host:{host or 'unknown'}"


def enforce_rate_limit(request, operation: str, limit: int) -> None:  # noqa: ANN001
    """Apply the configured window budget for ``operation``.

    Raises :class:`RateLimitExceeded` when the caller is over budget.
    """
    settings: Settings = request.app.state.settings
    get_limiter(request).check(
        operation=operation,
        key=_caller_key(request),
        limit=limit,
        window_seconds=settings.rate_limit_window_seconds,
    )


__all__ = [
    "FixedWindowRateLimiter",
    "RateLimitExceeded",
    "enforce_rate_limit",
    "get_limiter",
]
