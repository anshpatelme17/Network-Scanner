"""Controlled polling policy for configured connectors (Phase 2, Step 5).

This module adds *policy* around the existing Step 26–28 machinery; it does
not re-implement it. ``ingestion.poll_source`` remains the single bounded,
audited path that fetches, normalizes, deduplicates, correlates, stores and
audits. Nothing here touches a socket, a thread, a timer or a scheduler.

What this layer adds on top of the existing manual poll:

* **Overlap prevention.** A poll for a connector that is already running is
  refused (``PollInProgress``) rather than run concurrently, so two polls
  cannot interleave writes to the same checkpoint.
* **A failure cool-down.** After a failed poll the connector is not polled
  again until ``connector_failure_cooldown_seconds`` has elapsed, so an
  unreachable or mis-authenticating source is not hammered. When the
  upstream server supplied a ``Retry-After`` (or the connector is in
  ``RATE_LIMITED``), the longer of that and the configured cool-down is
  used.
* **A due-poll pass.** ``run_due_polls`` polls only connectors whose
  interval has elapsed, and only when ``connector_auto_poll_enabled`` is
  true. It is **disabled by default** and is never scheduled: calling it is
  an operator/invoker decision, exactly like the manual endpoint. No
  background thread, timer or daemon exists anywhere in this module.
* **Honest health metadata.** ``PollHealth`` records what happened, for
  presentation only. It contains no credential, token or secret of any
  kind, and it is never written to an audit row.

``NOT_CONFIGURED`` connectors are never polled: the due-poll pass skips
them, and :func:`poll_connector` refuses them before any network call.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.core.config import get_settings
from app.services import connectors
from app.services.ingestion import IngestionFailedError, poll_source

STATE_NOT_CONFIGURED = connectors.STATE_NOT_CONFIGURED
STATE_RATE_LIMITED = connectors.STATE_RATE_LIMITED


class PollInProgress(RuntimeError):
    """A poll for this connector is already running; this one was refused."""


class PollCooldown(RuntimeError):
    """Too soon after the last failure; this poll was refused.

    ``retry_after_seconds`` is operator-facing and always safe to show: it
    is a duration computed from settings and, when the upstream server
    supplied one, from that server's own ``Retry-After`` header.
    """

    def __init__(self, source: str, retry_after_seconds: float) -> None:
        super().__init__(
            f"{source}: a poll was attempted before the cool-down elapsed "
            f"({int(retry_after_seconds)}s remaining)."
        )
        self.source = source
        self.retry_after_seconds = retry_after_seconds


@dataclass
class PollHealth:
    """Safe, secret-free record of the last poll for one connector."""

    source: str
    last_poll_started_at: str | None = None
    last_poll_completed_at: str | None = None
    last_successful_poll_at: str | None = None
    last_error_category: str | None = None
    events_received: int = 0
    events_accepted: int = 0
    events_deduplicated: int = 0
    next_permitted_poll_at: str | None = None
    in_flight: bool = False
    polls: int = 0
    failures: int = 0

    def as_dict(self) -> dict[str, object]:
        """Presentation payload. Contains no secrets by construction."""
        return {
            "last_poll_started_at": self.last_poll_started_at,
            "last_poll_completed_at": self.last_poll_completed_at,
            "last_successful_poll_at": self.last_successful_poll_at,
            "last_error_category": self.last_error_category,
            "events_received": self.events_received,
            "events_accepted": self.events_accepted,
            "events_deduplicated": self.events_deduplicated,
            "next_permitted_poll_at": self.next_permitted_poll_at,
            "in_flight": self.in_flight,
            "polls": self.polls,
            "failures": self.failures,
        }


# Per-process polling state. No network I/O and no persistence here.
_health: dict[str, PollHealth] = {}
_locks: dict[str, threading.Lock] = {}
_registry_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(moment: datetime) -> str:
    return moment.isoformat()


def _lock_for(source: str) -> threading.Lock:
    with _registry_lock:
        lock = _locks.get(source)
        if lock is None:
            lock = threading.Lock()
            _locks[source] = lock
        return lock


def health_for(source: str) -> PollHealth:
    """Health for one connector, without creating network activity."""
    with _registry_lock:
        current = _health.get(source)
        if current is None:
            current = PollHealth(source=source)
            _health[source] = current
        return current


def reset() -> None:
    """Test helper: forget every poll outcome and release the locks."""
    with _registry_lock:
        _health.clear()
        _locks.clear()


def _cooldown_seconds(category: str | None, retry_after: float | None) -> float:
    """How long to wait before retrying this connector."""
    settings = get_settings()
    cooldown = float(settings.connector_failure_cooldown_seconds)
    if retry_after is not None and retry_after > 0:
        cooldown = max(cooldown, float(retry_after))
    if category == STATE_RATE_LIMITED:
        # Being throttled is not a transient blip; wait longer by default.
        cooldown = max(cooldown, float(settings.connector_failure_cooldown_seconds) * 5)
    return cooldown


def _category_for(exc: BaseException, source: str | None = None) -> str:
    """Map a poll failure onto a stable, secret-free category label.

    When the connector layer has already recorded a precise state for this
    source (it classifies every fetch as AUTH_FAILED / RATE_LIMITED /
    UNAVAILABLE / ERROR), that state is the authoritative label — it is
    more precise than anything re-derived from the exception type.
    """
    name = type(exc).__name__
    if isinstance(exc, connectors.ConnectorUnavailableError):
        if source is not None:
            try:
                recorded = connectors.health(source).connector_state
            except Exception:  # noqa: BLE001 - health must never mask the failure
                recorded = None
            if isinstance(recorded, str) and recorded and recorded != STATE_NOT_CONFIGURED:
                return recorded
        return "UNAVAILABLE"
    if isinstance(exc, IngestionFailedError):
        return "INGESTION_FAILED"
    if isinstance(exc, KeyError | ValueError):
        return "INVALID_CONFIGURATION"
    return name.upper()


def _retry_after_from(exc: BaseException) -> float | None:
    """Server-supplied Retry-After, when the connector surfaced one."""
    for attribute in ("retry_after", "retry_after_seconds"):
        value = getattr(exc, attribute, None)
        if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
            return float(value)
    return None


def is_due(source: str, *, now: datetime | None = None) -> bool:
    """Whether this connector may be polled again right now."""
    moment = now or _now()
    health = health_for(source)
    permitted = health.next_permitted_poll_at
    if permitted is None:
        return True
    try:
        return moment >= datetime.fromisoformat(permitted)
    except ValueError:  # pragma: no cover - defensive
        return True


def poll_connector(
    db,
    source: str,
    actor: str,
    *,
    replay: bool = False,
    respect_cooldown: bool = False,
) -> dict[str, object]:
    """Run one controlled, bounded, audited poll for ``source``.

    Refuses, without touching the network, when the connector is
    ``NOT_CONFIGURED`` and never runs two polls for one source at once.

    ``respect_cooldown`` defaults to **False** so that a manual
    "Poll Now" always does what the operator asked, including the
    idempotent repeat poll the existing tests rely on. Frequency control
    for a manual caller comes from the endpoint's existing
    ``rate_limit("connector_poll", ...)`` budget; the interval and failure
    cool-down are enforced by :func:`run_due_polls` / :func:`is_due`, which
    is the automated path. Pass ``respect_cooldown=True`` to opt in.
    """
    if source not in connectors.SOURCES:
        raise KeyError(f"Unknown connector source: {source!r}.")

    # NOTE: there is deliberately no early "NOT_CONFIGURED" refusal here.
    # `ingestion.poll_source` already refuses an unconfigured connector
    # *before any fetch*, so no network call happens either way — and going
    # through it preserves the Step 28 guarantee that a failed poll leaves the
    # checkpoint unmoved **and explicitly rejected and audited**. An early
    # raise here would silently lose that evidence.

    health = health_for(source)
    if respect_cooldown:
        permitted = health.next_permitted_poll_at
        if permitted is not None:
            try:
                remaining = (datetime.fromisoformat(permitted) - _now()).total_seconds()
            except ValueError:  # pragma: no cover - defensive
                remaining = 0.0
            if remaining > 0:
                raise PollCooldown(source, remaining)

    lock = _lock_for(source)
    if not lock.acquire(blocking=False):
        raise PollInProgress(f"{source}: a poll is already in progress.")
    try:
        health.in_flight = True
        health.last_poll_started_at = _iso(_now())
        health.polls += 1
        result = poll_source(db, source, actor, replay=replay)
        health.last_poll_completed_at = _iso(_now())
        health.last_successful_poll_at = health.last_poll_completed_at
        health.last_error_category = None
        health.events_received = int(result.get("retrieved", 0) or 0)
        health.events_accepted = int(result.get("accepted", 0) or 0)
        health.events_deduplicated = int(result.get("duplicates", 0) or 0)
        health.next_permitted_poll_at = _iso(
            _now() + timedelta(seconds=float(get_settings().connector_poll_interval_seconds))
        )
        return result
    except BaseException as exc:
        category = _category_for(exc, source)
        health.last_poll_completed_at = _iso(_now())
        health.last_error_category = category
        health.failures += 1
        cooldown = _cooldown_seconds(category, _retry_after_from(exc))
        health.next_permitted_poll_at = (
            _iso(_now() + timedelta(seconds=cooldown)) if cooldown > 0 else None
        )
        raise
    finally:
        health.in_flight = False
        lock.release()


def run_due_polls(db, actor: str, *, now: datetime | None = None) -> dict[str, object]:
    """Poll every connector that is due — **only if explicitly enabled**.

    Returns a summary and performs no network I/O when
    ``connector_auto_poll_enabled`` is false, which is the default. This
    function does not schedule itself; a caller (an operator-invoked
    endpoint, a CLI run, or a future, deliberately configured scheduler)
    decides when it runs.
    """
    settings = get_settings()
    summary: dict[str, object] = {
        "enabled": bool(settings.connector_auto_poll_enabled),
        "interval_seconds": float(settings.connector_poll_interval_seconds),
        "polled": [],
        "skipped_not_configured": [],
        "skipped_not_due": [],
        "failed": [],
    }
    if not settings.connector_auto_poll_enabled:
        summary["detail"] = (
            "Automatic polling is disabled (CONNECTOR_AUTO_POLL_ENABLED=false); "
            "nothing was polled. Use the manual poll endpoint."
        )
        return summary

    moment = now or _now()
    for source in connectors.SOURCES:
        status = connectors.health(source)
        if status.connector_state == STATE_NOT_CONFIGURED:
            summary["skipped_not_configured"].append(source)  # type: ignore[union-attr]
            continue
        if not is_due(source, now=moment):
            summary["skipped_not_due"].append(source)  # type: ignore[union-attr]
            continue
        try:
            result = poll_connector(db, source, actor)
            summary["polled"].append(  # type: ignore[union-attr]
                {
                    "source": source,
                    "retrieved": int(result.get("retrieved", 0) or 0),
                    "accepted": int(result.get("accepted", 0) or 0),
                    "termination": result.get("termination"),
                }
            )
        except PollInProgress:
            summary["skipped_not_due"].append(  # type: ignore[union-attr]
                f"{source}:already_running"
            )
        except PollCooldown as exc:
            summary["skipped_not_due"].append(  # type: ignore[union-attr]
                f"{source}:cooldown_{int(exc.retry_after_seconds)}s"
            )
        except BaseException as exc:  # noqa: BLE001 - one bad source must not stop the pass
            summary["failed"].append(  # type: ignore[union-attr]
                {"source": source, "category": _category_for(exc, source)}
            )
    return summary


__all__ = [
    "PollCooldown",
    "PollHealth",
    "PollInProgress",
    "health_for",
    "is_due",
    "poll_connector",
    "reset",
    "run_due_polls",
]
