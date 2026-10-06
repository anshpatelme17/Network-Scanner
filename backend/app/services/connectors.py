"""Live event-connector foundation (Steps 26–28).

Each source has a consistent lifecycle — configure (environment only)
→ validate_config → health → check → fetch (bounded) → normalize →
deduplicate → persist → audit — implemented against the Step 23
adapter registry and ingest pipeline. File sources read one
operator-configured local file; API sources (Wazuh, Microsoft Defender)
perform *controlled* outbound HTTP only through the shared Step 27
client layer (destination allow-list, timeouts, bounded bodies, no
redirects, safe GET-only retries, secret redaction). This module never
opens a network connection itself: it orchestrates, audits, and reports
truth. No step performs subprocess execution or shell commands.

Truthfulness contract (server-evaluated on every call; runtime health is
per-process and documented to reset on restart):

- Step 26 ``mode``/``state`` vocabulary is preserved verbatim:
  file sources: path unconfigured → FIXTURE / UNAVAILABLE; configured
  but unreadable → LIVE / UNAVAILABLE; readable → LIVE / CONNECTED.
  API sources: nothing configured → LIVE / UNAVAILABLE; partial or
  malformed config → LIVE / INVALID_CONFIGURATION; complete config →
  LIVE / UNAVAILABLE with an explicit not-attempted reason until a
  check or poll actually verifies it.
- Step 27 ``connector_state`` is the richer live vocabulary:
  NOT_CONFIGURED, CONFIGURED, CONNECTING, CONNECTED, AUTH_FAILED,
  UNAVAILABLE, RATE_LIMITED, ERROR. Configuration problems report
  NOT_CONFIGURED (nothing/only part set) or ERROR (complete but
  malformed); runtime results come from the last check/poll only —
  CONNECTED is never claimed without a verified response.
- ``GET`` status reads never perform network I/O: they report the
  cached runtime registry. Only ``POST .../check`` and ``POST
  .../poll`` contact an endpoint, and both are RBAC-gated
  (``MANAGE_EVENTS``) and audited.

Step 28 additions (all bounded and operator-initiated):

- Fetch retry: a poll retries a *transient* fetch failure (timeout /
  connection error) at most ``ingestion_retry_max`` extra times with
  linear backoff, each attempt audited ``INGESTION_RETRY``.
  Authentication, configuration, and HTTP-status failures are never
  retried at this level (the shared client already bounds its own safe
  GET retries).
- File identity: every file poll stats the configured path and compares
  it with the stored checkpoint cursor (rotation / truncation / invalid
  offset / missing), auditing ``INGESTION_ROTATION_DETECTED`` and
  restarting the bounded read at offset 0. Reads resume at the stored
  offset only when ``connector_file_resume`` is enabled (default off,
  preserving the Step 26/27 idempotent full-window replay).
- Processor hook: ``poll_*`` accept a ``processor`` callable so the
  Step 28 pipeline (bounded queue + batches + checkpoint) can wrap the
  shared normalization/dedup/store step without a second event model.

Secrets appear only as presence booleans in status responses and never
in audit details, error messages, or state names. File polls read at
most ``MAX_POLL_LINES`` lines; API polls are bounded by
``connector_max_pages``/``connector_max_events`` with an explicit
termination reason; unknown adapter keys raise ``KeyError`` via the
registry.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.services import (
    checkpoints,
    defender_client,
    event_adapters,
    event_service,
    ingestion_audits,
    log_file_reader,
    wazuh_client,
)
from app.services.http_connector import ConnectorHttpError, HttpErrorCategory

SOURCES = ("suricata", "zeek", "wazuh", "defender")
FILE_SOURCES = ("suricata", "zeek")
API_SOURCES = ("wazuh", "defender")

MODE_FIXTURE = "FIXTURE"
MODE_LIVE = "LIVE"

STATE_CONNECTED = "CONNECTED"
STATE_UNAVAILABLE = "UNAVAILABLE"
STATE_INVALID_CONFIGURATION = "INVALID_CONFIGURATION"

# Step 27 live connector vocabulary (reported as ``connector_state``).
STATE_NOT_CONFIGURED = "NOT_CONFIGURED"
STATE_CONFIGURED = "CONFIGURED"
STATE_CONNECTING = "CONNECTING"
STATE_AUTH_FAILED = "AUTH_FAILED"
STATE_RATE_LIMITED = "RATE_LIMITED"
STATE_ERROR = "ERROR"

CONNECTOR_STATES = (
    STATE_NOT_CONFIGURED,
    STATE_CONFIGURED,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_AUTH_FAILED,
    STATE_UNAVAILABLE,
    STATE_RATE_LIMITED,
    STATE_ERROR,
)

MAX_POLL_LINES = 100

# Audit actions for connector operations (all <= 32 chars for the
# event_audits.action column). Never carries secret values.
AUDIT_CHECK_STARTED = "CONNECTOR_CHECK_STARTED"
AUDIT_CONNECTED = "CONNECTOR_CONNECTED"
AUDIT_AUTH_FAILED = "CONNECTOR_AUTH_FAILED"
AUDIT_UNAVAILABLE = "CONNECTOR_UNAVAILABLE"
AUDIT_RATE_LIMITED = "CONNECTOR_RATE_LIMITED"
AUDIT_ERROR = "CONNECTOR_ERROR"
AUDIT_POLL_STARTED = "CONNECTOR_POLL_STARTED"
AUDIT_POLL_COMPLETED = "CONNECTOR_POLL_COMPLETED"
AUDIT_POLL_FAILED = "CONNECTOR_POLL_FAILED"

# Step 28: shared ingestion vocabulary (retry + file-identity change are
# fetch-level facts owned by this module; see ingestion_audits.py).
AUDIT_INGESTION_RETRY = ingestion_audits.AUDIT_INGESTION_RETRY
AUDIT_ROTATION_DETECTED = ingestion_audits.AUDIT_INGESTION_ROTATION_DETECTED

# Transient fetch failures that may be retried (bounded) by a poll.
TRANSIENT_CATEGORIES = frozenset({HttpErrorCategory.TIMEOUT, HttpErrorCategory.CONNECTION_ERROR})

# Optional Step 28 hook: given the parsed records of one poll, return
# (accepted, duplicates, rejected). ``errors`` is the shared per-record
# error list that both paths append to. The default path (None) stores
# records directly through the Step 23 pipeline.
IngestProcessor = Callable[
    [list[tuple[int, object]], list[dict[str, object]]], tuple[int, int, int]
]

# Ephemeral per-process stamp of the last poll that ingested anything,
# keyed by source. Lost on restart by design (recomputed live); the
# durable evidence is the ingested events and audit rows themselves.
_last_success: dict[str, str] = {}

# Step 28: how many fetch attempts the last bounded API fetch used
# (1 = first try succeeded). Per-process, reset with the registry.
_fetch_attempts: dict[str, int] = {}


class ConnectorError(ValueError):
    """Base class for connector failures (mapped to structured errors)."""


class ConnectorUnavailableError(ConnectorError):
    """The connector cannot run right now (not configured / not ready)."""


@dataclass(frozen=True)
class ConnectorStatus:
    """Point-in-time connector truth (Steps 26–27). No secret values."""

    source: str
    mode: str
    state: str
    detail: str
    configured: dict[str, bool] = field(default_factory=dict)
    last_success_at: str | None = None
    connector_state: str = STATE_NOT_CONFIGURED
    last_check_at: str | None = None
    last_poll_at: str | None = None
    last_error_category: str | None = None
    events_retrieved: int = 0
    latency_ms: int | None = None


@dataclass
class RuntimeHealth:
    """Ephemeral health of the last check/poll for one connector."""

    connector_state: str = STATE_CONFIGURED
    last_check_at: str | None = None
    last_poll_at: str | None = None
    last_error_category: str | None = None
    events_retrieved: int = 0
    latency_ms: int | None = None


# Per-process runtime registry; no network I/O ever happens here.
_runtime: dict[str, RuntimeHealth] = {}


def _now_iso() -> str:
    return datetime.now(UTC).replace(tzinfo=None).isoformat()


def _mark(
    source: str,
    connector_state: str,
    *,
    last_check_at: str | None = None,
    last_poll_at: str | None = None,
    last_error_category: str | None = None,
    events_retrieved: int | None = None,
    latency_ms: int | None = None,
    clear_error: bool = False,
) -> None:
    """Record the outcome of a check/poll in the runtime registry."""
    runtime = _runtime.get(source) or RuntimeHealth()
    runtime.connector_state = connector_state
    if last_check_at is not None:
        runtime.last_check_at = last_check_at
    if last_poll_at is not None:
        runtime.last_poll_at = last_poll_at
    if events_retrieved is not None:
        runtime.events_retrieved = events_retrieved
    if latency_ms is not None:
        runtime.latency_ms = latency_ms
    if clear_error:
        runtime.last_error_category = None
    elif last_error_category is not None:
        runtime.last_error_category = last_error_category
    _runtime[source] = runtime


def reset_runtime() -> None:
    """TEST/ops helper: drop ephemeral runtime health (no network)."""
    _runtime.clear()
    _fetch_attempts.clear()


def fetch_attempts(source: str) -> int:
    """Attempts used by the last bounded API fetch for ``source`` (>= 1)."""
    return max(1, _fetch_attempts.get(source, 1))


def _file_status(source: str, path_value: str, label: str) -> ConnectorStatus:
    if not path_value.strip():
        return ConnectorStatus(
            source=source,
            mode=MODE_FIXTURE,
            state=STATE_UNAVAILABLE,
            detail=f"No {label} configured; fixture ingestion remains available.",
            configured={"path": False},
            last_success_at=_last_success.get(source),
        )
    if not Path(path_value).is_file():
        return ConnectorStatus(
            source=source,
            mode=MODE_LIVE,
            state=STATE_UNAVAILABLE,
            detail=f"Configured {label} is not a readable file.",
            configured={"path": True},
            last_success_at=_last_success.get(source),
        )
    return ConnectorStatus(
        source=source,
        mode=MODE_LIVE,
        state=STATE_CONNECTED,
        detail=f"{label} readable; bounded poll available.",
        configured={"path": True},
        last_success_at=_last_success.get(source),
    )


def _api_status(
    source: str,
    fields: dict[str, str],
    required: tuple[str, ...],
) -> ConnectorStatus:
    present = {name: bool(fields.get(name, "").strip()) for name in required}
    if not any(present.values()):
        return ConnectorStatus(
            source=source,
            mode=MODE_LIVE,
            state=STATE_UNAVAILABLE,
            detail="No credentials configured; live connection not attempted.",
            configured=present,
            last_success_at=_last_success.get(source),
        )
    missing = sorted(name for name, ok in present.items() if not ok)
    if missing:
        return ConnectorStatus(
            source=source,
            mode=MODE_LIVE,
            state=STATE_INVALID_CONFIGURATION,
            detail=f"Incomplete configuration; missing: {', '.join(missing)}.",
            configured=present,
            last_success_at=_last_success.get(source),
        )
    url = fields.get("url", "")
    if url and not (url.startswith("http://") or url.startswith("https://")):
        return ConnectorStatus(
            source=source,
            mode=MODE_LIVE,
            state=STATE_INVALID_CONFIGURATION,
            detail="Configured URL must start with http:// or https://.",
            configured=present,
            last_success_at=_last_success.get(source),
        )
    return ConnectorStatus(
        source=source,
        mode=MODE_LIVE,
        state=STATE_UNAVAILABLE,
        detail="Credentials configured; live connection not attempted yet.",
        configured=present,
        last_success_at=_last_success.get(source),
    )


def _runtime_detail(status: ConnectorStatus, runtime: RuntimeHealth) -> str:
    state = runtime.connector_state
    if state == STATE_CONNECTING:
        return "Connection in progress."
    if state == STATE_CONNECTED:
        if runtime.last_check_at:
            latency = f" in {runtime.latency_ms} ms" if runtime.latency_ms is not None else ""
            head = f"Verified {runtime.last_check_at}{latency}"
        elif runtime.last_poll_at:
            head = f"Verified by poll {runtime.last_poll_at}"
        else:
            head = "Verified"
        polled = (
            f"; last poll {runtime.last_poll_at} ({runtime.events_retrieved} events)"
            if runtime.last_poll_at and runtime.last_check_at
            else ""
        )
        return f"{head}{polled}."
    if state == STATE_AUTH_FAILED:
        return "Authentication rejected by the endpoint on the last check."
    if state == STATE_RATE_LIMITED:
        return "Endpoint rate-limited the last check."
    if state == STATE_UNAVAILABLE:
        return "Endpoint unreachable or returned an error on the last check."
    if state == STATE_ERROR:
        return "Endpoint returned an unusable response on the last check."
    return status.detail


def _finalize(status: ConnectorStatus) -> ConnectorStatus:
    """Overlay Step 27 state and runtime health onto a base status.

    Configuration truth always wins: a connector that is unconfigured or
    malformed reports that truth no matter what the runtime registry
    says from an earlier check. File truth is also re-evaluated on every
    call (a removed file is UNAVAILABLE again immediately).
    """
    runtime = _runtime.get(status.source)
    complete = bool(status.configured) and all(status.configured.values())

    if status.state == STATE_INVALID_CONFIGURATION:
        return replace(
            status,
            connector_state=STATE_ERROR if complete else STATE_NOT_CONFIGURED,
        )
    if not complete:
        return replace(status, connector_state=STATE_NOT_CONFIGURED)

    if status.source in FILE_SOURCES:
        connector_state = STATE_CONNECTED if status.state == STATE_CONNECTED else STATE_UNAVAILABLE
        if runtime is None:
            return replace(status, connector_state=connector_state)
        return replace(
            status,
            connector_state=connector_state,
            last_check_at=runtime.last_check_at,
            last_poll_at=runtime.last_poll_at,
            last_error_category=runtime.last_error_category,
            events_retrieved=runtime.events_retrieved,
            latency_ms=runtime.latency_ms,
        )

    if runtime is None or runtime.connector_state == STATE_CONFIGURED:
        return replace(status, connector_state=STATE_CONFIGURED)
    connector_state = runtime.connector_state
    legacy_state = STATE_CONNECTED if connector_state == STATE_CONNECTED else STATE_UNAVAILABLE
    return replace(
        status,
        state=legacy_state,
        connector_state=connector_state,
        detail=_runtime_detail(status, runtime),
        last_check_at=runtime.last_check_at,
        last_poll_at=runtime.last_poll_at,
        last_error_category=runtime.last_error_category,
        events_retrieved=runtime.events_retrieved,
        latency_ms=runtime.latency_ms,
    )


def health(source: str) -> ConnectorStatus:
    """Evaluate a connector's truth right now (Steps 26–27).

    Raises ``KeyError`` for unknown sources (structured 422 upstream).
    Performs no network calls and no scans — only configuration, local
    file checks, and the ephemeral runtime registry.
    """
    if source not in SOURCES:
        raise KeyError(f"Unknown connector source: {source!r}.")
    settings = get_settings()
    if source == "suricata":
        status = _file_status(source, settings.suricata_eve_path, "EVE path")
    elif source == "zeek":
        status = _file_status(source, settings.zeek_log_path, "log path")
    elif source == "wazuh":
        status = _api_status(
            source,
            {
                "url": settings.wazuh_api_url,
                "username": settings.wazuh_username,
                "password": settings.wazuh_password,
            },
            ("url", "username", "password"),
        )
    else:
        status = _api_status(
            source,
            {
                "tenant_id": settings.defender_tenant_id,
                "client_id": settings.defender_client_id,
                "client_secret": settings.defender_client_secret,
            },
            ("tenant_id", "client_id", "client_secret"),
        )
    return _finalize(status)


def describe_all() -> list[ConnectorStatus]:
    """Stable connector catalog in registry order (Steps 26–27)."""
    return [health(source) for source in SOURCES]


def _is_complete(status: ConnectorStatus) -> bool:
    return bool(status.configured) and all(status.configured.values())


def _map_category(category: HttpErrorCategory | None) -> str:
    if category is HttpErrorCategory.AUTH_FAILED:
        return STATE_AUTH_FAILED
    if category is HttpErrorCategory.RATE_LIMITED:
        return STATE_RATE_LIMITED
    if category in {HttpErrorCategory.TIMEOUT, HttpErrorCategory.CONNECTION_ERROR}:
        return STATE_UNAVAILABLE
    if category is HttpErrorCategory.NOT_CONFIGURED:
        return STATE_NOT_CONFIGURED
    if category is HttpErrorCategory.HTTP_ERROR:
        return STATE_UNAVAILABLE
    if category in {
        HttpErrorCategory.RESPONSE_TOO_LARGE,
        HttpErrorCategory.MALFORMED_RESPONSE,
        HttpErrorCategory.DESTINATION_NOT_ALLOWED,
    }:
        return STATE_ERROR
    return STATE_ERROR


def _audit_for_state(action_state: str) -> str:
    return {
        STATE_AUTH_FAILED: AUDIT_AUTH_FAILED,
        STATE_RATE_LIMITED: AUDIT_RATE_LIMITED,
        STATE_UNAVAILABLE: AUDIT_UNAVAILABLE,
        STATE_NOT_CONFIGURED: AUDIT_UNAVAILABLE,
        STATE_ERROR: AUDIT_ERROR,
        STATE_CONNECTED: AUDIT_CONNECTED,
    }.get(action_state, AUDIT_UNAVAILABLE)


def _build_client(source: str):
    settings = get_settings()
    if source == "wazuh":
        return wazuh_client.WazuhClient(wazuh_client.WazuhConfig.from_settings(settings))
    if source == "defender":
        return defender_client.DefenderClient(
            defender_client.DefenderConfig.from_settings(settings)
        )
    raise KeyError(f"Unknown connector source: {source!r}.")


def check_connector(db: Session, source: str, actor: str) -> ConnectorStatus:
    """Perform one audited connectivity check (Steps 27G/27H).

    File sources re-evaluate the configured local file (no network).
    API sources run the shared client layer against the configured
    destination only. Returns the refreshed status; failures are
    reported *in* the status (CONNECTED/AUTH_FAILED/UNAVAILABLE/ERROR...)
    and audited, never raised — an operator needs the truth, not a 500.
    Raises ``KeyError`` only for unknown sources.
    """
    if source not in SOURCES:
        raise KeyError(f"Unknown connector source: {source!r}.")
    status = health(source)
    event_service.record_event_audit(
        db, AUDIT_CHECK_STARTED, None, actor, f"{source}: connectivity check requested."
    )
    db.commit()

    if not _is_complete(status) or status.state == STATE_INVALID_CONFIGURATION:
        connector_state = STATE_ERROR if _is_complete(status) else STATE_NOT_CONFIGURED
        _mark(source, connector_state, clear_error=True)
        event_service.record_event_audit(
            db, _audit_for_state(connector_state), None, actor, f"{source}: {status.detail}"
        )
        db.commit()
        return health(source)

    if source in FILE_SOURCES:
        connector_state = STATE_CONNECTED if status.state == STATE_CONNECTED else STATE_UNAVAILABLE
        _mark(
            source,
            connector_state,
            last_check_at=_now_iso(),
            clear_error=connector_state == STATE_CONNECTED,
        )
        event_service.record_event_audit(
            db, _audit_for_state(connector_state), None, actor, f"{source}: {status.detail}"
        )
        db.commit()
        return health(source)

    _mark(source, STATE_CONNECTING)
    try:
        client = _build_client(source)
        outcome = client.check()
    except ConnectorHttpError as exc:
        connector_state = _map_category(exc.category)
        category = exc.category.value if exc.category is not None else STATE_ERROR
        _mark(source, connector_state, last_check_at=_now_iso(), last_error_category=category)
        event_service.record_event_audit(
            db, _audit_for_state(connector_state), None, actor, f"{source}: {exc.message}"
        )
        db.commit()
        return health(source)
    if outcome.ok:
        _mark(
            source,
            STATE_CONNECTED,
            last_check_at=_now_iso(),
            latency_ms=outcome.latency_ms,
            clear_error=True,
        )
        event_service.record_event_audit(
            db, AUDIT_CONNECTED, None, actor, f"{source}: {outcome.detail}"
        )
    else:
        connector_state = _map_category(outcome.category)
        _mark(
            source,
            connector_state,
            last_check_at=_now_iso(),
            last_error_category=(
                outcome.category.value if outcome.category is not None else STATE_ERROR
            ),
        )
        event_service.record_event_audit(
            db, _audit_for_state(connector_state), None, actor, f"{source}: {outcome.detail}"
        )
    db.commit()
    return health(source)


def ingest_records(
    db: Session,
    registration: event_adapters.AdapterRegistration,
    indexed_records: list[tuple[int, object]],
    source: str,
    actor: str,
    errors: list[dict[str, object]],
    tracker: dict[str, Any] | None = None,
) -> tuple[int, int, int]:
    """Adapt + store each record through the shared Step 23 pipeline.

    One bounded unit of work: every record is normalized, deduplicated
    and committed individually (small transactions, never one giant
    batch transaction), and per-record failures are collected into
    ``errors`` instead of aborting the unit. When ``tracker`` is given
    it is updated with the last successfully processed event time and
    external id (used for the Step 28 checkpoint).
    """
    accepted = 0
    duplicates = 0
    rejected = 0
    for index, record in indexed_records:
        try:
            event, created = event_service.ingest_via_adapter(
                db, registration, record, source, actor
            )
        except registration.error as exc:
            rejected += 1
            errors.append({"index": index, "code": "INVALID_EVENT", "message": str(exc)[:200]})
            continue
        except event_service.PayloadTooLargeError as exc:
            rejected += 1
            errors.append({"index": index, "code": "PAYLOAD_TOO_LARGE", "message": str(exc)[:200]})
            continue
        if tracker is not None:
            seen_time = tracker.get("last_event_time")
            if seen_time is None or event.event_time > seen_time:
                tracker["last_event_time"] = event.event_time
            if event.external_event_id:
                tracker["last_external_event_id"] = event.external_event_id
        if created:
            accepted += 1
        else:
            duplicates += 1
    return accepted, duplicates, rejected


def _retry_sleep(seconds: float) -> None:
    """Bounded, injectable backoff between transient fetch attempts."""
    if seconds > 0:
        time.sleep(seconds)


@dataclass
class FileRead:
    """Result of one bounded, metadata-checked file read (Step 28)."""

    records: list[tuple[int, object]] = field(default_factory=list)
    errors: list[dict[str, object]] = field(default_factory=list)
    malformed: int = 0
    truncated: bool = False
    detection: str | None = None
    cursor: dict[str, Any] = field(default_factory=dict)


def _read_file_records(
    path_value: str, prior: Mapping[str, Any] | None, *, resume: bool
) -> FileRead:
    """Read at most ``MAX_POLL_LINES`` lines from the configured file.

    The single file-read call site in this module: it opens only the
    operator-configured path (never client input). Before reading, the
    stored cursor is compared with the file's current identity/size so
    rotation, truncation, and an invalid offset are detected rather than
    assumed away; a detection restarts the read at offset 0. Seeking to
    the stored offset happens only when ``resume`` is enabled.
    """
    state = log_file_reader.stat_file(path_value)
    detection = log_file_reader.evaluate(prior, state)
    start = 0
    if resume and detection is None and isinstance(prior, Mapping):
        stored = prior.get("offset")
        if isinstance(stored, int) and not isinstance(stored, bool) and stored > 0:
            start = stored
    read = FileRead(detection=detection)
    consumed = 0
    with open(path_value, "rb") as handle:
        if start:
            handle.seek(start)
        for index, line in enumerate(handle):
            if index >= MAX_POLL_LINES:
                read.truncated = True
                break
            consumed += len(line)
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError as exc:
                read.malformed += 1
                read.errors.append(
                    {"index": index, "code": "MALFORMED_LINE", "message": str(exc)[:200]}
                )
                continue
            read.records.append((index, record))
    read.cursor = {
        "v": 1,
        "kind": "file",
        "offset": start + consumed,
        "file_size": state.size,
        "file_identity": state.identity,
    }
    return read


def poll_file_source(
    db: Session, source: str, actor: str, *, processor: IngestProcessor | None = None
) -> dict[str, object]:
    """Bounded poll of a configured local file (Steps 26 + 28).

    Reads at most ``MAX_POLL_LINES`` lines from the operator-configured
    path (never a client-supplied path), detects rotation/truncation
    against the stored checkpoint cursor, and ingests valid records
    through the shared audited pipeline — directly, or through the
    Step 28 ``processor`` (bounded queue + batches) when one is given.
    One bad line counts as rejected without affecting the rest. Returns
    a summary dict; raises ``ConnectorUnavailableError`` when the
    connector is not runnable.
    """
    if source not in FILE_SOURCES:
        raise ConnectorUnavailableError(f"Source {source!r} has no local file poll.")
    status = health(source)
    if status.mode != MODE_LIVE or status.state != STATE_CONNECTED:
        event_service.record_event_audit(
            db, AUDIT_UNAVAILABLE, None, actor, f"{source}: {status.detail}"
        )
        db.commit()
        raise ConnectorUnavailableError(f"{source}: {status.detail}")
    registration = event_adapters.resolve_adapter(source)
    settings = get_settings()
    path_value = settings.suricata_eve_path if source == "suricata" else settings.zeek_log_path
    prior_cursor = checkpoints.load_cursor(db, source)
    read = _read_file_records(path_value, prior_cursor, resume=settings.connector_file_resume)
    if read.detection:
        event_service.record_event_audit(
            db,
            AUDIT_ROTATION_DETECTED,
            None,
            actor,
            f"{source}: {read.detection} detected since the last successful poll; "
            "bounded read restarted at offset 0.",
        )
        db.commit()
    errors: list[dict[str, object]] = list(read.errors)
    rejected = read.malformed
    if processor is None:
        accepted, duplicates, adapter_rejected = ingest_records(
            db, registration, read.records, source, actor, errors
        )
    else:
        accepted, duplicates, adapter_rejected = processor(read.records, errors)
    rejected += adapter_rejected
    retrieved = len(read.records)
    if accepted + duplicates > 0:
        _last_success[source] = _now_iso()
    _mark(
        source,
        STATE_CONNECTED,
        last_poll_at=_now_iso(),
        events_retrieved=retrieved,
        clear_error=True,
    )
    event_service.record_event_audit(
        db,
        AUDIT_CONNECTED,
        None,
        actor,
        f"{source} poll: {accepted} accepted, {duplicates} duplicates, {rejected} rejected.",
    )
    if rejected > 0:
        event_service.record_event_audit(
            db, "CONNECTOR_REJECTED", None, actor, f"{source} poll rejected {rejected} record(s)."
        )
    db.commit()
    return {
        "source": source,
        "accepted": accepted,
        "duplicates": duplicates,
        "rejected": rejected,
        "truncated": read.truncated,
        "errors": errors,
        "pages": 1,
        "retrieved": retrieved,
        "termination": "COMPLETED",
        # Step 28 provenance for the checkpoint (dropped by the API
        # response model; consumed by the ingestion pipeline).
        "cursor": dict(read.cursor),
        "fetch_attempts": 1,
    }


def _fetch_api_records(db: Session, source: str, actor: str) -> tuple[Any, int]:
    """One bounded API fetch with Step 28 transient retry.

    Returns ``(fetch_outcome, attempts)``. Retries only transient
    categories (timeout / connection error), at most
    ``ingestion_retry_max`` extra attempts with linear backoff, each
    audited ``INGESTION_RETRY``. Auth, configuration, HTTP-status and
    payload failures raise immediately — never retried here.
    """
    settings = get_settings()
    max_attempts = 1 + int(settings.ingestion_retry_max)
    backoff = float(settings.ingestion_retry_backoff_seconds)
    attempt = 0
    while True:
        attempt += 1
        try:
            client = _build_client(source)
            fetch = client.fetch_alerts()
            _fetch_attempts[source] = attempt
            return fetch, attempt
        except ConnectorHttpError as exc:
            transient = exc.category in TRANSIENT_CATEGORIES
            if not transient or attempt >= max_attempts:
                _fetch_attempts[source] = attempt
                raise
            event_service.record_event_audit(
                db,
                AUDIT_INGESTION_RETRY,
                None,
                actor,
                f"{source}: transient {exc.category.value} on fetch attempt {attempt}; "
                f"bounded retry {attempt + 1}/{max_attempts}.",
            )
            db.commit()
            _retry_sleep(backoff * attempt)


def poll_api_source(
    db: Session, source: str, actor: str, *, processor: IngestProcessor | None = None
) -> dict[str, object]:
    """Bounded live poll of a configured API connector (Steps 27B/27C + 28).

    Retrieves at most ``connector_max_pages`` pages /
    ``connector_max_events`` records through the shared client layer
    (with a bounded transient retry), then normalizes every record via
    the Step 23 adapter registry — directly, or through the Step 28
    ``processor`` (bounded queue + batches) when one is given — and
    audits start, termination reason, and outcome. Raises
    ``ConnectorUnavailableError`` for unconfigured connectors and for
    any transport/auth failure (category is audited first).
    """
    if source not in API_SOURCES:
        raise ConnectorUnavailableError(f"Source {source!r} has no API poll.")
    status = health(source)
    if not _is_complete(status) or status.state == STATE_INVALID_CONFIGURATION:
        event_service.record_event_audit(
            db, AUDIT_UNAVAILABLE, None, actor, f"{source}: {status.detail}"
        )
        db.commit()
        raise ConnectorUnavailableError(f"{source}: {status.detail}")

    settings = get_settings()
    registration = event_adapters.resolve_adapter(source)
    event_service.record_event_audit(
        db,
        AUDIT_POLL_STARTED,
        None,
        actor,
        (
            f"{source}: poll started (bounded to {settings.connector_max_pages} page(s) / "
            f"{settings.connector_max_events} event(s))."
        ),
    )
    db.commit()

    _mark(source, STATE_CONNECTING)
    try:
        fetch, attempts = _fetch_api_records(db, source, actor)
    except ConnectorHttpError as exc:
        connector_state = _map_category(exc.category)
        category = exc.category.value if exc.category is not None else STATE_ERROR
        _mark(source, connector_state, last_error_category=category)
        event_service.record_event_audit(
            db, AUDIT_POLL_FAILED, None, actor, f"{source}: poll failed ({category})."
        )
        event_service.record_event_audit(
            db, _audit_for_state(connector_state), None, actor, f"{source}: {exc.message}"
        )
        db.commit()
        raise ConnectorUnavailableError(f"{source}: connector poll failed ({category}).")

    errors: list[dict[str, object]] = []
    indexed = list(enumerate(fetch.records))
    if processor is None:
        accepted, duplicates, rejected = ingest_records(
            db, registration, indexed, source, actor, errors
        )
    else:
        accepted, duplicates, rejected = processor(indexed, errors)
    retrieved = len(fetch.records)
    termination = fetch.termination
    truncated = termination != wazuh_client.TERMINATION_COMPLETED
    if accepted + duplicates > 0:
        _last_success[source] = _now_iso()
    _mark(
        source,
        STATE_CONNECTED,
        last_poll_at=_now_iso(),
        events_retrieved=retrieved,
        clear_error=True,
    )
    event_service.record_event_audit(
        db,
        AUDIT_POLL_COMPLETED,
        None,
        actor,
        (
            f"{source}: {accepted} accepted, {duplicates} duplicates, {rejected} rejected; "
            f"retrieved {retrieved} in {fetch.pages} page(s); termination={termination}."
        ),
    )
    if rejected > 0:
        event_service.record_event_audit(
            db, "CONNECTOR_REJECTED", None, actor, f"{source} poll rejected {rejected} record(s)."
        )
    db.commit()
    return {
        "source": source,
        "accepted": accepted,
        "duplicates": duplicates,
        "rejected": rejected,
        "truncated": truncated,
        "errors": errors,
        "pages": fetch.pages,
        "retrieved": retrieved,
        "termination": termination,
        # Step 28 provenance for the checkpoint (dropped by the API
        # response model; consumed by the ingestion pipeline).
        "cursor": {"v": 1, "kind": "api", "pages": fetch.pages, "termination": termination},
        "fetch_attempts": attempts,
    }


def poll_source(
    db: Session,
    source: str,
    actor: str,
    *,
    processor: IngestProcessor | None = None,
) -> dict[str, object]:
    """Dispatch a poll to the source's bounded fetcher (file or API)."""
    if source in FILE_SOURCES:
        return poll_file_source(db, source, actor, processor=processor)
    return poll_api_source(db, source, actor, processor=processor)


__all__ = [
    "API_SOURCES",
    "AUDIT_INGESTION_RETRY",
    "AUDIT_ROTATION_DETECTED",
    "CONNECTOR_STATES",
    "FILE_SOURCES",
    "MAX_POLL_LINES",
    "MODE_FIXTURE",
    "MODE_LIVE",
    "SOURCES",
    "STATE_AUTH_FAILED",
    "STATE_CONFIGURED",
    "STATE_CONNECTING",
    "STATE_CONNECTED",
    "STATE_ERROR",
    "STATE_INVALID_CONFIGURATION",
    "STATE_NOT_CONFIGURED",
    "STATE_RATE_LIMITED",
    "STATE_UNAVAILABLE",
    "TRANSIENT_CATEGORIES",
    "ConnectorError",
    "ConnectorStatus",
    "ConnectorUnavailableError",
    "FileRead",
    "IngestProcessor",
    "RuntimeHealth",
    "check_connector",
    "describe_all",
    "fetch_attempts",
    "health",
    "ingest_records",
    "poll_api_source",
    "poll_file_source",
    "poll_source",
    "reset_runtime",
]
