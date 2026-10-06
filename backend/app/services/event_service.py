"""Event normalization + persistence service (Steps 3 + 23).

Pipeline::

    API envelope (validated by Pydantic)
      -> normalize_event(): clean, default, fingerprint
      -> correlate_asset(): server-side inventory link (read-only)
      -> store_event(): idempotency check -> insert or count
      -> Database

The normalizer is deliberately generic: it maps the *vendor-neutral*
ingest envelope into the canonical ``SecurityEvent``. Source adapters
(Suricata/Zeek/Wazuh/Defender) each produce this same envelope through
the static ``event_adapters`` registry — no adapters execute anything.

Safety rules enforced here:

- Raw payloads are serialized as JSON text and stored as **data only**.
  Nothing is executed, evaluated, imported, or passed to a shell —
  there is no code path that could do so.
- Serialized ``raw_event`` larger than ``MAX_RAW_BYTES`` is rejected
  (413), never silently truncated.
- The fingerprint covers only stable attributes (no ingest timestamps),
  is informational, and never causes an event to be dropped. Only the
  explicit ``(source_type, source_name, external_event_id)`` triple —
  backed by a UNIQUE constraint — deduplicates, and even then the
  existing row is *returned* (with occurrence accounting), not discarded.
- Asset correlation is read-only: inventory links are resolved, never
  created, never overwritten with weaker data.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.assets import Asset
from app.models.events import EventAudit, SecurityEvent

if TYPE_CHECKING:
    from app.services.event_adapters import AdapterRegistration

logger = get_logger(__name__)

# Serialized raw payloads beyond this are refused with 413.
MAX_RAW_BYTES = 64 * 1024

# Step 6: credential-shaped keys are scrubbed from the stored vendor payload
# before it is persisted. The list is deliberately narrow - it targets keys
# that name a credential, not free text that merely mentions one, so
# ordinary forensic data is never destroyed.
_SECRET_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "bearer",
        "api_key",
        "apikey",
        "api_secret",
        "client_secret",
        "private_key",
        "authorization",
        "auth_token",
        "session_token",
        "credential",
        "credentials",
        "pwd_hash",
        "passwd_hash",
    }
)
REDACTED_PLACEHOLDER = "***REDACTED***"
_SCRUB_TRUNCATED = "***TRUNCATED: nesting limit***"
_SCRUB_MAX_DEPTH = 12
_SCRUB_MAX_KEYS = 200


def _is_secret_key(name: str) -> bool:
    """True for a key that names a credential (exact or ``*_token`` style)."""
    lowered = name.strip().lower()
    if lowered in _SECRET_KEYS:
        return True
    return lowered.endswith(("_token", "_secret", "_password", "_key", "_credential"))


# Step 23 ingest audit actions (append-only; never contain secrets).
AUDIT_RECEIVED = "EVENT_RECEIVED"
AUDIT_NORMALIZED = "EVENT_NORMALIZED"
AUDIT_DEDUPLICATED = "EVENT_DEDUPLICATED"
AUDIT_REJECTED = "EVENT_REJECTED"

# Step 23: every ingest path is operator-submitted data today — no live
# sensor connections exist. Surfaced on responses and UI badges; becomes
# data-driven when live connectors land.
INGEST_MODE = "FIXTURE"


def ingest_mode() -> str:
    """Current ingestion grade for response labeling (Step 23)."""
    return INGEST_MODE


class PayloadTooLargeError(ValueError):
    """Raw event payload exceeds the storage cap."""


def _utcnow_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _as_naive_utc(value: datetime | None) -> datetime:
    if value is None:
        return _utcnow_naive()
    if value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


def _clean(value: object, limit: int) -> str | None:
    """Collapse whitespace, drop empties, enforce column length."""
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split())
    if not cleaned:
        return None
    return cleaned[:limit]


def _confidence(value: object) -> int | None:
    """Source-supplied confidence 0-100, else None (never inferred)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 0 <= value <= 100:
        return value
    if isinstance(value, float) and 0 <= value <= 100:
        return int(value)
    return None


def compute_fingerprint(attributes: dict[str, object]) -> str:
    """Deterministic SHA-256 over stable attributes (no timestamps)."""
    canonical = json.dumps(attributes, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def scrub_secrets(value: object, *, _depth: int = 0) -> object:
    """Replace credential-shaped values in a stored vendor payload (Step 6).

    A vendor record is stored verbatim so nothing is lost, which also means a
    rule that reports e.g. a failed login or a config file can carry a
    password, token or key in its ``data`` section. Those must not be
    persisted. Values under a secret-named key become
    :data:`REDACTED_PLACEHOLDER`; every other value is preserved.

    Bounded on purpose: depth and breadth are capped so a hostile or deeply
    nested payload cannot turn normalization into a CPU sink, and the size
    limit still applies afterwards.
    """
    if _depth > _SCRUB_MAX_DEPTH:
        return _SCRUB_TRUNCATED
    if isinstance(value, dict):
        scrubbed: dict[str, object] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _SCRUB_MAX_KEYS:
                scrubbed["__truncated__"] = True
                break
            name = key if isinstance(key, str) else str(key)
            if _is_secret_key(name):
                scrubbed[name] = REDACTED_PLACEHOLDER if item is not None else None
            else:
                scrubbed[name] = scrub_secrets(item, _depth=_depth + 1)
        return scrubbed
    if isinstance(value, list):
        return [scrub_secrets(item, _depth=_depth + 1) for item in value[:_SCRUB_MAX_KEYS]]
    return value


def normalize_event(payload: dict[str, object]) -> dict[str, object]:
    """Build the canonical attribute dict from a validated envelope.

    ``payload`` uses the API field names; values are already type-checked
    by Pydantic. Returns column-ready attributes (raw JSON included).
    Raises :class:`PayloadTooLargeError` when the raw payload is too big.
    """
    raw = payload.get("raw_event")
    raw_text: str | None = None
    if raw is not None:
        # Step 6: scrub credential-shaped values before the payload is
        # persisted, so a vendor rule that quotes a secret cannot store it.
        raw_text = json.dumps(scrub_secrets(raw), separators=(",", ":"), default=str)
        if len(raw_text.encode("utf-8")) > MAX_RAW_BYTES:
            raise PayloadTooLargeError(
                f"raw_event exceeds the {MAX_RAW_BYTES}-byte limit; "
                "split the payload or omit raw_event."
            )

    normalized: dict[str, object] = {
        "event_time": _as_naive_utc(cast("datetime | None", payload.get("event_time"))),
        "received_at": _utcnow_naive(),
        "source_type": payload["source_type"],
        "source_name": _clean(payload.get("source_name"), 128),
        "event_type": _clean(payload.get("event_type"), 64),
        "severity": payload.get("severity") or "INFO",
        "confidence": _confidence(payload.get("confidence")),
        "title": _clean(payload.get("title"), 512),
        "description": _clean(payload.get("description"), 4000),
        "source_ip": _clean(payload.get("source_ip"), 45),
        "destination_ip": _clean(payload.get("destination_ip"), 45),
        "source_port": payload.get("source_port"),
        "destination_port": payload.get("destination_port"),
        "protocol": _clean(str(payload["protocol"]).lower(), 8)
        if payload.get("protocol") is not None
        else None,
        "asset_id": payload.get("asset_id"),
        "hostname": _clean(payload.get("hostname"), 255),
        "username": _clean(payload.get("username"), 128),
        "process_name": _clean(payload.get("process_name"), 255),
        "action": _clean(payload.get("action"), 64),
        "status": _clean(payload.get("status"), 32),
        "raw_event": raw_text,
        "external_event_id": _clean(payload.get("external_event_id"), 255),
    }
    fingerprint_attributes = {
        key: normalized[key]
        for key in (
            "source_type",
            "source_name",
            "event_type",
            "severity",
            "confidence",
            "title",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
            "asset_id",
            "hostname",
            "username",
            "process_name",
            "action",
            "status",
            "external_event_id",
        )
    }
    fingerprint = compute_fingerprint(fingerprint_attributes)
    normalized["fingerprint"] = fingerprint
    normalized["correlation_key"] = _clean(payload.get("correlation_key"), 64) or fingerprint
    snapshot = {**{k: v for k, v in fingerprint_attributes.items()}, "fingerprint": fingerprint}
    # Vendor adapters may attach extra normalized context (e.g. Suricata
    # alert/dns/http sub-objects). Merged as data; capped to bound size.
    extras = payload.get("normalized_extras")
    if isinstance(extras, dict):
        snapshot["vendor"] = {str(key)[:64]: value for key, value in list(extras.items())[:12]}
    normalized["normalized_data"] = json.dumps(snapshot, separators=(",", ":"), default=str)[:32768]
    return normalized


def correlate_asset(db: Session, attributes: dict[str, object]) -> None:
    """Resolve ``asset_id`` against inventory, in place (Step 23).

    Rules (read-only; never creates, never overwrites known data):

    - a client-supplied ``asset_id`` that exists is kept as-is;
    - a client-supplied ``asset_id`` that does not exist is dropped
      (treated as unresolved, never trusted blindly);
    - otherwise the destination IP, then source IP, then hostname are
      matched against inventoried assets (exact match only);
    - no match leaves ``asset_id`` as None: explicitly unresolved.
    """
    supplied = attributes.get("asset_id")
    if isinstance(supplied, str) and supplied:
        exists = db.scalar(select(Asset.id).where(Asset.id == supplied))
        if exists is not None:
            return
    resolved: str | None = None
    for ip_key in ("destination_ip", "source_ip"):
        ip_value = attributes.get(ip_key)
        if isinstance(ip_value, str) and ip_value:
            hit = db.scalar(select(Asset.id).where(Asset.ip_address == ip_value))
            if hit is not None:
                resolved = hit
                break
    if resolved is None:
        hostname = attributes.get("hostname")
        if isinstance(hostname, str) and hostname:
            resolved = db.scalar(select(Asset.id).where(Asset.hostname == hostname))
    attributes["asset_id"] = resolved


def record_event_audit(
    db: Session,
    action: str,
    event_id: str | None,
    actor: str,
    detail: str | None = None,
) -> None:
    """Append one ingestion audit row. Never called with secrets."""
    db.add(EventAudit(event_id=event_id, action=action, actor=actor[:128], detail=detail))


def store_event(db: Session, attributes: dict[str, object]) -> tuple[SecurityEvent, bool]:
    """Idempotent persist. Returns ``(event, created)``.

    When ``external_event_id`` is set and the
    ``(source_type, source_name, external_event_id)`` triple already
    exists, the existing row is returned with ``created=False`` after
    bumping ``occurrence_count``/``last_seen_at`` (replay accounting;
    first-seen fields are never rewritten).
    """
    now = _utcnow_naive()
    external_id = attributes.get("external_event_id")
    if external_id:
        existing = db.scalar(
            select(SecurityEvent).where(
                SecurityEvent.source_type == attributes["source_type"],
                SecurityEvent.source_name == attributes["source_name"],
                SecurityEvent.external_event_id == external_id,
            )
        )
        if existing is not None:
            existing.occurrence_count = (existing.occurrence_count or 0) + 1
            existing.last_seen_at = now
            db.commit()
            db.refresh(existing)
            return existing, False
    attributes = dict(attributes)
    attributes.setdefault("occurrence_count", 1)
    attributes.setdefault("last_seen_at", now)
    event = SecurityEvent(**attributes)
    db.add(event)
    db.commit()
    db.refresh(event)
    return event, True


def ingest_via_adapter(
    db: Session, registration: AdapterRegistration, raw: object, source_name: str, actor: str
):
    """Adapt + normalize + correlate + store one source record (Step 23).

    Single orchestration point for every adapter endpoint (single and
    batch): the adapter is fixed by the caller's registry registration
    (never client input). Audits NORMALIZED on success, RECEIVED on
    store, DEDUPLICATED on replay, REJECTED on adapter/validation
    failure (re-raised for the endpoint to map). Returns
    ``(event, created)``.
    """
    try:
        envelope = registration.adapt(raw, source_name)
    except registration.error as exc:
        record_event_audit(db, AUDIT_REJECTED, None, actor, f"{registration.key}: {exc}")
        db.commit()
        raise
    try:
        attributes = normalize_event(envelope)
    except PayloadTooLargeError as exc:
        record_event_audit(db, AUDIT_REJECTED, None, actor, f"{registration.key}: {exc}")
        db.commit()
        raise
    correlate_asset(db, attributes)
    event, created = store_event(db, attributes)
    record_event_audit(db, AUDIT_NORMALIZED, event.id, actor, f"{registration.key} normalized.")
    record_event_audit(
        db,
        AUDIT_RECEIVED if created else AUDIT_DEDUPLICATED,
        event.id,
        actor,
        f"{registration.key} {'stored' if created else 'replay'} (occurrence {event.occurrence_count}).",
    )
    db.commit()
    return event, created
