"""Deterministic correlation rules (Step 9, analysis only).

Three vendor-neutral rules. Each rule is a pure function over normalized
``SecurityEvent`` rows: same input rows → same drafts, always. A draft
becomes a ``Correlation`` row only through ``correlation_service``.

Rules (all documented; every match explains itself):

- ``multi-source-target`` (R-TGT, confidence 75): ≥2 events with ≥2
  distinct ``source_type`` values sharing one ``destination_ip`` within
  60 minutes. Rationale: independent sensors observing the same target
  corroborate each other; a single sensor's lone event does not qualify.
- ``vuln-exposure`` (R-VULN, confidence 70): ≥1 ``VULNERABILITY_FINDING``
  plus ≥1 non-finding event touching the same host (finding
  ``destination_ip``/``hostname`` equals the event's source/destination
  IP or hostname) within 24 hours. Rationale: observed activity against
  a host with a known finding deserves a grouped look. Findings alone
  (no activity) do not qualify.
- ``repeated-source`` (R-SRC, confidence 60): ≥3 events sharing one
  ``source_ip`` within 15 minutes with at least one severity MEDIUM or
  higher. Rationale: a noisy source with at least one notable event is
  worth grouping; quiet or purely informational chatter is not.

Bounds: matches are grouped greedily by pivot key in event_time order;
a new window starts when the gap exceeds the rule window. Nothing is
correlated across unbounded time, and similar-looking events outside
these exact conditions never match.

Step 24: the effective window of every rule is additionally capped by
the ``correlation_max_window_minutes`` setting (default 1440, hard
ceiling 7 days): ``effective_window_minutes(rule_id)``. With defaults
all three rule windows apply unchanged; lowering the cap only narrows
matching, never widens it. Explanations always state the effective
window actually used.

Step 29: the rule model is now explicit — each ``RuleDefinition``
carries its operator ``enabled`` state and the literal ``conditions``
it matches (documentation-grade strings; never parsed, never executed
from client input). ``rule_enabled(rule_id)`` reads the server-side
``correlation_disabled_rules`` CSV; a disabled rule contributes no
drafts while remaining in the catalog, so counts and identities stay
stable. The Step 29 analysis rules live separately in
``app.services.incident_rules`` and never enter this catalog, keeping
the Step 24 recompute contract byte-for-byte unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class RuleDefinition:
    """Deterministic rule model (Step 24, extended Step 29).

    Every rule carries the full documented shape required for audit:
    stable ``id``, ``name``, ``description``, operator ``enabled`` state,
    a bounded ``window_minutes``, the literal ``conditions`` it matches
    (documentation-grade, never parsed or executed), and a fixed
    ``confidence`` (0-100 evidence strength, not probability).
    """

    id: str
    name: str
    description: str
    window_minutes: int
    confidence: int
    enabled: bool = True
    conditions: tuple[str, ...] = ()


RULES: dict[str, RuleDefinition] = {
    "multi-source-target": RuleDefinition(
        id="multi-source-target",
        name="Same target, multiple sources",
        description=(
            "Events from at least two distinct source types sharing one target "
            "(a destination address or a host name)."
        ),
        window_minutes=60,
        confidence=75,
        conditions=(
            "a target key is present (destination address or host name)",
            "at least 2 distinct source_type values",
            "all matched events within the effective window",
        ),
    ),
    "vuln-exposure": RuleDefinition(
        id="vuln-exposure",
        name="Activity on a host with a known finding",
        description="Observed activity touching a host that has a vulnerability finding.",
        window_minutes=24 * 60,
        confidence=70,
        conditions=(
            "one VULNERABILITY_FINDING event with destination_ip or hostname",
            "at least one non-finding event sharing that host key",
            "activity within the effective window of the finding",
        ),
    ),
    "repeated-source": RuleDefinition(
        id="repeated-source",
        name="Repeated activity from one source",
        description="Three or more events from one source IP, including a notable severity.",
        window_minutes=15,
        confidence=60,
        conditions=(
            "source_ip is present",
            "at least 3 events within the effective window",
            "at least one severity MEDIUM or higher",
        ),
    ),
}


def rule_enabled(rule_id: str) -> bool:
    """Operator-controlled enabled state for a catalog rule (Step 29).

    Reads the server-side ``correlation_disabled_rules`` CSV setting on
    every call (same pattern as ``effective_window_minutes``). Unknown
    ids in the CSV are ignored — configuration can never change which
    rules exist, only whether a known rule runs. Clients cannot supply
    this setting.
    """
    from app.core.config import get_settings

    raw = get_settings().correlation_disabled_rules
    disabled = {item.strip() for item in raw.split(",") if item.strip()}
    return rule_id not in disabled


# Hard ceiling for the configurable window cap (Step 24): history scans
# stay bounded no matter the deployment setting.
MAX_WINDOW_MINUTES = 7 * 24 * 60


def effective_window_minutes(rule_id: str) -> int:
    """Rule window capped by deployment configuration (Step 24).

    Returns ``min(rule window, correlation_max_window_minutes)`` with
    the setting itself clamped to [1, 7 days]. Pure function of stored
    configuration — deterministic for a given deployment.
    """
    from app.core.config import get_settings

    rule = RULES[rule_id]
    configured = get_settings().correlation_max_window_minutes
    cap = max(1, min(configured, MAX_WINDOW_MINUTES))
    return max(1, min(rule.window_minutes, cap))


@dataclass
class EventView:
    """Minimal normalized view the rules match on (built from SecurityEvent)."""

    id: str
    event_time: datetime
    source_type: str
    event_type: str
    severity: str
    title: str
    source_ip: str | None
    destination_ip: str | None
    hostname: str | None

    def moment(self) -> datetime:
        moment = self.event_time
        if moment.tzinfo is not None:
            moment = moment.astimezone(UTC).replace(tzinfo=None)
        return moment


@dataclass
class CorrelationDraft:
    rule_id: str
    event_ids: list[str]  # sorted for deterministic identity
    primary_ip: str | None
    hostname: str | None
    explanation: str
    roles: dict[str, str] = field(default_factory=dict)  # event_id -> role


def _window_groups(ordered: list[EventView], window: timedelta) -> list[list[EventView]]:
    groups: list[list[EventView]] = []
    current: list[EventView] = []
    for event in ordered:
        if current and event.moment() - current[-1].moment() > window:
            if len(current) >= 2:
                groups.append(current)
            current = []
        current.append(event)
    if len(current) >= 2:
        groups.append(current)
    return groups


def _target_keys(event: EventView) -> list[str]:
    """Deterministic target identifiers for one event (Step 7).

    A vendor alert about a host may carry the address, the host name, or
    only the remote address. Keying the "same target" rule on the address
    alone meant a Wazuh alert (which reports ``dstip``) and a Defender alert
    (which reports ``remoteIp`` and ``computerName``) about the *same*
    machine never shared a key and so never correlated. The host name is an
    equally valid target identity, so it is included as a second key.

    Prefixed so an address can never collide with a name. Ordered, so the
    chosen pivot is deterministic for a given event.
    """
    keys: list[str] = []
    if event.destination_ip:
        keys.append(f"ip:{event.destination_ip}")
    if event.hostname:
        keys.append(f"host:{event.hostname}")
    return keys


def rule_multi_source_target(events: list[EventView]) -> list[CorrelationDraft]:
    rule = RULES["multi-source-target"]
    if not rule_enabled(rule.id):
        return []
    window_minutes = effective_window_minutes(rule.id)
    window = timedelta(minutes=window_minutes)
    by_target: dict[str, list[EventView]] = {}
    for event in events:
        for key in _target_keys(event):
            by_target.setdefault(key, []).append(event)
    drafts: list[CorrelationDraft] = []
    for key in sorted(by_target):
        grouped = by_target[key]
        ordered = sorted(grouped, key=lambda event: event.moment())
        for cluster in _window_groups(ordered, window):
            sources = sorted({event.source_type for event in cluster})
            if len(sources) < 2:
                continue
            ids = sorted(event.id for event in cluster)
            kind, _, value = key.partition(":")
            label = f"address {value}" if kind == "ip" else f"host {value}"
            drafts.append(
                CorrelationDraft(
                    rule_id=rule.id,
                    event_ids=ids,
                    primary_ip=value if kind == "ip" else _shared_address(cluster),
                    hostname=value if kind == "host" else _shared_hostname(cluster),
                    explanation=(
                        f"{len(cluster)} events from {len(sources)} distinct sources "
                        f"({', '.join(sources)}) observed the same {label} "
                        f"within {window_minutes} minutes."
                    ),
                )
            )
    return drafts


def _shared_address(events: list[EventView]) -> str | None:
    """The one destination address shared by a cluster, if unambiguous."""
    values = {event.destination_ip for event in events if event.destination_ip}
    return values.pop() if len(values) == 1 else None


def _shared_hostname(events: list[EventView]) -> str | None:
    """The one host name shared by a cluster, if unambiguous."""
    values = {event.hostname for event in events if event.hostname}
    return values.pop() if len(values) == 1 else None


def rule_vuln_exposure(events: list[EventView]) -> list[CorrelationDraft]:
    rule = RULES["vuln-exposure"]
    if not rule_enabled(rule.id):
        return []
    window_minutes = effective_window_minutes(rule.id)
    window = timedelta(minutes=window_minutes)
    findings = [event for event in events if event.event_type == "VULNERABILITY_FINDING"]
    activity = [event for event in events if event.event_type != "VULNERABILITY_FINDING"]
    drafts: list[CorrelationDraft] = []
    for finding in findings:
        keys = {key for key in (finding.destination_ip, finding.hostname) if key}
        if not keys:
            continue
        matched = [
            event
            for event in activity
            if keys & ({event.source_ip, event.destination_ip, event.hostname} - {None})
        ]
        pool = sorted([finding, *matched], key=lambda event: event.moment())
        # Keep only activity within the window of the finding.
        cluster = [
            event
            for event in pool
            if abs(event.moment() - finding.moment()) <= window and event.id != finding.id
        ]
        if not cluster:
            continue
        ordered_ids = sorted([finding.id, *(event.id for event in cluster)])
        pivot = finding.destination_ip or finding.hostname
        drafts.append(
            CorrelationDraft(
                rule_id=rule.id,
                event_ids=ordered_ids,
                primary_ip=finding.destination_ip,
                hostname=finding.hostname,
                explanation=(
                    f"Host {pivot or 'unknown'} has a recorded vulnerability finding "
                    f"and {len(cluster)} related observed event(s) within "
                    f"{window_minutes // 60} hours."
                ),
                roles={finding.id: "vulnerability"} | {event.id: "activity" for event in cluster},
            )
        )
    return drafts


def rule_repeated_source(events: list[EventView]) -> list[CorrelationDraft]:
    rule = RULES["repeated-source"]
    if not rule_enabled(rule.id):
        return []
    window_minutes = effective_window_minutes(rule.id)
    window = timedelta(minutes=window_minutes)
    by_source: dict[str, list[EventView]] = {}
    for event in events:
        if event.source_ip:
            by_source.setdefault(event.source_ip, []).append(event)
    drafts: list[CorrelationDraft] = []
    for source, grouped in by_source.items():
        ordered = sorted(grouped, key=lambda event: event.moment())
        for cluster in _window_groups(ordered, window):
            if len(cluster) < 3:
                continue
            if not any(
                SEVERITY_RANK.get(event.severity, 0) >= SEVERITY_RANK["MEDIUM"] for event in cluster
            ):
                continue
            ids = sorted(event.id for event in cluster)
            hostnames = {event.hostname for event in cluster if event.hostname}
            drafts.append(
                CorrelationDraft(
                    rule_id=rule.id,
                    event_ids=ids,
                    primary_ip=source,
                    hostname=sorted(hostnames)[0] if len(hostnames) == 1 else None,
                    explanation=(
                        f"{len(cluster)} events from source {source} within "
                        f"{window_minutes} minutes, including at least one "
                        f"MEDIUM-or-higher severity event."
                    ),
                )
            )
    return drafts


ALL_RULES = (rule_multi_source_target, rule_vuln_exposure, rule_repeated_source)


def apply_all_rules(events: list[EventView]) -> list[CorrelationDraft]:
    """Run every rule; drafts are deduplicated by (rule, evidence set)."""
    seen: set[tuple[str, tuple[str, ...]]] = set()
    drafts: list[CorrelationDraft] = []
    for rule_fn in ALL_RULES:
        for draft in rule_fn(events):
            key = (draft.rule_id, tuple(draft.event_ids))
            if key not in seen:
                seen.add(key)
                drafts.append(draft)
    return drafts
