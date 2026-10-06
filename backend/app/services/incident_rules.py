"""Step 29 analysis rules (deterministic incident intelligence, stored data only).

Pure, bounded, explainable rule functions over the evidence events of one
incident. Same input rows → same drafts, always. Drafts become
``IncidentRelationship`` rows only through ``incident_analysis``.

These rules extend — but never modify — the Step 24 catalog in
``correlation_rules``: they never produce ``Correlation`` rows and never
run inside ``POST /correlations/recompute``, so the Step 24 contract
(rules_evaluated == 3, pinned by tests) stays byte-for-byte unchanged.

Rule model (spec §2 — every rule has all of this):

- stable rule ``id``; ``name``; ``description``; operator ``enabled``
  state (static field AND the server-side ``correlation_disabled_rules``
  CSV — never client input); bounded ``window_minutes``; literal
  deterministic ``conditions`` (documentation-grade, never parsed); a
  fixed ``confidence``; and an explanation built by the rule itself.

Catalog (id — window — confidence → label):

- ``entity-event-asset``      — evidence span   — 90 → DIRECT
- ``entity-event-user``       — evidence span   — 85 → DIRECT
- ``entity-event-indicator``  — evidence span   — 80 → STRONG
- ``temporal-auth-sequence``  — 60 min default  — 75 → STRONG   (§3)
- ``vulnerability-activity-link`` — 24 h         — 70 → STRONG
- ``cross-source-observation``— 60 min default  — 65 → MODERATE (§4)
- ``same-entity-window``      — 5 min default   — 60 → MODERATE (§11)
- ``same-host-repeated-activity`` — 15 min      — 45 → WEAK

Confidence labels (§11) are DETERMINISTIC RELATIONSHIP DESCRIPTIONS, not
machine-learning predictions: ``DIRECT`` (≥85), ``STRONG`` (≥70),
``MODERATE`` (≥55), ``WEAK`` (<55). Every stored relationship explains
the window and shared fields it was built from; Step 25 risk scoring
remains the authoritative incident risk mechanism (§11/§12).

Bounds: effective windows are ``min(rule window, server setting,
7-day hard ceiling)`` — settings can only narrow, never widen (same
convention as Step 24). Candidates are the incident's evidence events,
already capped by ``correlation_max_events_per_operation``. Missing or
unknown fields simply produce no match: identity is never inferred
across unrelated fields, and no asset/user/IP/hostname is ever invented.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.services.correlation_rules import MAX_WINDOW_MINUTES, _window_groups, rule_enabled

# Deterministic label thresholds (documented; never probabilistic).
CONFIDENCE_LABELS: tuple[tuple[int, str], ...] = (
    (85, "DIRECT"),
    (70, "STRONG"),
    (55, "MODERATE"),
    (0, "WEAK"),
)
LABEL_DIRECT = "DIRECT"
LABEL_STRONG = "STRONG"
LABEL_MODERATE = "MODERATE"
LABEL_WEAK = "WEAK"

ANALYSIS_VERSION = "1.0.0"

# Node vocabulary for relationships (§8): only kinds the platform can
# prove from stored fields. "unknown" is represented by absence — rows
# are simply not created.
KIND_EVENT = "event"
KIND_ASSET = "asset"
KIND_USER = "user"
KIND_INDICATOR = "indicator"
KINDS = (KIND_EVENT, KIND_ASSET, KIND_USER, KIND_INDICATOR)

# Auth classification vocabulary (closed, documented, field-based).
AUTH_TYPE_TOKENS = ("AUTH", "LOGIN")
FAILURE_TOKENS = ("fail", "denied", "invalid", "unsuccessful", "bad_password", "reject")
SUCCESS_TOKENS = ("success", "accept", "authenticated", "valid", "ok")
# Suspicious classification: canonical event_type tokens only (never a
# free-text guess from titles or descriptions).
SUSPICIOUS_TYPE_TOKENS = ("SUSPICIOUS", "MALWARE", "EXPLOIT", "THREAT")

ROLE_FOLLOWED = "followed_by"
ROLE_CO_OBSERVED = "co_observed"
ROLE_PAIRED = "paired_activity"
ROLE_REPEATED = "repeated_activity"
ROLE_RELATED_FINDING = "related_finding"
ROLE_OBSERVED_ON = "observed_on"
ROLE_USER_OBSERVED = "user_observed"
ROLE_INDICATOR = "observed_indicator"


def confidence_label(confidence: int) -> str:
    """Deterministic label for a rule confidence (spec §11)."""
    value = max(min(int(confidence), 100), 0)
    for minimum, label in CONFIDENCE_LABELS:
        if value >= minimum:
            return label
    return LABEL_WEAK  # unreachable: bands cover 0-100


@dataclass(frozen=True)
class AnalysisRuleDefinition:
    """Step 29 rule model: everything auditable, nothing executable."""

    id: str
    name: str
    description: str
    window_minutes: int
    confidence: int
    enabled: bool = True
    conditions: tuple[str, ...] = ()


ANALYSIS_RULES: dict[str, AnalysisRuleDefinition] = {
    "entity-event-asset": AnalysisRuleDefinition(
        id="entity-event-asset",
        name="Event observed on an inventoried asset",
        description="An evidence event whose normalized fields match a stored asset row.",
        window_minutes=MAX_WINDOW_MINUTES,
        confidence=90,
        conditions=(
            "event source_ip, destination_ip or hostname equals a stored asset address",
            "asset row must already exist (never manufactured)",
            "match is a direct field equality, not a subnet or fuzzy guess",
        ),
    ),
    "entity-event-user": AnalysisRuleDefinition(
        id="entity-event-user",
        name="Event explicitly reports a user",
        description="An evidence event that carries an explicit username field.",
        window_minutes=MAX_WINDOW_MINUTES,
        confidence=85,
        conditions=(
            "event username field is present and non-empty",
            "identity is taken only from that field (never inferred)",
        ),
    ),
    "entity-event-indicator": AnalysisRuleDefinition(
        id="entity-event-indicator",
        name="Event observed against a network indicator",
        description="An evidence event's source or destination IP stored as an indicator.",
        window_minutes=MAX_WINDOW_MINUTES,
        confidence=80,
        conditions=(
            "event source_ip or destination_ip is present",
            "indicator is stored as observed — never attributed to an identity",
        ),
    ),
    "temporal-auth-sequence": AnalysisRuleDefinition(
        id="temporal-auth-sequence",
        name="Auth failure then success then suspicious observation",
        description=(
            "Bounded temporal chain: authentication failure followed by successful "
            "authentication followed by a suspicious process/network observation."
        ),
        window_minutes=60,
        confidence=75,
        conditions=(
            "step 1: auth event with a failure outcome (status/action vocabulary)",
            "step 2: auth event with a success outcome, same pivot, within the window",
            "step 3: suspicious canonical event_type, same pivot, within the window",
            "pivot is the shared username when present on every step, else shared source_ip",
            "ordered by event_time with event-id tiebreak; no step is ever reordered",
        ),
    ),
    "vulnerability-activity-link": AnalysisRuleDefinition(
        id="vulnerability-activity-link",
        name="Finding linked to observed activity on the same host",
        description="A stored vulnerability-finding event paired with activity on its host.",
        window_minutes=24 * 60,
        confidence=70,
        conditions=(
            "one VULNERABILITY_FINDING event with destination_ip or hostname",
            "activity event shares that host key",
            "within the effective window of the finding (Step 24 cap applies)",
        ),
    ),
    "cross-source-observation": AnalysisRuleDefinition(
        id="cross-source-observation",
        name="Multiple sensors co-observed one destination",
        description=(
            "Events from at least two distinct source types sharing one destination "
            "IP inside the configured window."
        ),
        window_minutes=60,
        confidence=65,
        conditions=(
            "destination_ip is present",
            "at least 2 distinct source_type values in the window group",
            "reason is the shared destination field, never proximity alone",
        ),
    ),
    "same-entity-window": AnalysisRuleDefinition(
        id="same-entity-window",
        name="Same asset and source IP inside one window",
        description="Two or more events sharing source IP and destination IP in a short window.",
        window_minutes=5,
        confidence=60,
        conditions=(
            "source_ip and destination_ip both present and equal across events",
            "within the configured entity window (default 5 minutes)",
        ),
    ),
    "same-host-repeated-activity": AnalysisRuleDefinition(
        id="same-host-repeated-activity",
        name="Repeated activity from one source (weak alone)",
        description=(
            "Three or more events from one source IP inside the repeated-activity "
            "window; grouped as a weak lead that needs corroboration."
        ),
        window_minutes=15,
        confidence=45,
        conditions=(
            "source_ip is present",
            "at least 3 events within the effective window",
        ),
    ),
}


def effective_window_minutes(rule_id: str) -> int:
    """Effective (narrowed) window for one Step 29 rule.

    ``min(rule window, server setting for that rule, 7-day hard ceiling)``
    — the setting can only narrow matching (Step 24 convention). Raises
    ``KeyError`` for unknown rule ids, same convention as Step 24.
    """
    from app.core.config import get_settings

    rule = ANALYSIS_RULES[rule_id]  # KeyError documents unknown ids
    settings = get_settings()
    if rule_id == "temporal-auth-sequence":
        configured = settings.correlation_temporal_window_minutes
    elif rule_id == "cross-source-observation":
        configured = settings.correlation_cross_source_window_minutes
    elif rule_id == "same-entity-window":
        configured = settings.correlation_entity_window_minutes
    else:
        configured = settings.correlation_max_window_minutes
    return max(1, min(rule.window_minutes, configured, MAX_WINDOW_MINUTES))


def analysis_rule_enabled(rule_id: str) -> bool:
    """Enabled state: static field AND the operator CSV (server-side only)."""
    rule = ANALYSIS_RULES[rule_id]
    return rule.enabled and rule_enabled(rule_id)


@dataclass(frozen=True)
class AnalysisEvent:
    """Normalized evidence view the Step 29 rules match on."""

    id: str
    event_time: datetime
    source_type: str
    event_type: str
    severity: str
    title: str
    source_ip: str | None
    destination_ip: str | None
    hostname: str | None
    username: str | None
    action: str | None
    status: str | None

    def moment(self) -> datetime:
        moment = self.event_time
        if moment.tzinfo is not None:
            moment = moment.astimezone(UTC).replace(tzinfo=None)
        return moment


@dataclass
class RelationshipDraft:
    """One deterministic relationship candidate produced by a rule."""

    rule_id: str
    relation: str
    source_kind: str
    source_id: str
    source_label: str | None
    target_kind: str
    target_id: str
    target_label: str | None
    explanation: str
    evidence_event_ids: list[str]  # sorted for deterministic identity
    first_seen: datetime
    last_seen: datetime


def _label(event: AnalysisEvent) -> str:
    return event.title[:120] or event.event_type


def _pivot(events: list[AnalysisEvent]) -> tuple[str, str] | None:
    """Shared pivot across every event of a candidate chain.

    Username only when explicitly present and identical on ALL events;
    otherwise the shared source IP. Returns None when neither is shared —
    identity is never inferred across unrelated fields.
    """
    usernames = [event.username for event in events]
    if all(usernames):
        distinct = {value for value in usernames if value}
        if len(distinct) == 1:
            return ("user", next(iter(distinct)))
    addresses = [event.source_ip for event in events]
    if all(addresses):
        distinct = {value for value in addresses if value}
        if len(distinct) == 1:
            return ("source_ip", next(iter(distinct)))
    return None


def _star(
    rule: AnalysisRuleDefinition,
    relation: str,
    anchor: AnalysisEvent,
    others: list[AnalysisEvent],
    evidence: list[AnalysisEvent],
    explanation: str,
) -> list[RelationshipDraft]:
    """Anchor event -> each other event (bounded, deterministic)."""
    moments = sorted(event.moment() for event in evidence)
    ids = sorted(event.id for event in evidence)
    return [
        RelationshipDraft(
            rule_id=rule.id,
            relation=relation,
            source_kind=KIND_EVENT,
            source_id=anchor.id,
            source_label=_label(anchor),
            target_kind=KIND_EVENT,
            target_id=other.id,
            target_label=_label(other),
            explanation=explanation,
            evidence_event_ids=ids,
            first_seen=moments[0],
            last_seen=moments[-1],
        )
        for other in others
        if other.id != anchor.id
    ]


def rule_entity_event_asset(
    events: list[AnalysisEvent], known_assets: dict[str, str]
) -> list[RelationshipDraft]:
    rule = ANALYSIS_RULES["entity-event-asset"]
    if not analysis_rule_enabled(rule.id):
        return []
    drafts: list[RelationshipDraft] = []
    for event in events:
        matched: list[tuple[str, str, str]] = []  # (field, value, asset_id)
        for field, value in (
            ("destination_ip", event.destination_ip),
            ("source_ip", event.source_ip),
            ("hostname", event.hostname),
        ):
            if not value:
                continue
            asset_id = known_assets.get(value)
            if asset_id:
                matched.append((field, value, asset_id))
        seen: set[str] = set()
        for field, value, asset_id in matched:
            if asset_id in seen:
                continue
            seen.add(asset_id)
            drafts.append(
                RelationshipDraft(
                    rule_id=rule.id,
                    relation=ROLE_OBSERVED_ON,
                    source_kind=KIND_EVENT,
                    source_id=event.id,
                    source_label=_label(event),
                    target_kind=KIND_ASSET,
                    target_id=asset_id,
                    target_label=value,
                    explanation=(
                        f"Event {event.id} reports {field}={value}, which equals stored asset "
                        f"{asset_id} — direct field match, no inference and no manufactured asset."
                    ),
                    evidence_event_ids=[event.id],
                    first_seen=event.moment(),
                    last_seen=event.moment(),
                )
            )
    return drafts


def rule_entity_event_user(
    events: list[AnalysisEvent], known_assets: dict[str, str]
) -> list[RelationshipDraft]:
    rule = ANALYSIS_RULES["entity-event-user"]
    if not analysis_rule_enabled(rule.id):
        return []
    drafts: list[RelationshipDraft] = []
    for event in events:
        if not event.username:
            continue
        drafts.append(
            RelationshipDraft(
                rule_id=rule.id,
                relation=ROLE_USER_OBSERVED,
                source_kind=KIND_EVENT,
                source_id=event.id,
                source_label=_label(event),
                target_kind=KIND_USER,
                target_id=event.username,
                target_label=event.username,
                explanation=(
                    f"Event {event.id} explicitly reports username '{event.username}'. "
                    "The identity comes from the event field only — never inferred from "
                    "addresses, hostnames or timing."
                ),
                evidence_event_ids=[event.id],
                first_seen=event.moment(),
                last_seen=event.moment(),
            )
        )
    return drafts


def rule_entity_event_indicator(
    events: list[AnalysisEvent], known_assets: dict[str, str]
) -> list[RelationshipDraft]:
    rule = ANALYSIS_RULES["entity-event-indicator"]
    if not analysis_rule_enabled(rule.id):
        return []
    drafts: list[RelationshipDraft] = []
    for event in events:
        seen: set[str] = set()
        for field, value in (
            ("source_ip", event.source_ip),
            ("destination_ip", event.destination_ip),
        ):
            if not value or value in seen:
                continue
            seen.add(value)
            drafts.append(
                RelationshipDraft(
                    rule_id=rule.id,
                    relation=ROLE_INDICATOR,
                    source_kind=KIND_EVENT,
                    source_id=event.id,
                    source_label=_label(event),
                    target_kind=KIND_INDICATOR,
                    target_id=value,
                    target_label=value,
                    explanation=(
                        f"Event {event.id} reports {field}={value}. Stored as an observed "
                        "network indicator — not attributed to any user, asset or identity."
                    ),
                    evidence_event_ids=[event.id],
                    first_seen=event.moment(),
                    last_seen=event.moment(),
                )
            )
    return drafts


def _is_auth_event(event: AnalysisEvent) -> bool:
    upper = (event.event_type or "").upper()
    return any(token in upper for token in AUTH_TYPE_TOKENS)


def auth_outcome(event: AnalysisEvent) -> str | None:
    """Deterministic outcome from documented status/action vocabulary."""
    text = " ".join(part for part in (event.status, event.action) if part).lower()
    if not text:
        return None
    if any(token in text for token in FAILURE_TOKENS):
        return "failure"
    if any(token in text for token in SUCCESS_TOKENS):
        return "success"
    return None


def is_suspicious(event: AnalysisEvent) -> bool:
    upper = (event.event_type or "").upper()
    return any(token in upper for token in SUSPICIOUS_TYPE_TOKENS)


def rule_temporal_auth_sequence(
    events: list[AnalysisEvent], known_assets: dict[str, str]
) -> list[RelationshipDraft]:
    rule = ANALYSIS_RULES["temporal-auth-sequence"]
    if not analysis_rule_enabled(rule.id):
        return []
    window = timedelta(minutes=effective_window_minutes(rule.id))
    ordered = sorted(events, key=lambda event: (event.moment(), event.id))
    failures = [
        event for event in ordered if _is_auth_event(event) and auth_outcome(event) == "failure"
    ]
    successes = [
        event for event in ordered if _is_auth_event(event) and auth_outcome(event) == "success"
    ]
    suspicious = [event for event in ordered if is_suspicious(event)]
    drafts: list[RelationshipDraft] = []
    for failure in failures:
        chain_pivot: tuple[str, str] | None = None
        success = None
        for candidate in successes:
            if candidate.moment() < failure.moment():
                continue
            if candidate.moment() - failure.moment() > window:
                break  # ordered: no later success can fit either
            pair = _pivot([failure, candidate])
            if pair is None:
                continue
            success = candidate
            chain_pivot = pair
            break
        if success is None or chain_pivot is None:
            continue
        suspicious_event = None
        for candidate in suspicious:
            if candidate.moment() < success.moment():
                continue
            if candidate.moment() - success.moment() > window:
                break
            if _pivot([success, candidate]) != chain_pivot:
                continue
            suspicious_event = candidate
            break
        if suspicious_event is None:
            continue
        chain = [failure, success, suspicious_event]
        if _pivot(chain) != chain_pivot:
            continue
        pivot_kind, pivot_value = chain_pivot
        pivot_label = (
            f"user '{pivot_value}'" if pivot_kind == "user" else f"source IP {pivot_value}"
        )
        window_minutes = int(window.total_seconds() // 60)
        evidence = sorted(chain, key=lambda event: (event.moment(), event.id))
        explanation = (
            f"Authentication failure then successful authentication then suspicious "
            f"observation for {pivot_label} within the configured {window_minutes}-minute "
            f"correlation window (ordered by timestamp; chain "
            f"{failure.id} -> {success.id} -> {suspicious_event.id})."
        )
        moments = sorted(event.moment() for event in evidence)
        ids = sorted(event.id for event in evidence)
        for source, target in ((failure, success), (success, suspicious_event)):
            drafts.append(
                RelationshipDraft(
                    rule_id=rule.id,
                    relation=ROLE_FOLLOWED,
                    source_kind=KIND_EVENT,
                    source_id=source.id,
                    source_label=_label(source),
                    target_kind=KIND_EVENT,
                    target_id=target.id,
                    target_label=_label(target),
                    explanation=explanation,
                    evidence_event_ids=ids,
                    first_seen=moments[0],
                    last_seen=moments[-1],
                )
            )
    return drafts


def rule_vulnerability_activity_link(
    events: list[AnalysisEvent], known_assets: dict[str, str]
) -> list[RelationshipDraft]:
    from app.services.correlation_rules import effective_window_minutes as step24_window

    rule = ANALYSIS_RULES["vulnerability-activity-link"]
    if not analysis_rule_enabled(rule.id):
        return []
    window_minutes = step24_window("vuln-exposure")
    window = timedelta(minutes=window_minutes)
    findings = [event for event in events if event.event_type == "VULNERABILITY_FINDING"]
    activity = [event for event in events if event.event_type != "VULNERABILITY_FINDING"]
    drafts: list[RelationshipDraft] = []
    for finding in findings:
        keys = {key for key in (finding.destination_ip, finding.hostname) if key}
        if not keys:
            continue
        matched = [
            event
            for event in activity
            if keys & ({event.source_ip, event.destination_ip, event.hostname} - {None})
            and abs(event.moment() - finding.moment()) <= window
        ]
        if not matched:
            continue
        pivot = finding.destination_ip or finding.hostname
        explanation = (
            f"Vulnerability finding {finding.id} and {len(matched)} observed activity "
            f"event(s) share host {pivot} within {window_minutes} minutes — the finding "
            "alone never creates this relationship."
        )
        drafts.extend(
            _star(rule, ROLE_RELATED_FINDING, finding, matched, [finding, *matched], explanation)
        )
    return drafts


def rule_cross_source_observation(
    events: list[AnalysisEvent], known_assets: dict[str, str]
) -> list[RelationshipDraft]:
    rule = ANALYSIS_RULES["cross-source-observation"]
    if not analysis_rule_enabled(rule.id):
        return []
    window_minutes = effective_window_minutes(rule.id)
    window = timedelta(minutes=window_minutes)
    by_target: dict[str, list[AnalysisEvent]] = {}
    for event in events:
        if event.destination_ip:
            by_target.setdefault(event.destination_ip, []).append(event)
    drafts: list[RelationshipDraft] = []
    for target, grouped in by_target.items():
        ordered = sorted(grouped, key=lambda event: (event.moment(), event.id))
        for cluster in _window_groups(ordered, window):
            sources = sorted({event.source_type for event in cluster})
            if len(sources) < 2 or len(cluster) < 2:
                continue
            anchor = cluster[0]
            others = cluster[1:]
            explanation = (
                f"{len(cluster)} events from {len(sources)} distinct sources "
                f"({', '.join(sources)}) share destination {target} within the configured "
                f"{window_minutes}-minute window — the shared destination field is the "
                "explicit reason; timing alone never correlates events."
            )
            drafts.extend(_star(rule, ROLE_CO_OBSERVED, anchor, others, cluster, explanation))
    return drafts


def rule_same_entity_window(
    events: list[AnalysisEvent], known_assets: dict[str, str]
) -> list[RelationshipDraft]:
    rule = ANALYSIS_RULES["same-entity-window"]
    if not analysis_rule_enabled(rule.id):
        return []
    window_minutes = effective_window_minutes(rule.id)
    window = timedelta(minutes=window_minutes)
    by_pair: dict[tuple[str, str], list[AnalysisEvent]] = {}
    for event in events:
        if event.source_ip and event.destination_ip:
            by_pair.setdefault((event.source_ip, event.destination_ip), []).append(event)
    drafts: list[RelationshipDraft] = []
    for (source_ip, destination_ip), grouped in sorted(by_pair.items()):
        ordered = sorted(grouped, key=lambda event: (event.moment(), event.id))
        for cluster in _window_groups(ordered, window):
            if len(cluster) < 2:
                continue
            anchor = cluster[0]
            others = cluster[1:]
            explanation = (
                f"Same asset and source IP observed within the configured "
                f"{window_minutes}-minute correlation window "
                f"(source {source_ip}, asset {destination_ip}, {len(cluster)} events)."
            )
            drafts.extend(_star(rule, ROLE_PAIRED, anchor, others, cluster, explanation))
    return drafts


def rule_same_host_repeated_activity(
    events: list[AnalysisEvent], known_assets: dict[str, str]
) -> list[RelationshipDraft]:
    from app.services.correlation_rules import effective_window_minutes as step24_window

    rule = ANALYSIS_RULES["same-host-repeated-activity"]
    if not analysis_rule_enabled(rule.id):
        return []
    window_minutes = step24_window("repeated-source")
    window = timedelta(minutes=window_minutes)
    by_source: dict[str, list[AnalysisEvent]] = {}
    for event in events:
        if event.source_ip:
            by_source.setdefault(event.source_ip, []).append(event)
    drafts: list[RelationshipDraft] = []
    for source, grouped in sorted(by_source.items()):
        ordered = sorted(grouped, key=lambda event: (event.moment(), event.id))
        for cluster in _window_groups(ordered, window):
            if len(cluster) < 3:
                continue
            anchor = cluster[0]
            others = cluster[1:]
            explanation = (
                f"{len(cluster)} events from source {source} within {window_minutes} minutes. "
                "Grouped as repeated activity — labelled WEAK on its own; it needs "
                "corroboration from another rule before it means anything."
            )
            drafts.extend(_star(rule, ROLE_REPEATED, anchor, others, cluster, explanation))
    return drafts


ANALYSIS_RULE_FUNCTIONS = (
    rule_entity_event_asset,
    rule_entity_event_user,
    rule_entity_event_indicator,
    rule_temporal_auth_sequence,
    rule_vulnerability_activity_link,
    rule_cross_source_observation,
    rule_same_entity_window,
    rule_same_host_repeated_activity,
)


def apply_analysis_rules(
    events: list[AnalysisEvent], known_assets: dict[str, str]
) -> list[RelationshipDraft]:
    """Run every Step 29 rule; drafts deduplicated by relationship identity."""
    seen: set[tuple[str, str, str, str, str]] = set()
    drafts: list[RelationshipDraft] = []
    for rule_fn in ANALYSIS_RULE_FUNCTIONS:
        for draft in rule_fn(events, known_assets):
            key = (
                draft.rule_id,
                draft.source_kind,
                draft.source_id,
                draft.target_kind,
                draft.target_id,
            )
            if key in seen:
                continue
            seen.add(key)
            drafts.append(draft)
    return drafts


__all__ = [
    "ANALYSIS_RULES",
    "ANALYSIS_RULE_FUNCTIONS",
    "ANALYSIS_VERSION",
    "CONFIDENCE_LABELS",
    "KINDS",
    "LABEL_DIRECT",
    "LABEL_MODERATE",
    "LABEL_STRONG",
    "LABEL_WEAK",
    "AnalysisEvent",
    "AnalysisRuleDefinition",
    "RelationshipDraft",
    "analysis_rule_enabled",
    "apply_analysis_rules",
    "auth_outcome",
    "confidence_label",
    "effective_window_minutes",
    "is_suspicious",
]
