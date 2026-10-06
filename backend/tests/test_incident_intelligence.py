"""Step 29 incident-intelligence tests.

Covers spec §18 plus adversarial and bound cases: rule model shape and
confidence labels, disabled rules, temporal chains (positive and
negative), multi-source analysis, entity/asset/user/indicator links,
idempotent recalculation with audits, evidence and timeline
extensions, the relationships API (filters, pagination, bounds),
correlation confidence labels, the informational risk factor,
no-body enforcement, RBAC, no fabrication, no merge/split, the
migration, and AST-level regressions — without weakening Steps 1-28.
"""

import json
from datetime import datetime
from pathlib import Path

from app.core.config import get_settings

FIXTURES = Path(__file__).parent / "fixtures" / "correlation"


def _fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _ingest(client, *names):
    for name in names:
        response = client.post("/api/v1/events", json=_fixture(name))
        assert response.status_code == 201, name


def _recompute(client):
    response = client.post("/api/v1/correlations/recompute")
    assert response.status_code == 200
    return response.json()


def _correlations(client, **params):
    return client.get("/api/v1/correlations", params=params).json()["items"]


def _detect(client, correlation_id):
    body = client.post("/api/v1/incidents/detect", json={"correlation_id": correlation_id}).json()
    assert body["created"] == 1, body
    return body["outcomes"][0]["incident_id"]


def _recalc(client, incident_id, payload=None):
    url = f"/api/v1/incidents/{incident_id}/recalculate"
    if payload is None:
        return client.post(url)
    return client.post(url, json=payload)


def _audit_actions(client, incident_id):
    entries = client.get(f"/api/v1/incidents/{incident_id}/audit").json()["entries"]
    return [entry["action"] for entry in entries]


def _post_event(client, **overrides):
    payload = {
        "source_type": "WAZUH",
        "source_name": "step29-wazuh",
        "event_type": "WAZUH_AUTH",
        "severity": "MEDIUM",
        "title": "Step 29 event",
        "event_time": "2026-09-27T07:00:00Z",
        "source_ip": "203.0.113.9",
        "destination_ip": "192.0.2.77",
        "username": "alice",
        "external_event_id": "step29-unique-1",
    }
    payload.update(overrides)
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _insert_asset(ip, hostname=None):
    from sqlalchemy import select

    from app.database import session as session_module
    from app.models.assets import Asset

    db = session_module.get_session_factory()()
    try:
        existing = db.scalar(select(Asset).where(Asset.ip_address == ip))
        if existing:
            return existing.id
        asset = Asset(ip_address=ip, hostname=hostname)
        db.add(asset)
        db.commit()
        return asset.id
    finally:
        db.close()


def _seed_auth_chain(client):
    """Three events (failure -> success -> suspicious), one correlation.

    Returns (incident_id, [event_id, event_id, event_id]).
    """
    first = _post_event(
        client, event_time="2026-09-27T07:00:00Z", status="failure", external_event_id="s29-1"
    )
    second = _post_event(
        client,
        event_type="WAZUH_AUTH",
        event_time="2026-09-27T07:05:00Z",
        severity="HIGH",
        status="success",
        title="Authentication succeeded",
        external_event_id="s29-2",
    )
    third = _post_event(
        client,
        event_type="WAZUH_SUSPICIOUS",
        event_time="2026-09-27T07:10:00Z",
        severity="HIGH",
        status=None,
        title="Suspicious process observed",
        external_event_id="s29-3",
    )
    _recompute(client)
    matches = _correlations(client, rule_id="repeated-source")
    assert len(matches) == 1, matches
    incident_id = _detect(client, matches[0]["id"])
    # Stored asset so entity-event-asset contributes its three DIRECT rows (18 total).
    _insert_asset("192.0.2.77", "workstation-77")
    return incident_id, [first, second, third]


def _seed_chain_a_incident(client):
    """Multi-source incident: SURICATA + ZEEK + WAZUH on one destination."""
    _ingest(client, "chain_a_1.json", "chain_a_2.json", "chain_a_3.json")
    _recompute(client)
    matches = _correlations(client, rule_id="multi-source-target")
    assert len(matches) == 1, matches
    return _detect(client, matches[0]["id"])


def _seed_vuln_incident(client):
    """Finding + activity on 192.0.2.50 (qualifies by construction)."""
    _ingest(client, "vuln.json", "vuln_activity.json")
    _recompute(client)
    matches = _correlations(client, rule_id="vuln-exposure")
    assert len(matches) == 1, matches
    return _detect(client, matches[0]["id"])


def _configure(monkeypatch, **overrides):
    for key, value in overrides.items():
        monkeypatch.setenv(key, str(value))
    get_settings.cache_clear()
    return get_settings()


def _analysis_event(**overrides):
    from app.services.incident_rules import AnalysisEvent

    defaults = {
        "id": "evt-1",
        "event_time": datetime(2026, 9, 27, 7, 0),
        "source_type": "WAZUH",
        "event_type": "WAZUH_AUTH",
        "severity": "HIGH",
        "title": "Auth event",
        "source_ip": "203.0.113.9",
        "destination_ip": "192.0.2.77",
        "hostname": None,
        "username": "alice",
        "action": None,
        "status": "failure",
    }
    defaults.update(overrides)
    return AnalysisEvent(**defaults)


def test_rule_model_shape_and_confidence_labels():
    from app.services.incident_rules import (
        ANALYSIS_RULE_FUNCTIONS,
        ANALYSIS_RULES,
        confidence_label,
    )

    expected = {
        "entity-event-asset": (90, "DIRECT"),
        "entity-event-user": (85, "DIRECT"),
        "entity-event-indicator": (80, "STRONG"),
        "temporal-auth-sequence": (75, "STRONG"),
        "vulnerability-activity-link": (70, "STRONG"),
        "cross-source-observation": (65, "MODERATE"),
        "same-entity-window": (60, "MODERATE"),
        "same-host-repeated-activity": (45, "WEAK"),
    }
    assert set(ANALYSIS_RULES) == set(expected)
    assert len(ANALYSIS_RULE_FUNCTIONS) == len(ANALYSIS_RULES) == 8
    for rule_id, (confidence, label) in expected.items():
        rule = ANALYSIS_RULES[rule_id]
        assert rule.id == rule_id
        assert rule.name and rule.description
        assert rule.confidence == confidence
        assert rule.enabled is True
        assert rule.conditions, rule_id  # every rule documents its conditions
        for condition in rule.conditions:
            assert isinstance(condition, str) and condition.strip()
        assert confidence_label(confidence) == label
    # Deterministic label bands (§11): labels describe rule confidence.
    assert confidence_label(85) == "DIRECT"
    assert confidence_label(84) == "STRONG"
    assert confidence_label(70) == "STRONG"
    assert confidence_label(69) == "MODERATE"
    assert confidence_label(55) == "MODERATE"
    assert confidence_label(54) == "WEAK"
    assert confidence_label(0) == "WEAK"
    assert confidence_label(100) == "DIRECT"
    assert confidence_label(-5) == "WEAK"  # clamped, never crashes


def test_effective_windows_are_bounded(monkeypatch):
    from app.services.incident_rules import ANALYSIS_RULES, effective_window_minutes

    get_settings.cache_clear()
    # Defaults match the documented windows.
    assert effective_window_minutes("temporal-auth-sequence") == 60
    assert effective_window_minutes("cross-source-observation") == 60
    assert effective_window_minutes("same-entity-window") == 5
    # The setting narrows (never widens) the rule window.
    _configure(monkeypatch, CORRELATION_TEMPORAL_WINDOW_MINUTES="10")
    assert effective_window_minutes("temporal-auth-sequence") == 10
    _configure(monkeypatch, CORRELATION_TEMPORAL_WINDOW_MINUTES="5000")
    assert effective_window_minutes("temporal-auth-sequence") == 60  # rule window caps it
    _configure(monkeypatch, CORRELATION_ENTITY_WINDOW_MINUTES="1")
    assert effective_window_minutes("same-entity-window") == 1
    _configure(monkeypatch)  # recompute settings; earlier envs from this test persist
    # Unknown ids fail loudly (same convention as Step 24).
    try:
        effective_window_minutes("no-such-rule")
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for unknown rule id")
    for rule_id in ANALYSIS_RULES:
        assert 1 <= effective_window_minutes(rule_id) <= 7 * 24 * 60


def test_disabled_rules_produce_no_drafts(monkeypatch):
    from app.services.correlation_rules import (
        EventView,
        rule_enabled,
        rule_repeated_source,
    )
    from app.services.incident_rules import (
        ANALYSIS_RULES,
        analysis_rule_enabled,
        rule_cross_source_observation,
        rule_temporal_auth_sequence,
    )

    chain = [
        _analysis_event(
            id="evt-1",
            event_time=datetime(2026, 9, 27, 7, 0),
            status="failure",
        ),
        _analysis_event(
            id="evt-2",
            event_time=datetime(2026, 9, 27, 7, 5),
            status="success",
        ),
        _analysis_event(
            id="evt-3",
            event_time=datetime(2026, 9, 27, 7, 10),
            event_type="WAZUH_SUSPICIOUS",
            status=None,
        ),
    ]
    assert len(rule_temporal_auth_sequence(chain, {})) == 2  # both edges present

    _configure(
        monkeypatch,
        CORRELATION_DISABLED_RULES="temporal-auth-sequence, cross-source-observation, repeated-source",
    )
    assert analysis_rule_enabled("temporal-auth-sequence") is False
    assert rule_temporal_auth_sequence(chain, {}) == []
    assert rule_cross_source_observation(chain, {}) == []
    assert analysis_rule_enabled("entity-event-user") is True
    # Unknown ids in the CSV are ignored; the catalog itself never changes.
    assert set(ANALYSIS_RULES) == {
        "entity-event-asset",
        "entity-event-user",
        "entity-event-indicator",
        "temporal-auth-sequence",
        "vulnerability-activity-link",
        "cross-source-observation",
        "same-entity-window",
        "same-host-repeated-activity",
    }
    # The Step 24 catalog reads the same operator switch.
    assert rule_enabled("repeated-source") is False
    views = [
        EventView(
            id="e1",
            event_time=chain[0].event_time,
            source_type="WAZUH",
            event_type="WAZUH_AUTH",
            severity="HIGH",
            title="t",
            source_ip="203.0.113.9",
            destination_ip=None,
            hostname=None,
        )
    ] * 3
    assert rule_repeated_source(views) == []
    _configure(monkeypatch, CORRELATION_DISABLED_RULES="")  # clear the operator CSV
    assert rule_enabled("repeated-source") is True


def test_auth_and_suspicious_predicates():
    from app.services.incident_rules import auth_outcome, is_suspicious

    assert auth_outcome(_analysis_event(status="failure")) == "failure"
    assert auth_outcome(_analysis_event(status="denied")) == "failure"
    assert auth_outcome(_analysis_event(status="success")) == "success"
    assert auth_outcome(_analysis_event(status="authenticated")) == "success"
    assert auth_outcome(_analysis_event(status="weird", action="denied")) == "failure"
    assert auth_outcome(_analysis_event(status=None, action=None)) is None
    assert auth_outcome(_analysis_event(status="in-progress")) is None
    assert is_suspicious(_analysis_event(event_type="WAZUH_SUSPICIOUS")) is True
    assert is_suspicious(_analysis_event(event_type="SURICATA_ALERT")) is False
    assert is_suspicious(_analysis_event(event_type="MALWARE_DETECTION")) is True


def test_temporal_chain_positive_and_negatives():
    from datetime import timedelta

    from app.services.incident_rules import rule_temporal_auth_sequence

    def chain_events(start, pivot_break=False):
        shared = {"username": None} if pivot_break else {"username": "alice"}
        sources = (
            ("203.0.113.9", "198.51.100.7", "203.0.113.44")
            if pivot_break
            else ("203.0.113.9", "203.0.113.9", "203.0.113.9")
        )
        return [
            _analysis_event(
                id="f", event_time=start, status="failure", source_ip=sources[0], **shared
            ),
            _analysis_event(
                id="s",
                event_time=start + timedelta(minutes=5),
                status="success",
                source_ip=sources[1],
                **shared,
            ),
            _analysis_event(
                id="c",
                event_time=start + timedelta(minutes=8),
                event_type="WAZUH_SUSPICIOUS",
                status=None,
                source_ip=sources[2],
                **shared,
            ),
        ]

    drafts = rule_temporal_auth_sequence(chain_events(datetime(2026, 9, 27, 7, 0)), {})
    assert len(drafts) == 2
    pairs = {(draft.source_id, draft.target_id) for draft in drafts}
    assert pairs == {("f", "s"), ("s", "c")}
    assert all(draft.relation == "followed_by" for draft in drafts)
    assert all(draft.evidence_event_ids == ["c", "f", "s"] for draft in drafts)
    explanation = drafts[0].explanation
    assert "60-minute correlation window" in explanation
    assert "user 'alice'" in explanation
    assert "f -> s -> c" in explanation

    # Success before failure: no chain, no drafts.
    reordered = [
        _analysis_event(id="s", event_time=datetime(2026, 9, 27, 7, 0), status="success"),
        _analysis_event(id="f", event_time=datetime(2026, 9, 27, 7, 5), status="failure"),
        _analysis_event(
            id="c",
            event_time=datetime(2026, 9, 27, 7, 10),
            event_type="WAZUH_SUSPICIOUS",
            status=None,
        ),
    ]
    assert rule_temporal_auth_sequence(reordered, {}) == []

    # No shared pivot across the chain: identity is never guessed.
    assert (
        rule_temporal_auth_sequence(chain_events(datetime(2026, 9, 27, 7, 0), pivot_break=True), {})
        == []
    )

    # Success outside the window: nothing is correlated across time.
    far = chain_events(datetime(2026, 9, 27, 5, 0))
    far[1] = _analysis_event(
        id="s",
        event_time=datetime(2026, 9, 27, 7, 0),  # 120 minutes after the failure
        status="success",
    )
    far[2] = _analysis_event(
        id="c",
        event_time=datetime(2026, 9, 27, 7, 5),
        event_type="WAZUH_SUSPICIOUS",
        status=None,
    )
    assert rule_temporal_auth_sequence(far, {}) == []

    # Failure only: nothing follows it.
    assert rule_temporal_auth_sequence([_analysis_event(id="f", status="failure")], {}) == []


def test_apply_analysis_rules_is_deterministic():
    from app.services.incident_rules import apply_analysis_rules

    events = [
        _analysis_event(id="e1", event_time=datetime(2026, 9, 27, 7, 0)),
        _analysis_event(
            id="e2",
            event_time=datetime(2026, 9, 27, 7, 5),
            status="success",
        ),
        _analysis_event(
            id="e3",
            event_time=datetime(2026, 9, 27, 7, 10),
            event_type="WAZUH_SUSPICIOUS",
            status=None,
        ),
    ]
    assets = {"192.0.2.77": "asset-1"}
    first = apply_analysis_rules(events, assets)
    second = apply_analysis_rules(events, assets)
    assert first == second  # same input -> identical drafts
    keys = [(d.rule_id, d.source_kind, d.source_id, d.target_kind, d.target_id) for d in first]
    assert len(keys) == len(set(keys))  # deduplicated by identity
    assert first  # asset + user + indicators + temporal all fire here

    from app.services.incident_analysis import relationship_id

    same = relationship_id("inc-1", "r", "event", "e1", "asset", "a1")
    assert same == relationship_id("inc-1", "r", "event", "e1", "asset", "a1")
    assert len(same) == 64
    assert same != relationship_id("inc-2", "r", "event", "e1", "asset", "a1")
    assert same != relationship_id("inc-1", "r", "event", "e1", "user", "a1")


def test_recalculate_guards_and_idempotent_flow(client, clean_db):
    incident_id, event_ids = _seed_auth_chain(client)

    missing = _recalc(client, "does-not-exist")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "INCIDENT_NOT_FOUND"

    # Client-supplied rules/bodies are never accepted (Step 24/29 rule).
    for payload in ({"rule_id": "entity-event-user"}, {"threshold": 50}, {"enabled": True}):
        rejected = _recalc(client, incident_id, payload)
        assert rejected.status_code == 422, payload
        assert rejected.json()["error"]["code"] == "INVALID_REQUEST"

    before = _audit_actions(client, incident_id)
    empty_object = _recalc(client, incident_id, {})
    assert empty_object.status_code == 200  # {} is an accepted empty body
    first = empty_object.json()
    assert first["incident_id"] == incident_id
    assert first["analysis_version"] == "1.0.0"
    assert first["rules_evaluated"] == 8
    assert first["events_considered"] == 3
    assert first["relationships_created"] == 18
    assert first["relationships_refreshed"] == 0
    assert first["relationships_total"] == 18
    assert first["truncated"] is False
    assert first["bounds"] == {
        "max_events": 200,
        "max_relationships": 200,
        "max_evidence_per_relationship": 20,
        "temporal_window_minutes": 60,
        "cross_source_window_minutes": 60,
        "entity_window_minutes": 5,
    }

    after = _audit_actions(client, incident_id)
    assert sorted(after) == sorted(before + ["INCIDENT_RECALCULATED", "INCIDENT_CORRELATED"])

    # Idempotent: same evidence -> same relationships, no duplicates.
    second = _recalc(client, incident_id).json()
    assert second["relationships_created"] == 0
    assert second["relationships_refreshed"] == 18
    assert second["relationships_total"] == 18
    assert second["events_considered"] == 3
    after_second = _audit_actions(client, incident_id)
    assert sorted(after_second) == sorted(after + ["INCIDENT_RECALCULATED"])
    assert client.get(f"/api/v1/incidents/{incident_id}/relationships").json()["total"] == 18

    # Analysis created no evidence, no events, no assets, no responses.
    from sqlalchemy import func, select

    from app.database import session as session_module
    from app.models.assets import Asset
    from app.models.events import SecurityEvent

    db = session_module.get_session_factory()()
    try:
        assert db.scalar(select(func.count(SecurityEvent.id))) == 3
        # Only the seed's stored asset exists: analysis manufactured none.
        assert db.scalar(select(func.count(Asset.id))) == 1
    finally:
        db.close()
    assert client.get("/api/v1/responses").json()["items"] == []
    assert len(event_ids) == 3


def test_relationship_rows_explain_their_evidence(client, clean_db):
    incident_id, event_ids = _seed_auth_chain(client)
    _recalc(client, incident_id)

    body = client.get(f"/api/v1/incidents/{incident_id}/relationships").json()
    assert body["incident_id"] == incident_id
    assert body["total"] == 18
    assert body["limit"] == 50 and body["offset"] == 0
    labels = {}
    for item in body["items"]:
        assert len(item["id"]) == 64
        assert item["incident_id"] == incident_id
        assert item["explanation"]
        assert set(item["evidence_event_ids"]) <= set(event_ids)
        assert item["first_seen"] <= item["last_seen"]
        assert item["confidence_label"] in {"DIRECT", "STRONG", "MODERATE", "WEAK"}
        labels.setdefault(item["confidence_label"], set()).add(item["confidence"])
    assert labels["DIRECT"] == {90, 85}
    assert labels["STRONG"] == {80, 75}
    assert labels["MODERATE"] == {60}
    assert labels["WEAK"] == {45}
    # Strongest confidence first (deterministic total order).
    confidences = [item["confidence"] for item in body["items"]]
    assert confidences == sorted(confidences, reverse=True)

    # Rule filter (valid).
    filtered = client.get(
        f"/api/v1/incidents/{incident_id}/relationships",
        params={"rule_id": "entity-event-indicator"},
    ).json()
    assert filtered["total"] == 6
    assert {item["rule_id"] for item in filtered["items"]} == {"entity-event-indicator"}
    # Unknown rule ids are rejected, never silently ignored.
    bad = client.get(f"/api/v1/incidents/{incident_id}/relationships", params={"rule_id": "nope"})
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "INVALID_FILTER"
    # Pagination bounds.
    assert (
        client.get(
            f"/api/v1/incidents/{incident_id}/relationships", params={"limit": 0}
        ).status_code
        == 422
    )
    assert (
        client.get(
            f"/api/v1/incidents/{incident_id}/relationships", params={"limit": 201}
        ).status_code
        == 422
    )
    page = client.get(
        f"/api/v1/incidents/{incident_id}/relationships",
        params={"limit": 5, "offset": 5},
    ).json()
    assert len(page["items"]) == 5 and page["total"] == 18
    past_end = client.get(
        f"/api/v1/incidents/{incident_id}/relationships",
        params={"limit": 5, "offset": 100},
    ).json()
    assert past_end["items"] == [] and past_end["total"] == 18
    # Missing incident.
    assert client.get("/api/v1/incidents/nope/relationships").status_code == 404
    assert _recalc(client, "nope").status_code == 404


def test_temporal_relationship_rows(client, clean_db):
    incident_id, event_ids = _seed_auth_chain(client)
    _recalc(client, incident_id)
    rows = client.get(
        f"/api/v1/incidents/{incident_id}/relationships",
        params={"rule_id": "temporal-auth-sequence"},
    ).json()["items"]
    assert len(rows) == 2
    pairs = {(row["source_id"], row["target_id"]) for row in rows}
    assert pairs == {(event_ids[0], event_ids[1]), (event_ids[1], event_ids[2])}
    for row in rows:
        assert row["relation"] == "followed_by"
        assert row["confidence"] == 75
        assert row["confidence_label"] == "STRONG"
        assert row["evidence_event_ids"] == sorted(event_ids)
        assert "60-minute correlation window" in row["explanation"]
        assert row["source_kind"] == row["target_kind"] == "event"


def test_entity_rows_use_only_stored_fields(client, clean_db):
    incident_id, event_ids = _seed_auth_chain(client)
    asset_id = _insert_asset("192.0.2.77", "workstation-77")
    _recalc(client, incident_id)
    items = client.get(f"/api/v1/incidents/{incident_id}/relationships").json()["items"]

    by_rule: dict[str, list[dict]] = {}
    for item in items:
        by_rule.setdefault(item["rule_id"], []).append(item)

    asset_rows = by_rule["entity-event-asset"]
    assert len(asset_rows) == 3
    assert {row["target_id"] for row in asset_rows} == {asset_id}
    assert all(row["target_kind"] == "asset" for row in asset_rows)
    assert all(row["confidence_label"] == "DIRECT" for row in asset_rows)
    assert "no inference and no manufactured asset" in asset_rows[0]["explanation"]

    user_rows = by_rule["entity-event-user"]
    assert len(user_rows) == 3
    assert {row["target_id"] for row in user_rows} == {"alice"}
    assert all(row["target_kind"] == "user" for row in user_rows)
    assert "never inferred" in user_rows[0]["explanation"]

    indicator_rows = by_rule["entity-event-indicator"]
    assert len(indicator_rows) == 6  # source + destination per event
    assert {row["target_id"] for row in indicator_rows} == {"203.0.113.9", "192.0.2.77"}
    assert all(row["target_kind"] == "indicator" for row in indicator_rows)
    assert "not attributed to any user, asset or identity" in indicator_rows[0]["explanation"]

    same_entity = by_rule["same-entity-window"]
    assert len(same_entity) == 2
    assert same_entity[0]["explanation"].startswith(
        "Same asset and source IP observed within the configured 5-minute"
    )

    repeated = by_rule["same-host-repeated-activity"]
    assert len(repeated) == 2
    assert "WEAK" in repeated[0]["explanation"]

    # Window and identity statements are present in every explanation.
    for item in items:
        assert item["explanation"].strip()


def test_multi_source_analysis(client, clean_db):
    incident_id = _seed_chain_a_incident(client)
    _recalc(client, incident_id)
    body = client.get(f"/api/v1/incidents/{incident_id}/relationships").json()
    assert body["total"] == 8  # 6 indicator rows + 2 co-observed edges

    cross = client.get(
        f"/api/v1/incidents/{incident_id}/relationships",
        params={"rule_id": "cross-source-observation"},
    ).json()["items"]
    assert len(cross) == 2
    assert {row["confidence_label"] for row in cross} == {"MODERATE"}
    explanation = cross[0]["explanation"]
    assert "3 events from 3 distinct sources" in explanation
    for source in ("SURICATA", "ZEEK", "WAZUH"):
        assert source in explanation
    assert "198.51.100.23" in explanation
    assert "timing alone never correlates events" in explanation
    assert cross[0]["evidence_event_ids"] == sorted(cross[0]["evidence_event_ids"])
    assert len(cross[0]["evidence_event_ids"]) == 3

    # No asset or username exists here: those rows are simply absent.
    kinds = {row["source_kind"] for row in body["items"]} | {
        row["target_kind"] for row in body["items"]
    }
    assert kinds <= {"event", "indicator"}
    assert not any(row["rule_id"] == "entity-event-asset" for row in body["items"])
    assert not any(row["rule_id"] == "entity-event-user" for row in body["items"])


def test_vulnerability_link_and_no_fabrication(client, clean_db):
    incident_id = _seed_vuln_incident(client)
    _recalc(client, incident_id)

    from sqlalchemy import func, select

    from app.database import session as session_module
    from app.models.assets import Asset
    from app.models.events import SecurityEvent
    from app.models.incidents import IncidentRelationship

    db = session_module.get_session_factory()()
    try:
        # No asset rows exist and none were manufactured by analysis.
        assert db.scalar(select(func.count(Asset.id))) == 0
        assert db.scalar(select(func.count(SecurityEvent.id))) == 2
        assert (
            db.scalar(
                select(func.count(IncidentRelationship.id)).where(
                    IncidentRelationship.target_kind == "asset"
                )
            )
            == 0
        )
    finally:
        db.close()

    body = client.get(f"/api/v1/incidents/{incident_id}/relationships").json()
    assert body["total"] == 4  # 3 indicator rows + 1 finding link
    vuln_rows = [row for row in body["items"] if row["rule_id"] == "vulnerability-activity-link"]
    assert len(vuln_rows) == 1
    row = vuln_rows[0]
    assert row["relation"] == "related_finding"
    assert row["source_kind"] == row["target_kind"] == "event"
    assert len(row["evidence_event_ids"]) == 2
    assert "share host 192.0.2.50 within 1440 minutes" in row["explanation"]
    assert "the finding alone never creates this relationship" in row["explanation"]
    assert row["confidence_label"] == "STRONG"


def test_evidence_view_extensions(client, clean_db):
    incident_id = _seed_vuln_incident(client)
    _insert_asset("192.0.2.50", "exposed-host")
    _recalc(client, incident_id)

    evidence = client.get(f"/api/v1/incidents/{incident_id}/evidence").json()
    # Existing contract unchanged.
    assert evidence["incident_type"] == "VULNERABILITY_ACTIVITY"
    assert evidence["correlation"]["rule_id"] == "vuln-exposure"
    assert len(evidence["events"]) == 2
    roles = {event["id"]: event["role"] for event in evidence["events"]}
    assert set(roles.values()) == {"vulnerability", "activity"}
    assert evidence["vulnerabilities"] == []

    # Step 29 additive overview over the same references.
    assert evidence["evidence_count"] == 2
    assert evidence["truncated"] is False
    assert evidence["primary_event"]["role"] == "vulnerability"
    assert evidence["source_distribution"] == {"GENERIC": 1, "VULNERABILITY_SCANNER": 1}
    assert evidence["entities"]["destination_ips"] == ["192.0.2.50", "198.51.100.70"]
    assert evidence["entities"]["source_ips"] == ["192.0.2.50"]
    assert evidence["entities"]["usernames"] == []
    assert [asset["hostname"] for asset in evidence["assets"]] == ["exposed-host"]
    times = sorted(event["event_time"] for event in evidence["events"])
    assert evidence["first_observed"] == times[0]
    assert evidence["last_observed"] == times[-1]

    rules = {rule["rule_id"]: rule for rule in evidence["correlation_rules"]}
    assert rules["vuln-exposure"]["relationship_count"] == 0
    assert rules["vuln-exposure"]["confidence_label"] == "STRONG"  # confidence 70
    assert rules["entity-event-asset"]["relationship_count"] == 2
    assert rules["entity-event-asset"]["confidence_label"] == "DIRECT"
    assert rules["vulnerability-activity-link"]["relationship_count"] == 1
    assert "entity-event-user" not in rules  # no usernames -> no rule contribution
    assert evidence["correlation_rules"][0]["rule_id"] == "vuln-exposure"


def test_timeline_includes_events_and_keeps_lifecycle_order(client, clean_db):
    incident_id, event_ids = _seed_auth_chain(client)
    client.post(f"/api/v1/incidents/{incident_id}/status", json={"status": "ACKNOWLEDGED"})
    client.post(f"/api/v1/incidents/{incident_id}/status", json={"status": "CLOSED"})
    _recalc(client, incident_id)

    timeline = client.get(f"/api/v1/incidents/{incident_id}/timeline").json()
    kinds = [entry["kind"] for entry in timeline["entries"]]
    assert timeline["truncated"] is False
    assert kinds[0] == "observation"
    assert kinds[-1] == "resolution"
    assert kinds.count("status") == 2
    assert kinds.count("event") == 3
    assert "opened" in kinds
    stamps = [entry["at"] for entry in timeline["entries"] if entry["at"]]
    assert stamps == sorted(stamps)

    event_entries = [entry for entry in timeline["entries"] if entry["kind"] == "event"]
    assert {entry["event_id"] for entry in event_entries} == set(event_ids)  # ids are uuid4
    assert len(event_entries) == 3
    for entry in event_entries:
        assert entry["event_type"]
        assert entry["source"] == "WAZUH"
        assert entry["severity"] in {"MEDIUM", "HIGH"}
        assert entry["entity"] in {"192.0.2.77", "203.0.113.9"}
        assert entry["label"] and entry["detail"]
    assert event_entries[0]["at"] <= event_entries[-1]["at"]


def test_correlations_carry_confidence_label(client, clean_db):
    _ingest(client, "vuln.json", "vuln_activity.json")
    _recompute(client)
    items = client.get("/api/v1/correlations").json()["items"]
    assert len(items) == 1
    assert items[0]["confidence"] == 70
    assert items[0]["confidence_label"] == "STRONG"
    detail = client.get(f"/api/v1/correlations/{items[0]['id']}").json()
    assert detail["confidence_label"] == "STRONG"
    # multi-source-target confidence 75 -> STRONG as well.
    from app.services.incident_rules import confidence_label

    assert confidence_label(75) == "STRONG"
    assert confidence_label(45) == "WEAK"


def test_risk_relationship_factor_is_informational():
    from app.services import risk_service

    base = risk_service.score_incident("HIGH", 70, 2, 1, 0)
    boosted = risk_service.score_incident("HIGH", 70, 2, 1, 0, relationship_count=17)
    assert base["score"] == boosted["score"]  # formula unchanged (Step 25)
    assert base["factors"]["signal_pts"] == boosted["factors"]["signal_pts"]
    assert base["factors"]["relationship_count"] == 0
    assert boosted["factors"]["relationship_count"] == 17
    assert "informational factor" in boosted["explanation"]
    assert "informational factor" not in base["explanation"]
    # Positional Step 25 call signature still works unchanged.
    assert risk_service.score_incident("INFO", None, 0, 0, None)["score"] == 10


def test_risk_endpoint_records_relationship_count(client, clean_db):
    incident_id, _ = _seed_auth_chain(client)
    _recalc(client, incident_id)
    body = client.post(f"/api/v1/risk/incidents/{incident_id}/calculate", json={}).json()
    assert body["entity_type"] == "incident"
    assert body["factors"]["relationship_count"] == 18
    assert "informational factor" in body["explanation"]
    assert 0 <= body["score"] <= 100
    # Recalculating again keeps the same score (deterministic upsert).
    again = client.post(f"/api/v1/risk/incidents/{incident_id}/calculate", json={}).json()
    assert again["score"] == body["score"] and again["id"] == body["id"]


def test_analysis_bounds_and_truncation(client, clean_db, monkeypatch):
    incident_id, _ = _seed_auth_chain(client)

    _configure(monkeypatch, CORRELATION_MAX_EVENTS_PER_OPERATION="1")
    first = _recalc(client, incident_id).json()
    assert first["events_considered"] == 1
    assert first["bounds"]["max_events"] == 1
    assert first["relationships_total"] <= 4
    assert first["truncated"] is False

    _configure(
        monkeypatch,
        CORRELATION_MAX_EVENTS_PER_OPERATION="200",
        CORRELATION_RELATIONSHIP_MAX="5",
    )
    second = _recalc(client, incident_id).json()
    assert second["truncated"] is True
    assert second["relationships_total"] == 5
    assert second["bounds"]["max_relationships"] == 5
    listed = client.get(f"/api/v1/incidents/{incident_id}/relationships").json()
    assert listed["total"] == 5

    _configure(monkeypatch, CORRELATION_EVIDENCE_MAX="1")
    evidence = client.get(f"/api/v1/incidents/{incident_id}/evidence").json()
    assert evidence["evidence_count"] == 3
    assert evidence["truncated"] is True
    assert len(evidence["events"]) == 1

    # Grow the timeline past the floor-bounded cap (min 10 entries).
    client.post(f"/api/v1/incidents/{incident_id}/status", json={"status": "ACKNOWLEDGED"})
    client.post(f"/api/v1/incidents/{incident_id}/status", json={"status": "CLOSED"})
    _configure(monkeypatch, CORRELATION_TIMELINE_MAX_ENTRIES="10")
    timeline = client.get(f"/api/v1/incidents/{incident_id}/timeline").json()
    assert timeline["truncated"] is True
    assert len(timeline["entries"]) == 10
    assert [entry["kind"] for entry in timeline["entries"]][0] == "observation"
    assert [entry["kind"] for entry in timeline["entries"]][-1] == "resolution"


def test_rbac_on_relationship_endpoints(client, clean_db):
    incident_id, _ = _seed_auth_chain(client)
    _recalc(client, incident_id)

    client.post(
        "/api/v1/users",
        json={
            "username": "admin29",
            "password": "admin-pass-word-1",
            "display_name": "A",
            "roles": ["ADMIN"],
        },
    )
    admin_token = client.post(
        "/api/v1/auth/login", json={"username": "admin29", "password": "admin-pass-word-1"}
    ).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    client.post(
        "/api/v1/users",
        json={
            "username": "viewer29",
            "password": "viewer-pass-1234",
            "display_name": "V",
            "roles": ["VIEWER"],
        },
        headers=admin_headers,
    )
    viewer_token = client.post(
        "/api/v1/auth/login", json={"username": "viewer29", "password": "viewer-pass-1234"}
    ).json()["access_token"]
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # Anonymous is rejected once users exist.
    assert client.get(f"/api/v1/incidents/{incident_id}/relationships").status_code == 401
    # Viewer can read relationships but cannot run analysis.
    assert (
        client.get(
            f"/api/v1/incidents/{incident_id}/relationships", headers=viewer_headers
        ).status_code
        == 200
    )
    assert _recalc(client, incident_id).status_code == 401
    viewer_attempt = client.post(
        f"/api/v1/incidents/{incident_id}/recalculate", headers=viewer_headers
    )
    assert viewer_attempt.status_code == 403
    # Admin can recalculate (idempotent: 0 new rows).
    admin_run = client.post(f"/api/v1/incidents/{incident_id}/recalculate", headers=admin_headers)
    assert admin_run.status_code == 200
    assert admin_run.json()["relationships_created"] == 0


def test_no_merge_or_split_functionality(client, clean_db):
    """Spec §10: merge/split is explicitly not implemented (Step 29)."""
    from app.models.incidents import Incident

    paths = [route.path for route in client.app.routes if hasattr(route, "path")]
    assert not [path for path in paths if "merge" in path or "split" in path]
    assert not hasattr(Incident, "merged_into")
    assert not hasattr(Incident, "parent_incident_id")
    # And no hidden merge parameters on the update path.
    rejected = client.patch(
        "/api/v1/incidents/any", json={"merged_into": "other", "split_from": "x"}
    )
    assert rejected.status_code in (404, 422)


def test_migration_step29_creates_relationships_table(tmp_path, monkeypatch):
    from sqlalchemy import create_engine, inspect

    from alembic import command
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    db_file = tmp_path / "mig29.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    backend = Path(__file__).parent.parent
    config = Config(str(backend / "alembic.ini"))
    config.set_main_option("script_location", str(backend / "alembic"))
    # Step 30 is additive and revises this step, so the head has moved on.
    # What must stay true is that step29_intelligence is still in the
    # chain, that upgrading to it directly still builds the Step 29
    # objects, and that no later step rewrote them.
    script = ScriptDirectory.from_config(config)
    assert "step29_intelligence" in {revision.revision for revision in script.walk_revisions()}
    assert script.get_revision("step30_controlled_response").down_revision == "step29_intelligence"
    command.upgrade(config, "step29_intelligence")
    inspector = inspect(create_engine(f"sqlite:///{db_file}"))
    assert "incident_relationships" in inspector.get_table_names()
    columns = {column["name"] for column in inspector.get_columns("incident_relationships")}
    assert {
        "confidence_label",
        "evidence_json",
        "rule_id",
        "relation",
        "source_kind",
        "target_kind",
        "first_seen",
        "last_seen",
    } <= columns
    constraints = inspector.get_unique_constraints("incident_relationships")
    assert any(constraint["name"] == "uq_incident_relationship" for constraint in constraints)
    indexes = {index["name"] for index in inspector.get_indexes("incident_relationships")}
    assert "ix_incident_relationships_incident_id" in indexes
    # Step 30 must be additive on top: it adds governance columns and a
    # rollbacks table without dropping or narrowing anything Step 29 made.
    command.upgrade(config, "head")
    upgraded = inspect(create_engine(f"sqlite:///{db_file}"))
    assert "response_rollbacks" in upgraded.get_table_names()
    action_columns = {column["name"] for column in upgraded.get_columns("response_actions")}
    assert {
        "provider",
        "policy_decision",
        "approval_required",
        "rollback_supported",
        "rollback_state",
        "rollback_reference",
        "target_evidence",
    } <= action_columns
    assert "incident_relationships" in upgraded.get_table_names()


def test_security_regression_step29_modules():
    """AST-level proof for the Step 29 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.api.v1.endpoints.incidents as endpoints
    import app.services.incident_analysis as analysis
    import app.services.incident_rules as rules

    banned_imports = {
        "subprocess",
        "os",
        "pty",
        "shutil",
        "importlib",
        "socket",
        "requests",
        "urllib",
        "httpx",
        "ftplib",
        "telnetlib",
    }
    banned_names = {"eval", "exec", "compile", "open", "__import__"}
    for module in (rules, analysis, endpoints):
        source = _inspect.getsource(module)
        tree = _ast.parse(source)
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
                assert not (set(names) & banned_imports), names
            elif isinstance(node, _ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                assert mod not in banned_imports, mod
            if isinstance(node, _ast.Call):
                func = node.func
                if isinstance(func, _ast.Name):
                    assert func.id not in banned_names, func.id
                elif isinstance(func, _ast.Attribute):
                    assert func.attr not in {"system", "popen"}, func.attr
        lowered = source.lower()
        for token in ("openai", "langchain", "torch", "numpy", "pickle", "chatgpt"):
            assert token not in lowered, token
        assert " import random" not in lowered and "from random" not in lowered


def test_step24_recompute_contract_untouched(client, clean_db):
    """Step 24 pins stay byte-for-byte true after Step 29."""
    _ingest(client, "chain_a_1.json", "chain_a_2.json", "chain_a_3.json")
    result = _recompute(client)
    assert result["rules_evaluated"] == 3
    assert result["events_scanned"] == 3
    items = _correlations(client)
    by_rule = {}
    for item in items:
        by_rule.setdefault(item["rule_id"], []).append(item)
    assert sorted(by_rule) == ["multi-source-target"]
    # Step 29 analysis never runs during recompute (no incident rows yet).
    from sqlalchemy import func, select

    from app.database import session as session_module
    from app.models.incidents import Incident, IncidentRelationship

    db = session_module.get_session_factory()()
    try:
        assert db.scalar(select(func.count(Incident.id))) == 0
        assert db.scalar(select(func.count(IncidentRelationship.id))) == 0
    finally:
        db.close()
