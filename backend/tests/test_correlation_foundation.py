"""Correlation + incident formation tests (Step 24, deterministic rules).

Maps the Step 24 fixture scenarios A-J explicitly, plus window-cap,
audit, observations, severity/explanation, RBAC, and structural safety
coverage — without weakening Steps 1-23.
"""

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "correlation"


def _fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _ingest(client, *names):
    for name in names:
        response = client.post("/api/v1/events", json=_fixture(name))
        assert response.status_code in (200, 201), name


def _recompute(client):
    response = client.post("/api/v1/correlations/recompute")
    assert response.status_code == 200
    return response.json()


def _by_rule(client):
    items = client.get("/api/v1/correlations").json()["items"]
    grouped = {}
    for item in items:
        grouped.setdefault(item["rule_id"], []).append(item)
    return grouped


def _detect_all(client):
    return client.post("/api/v1/incidents/detect", json={}).json()


def test_scenario_a_two_events_one_incident(client, clean_db):
    """A: two events on the same asset within the window -> one incident."""
    _ingest(client, "chain_a_1.json", "chain_a_2.json")
    result = _recompute(client)
    assert result["created"] == 1
    assert sorted(_by_rule(client)) == ["multi-source-target"]
    summary = _detect_all(client)
    assert summary["created"] == 1
    assert client.get("/api/v1/incidents").json()["total"] == 1


def test_scenario_b_replay_no_duplicate_incident(client, clean_db):
    """B: same event ingested twice -> no duplicate incident."""
    _ingest(client, "chain_a_1.json", "chain_a_2.json")
    _ingest(client, "chain_a_1.json", "chain_a_2.json")  # replay
    _recompute(client)
    _detect_all(client)
    assert client.get("/api/v1/incidents").json()["total"] == 1
    assert client.get("/api/v1/events").json()["total"] == 2  # deduped at ingest


def test_scenario_c_event_plus_vulnerability(client, clean_db):
    """C: event + finding on one asset -> one incident with both observations."""
    _ingest(client, "vuln.json", "vuln_activity.json")
    _recompute(client)
    assert sorted(_by_rule(client)) == ["vuln-exposure"]
    summary = _detect_all(client)
    assert summary["created"] == 1
    incident_id = summary["outcomes"][0]["incident_id"]
    observations = client.get(f"/api/v1/incidents/{incident_id}/observations").json()
    assert observations["event_count"] >= 2
    assert observations["correlation_count"] == 1
    kinds = {item["observation_type"] for item in observations["observations"]}
    assert {"correlation", "event"} <= kinds


def test_scenario_d_no_cross_asset_correlation(client, clean_db):
    """D: events on different assets stay separate unless a rule allows it."""
    _ingest(client, "chain_a_1.json", "chain_a_2.json", "chain_d_1.json", "chain_d_2.json")
    _recompute(client)
    grouped = _by_rule(client)
    assert len(grouped["multi-source-target"]) == 2  # one per asset, never merged
    pivots = {item["primary_ip"] for item in grouped["multi-source-target"]}
    assert pivots == {"198.51.100.23", "2001:db8::99"}


def test_scenario_e_outside_window_no_correlation(client, clean_db):
    """E: events outside the rule window do not correlate."""
    _ingest(client, "chain_a_1.json", "outside_window.json")
    result = _recompute(client)
    assert result["created"] == 0
    assert _detect_all(client)["created"] == 0
    assert client.get("/api/v1/incidents").json()["total"] == 0


def test_scenario_f_repeat_run_same_incident(client, clean_db):
    """F: repeated correlation/detection -> same incident and links."""
    _ingest(client, "chain_a_1.json", "chain_a_2.json")
    _recompute(client)
    first = _detect_all(client)
    incident_id = first["outcomes"][0]["incident_id"]
    before = client.get(f"/api/v1/incidents/{incident_id}").json()
    obs_before = client.get(f"/api/v1/incidents/{incident_id}/observations").json()
    _recompute(client)
    second = _detect_all(client)
    assert second["created"] == 0
    assert second["outcomes"][0]["incident_id"] == incident_id
    after = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert after["first_seen"] == before["first_seen"]
    assert after["severity"] == before["severity"]
    assert client.get(f"/api/v1/incidents/{incident_id}/observations").json() == obs_before
    assert client.get("/api/v1/incidents").json()["total"] == 1


def test_scenario_g_unresolved_asset_no_invention(client, clean_db):
    """G: unknown assets stay unresolved; correlation invents nothing."""
    _ingest(client, "vuln.json", "vuln_activity.json")
    _recompute(client)
    incident_id = _detect_all(client)["outcomes"][0]["incident_id"]
    incident = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert incident["primary_asset_id"] is None  # 192.0.2.50 not inventoried
    assert client.get("/api/v1/assets").json()["total"] == 0  # nothing manufactured


def test_scenario_h_cross_source_normalized_evidence(client, clean_db):
    """H: correlation keys on normalized evidence, not source names."""
    _ingest(client, "chain_a_1.json", "chain_a_2.json")
    _recompute(client)
    correlation = _by_rule(client)["multi-source-target"][0]
    assert correlation["confidence"] == 75  # rule-fixed, not source-derived
    detail = client.get(f"/api/v1/correlations/{correlation['id']}").json()
    assert "198.51.100.23" in detail["explanation"]
    # A lone single-source event never matches the multi-source rule.
    _ingest(client, "loner.json")
    assert _recompute(client)["created"] == 0


def test_scenario_i_arbitrary_rule_command_rejected(client, clean_db):
    """I: rule/command injection attempts are rejected with 422."""
    assert (
        client.post("/api/v1/correlations/recompute", json={"rule_id": "custom"}).status_code == 422
    )
    assert (
        client.post(
            "/api/v1/incidents/detect", json={"correlation_id": "x", "rule": "custom"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/incidents/detect", json={"correlation_id": "x", "command": "run"}
        ).status_code
        == 422
    )


def test_scenario_j_authz_enforced(client, clean_db):
    """J: 401/403 per existing auth semantics."""
    assert (
        client.post("/api/v1/correlations/recompute", json={}).status_code == 200
    )  # bootstrap open
    # Bootstrap mode is open; with users present, enforcement applies.
    client.post(
        "/api/v1/users",
        json={
            "username": "admin",
            "password": "admin-pass-word-1",
            "display_name": "A",
            "roles": ["ADMIN"],
        },
    )
    admin_token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin-pass-word-1"}
    ).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    client.post(
        "/api/v1/users",
        json={
            "username": "viewer1",
            "password": "viewer-pass-1234",
            "display_name": "V",
            "roles": ["VIEWER"],
        },
        headers=admin_headers,
    )
    viewer_token = client.post(
        "/api/v1/auth/login", json={"username": "viewer1", "password": "viewer-pass-1234"}
    ).json()["access_token"]
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
    assert client.post("/api/v1/correlations/recompute", json={}).status_code == 401
    assert (
        client.post("/api/v1/correlations/recompute", json={}, headers=viewer_headers).status_code
        == 403
    )
    assert (
        client.post("/api/v1/incidents/detect", json={}, headers=viewer_headers).status_code == 403
    )
    assert (
        client.post("/api/v1/correlations/recompute", json={}, headers=admin_headers).status_code
        == 200
    )
    assert (
        client.get("/api/v1/incidents/nope/observations", headers=admin_headers).status_code == 404
    )


def test_window_cap_configurable_and_bounded(client, clean_db):
    """Step 24 §4: effective windows respect the deployment cap."""
    from app.core.config import get_settings
    from app.services.correlation_rules import MAX_WINDOW_MINUTES, RULES, effective_window_minutes

    assert get_settings().correlation_max_window_minutes == 1440
    assert MAX_WINDOW_MINUTES == 7 * 24 * 60
    assert effective_window_minutes("multi-source-target") == 60
    assert effective_window_minutes("vuln-exposure") == 1440
    assert effective_window_minutes("repeated-source") == 15
    assert all(effective_window_minutes(rule) <= MAX_WINDOW_MINUTES for rule in RULES)
    import pytest

    with pytest.raises(KeyError):
        effective_window_minutes("no-such-rule")


def test_window_cap_narrows_matching(monkeypatch, client, clean_db):
    """A lowered cap narrows matching without touching rule definitions."""
    from app.services import correlation_rules

    _ingest(client, "chain_a_1.json", "chain_a_2.json")  # 10 minutes apart
    original = correlation_rules.RULES["multi-source-target"].window_minutes
    assert original == 60
    # Effective window honors the cap: simulate a 5-minute deployment cap.
    monkeypatch.setattr(correlation_rules, "MAX_WINDOW_MINUTES", 5)
    assert correlation_rules.effective_window_minutes("multi-source-target") == 5
    assert _recompute(client)["created"] == 0  # 10-minute gap exceeds the 5-minute cap


def test_correlation_run_audit(client, clean_db):
    """Step 24 §15: recompute lifecycle is audited."""
    from sqlalchemy import func, select

    from app.database import session as session_module
    from app.models.correlations import CorrelationAudit

    _ingest(client, "chain_a_1.json", "chain_a_2.json")
    _recompute(client)
    db = session_module.get_session_factory()()
    try:
        actions = [
            row.action
            for row in db.scalars(
                select(CorrelationAudit).order_by(CorrelationAudit.created_at)
            ).all()
        ]
    finally:
        db.close()
    assert actions[0] == "RUN_STARTED"
    assert "CORRELATION_MATCHED" in actions
    assert actions[-1] == "RUN_COMPLETED"
    _recompute(client)  # refresh-only run: no new MATCHED rows
    db = session_module.get_session_factory()()
    try:
        matched = db.scalar(
            select(func.count(CorrelationAudit.id)).where(
                CorrelationAudit.action == "CORRELATION_MATCHED"
            )
        )
    finally:
        db.close()
    assert matched == 1


def test_observations_endpoint_shape(client, clean_db):
    """Step 24 §9: observation links are typed, reasoned, deduplicated."""
    _ingest(client, "chain_a_1.json", "chain_a_2.json")
    _recompute(client)
    incident_id = _detect_all(client)["outcomes"][0]["incident_id"]
    body = client.get(f"/api/v1/incidents/{incident_id}/observations").json()
    assert body["incident_id"] == incident_id
    assert body["event_count"] == 2
    assert body["correlation_count"] == 1
    for item in body["observations"]:
        assert set(item) == {"observation_type", "observation_id", "reason", "created_at"}
        assert item["observation_type"] in ("correlation", "event", "vulnerability")
    pairs = [(item["observation_type"], item["observation_id"]) for item in body["observations"]]
    assert len(pairs) == len(set(pairs))  # unique constraint holds


def test_severity_explanation_reproducible(client, clean_db):
    """Step 24 §6/§8: severity factors and reasons derive from evidence."""
    _ingest(client, "chain_a_1.json", "chain_a_2.json")
    _recompute(client)
    incident_id = _detect_all(client)["outcomes"][0]["incident_id"]
    incident = client.get(f"/api/v1/incidents/{incident_id}").json()
    correlation = client.get(f"/api/v1/correlations/{incident['correlation_id']}").json()
    assert incident["severity"] == correlation["severity"] == "HIGH"  # evidence maximum
    assert "198.51.100.23" in incident["detection_reason"]
    assert "compromised" not in incident["detection_reason"].lower()
    assert "compromised" not in correlation["explanation"].lower()
    timeline = client.get(f"/api/v1/incidents/{incident_id}/timeline").json()
    stamps = [entry["at"] for entry in timeline["entries"] if entry["at"]]
    assert stamps == sorted(stamps)


def test_no_subprocess_in_correlation_path():
    """Step 24 §11/§22: stored-data-only engine, structurally proven."""
    import ast as _ast
    import inspect

    import app.api.v1.endpoints.correlations as endpoints
    import app.api.v1.endpoints.incidents as incident_endpoints
    import app.services.correlation_rules as rules
    import app.services.correlation_service as service
    import app.services.incident_detection as detection

    for module in (rules, service, detection, endpoints, incident_endpoints):
        tree = _ast.parse(inspect.getsource(module))
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
                assert not (
                    set(names) & {"subprocess", "os", "pty", "shutil", "importlib", "socket"}
                ), names
            elif isinstance(node, _ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                assert mod not in {"subprocess", "os", "socket"}, mod
            if isinstance(node, _ast.Call):
                func = node.func
                if isinstance(func, _ast.Name):
                    assert func.id not in {
                        "eval",
                        "exec",
                        "compile",
                        "open",
                        "__import__",
                    }, func.id
                elif isinstance(func, _ast.Attribute):
                    assert func.attr not in {"system", "popen"}, func.attr
