"""Phase 2 Step 7 — controlled correlation and incident grouping.

Step 7 closes one empirically-confirmed defect in the Step 9 correlation
engine: the "same target" rule keyed only on ``destination_ip``, so a Wazuh
alert (which reports ``dstip``) and a Microsoft Defender alert (which
reports ``remoteIp`` and ``computerName``) about the *same* machine shared
no key and produced **zero** correlations. The rule now also keys on the
host name.

Everything else is asserted, not rewritten: the deterministic rule catalog,
bounded scans and windows, deterministic identity, upsert-based duplicate
prevention, server-side-only computation, and the audit trail.

**No test contacts a real Wazuh or Defender service.** HTTP goes through
``httpx.MockTransport``.
"""

import httpx

GRAPH = "graph.microsoft.com"
AUTHORITY = "login.microsoftonline.com"


def _install(handler):
    from app.services import http_connector

    http_connector.install_test_transport(httpx.MockTransport(handler))


def _configure(monkeypatch, **overrides):
    from app.core.config import get_settings

    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()


def _clear():
    from app.core.config import get_settings
    from app.services import connector_polling, connectors, ingestion

    connector_polling.reset()
    connectors.reset_runtime()
    ingestion.reset_runtime()
    get_settings.cache_clear()


def _tokens(client):
    client.post(
        "/api/v1/users",
        json={
            "username": "admin",
            "password": "admin-pass-word-1",
            "display_name": "A",
            "roles": ["ADMIN"],
        },
    )
    token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin-pass-word-1"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _wazuh_alert(alert_id, *, dstip="10.0.0.5", hostname="ws-01", minute=0, level=12):
    return {
        "id": alert_id,
        "timestamp": f"2026-01-05T10:{minute:02d}:00.000+0000",
        "rule": {"id": "5712", "level": level, "description": f"rule {alert_id}"},
        "agent": {"id": "001", "name": hostname, "ip": "10.0.0.5"},
        "data": {"srcip": "203.0.113.10", **({"dstip": dstip} if dstip else {})},
    }


def _defender_alert(alert_id, *, hostname="ws-01", minute=5, severity="high"):
    record = {
        "id": alert_id,
        "title": f"alert {alert_id}",
        "severity": severity,
        "category": "Execution",
        "status": "new",
        "firstDetectedDateTime": f"2026-01-05T10:{minute:02d}:00Z",
        "remoteIp": "203.0.113.10",
    }
    if hostname:
        record["host"] = {"computerName": hostname}
    return record


def _vendor_handler(wazuh_alerts, defender_alerts):
    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host.endswith("wazuh.test"):
            if request.url.path.endswith("/security/user/authenticate"):
                return httpx.Response(200, json={"token": "mock-jwt"})
            return httpx.Response(
                200,
                json={
                    "data": {"totalItems": len(wazuh_alerts), "alerts": wazuh_alerts},
                    "error": 0,
                },
            )
        if host == AUTHORITY:
            return httpx.Response(200, json={"access_token": "mock-token", "expires_in": 3599})
        if host == GRAPH:
            return httpx.Response(200, json={"value": defender_alerts})
        raise AssertionError(f"unexpected host {host}")

    return handler


def _poll_both(client, admin):
    client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
    client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)


def _configure_both(monkeypatch, **overrides):
    base = {
        "WAZUH_API_URL": "https://wazuh.test:55000",
        "WAZUH_USERNAME": "u",
        "WAZUH_PASSWORD": "p",
        "DEFENDER_TENANT_ID": "t",
        "DEFENDER_CLIENT_ID": "c",
        "DEFENDER_CLIENT_SECRET": "s",
        "CONNECTOR_RETRY_MAX": "0",
    }
    base.update(overrides)
    _configure(monkeypatch, **base)


# ---------------------------------------------------------------------------
# 1/2/3. Single-event, multi-event and Wazuh + Defender correlation
# ---------------------------------------------------------------------------


def test_wazuh_and_defender_events_correlate(monkeypatch, client, clean_db):
    """The Step 7 defect: same host, two vendors, previously zero matches."""
    _install(_vendor_handler([_wazuh_alert("s7-w1")], [_defender_alert("s7-d1")]))
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        assert client.get("/api/v1/events", headers=admin).json()["total"] == 2

        result = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
        assert result["created"] == 1
        page = client.get("/api/v1/correlations", headers=admin).json()
        assert page["total"] == 1
        summary = page["items"][0]
        assert summary["rule_id"] == "multi-source-target"
        assert summary["event_count"] == 2
        # Severity is the evidence maximum, never invented.
        assert summary["severity"] == "CRITICAL"
    finally:
        _clear()


def test_single_event_never_produces_a_correlation(monkeypatch, client, clean_db):
    _install(_vendor_handler([_wazuh_alert("s7-single")], []))
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        result = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
        assert result["events_scanned"] == 1
        assert result["created"] == 0
    finally:
        _clear()


def test_multi_event_same_vendor_does_not_match_the_cross_source_rule(
    monkeypatch, client, clean_db
):
    """Two Wazuh alerts on one host are one source, so no cross-source match."""
    _install(_vendor_handler([_wazuh_alert("s7-a", minute=0), _wazuh_alert("s7-b", minute=1)], []))
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        result = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
        assert result["created"] == 0
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 4. Duplicate event handling / duplicate incident prevention
# ---------------------------------------------------------------------------


def test_reprocessing_the_same_events_never_creates_a_second_correlation(
    monkeypatch, client, clean_db
):
    _install(_vendor_handler([_wazuh_alert("s7-dup-w")], [_defender_alert("s7-dup-d")]))
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        first = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
        assert first["created"] == 1

        # Re-poll the same records (dedup at the event layer) and recompute.
        _poll_both(client, admin)
        assert client.get("/api/v1/events", headers=admin).json()["total"] == 2
        second = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
        assert second["created"] == 0
        assert second["refreshed"] == 1
        assert second["correlation_ids"] == first["correlation_ids"]
        assert client.get("/api/v1/correlations", headers=admin).json()["total"] == 1
    finally:
        _clear()


def test_correlation_identity_is_deterministic(monkeypatch, client, clean_db):
    from app.services.correlation_service import deterministic_id

    a = deterministic_id("multi-source-target", ["e2", "e1"])
    b = deterministic_id("multi-source-target", ["e1", "e2"])
    assert a == b, "evidence order must not change identity"
    assert deterministic_id("repeated-source", ["e1", "e2"]) != a


# ---------------------------------------------------------------------------
# 5. Unrelated events (requirement 15)
# ---------------------------------------------------------------------------


def test_events_sharing_only_a_source_ip_do_not_correlate(monkeypatch, client, clean_db):
    """Two unrelated events must not be grouped merely by a shared source IP."""
    _install(
        _vendor_handler(
            [_wazuh_alert("s7-u1", dstip="10.0.0.5", hostname="ws-01", minute=0)],
            [_defender_alert("s7-u2", hostname="other-host", minute=5)],
        )
    )
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        result = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
        # Same remote IP (203.0.113.10) but different hosts and no shared
        # destination: no correlation may be inferred.
        assert result["created"] == 0
    finally:
        _clear()


def test_two_vendors_on_completely_different_hosts_do_not_correlate(monkeypatch, client, clean_db):
    _install(
        _vendor_handler(
            [_wazuh_alert("s7-d1", dstip="10.0.0.5", hostname="ws-a", minute=0)],
            [_defender_alert("s7-d2", hostname="ws-b", minute=5)],
        )
    )
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        assert (
            client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()["created"]
            == 0
        )
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 6. Unknown asset handled honestly
# ---------------------------------------------------------------------------


def test_unresolved_asset_still_correlates_by_observed_fields(monkeypatch, client, clean_db):
    """No asset is invented; the relation is stated from observed fields."""
    _install(_vendor_handler([_wazuh_alert("s7-x1")], [_defender_alert("s7-x2")]))
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        events = client.get("/api/v1/events", headers=admin).json()["items"]
        assert all(not e.get("asset_id") for e in events)

        client.post("/api/v1/correlations/recompute", json={}, headers=admin)
        page = client.get("/api/v1/correlations", headers=admin).json()
        assert page["total"] == 1
        detail = client.get(f"/api/v1/correlations/{page['items'][0]['id']}", headers=admin).json()
        # The explanation names what was actually observed, not an asset.
        assert "ws-01" in detail["explanation"] or "10.0.0.5" in detail["explanation"]
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 7. Time-window boundaries
# ---------------------------------------------------------------------------


def test_events_outside_the_window_do_not_correlate(monkeypatch, client, clean_db):
    _install(
        _vendor_handler(
            [_wazuh_alert("s7-w-in", minute=0)],
            [_defender_alert("s7-w-out", minute=59)],
        )
    )
    _configure_both(monkeypatch, CORRELATION_MAX_WINDOW_MINUTES=10)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        result = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
        assert result["created"] == 0, "a 59-minute gap must not match a 10-minute window"
    finally:
        _clear()


def test_events_inside_the_window_do_correlate(monkeypatch, client, clean_db):
    _install(
        _vendor_handler(
            [_wazuh_alert("s7-w1", minute=0)],
            [_defender_alert("s7-w2", minute=5)],
        )
    )
    _configure_both(monkeypatch, CORRELATION_MAX_WINDOW_MINUTES=10)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        result = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
        assert result["created"] == 1
    finally:
        _clear()


def test_window_is_capped_even_if_configured_higher(monkeypatch, client, clean_db):
    from app.services.correlation_rules import MAX_WINDOW_MINUTES, effective_window_minutes

    _configure(monkeypatch, CORRELATION_MAX_WINDOW_MINUTES=10_000_000)
    try:
        assert effective_window_minutes("vuln-exposure") <= MAX_WINDOW_MINUTES
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 8. Event-count limits / bounded work
# ---------------------------------------------------------------------------


def test_recompute_scans_a_bounded_number_of_events(monkeypatch, client, clean_db):
    from app.services.correlation_service import MAX_EVENTS_SCANNED

    _install(_vendor_handler([_wazuh_alert("s7-lim")], []))
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        result = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
        assert result["events_scanned"] <= MAX_EVENTS_SCANNED
    finally:
        _clear()


def test_recompute_takes_no_client_parameters(monkeypatch, client, clean_db):
    """No client-supplied window, rule list, severity or event id is honoured.

    The endpoint takes no request body at all, so an attempt to steer it is
    rejected outright rather than silently ignored.
    """
    _install(_vendor_handler([_wazuh_alert("s7-parm")], [_defender_alert("s7-parm2")]))
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        steered = client.post(
            "/api/v1/correlations/recompute",
            json={
                "window_minutes": 999999,
                "rule_ids": ["repeated-source"],
                "min_severity": "INFO",
                "event_ids": ["attacker-supplied"],
                "asset_id": "attacker-supplied",
            },
            headers=admin,
        )
        assert steered.status_code == 422, "a steered recompute must be refused"

        # A normal recompute still evaluates the whole catalog server-side.
        result = client.post("/api/v1/correlations/recompute", json={}, headers=admin).json()
        assert result["rules_evaluated"] == 3
        assert result["created"] == 1
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 9. Rule explanation / audit trail
# ---------------------------------------------------------------------------


def test_correlation_explains_itself(monkeypatch, client, clean_db):
    _install(_vendor_handler([_wazuh_alert("s7-e1")], [_defender_alert("s7-e2")]))
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        client.post("/api/v1/correlations/recompute", json={}, headers=admin)
        page = client.get("/api/v1/correlations", headers=admin).json()
        detail = client.get(f"/api/v1/correlations/{page['items'][0]['id']}", headers=admin).json()

        # rule id, matched events, window, affected entity, relatedness
        assert detail["rule_id"] == "multi-source-target"
        assert detail["event_count"] == 2
        assert len(detail["evidence"]) == 2
        assert detail["window_start"] and detail["window_end"]
        assert "ws-01" in detail["explanation"] or "10.0.0.5" in detail["explanation"]
        assert "WAZUH" in detail["explanation"] and "DEFENDER" in detail["explanation"]
        assert "not proof of compromise" in detail["description"]
    finally:
        _clear()


def test_correlation_run_is_audited(monkeypatch, client, clean_db):
    from sqlalchemy import select

    from app.database import session as session_module
    from app.models.correlations import CorrelationAudit

    _install(_vendor_handler([_wazuh_alert("s7-au1")], [_defender_alert("s7-au2")]))
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        client.post("/api/v1/correlations/recompute", json={}, headers=admin)
        db = session_module.get_session_factory()()
        try:
            rows = db.scalars(select(CorrelationAudit)).all()
        finally:
            db.close()
        actions = [row.action for row in rows]
        assert "RUN_STARTED" in actions
        assert "CORRELATION_MATCHED" in actions
        assert "RUN_COMPLETED" in actions
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 10. Malicious / malformed input
# ---------------------------------------------------------------------------


def test_malformed_events_do_not_crash_correlation(monkeypatch, client, clean_db):
    _install(
        _vendor_handler(
            [_wazuh_alert("s7-m1"), "not-an-object", {"junk": 1}],
            [_defender_alert("s7-m2")],
        )
    )
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        _poll_both(client, admin)
        response = client.post("/api/v1/correlations/recompute", json={}, headers=admin)
        assert response.status_code == 200

        # The non-object record is rejected outright; the unrecognised-shape
        # object is kept as a generic event (documented Step 6 behaviour) but
        # carries no target key, so it cannot join a host group.
        events = client.get("/api/v1/events", headers=admin).json()
        assert events["total"] == 3

        # The valid vendor pair still correlates: one bad record neither
        # crashed the run nor discarded the batch.
        assert response.json()["created"] == 1
    finally:
        _clear()


def test_correlation_requires_run_analysis_permission(monkeypatch, client, clean_db):
    _install(_vendor_handler([_wazuh_alert("s7-r1")], [_defender_alert("s7-r2")]))
    _configure_both(monkeypatch)
    try:
        admin = _tokens(client)
        client.post(
            "/api/v1/users",
            json={
                "username": "viewer1",
                "password": "viewer-pass-1234",
                "display_name": "V",
                "roles": ["VIEWER"],
            },
            headers=admin,
        )
        viewer_token = client.post(
            "/api/v1/auth/login",
            json={"username": "viewer1", "password": "viewer-pass-1234"},
        ).json()["access_token"]
        viewer = {"Authorization": f"Bearer {viewer_token}"}
        denied = client.post("/api/v1/correlations/recompute", json={}, headers=viewer)
        assert denied.status_code == 403
        # Reads stay open to a viewer.
        assert client.get("/api/v1/correlations", headers=viewer).status_code == 200
    finally:
        _clear()


def test_no_ai_or_probabilistic_scoring_is_used():
    """The catalog stays a fixed, enumerated set of deterministic rules."""
    from app.services import correlation_rules

    assert set(correlation_rules.RULES) == {
        "multi-source-target",
        "vuln-exposure",
        "repeated-source",
    }
    for rule in correlation_rules.RULES.values():
        assert isinstance(rule.confidence, int)
        assert 0 < rule.confidence <= 100
        assert rule.window_minutes > 0
    source = open(  # noqa: SIM115 - read once for a static assertion
        correlation_rules.__file__, encoding="utf-8"
    ).read()
    for banned in ("random", "numpy", "sklearn", "tensorflow", "torch"):
        assert banned not in source.lower(), banned
