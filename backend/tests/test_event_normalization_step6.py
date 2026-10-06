"""Phase 2 Step 6 — event normalization, correlation input and statistics.

Covers the three gaps closed in Step 6:

* **consistent vendor normalization** — Wazuh and Defender both populate the
  same canonical identity fields, and absent ones stay ``None``;
* **unambiguous statistics** — received / normalized / accepted / rejected /
  duplicated are each reported and independently checkable;
* **no credential material in stored events** — a vendor payload that quotes
  a secret has that value scrubbed before persistence, while every other
  field is preserved.

Also re-asserts the guarantees Step 6 must not break: server-side
validation, per-record failure isolation inside a batch, bounded batches,
deduplication, asset correlation and the audit trail.

**No test contacts a real Wazuh or Defender service.** HTTP goes through
``httpx.MockTransport``; fixture/ingest paths submit records directly.
"""

import json

import httpx

WAZUH_ALERT = {
    "id": "s6-valid-1",
    "timestamp": "2026-01-05T10:00:00.000+0000",
    "rule": {"id": "5712", "level": 12, "description": "Step 6 valid rule"},
    "agent": {"id": "001", "name": "agent-1", "ip": "10.0.0.5"},
    "data": {
        "srcip": "203.0.113.10",
        "dstip": "10.0.0.5",
        "uname": "root",
        "cmdline": "/usr/bin/id",
    },
    "location": "/var/log/test",
}

GRAPH_ALERT = {
    "id": "s6-valid-1",
    "title": "Suspicious process executed",
    "description": "Step 6 valid alert",
    "severity": "high",
    "category": "Execution",
    "status": "new",
    "firstDetectedDateTime": "2026-01-05T10:00:00Z",
    "host": {"computerName": "ws-01"},
    "accountName": "svc-account",
    "processName": "cmd.exe",
    "processCommandLine": "cmd.exe /c whoami",
    "remoteIp": "203.0.113.10",
}

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


def _wazuh_handler(alerts):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": "mock-jwt-token-value"})
        if request.url.path.endswith("/manager/info"):
            return httpx.Response(200, json={"data": {}, "error": 0})
        if request.url.path.endswith("/alerts"):
            return httpx.Response(
                200, json={"data": {"totalItems": len(alerts), "alerts": alerts}, "error": 0}
            )
        raise AssertionError(f"unexpected path {request.url.path}")

    return handler


def _defender_handler(alerts):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == AUTHORITY:
            return httpx.Response(200, json={"access_token": "mock-token", "expires_in": 3599})
        if request.url.host == GRAPH:
            return httpx.Response(200, json={"value": alerts})
        raise AssertionError(f"unexpected host {request.url.host}")

    return handler


def _configure_wazuh(monkeypatch, **overrides):
    base = {
        "WAZUH_API_URL": "https://wazuh.test:55000",
        "WAZUH_USERNAME": "u",
        "WAZUH_PASSWORD": "p",
        "CONNECTOR_RETRY_MAX": "0",
    }
    base.update(overrides)
    _configure(monkeypatch, **base)


def _configure_defender(monkeypatch, **overrides):
    _configure(
        monkeypatch,
        DEFENDER_TENANT_ID="t",
        DEFENDER_CLIENT_ID="c",
        DEFENDER_CLIENT_SECRET="s",
        CONNECTOR_RETRY_MAX="0",
        **overrides,
    )


def _events(client, headers, **params):
    return client.get("/api/v1/events", params=params or None, headers=headers).json()


# ---------------------------------------------------------------------------
# 1/2. Valid Wazuh and valid Defender events, normalized consistently
# ---------------------------------------------------------------------------


def test_valid_wazuh_event_is_normalized(monkeypatch, client, clean_db):
    _install(_wazuh_handler([WAZUH_ALERT]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert body["accepted"] == 1
        item = _events(client, admin, source_type="WAZUH")["items"][0]
        assert item["source_type"] == "WAZUH"
        assert item["event_type"] == "WAZUH_ALERT"
        assert item["severity"] == "CRITICAL"
        assert item["hostname"] == "agent-1"
        assert item["source_ip"] == "203.0.113.10"
        assert item["event_time"]
        assert item["external_event_id"].startswith("wazuh:")
    finally:
        _clear()


def test_valid_defender_event_is_normalized(monkeypatch, client, clean_db):
    _install(_defender_handler([GRAPH_ALERT]))
    _configure_defender(monkeypatch)
    try:
        admin = _tokens(client)
        body = client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin).json()
        assert body["accepted"] == 1
        item = _events(client, admin, source_type="DEFENDER")["items"][0]
        assert item["source_type"] == "DEFENDER"
        assert item["event_type"] == "DEFENDER_ALERT"
        assert item["severity"] == "HIGH"
        assert item["hostname"] == "ws-01"
        assert item["event_time"]
        assert item["external_event_id"].startswith("defender:")
    finally:
        _clear()


def test_both_vendors_populate_the_same_canonical_identity_fields(monkeypatch, client, clean_db):
    """Step 6: Wazuh now carries username/process_name like Defender."""
    _install(_wazuh_handler([WAZUH_ALERT]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        wazuh = _events(client, admin, source_type="WAZUH")["items"][0]
    finally:
        _clear()

    _install(_defender_handler([GRAPH_ALERT]))
    _configure_defender(monkeypatch)
    try:
        admin = _tokens(client)
        client.post("/api/v1/events/connectors/defender/poll", json={}, headers=admin)
        defender = _events(client, admin, source_type="DEFENDER")["items"][0]
    finally:
        _clear()

    assert wazuh["username"] == "root"
    assert wazuh["process_name"] == "/usr/bin/id"
    assert defender["username"] == "svc-account"
    assert defender["process_name"] == "cmd.exe"
    # Both carry the same canonical field names.
    shared = {"event_type", "severity", "hostname", "username", "process_name", "event_time"}
    assert shared <= set(wazuh)
    assert shared <= set(defender)


def test_wazuh_user_field_names_all_map_to_the_canonical_username(monkeypatch, client, clean_db):
    """Step 6: whichever user field Wazuh emits, the canonical field is the same."""
    for index, (data_key, expected) in enumerate(
        (("uname", "root"), ("user", "svc"), ("srcuser", "alice"), ("dstuser", "bob"))
    ):
        # Distinct timestamps so the newest-first event list is deterministic.
        record = dict(
            WAZUH_ALERT,
            id=f"s6-{data_key}",
            timestamp=f"2026-01-05T10:0{index}:00.000+0000",
            data={data_key: expected},
        )
        _install(_wazuh_handler([record]))
        _configure_wazuh(monkeypatch)
        try:
            admin = _tokens(client)
            client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
            item = _events(client, admin, source_type="WAZUH")["items"][0]
            assert item["username"] == expected, data_key
        finally:
            _clear()


def test_absent_identity_fields_stay_none_and_are_never_inferred(monkeypatch, client, clean_db):
    """A Wazuh alert with no user/process must report None, not a guess."""
    bare = {
        "id": "s6-bare",
        "timestamp": "2026-01-05T10:00:00.000+0000",
        "rule": {"id": "1", "level": 3},
        "agent": {"id": "002", "name": "agent-bare"},
        "data": {},
    }
    _install(_wazuh_handler([bare]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        item = _events(client, admin, source_type="WAZUH")["items"][0]
        assert item["username"] is None
        assert item["process_name"] is None
        assert item["confidence"] is None
        assert not item.get("asset_id")
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 3-5. Malformed / missing-field / invalid-timestamp rejection
# ---------------------------------------------------------------------------


def test_malformed_event_is_rejected_without_crashing_the_cycle(monkeypatch, client, clean_db):
    _install(_wazuh_handler(["not-an-object"]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        # The cycle completes; the bad record is counted, not fatal.
        assert response.status_code in {200, 422}
        if response.status_code == 200:
            assert response.json()["rejected"] >= 1
            assert response.json()["accepted"] == 0
        assert _events(client, admin)["total"] == 0
    finally:
        _clear()


def test_missing_required_fields_are_rejected(monkeypatch, client, clean_db):
    """Direct ingest: a record with no title/event_type cannot be stored."""
    _configure(monkeypatch)
    try:
        admin = _tokens(client)
        response = client.post(
            "/api/v1/events",
            json={"source_type": "WAZUH", "source_name": "s6", "severity": "LOW"},
            headers=admin,
        )
        assert response.status_code == 422
    finally:
        _clear()


def test_invalid_timestamp_is_handled(monkeypatch, client, clean_db):
    """A garbage timestamp must not produce an event with a wrong time."""
    from app.services import wazuh_adapter

    adapted = wazuh_adapter.adapt_wazuh_event(
        {
            "id": "s6-bad-time",
            "event_type": "alert",
            "timestamp": "not-a-timestamp",
            "rule": {"id": "1", "level": 5, "description": "bad time"},
            "agent": {"id": "003", "name": "a"},
        }
    )
    # The adapter must still return a usable canonical dict (defaults to
    # ingest time) rather than raising or inventing a wrong time.
    assert isinstance(adapted, dict)
    assert "event_time" in adapted
    assert adapted["event_time"] is not None


# ---------------------------------------------------------------------------
# 6. Duplicate event
# ---------------------------------------------------------------------------


def test_duplicate_event_is_deduplicated_across_polls(monkeypatch, client, clean_db):
    _install(_wazuh_handler([WAZUH_ALERT]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        first = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert first["accepted"] == 1
        second = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert second["accepted"] == 0
        assert second["duplicates"] >= 1
        assert _events(client, admin)["total"] == 1
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 7. Mixed valid/invalid batch - one bad record must not discard the batch
# ---------------------------------------------------------------------------


def test_mixed_batch_keeps_valid_records_and_rejects_only_the_bad_one(
    monkeypatch, client, clean_db
):
    mixed = [
        WAZUH_ALERT,
        "not-an-object",
        dict(WAZUH_ALERT, id="s6-valid-2"),
    ]
    _install(_wazuh_handler(mixed))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert body["accepted"] == 2
        assert body["rejected"] == 1
        stored = _events(client, admin, source_type="WAZUH")
        assert stored["total"] == 2
        # The rejection is reported per record, with an index and a code.
        codes = {e.get("code") for e in body.get("errors", [])}
        assert codes & {"INVALID_EVENT", "MALFORMED_LINE", "REJECTED"}
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 8. Oversized / bounded batch
# ---------------------------------------------------------------------------


def test_batch_is_bounded_by_the_configured_maximum(monkeypatch, client, clean_db):
    many = [dict(WAZUH_ALERT, id=f"s6-bulk-{i}") for i in range(25)]
    _install(_wazuh_handler(many))
    _configure_wazuh(monkeypatch, CONNECTOR_MAX_EVENTS="10", CONNECTOR_MAX_PAGES="2")
    try:
        admin = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert body["retrieved"] == 10
        assert body["accepted"] == 10
        assert body["truncated"] is True
        assert body["termination"] in {"MAX_EVENTS", "MAX_PAGES"}
    finally:
        _clear()


def test_batch_processing_stays_bounded_by_batch_size(monkeypatch, client, clean_db):
    _install(_wazuh_handler([dict(WAZUH_ALERT, id=f"s6-b{i}") for i in range(8)]))
    _configure_wazuh(monkeypatch, INGESTION_MAX_BATCH_SIZE="2", CONNECTOR_MAX_EVENTS="8")
    try:
        admin = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert body["accepted"] == 8
        assert body["batches"] == 4
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 9. Unknown asset
# ---------------------------------------------------------------------------


def test_unknown_asset_stays_unresolved_and_is_not_invented(monkeypatch, client, clean_db):
    orphan = dict(WAZUH_ALERT, id="s6-orphan", agent={"id": "9", "name": "unknown-host"})
    _install(_wazuh_handler([orphan]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert body["accepted"] == 1
        item = _events(client, admin, source_type="WAZUH")["items"][0]
        assert not item.get("asset_id")
        assert item["hostname"] == "unknown-host"
    finally:
        _clear()


def test_known_asset_is_correlated_by_ip(monkeypatch, client, clean_db):
    from app.database import session as session_module
    from app.models.assets import Asset

    db = session_module.get_session_factory()()
    try:
        db.add(Asset(ip_address="203.0.113.10", state="up"))
        db.commit()
    finally:
        db.close()

    _install(_wazuh_handler([WAZUH_ALERT]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        item = _events(client, admin, source_type="WAZUH")["items"][0]
        assert item["asset_id"], "an inventoried source IP must resolve to an asset"
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 10. Secret redaction inside stored events
# ---------------------------------------------------------------------------


def test_credentials_in_a_vendor_payload_are_not_persisted(monkeypatch, client, clean_db):
    """A rule that quotes a secret must not store it (Step 6)."""
    leaky = dict(
        WAZUH_ALERT,
        id="s6-leak",
        data={
            "srcip": "203.0.113.10",
            "dstip": "10.0.0.5",
            "user": "admin",
            "password": "SUPER-SECRET-PASSWORD",
            "api_key": "SUPER-SECRET-APIKEY",
            "session_token": "SUPER-SECRET-TOKEN",
        },
    )
    _install(_wazuh_handler([leaky]))
    _configure_wazuh(monkeypatch, WAZUH_PASSWORD="CONFIG-PASSWORD")
    try:
        admin = _tokens(client)
        assert (
            client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()[
                "accepted"
            ]
            == 1
        )
        item = _events(client, admin, source_type="WAZUH")["items"][0]
        blob = json.dumps(item)
        assert "SUPER-SECRET-PASSWORD" not in blob
        assert "SUPER-SECRET-APIKEY" not in blob
        assert "SUPER-SECRET-TOKEN" not in blob
        assert "CONFIG-PASSWORD" not in blob
        assert "***REDACTED***" in blob
        # Non-secret forensic fields survive intact.
        assert "203.0.113.10" in blob
        assert "admin" in blob
    finally:
        _clear()


def test_scrub_is_bounded_and_preserves_structure():
    """Deeply nested / huge payloads must not become a CPU sink."""
    from app.services.event_service import REDACTED_PLACEHOLDER, scrub_secrets

    # Shallow secret -> redacted.
    assert scrub_secrets({"password": "shallow"}) == {"password": REDACTED_PLACEHOLDER}
    # Past the depth ceiling -> truncated, so the value cannot leak either.
    deep: object = {"password": "bottom"}
    for _ in range(40):
        deep = {"level": deep}
    text = json.dumps(scrub_secrets(deep))
    assert "bottom" not in text
    assert "TRUNCATED" in text

    wide = {f"k{i}": i for i in range(1000)}
    assert len(scrub_secrets(wide)) <= 201

    # Non-dict/list values pass through untouched.
    assert scrub_secrets("plain") == "plain"
    assert scrub_secrets(7) == 7
    assert scrub_secrets(None) is None


# ---------------------------------------------------------------------------
# 11. Statistics distinguish received / normalized / accepted / rejected / duplicated
# ---------------------------------------------------------------------------


def test_poll_statistics_distinguish_every_stage(monkeypatch, client, clean_db):
    _install(_wazuh_handler([WAZUH_ALERT, "not-an-object"]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        first = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        # received 2, normalized 1, accepted 1, rejected 1, duplicated 0
        assert first["retrieved"] == 2
        assert first["normalized"] == 1
        assert first["accepted"] == 1
        assert first["rejected"] == 1
        assert first["duplicates"] == 0

        second = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        # Second pass: nothing new, one duplicate, same rejection.
        assert second["normalized"] == 1
        assert second["accepted"] == 0
        assert second["duplicates"] == 1
        assert second["rejected"] == 1
    finally:
        _clear()


def test_ingestion_metrics_report_normalized(monkeypatch, client, clean_db):
    _install(_wazuh_handler([WAZUH_ALERT]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        metrics = client.get("/api/v1/events/ingestion/status", headers=admin).json()
        assert "normalized" in metrics["totals"]
        wazuh = next(s for s in metrics["sources"] if s["source"] == "wazuh")
        assert wazuh["events_normalized"] == 1
        assert wazuh["events_accepted"] == 1
        assert wazuh["events_fetched"] == 1
    finally:
        _clear()


# ---------------------------------------------------------------------------
# 12. Audit trail preserved
# ---------------------------------------------------------------------------


def test_audit_trail_is_preserved(monkeypatch, client, clean_db):
    from sqlalchemy import select

    from app.database import session as session_module
    from app.models.events import EventAudit

    _install(_wazuh_handler([WAZUH_ALERT, "not-an-object"]))
    _configure_wazuh(monkeypatch)
    try:
        admin = _tokens(client)
        client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        db = session_module.get_session_factory()()
        try:
            actions = [r.action for r in db.scalars(select(EventAudit)).all()]
        finally:
            db.close()
        assert "EVENT_RECEIVED" in actions
        assert "EVENT_NORMALIZED" in actions
        assert "INGESTION_STARTED" in actions
        assert "INGESTION_BATCH_COMPLETED" in actions
    finally:
        _clear()
