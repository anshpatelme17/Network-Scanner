"""Security event ingestion tests: validation, filters, idempotency, safety."""

from sqlalchemy import func, select

from app.models.events import SecurityEvent
from app.services import event_service


def _payload(**overrides):
    base = {
        "source_type": "GENERIC",
        "source_name": "lab-sensor",
        "event_type": "test.event",
        "severity": "HIGH",
        "title": "Something happened",
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.9",
        "destination_port": 443,
        "protocol": "TCP",
        "raw_event": {"vendor": "acme", "code": 7},
        "external_event_id": "evt-001",
    }
    base.update(overrides)
    return base


def test_valid_ingestion_normalizes_and_stores(client, clean_db):
    response = client.post("/api/v1/events", json=_payload())
    assert response.status_code == 201
    body = response.json()
    assert body["severity"] == "HIGH"
    assert body["protocol"] == "tcp"  # normalized to lowercase
    assert body["raw_event"] == {"vendor": "acme", "code": 7}
    assert body["fingerprint"] and len(body["fingerprint"]) == 64
    assert body["correlation_key"] == body["fingerprint"]  # defaulted
    assert body["normalized_data"]["title"] == "Something happened"
    assert body["event_time"] and body["received_at"] and body["created_at"]


def test_missing_required_fields_rejected(client):
    assert client.post("/api/v1/events", json={}).status_code == 422
    bad = _payload()
    del bad["title"]
    assert client.post("/api/v1/events", json=bad).status_code == 422


def test_invalid_severity_and_source_rejected(client):
    assert client.post("/api/v1/events", json=_payload(severity="URGENT")).status_code == 422
    assert client.post("/api/v1/events", json=_payload(source_type="MYTOOL")).status_code == 422
    assert client.post("/api/v1/events", json=_payload(source_port=99999)).status_code == 422
    smuggled = _payload()
    smuggled["nmap_flags"] = "-sS"
    assert client.post("/api/v1/events", json=smuggled).status_code == 422


def test_all_severities_and_sources_accepted(client, clean_db):
    for index, severity in enumerate(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]):
        response = client.post(
            "/api/v1/events",
            json=_payload(severity=severity, external_event_id=f"sev-{index}"),
        )
        assert response.status_code == 201, severity
    for index, source in enumerate(
        [
            "NMAP",
            "GENERIC",
            "WINDOWS",
            "DEFENDER",
            "SURICATA",
            "ZEEK",
            "WAZUH",
            "VULNERABILITY_SCANNER",
            "FIREWALL",
        ]
    ):
        response = client.post(
            "/api/v1/events",
            json=_payload(source_type=source, external_event_id=f"src-{index}"),
        )
        assert response.status_code == 201, source


def test_idempotent_replay_returns_existing(client, clean_db):
    first = client.post("/api/v1/events", json=_payload()).json()
    second_response = client.post("/api/v1/events", json=_payload(title="A different title"))
    assert second_response.status_code == 200  # replay, not a new resource
    assert second_response.json()["id"] == first["id"]
    # Similar event WITHOUT the external id is stored, never dropped.
    third = client.post("/api/v1/events", json=_payload(external_event_id=None)).json()
    assert third["id"] != first["id"]
    total = client.get("/api/v1/events").json()["total"]
    assert total == 2


def test_filters_pagination_lookup(client, clean_db):
    from app.database import session as session_module
    from app.models.assets import Asset

    db = session_module.get_session_factory()()
    try:
        db.add(Asset(ip_address="10.0.0.9", hostname="asset-9-host", state="up"))
        db.commit()
        asset_id = db.scalar(select(Asset.id).where(Asset.ip_address == "10.0.0.9"))
    finally:
        db.close()
    # destination_ip resolves server-side to the inventoried asset.
    client.post(
        "/api/v1/events", json=_payload(severity="CRITICAL", event_type="a.one", asset_id=asset_id)
    )
    client.post(
        "/api/v1/events",
        json=_payload(
            severity="LOW",
            event_type="b.two",
            source_type="SURICATA",
            external_event_id="e2",
            destination_ip="10.0.0.99",
        ),
    )
    assert client.get("/api/v1/events", params={"severity": "CRITICAL"}).json()["total"] == 1
    assert client.get("/api/v1/events", params={"source_type": "SURICATA"}).json()["total"] == 1
    assert client.get("/api/v1/events", params={"event_type": "a.one"}).json()["total"] == 1
    assert client.get("/api/v1/events", params={"asset_id": asset_id}).json()["total"] == 1
    assert client.get("/api/v1/events", params={"severity": "NOPE"}).status_code == 422
    page = client.get("/api/v1/events", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 2 and len(page["items"]) == 1

    event_id = client.get("/api/v1/events").json()["items"][0]["id"]
    assert client.get(f"/api/v1/events/{event_id}").json()["id"] == event_id
    missing = client.get("/api/v1/events/does-not-exist")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "EVENT_NOT_FOUND"


def test_time_range_and_summary(client, clean_db):
    client.post(
        "/api/v1/events",
        json=_payload(
            severity="CRITICAL", event_time="2020-01-01T00:00:00Z", external_event_id="old"
        ),
    )
    client.post("/api/v1/events", json=_payload(severity="HIGH", external_event_id="new"))
    assert (
        client.get("/api/v1/events", params={"since": "2021-01-01T00:00:00Z"}).json()["total"] == 1
    )
    assert (
        client.get("/api/v1/events", params={"until": "2021-01-01T00:00:00Z"}).json()["total"] == 1
    )
    summary = client.get("/api/v1/events/summary").json()
    assert summary["total_events"] == 2
    assert summary["critical_events"] == 1
    assert summary["high_events"] == 1
    assert summary["last_24h_events"] == 1


def test_oversized_raw_payload_rejected(client):
    big = _payload(raw_event={"blob": "x" * (70 * 1024)})
    response = client.post("/api/v1/events", json=big)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_malformed_raw_event_rejected(client):
    bad = _payload(raw_event="just a string, not an object")
    assert client.post("/api/v1/events", json=bad).status_code == 422
    bad_list = _payload(raw_event=["a", "list"])
    assert client.post("/api/v1/events", json=bad_list).status_code == 422


def test_malicious_strings_stay_inert_data(client, clean_db, _sqlite_engine):
    nasty_title = "'; DROP TABLE security_events; --"
    nasty_raw = {
        "cmd": "rm -rf /",
        "expr": "__import__('os').system('id')",
        "script": "<script>alert(1)</script>",
        "nested": {"pipe": "a | b && c"},
    }
    body = client.post(
        "/api/v1/events", json=_payload(title=nasty_title, raw_event=nasty_raw)
    ).json()
    assert body["title"] == nasty_title
    assert body["raw_event"] == nasty_raw
    # Table intact, exactly one row, nothing executed.
    from app.database import session as session_module

    db = session_module.get_session_factory()()
    try:
        assert db.scalar(select(func.count(SecurityEvent.id))) == 1
        assert db.scalars(select(SecurityEvent.title)).all() == [nasty_title]
    finally:
        db.close()


def test_fingerprint_stable_and_timestamp_free():
    attributes = {
        "source_type": "GENERIC",
        "source_name": "s",
        "event_type": "t",
        "severity": "INFO",
        "title": "same",
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "protocol": None,
        "asset_id": None,
        "hostname": None,
        "username": None,
        "process_name": None,
        "action": None,
        "status": None,
        "external_event_id": None,
    }
    first = event_service.compute_fingerprint(attributes)
    second = event_service.compute_fingerprint(dict(attributes))
    assert first == second and len(first) == 64
    changed = dict(attributes, title="different")
    assert event_service.compute_fingerprint(changed) != first
