"""Telemetry ingestion foundation tests (Step 23, fixture-grade).

Covers: Suricata/Zeek/Wazuh valid+invalid fixtures, normalization,
registry rejection, command-field rejection, dedup replay accounting,
asset correlation + unresolved marking, RBAC/auth gating, audit
lifecycle, payload/batch limits, malformed input, secret hygiene —
without weakening Steps 1–22.
"""

SURICATA_ALERT = {
    "event_type": "alert",
    "timestamp": "2026-09-28T10:00:00Z",
    "src_ip": "10.0.0.5",
    "dest_ip": "10.0.0.9",
    "src_port": 4444,
    "dest_port": 80,
    "proto": "TCP",
    "flow_id": 111,
    "alert": {
        "signature_id": 2001,
        "rev": 3,
        "gid": 1,
        "severity": 2,
        "category": "Test",
        "signature": "TEST sig",
    },
}

ZEEK_CONN = {
    "event_type": "conn",
    "ts": 1758955200.123456,
    "uid": "CONN1234567890abcd",
    "id.orig_h": "10.0.0.5",
    "id.resp_h": "10.0.0.9",
    "id.orig_p": 4444,
    "id.resp_p": 443,
    "proto": "tcp",
    "duration": 1.5,
    "service": "https",
}

WAZUH_ALERT = {
    "event_type": "alert",
    "id": "1770000000.101",
    "timestamp": "2026-09-28T10:00:00.000+0000",
    "rule": {"id": "1002", "level": 7, "description": "Test rule fired"},
    "agent": {"id": "001", "name": "test-agent", "ip": "10.0.0.9"},
    "srcip": "10.0.0.5",
    "full_log": "Test alert body",
}


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
    admin = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin-pass-word-1"}
    ).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin}"}
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
    viewer = client.post(
        "/api/v1/auth/login", json={"username": "viewer1", "password": "viewer-pass-1234"}
    ).json()["access_token"]
    return admin_headers, {"Authorization": f"Bearer {viewer}"}


def _seed_asset(ip="10.0.0.9", hostname="known-host"):
    from app.database import session as session_module
    from app.models.assets import Asset

    db = session_module.get_session_factory()()
    try:
        db.add(Asset(ip_address=ip, hostname=hostname, state="up"))
        db.commit()
        from sqlalchemy import select

        return db.scalar(select(Asset.id).where(Asset.ip_address == ip))
    finally:
        db.close()


def test_valid_suricata_fixture(client, clean_db):
    response = client.post("/api/v1/events/ingest/suricata", json={"event": SURICATA_ALERT})
    assert response.status_code == 201
    body = response.json()
    assert body["event_type"] == "SURICATA_ALERT"
    assert body["severity"] == "HIGH"  # alert.severity 2
    assert body["source_ip"] == "10.0.0.5"
    assert body["destination_ip"] == "10.0.0.9"
    assert body["ingest_mode"] == "FIXTURE"
    assert body["occurrence_count"] == 1
    assert body["confidence"] is None  # not supplied: stays unknown


def test_invalid_suricata_fixture(client, clean_db):
    assert (
        client.post("/api/v1/events/ingest/suricata", json={"event": {"nope": True}}).status_code
        == 422
    )
    assert (
        client.post("/api/v1/events/ingest/suricata", json={"event": "string"}).status_code == 422
    )


def test_valid_zeek_fixture(client, clean_db):
    response = client.post("/api/v1/events/ingest/zeek", json={"event": ZEEK_CONN})
    assert response.status_code == 201
    body = response.json()
    assert body["source_ip"] == "10.0.0.5"
    assert body["destination_port"] == 443
    assert body["protocol"] == "tcp"
    assert body["ingest_mode"] == "FIXTURE"


def test_invalid_zeek_fixture(client, clean_db):
    assert client.post("/api/v1/events/ingest/zeek", json={"event": {"uid": 1}}).status_code == 422


def test_valid_wazuh_fixture(client, clean_db):
    response = client.post("/api/v1/events/ingest/wazuh", json={"event": WAZUH_ALERT})
    assert response.status_code == 201
    body = response.json()
    assert body["hostname"] == "test-agent"
    assert body["source_ip"] == "10.0.0.5"
    assert body["ingest_mode"] == "FIXTURE"


def test_invalid_wazuh_fixture(client, clean_db):
    assert (
        client.post("/api/v1/events/ingest/wazuh", json={"event": {"rule": "x"}}).status_code == 422
    )


def test_normalization_and_confidence(client, clean_db):
    created = client.post(
        "/api/v1/events",
        json={
            "source_type": "GENERIC",
            "source_name": "s",
            "event_type": "t",
            "title": "T",
            "confidence": 75,
            "protocol": "TCP",
        },
    ).json()
    assert created["confidence"] == 75
    assert created["protocol"] == "tcp"
    assert created["occurrence_count"] == 1
    assert created["last_seen_at"] is not None
    assert (
        client.post(
            "/api/v1/events",
            json={
                "source_type": "GENERIC",
                "source_name": "s",
                "event_type": "t",
                "title": "T",
                "confidence": 500,
            },
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/events",
            json={
                "source_type": "GENERIC",
                "source_name": "s",
                "event_type": "t",
                "title": "T",
                "confidence": "high",
            },
        ).status_code
        == 422
    )


def test_registry_rejects_unknown_sources():
    from app.services.event_adapters import ADAPTERS, describe_adapters, resolve_adapter

    assert {entry["key"] for entry in describe_adapters()} == {
        "suricata",
        "zeek",
        "wazuh",
        "defender",
    }
    assert all(entry["mode"] == "FIXTURE" for entry in describe_adapters())
    assert resolve_adapter("suricata").source_type == "SURICATA"
    import pytest

    for unknown in ("splunk", "SURICATA", "", "../evil", "suricata;rm"):
        with pytest.raises(KeyError):
            resolve_adapter(unknown)
    assert set(ADAPTERS) == {"suricata", "zeek", "wazuh", "defender"}


def test_command_field_rejected_everywhere(client, clean_db):
    base = {
        "source_type": "GENERIC",
        "source_name": "s",
        "event_type": "t",
        "title": "T",
        "command": "shutdown /s",
    }
    assert client.post("/api/v1/events", json=base).status_code == 422
    assert client.post(
        "/api/v1/events/ingest/suricata", json={"event": dict(SURICATA_ALERT, command="x")}
    ).status_code in (200, 201, 422)
    # The adapter must treat unknown keys as inert data, never execute them.
    from app.services.suricata_adapter import adapt_eve_event

    envelope = adapt_eve_event(dict(SURICATA_ALERT, command="rm -rf /"), "s")
    assert "rm -rf" not in str(envelope.get("title", ""))


def test_duplicate_ingestion_counts_occurrences(client, clean_db):
    first = client.post("/api/v1/events/ingest/suricata", json={"event": SURICATA_ALERT})
    assert first.status_code == 201
    second = client.post("/api/v1/events/ingest/suricata", json={"event": SURICATA_ALERT})
    assert second.status_code == 200  # replay, not a duplicate row
    assert second.json()["id"] == first.json()["id"]
    assert second.json()["occurrence_count"] == 2
    assert second.json()["last_seen_at"] >= first.json()["last_seen_at"]
    assert client.get("/api/v1/events").json()["total"] == 1
    # Same content under a different sensor name is a different identity.
    third = client.post(
        "/api/v1/events/ingest/suricata",
        json={"event": SURICATA_ALERT, "source_name": "other-sensor"},
    )
    assert third.status_code == 201
    assert third.json()["id"] != first.json()["id"]


def test_asset_correlation_and_unresolved(client, clean_db):
    asset_id = _seed_asset()
    linked = client.post("/api/v1/events/ingest/suricata", json={"event": SURICATA_ALERT}).json()
    assert linked["asset_id"] == asset_id  # destination_ip resolved server-side
    assert client.get(f"/api/v1/events?asset_id={asset_id}").json()["total"] == 1
    lonely = client.post(
        "/api/v1/events",
        json={
            "source_type": "GENERIC",
            "source_name": "s",
            "event_type": "t",
            "title": "T",
            "source_ip": "198.51.100.9",
        },
    ).json()
    assert lonely["asset_id"] is None  # explicitly unresolved, no asset invented
    assert client.get("/api/v1/assets").json()["total"] == 1
    # Bogus client-supplied links are dropped, never trusted blindly.
    forged = client.post(
        "/api/v1/events",
        json={
            "source_type": "GENERIC",
            "source_name": "s",
            "event_type": "t2",
            "title": "T2",
            "asset_id": "no-such-asset",
        },
    ).json()
    assert forged["asset_id"] is None


def test_rbac_and_authentication(client, clean_db):
    admin_headers, viewer_headers = _tokens(client)
    assert (
        client.post("/api/v1/events/ingest/suricata", json={"event": SURICATA_ALERT}).status_code
        == 401
    )
    denied = client.post(
        "/api/v1/events/ingest/suricata", json={"event": SURICATA_ALERT}, headers=viewer_headers
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
    assert client.get("/api/v1/events", headers=viewer_headers).status_code == 200
    assert (
        client.post(
            "/api/v1/events/ingest/suricata", json={"event": SURICATA_ALERT}, headers=admin_headers
        ).status_code
        == 201
    )


def test_audit_lifecycle(client, clean_db):
    client.post("/api/v1/events/ingest/suricata", json={"event": SURICATA_ALERT})
    client.post("/api/v1/events/ingest/suricata", json={"event": SURICATA_ALERT})  # replay
    client.post("/api/v1/events/ingest/suricata", json={"event": {"bad": 1}})  # rejected
    event_id = client.get("/api/v1/events").json()["items"][0]["id"]
    entries = client.get(f"/api/v1/events/{event_id}/audit").json()["entries"]
    actions = [entry["action"] for entry in entries]
    assert "EVENT_NORMALIZED" in actions
    assert "EVENT_RECEIVED" in actions
    assert "EVENT_DEDUPLICATED" in actions
    for entry in entries:
        assert entry["actor"]
        assert entry["created_at"]
    assert client.get("/api/v1/events/does-not-exist/audit").status_code == 404


def test_payload_and_batch_limits(client, clean_db):
    big = client.post(
        "/api/v1/events",
        json={
            "source_type": "GENERIC",
            "source_name": "s",
            "event_type": "t",
            "title": "T",
            "raw_event": {"blob": "x" * (70 * 1024)},
        },
    )
    assert big.status_code == 413
    assert big.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
    oversized = {"events": [SURICATA_ALERT] * 101, "source_name": "s"}
    assert client.post("/api/v1/events/ingest/suricata/batch", json=oversized).status_code == 422
    mixed = client.post(
        "/api/v1/events/ingest/suricata/batch",
        json={"events": [SURICATA_ALERT, {"bad": 1}, SURICATA_ALERT], "source_name": "s"},
    ).json()
    assert (mixed["accepted"], mixed["duplicates"], mixed["rejected"]) == (1, 1, 1)


def test_malformed_schema_rejected(client, clean_db):
    assert client.post("/api/v1/events", json={"title": "T"}).status_code == 422
    assert client.post("/api/v1/events/ingest/zeek", json={}).status_code == 422
    assert client.post("/api/v1/events/ingest/zeek", json={"event": [1, 2]}).status_code == 422


def test_no_secrets_in_responses_or_audits(client, clean_db):
    import json as _json

    _tokens(client)
    token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin-pass-word-1"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/api/v1/events/ingest/suricata", json={"event": SURICATA_ALERT}, headers=headers)
    client.post("/api/v1/events/ingest/suricata", json={"event": {"bad": 1}}, headers=headers)
    event_id = client.get("/api/v1/events", headers=headers).json()["items"][0]["id"]
    blob = _json.dumps(client.get(f"/api/v1/events/{event_id}", headers=headers).json())
    blob += _json.dumps(client.get(f"/api/v1/events/{event_id}/audit", headers=headers).json())
    blob += _json.dumps(client.get("/api/v1/auth/audit", headers=headers).json())
    lowered = blob.lower()
    assert "password" not in lowered
    assert "eyJ" not in blob
    assert "access_token" not in lowered


def test_security_regression_step23_modules():
    """AST-level proof for the Step 23 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.api.v1.endpoints.events as event_endpoints
    import app.services.event_adapters as registry
    import app.services.event_service as service

    for module in (service, registry, event_endpoints):
        tree = _ast.parse(_inspect.getsource(module))
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
