"""Wazuh adapter + ingest endpoint tests (synthetic fixtures only)."""

import json
from pathlib import Path

import pytest

from app.services.wazuh_adapter import WazuhAdapterError, adapt_wazuh_event

FIXTURES = Path(__file__).parent / "fixtures" / "wazuh"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_alert_mapping():
    envelope = adapt_wazuh_event(load("alert.json"), "test-manager")
    assert envelope["source_type"] == "WAZUH"
    assert envelope["source_name"] == "test-manager"
    assert envelope["event_type"] == "WAZUH_ALERT"
    assert envelope["severity"] == "MEDIUM"  # rule level 5
    assert envelope["title"] == "SSHD authentication failed."
    assert envelope["hostname"] == "test-agent-01"
    assert envelope["event_time"] is not None and envelope["event_time"].year == 2026
    assert envelope["external_event_id"].startswith("wazuh:")
    assert envelope["raw_event"]["rule"]["id"] == "5716"


@pytest.mark.parametrize(
    ("fixture", "event_type"),
    [
        ("fim.json", "WAZUH_FIM"),
        ("authentication.json", "WAZUH_AUTH"),
        ("syscheck.json", "WAZUH_SYSCHECK"),
        ("sca.json", "WAZUH_SCA"),
        ("vulnerability.json", "WAZUH_VULNERABILITY"),
        ("rootcheck.json", "WAZUH_ROOTCHECK"),
        ("command.json", "WAZUH_COMMAND"),
    ],
)
def test_supported_categories(fixture, event_type):
    envelope = adapt_wazuh_event(load(fixture))
    assert envelope["event_type"] == event_type
    assert envelope["source_type"] == "WAZUH"
    assert envelope["source_name"] == "wazuh"  # declared default


def test_severity_thresholds():
    assert adapt_wazuh_event(load("alert.json"))["severity"] == "MEDIUM"  # level 5
    assert adapt_wazuh_event(load("vulnerability.json"))["severity"] == "HIGH"  # level 10
    assert adapt_wazuh_event(load("authentication.json"))["severity"] == "LOW"  # level 3
    assert adapt_wazuh_event({"event_type": "alert"})["severity"] == "INFO"  # missing level
    assert (
        adapt_wazuh_event({"event_type": "alert", "rule": {"level": 15}})["severity"] == "CRITICAL"
    )
    assert (
        adapt_wazuh_event({"event_type": "alert", "rule": {"level": 16}})["severity"] == "CRITICAL"
    )
    assert (
        adapt_wazuh_event({"event_type": "alert", "rule": {"level": 12}})["severity"] == "CRITICAL"
    )
    assert adapt_wazuh_event({"event_type": "alert", "rule": {"level": 11}})["severity"] == "HIGH"
    assert (
        adapt_wazuh_event({"event_type": "alert", "rule": {"level": 99}})["severity"] == "CRITICAL"
    )
    assert adapt_wazuh_event({"event_type": "alert", "rule": {"level": 0}})["severity"] == "INFO"
    assert (
        adapt_wazuh_event({"event_type": "alert", "rule": {"level": "high"}})["severity"] == "INFO"
    )


def test_timestamps_iso_epoch_and_millis():
    assert adapt_wazuh_event(load("alert.json"))["event_time"].year == 2026
    auth_time = adapt_wazuh_event(load("authentication.json"))["event_time"]
    assert auth_time is not None and auth_time.year == 2025  # epoch seconds
    syscheck_time = adapt_wazuh_event(load("syscheck.json"))["event_time"]
    assert syscheck_time is not None and syscheck_time.year == 2025  # epoch millis
    fallback = adapt_wazuh_event({"event_type": "alert", "timestamp": "not-a-time"})
    assert fallback["event_time"] is not None  # documented fallback to now


def test_agent_rule_network_mappings():
    envelope = adapt_wazuh_event(load("authentication.json"))
    assert envelope["source_ip"] == "203.0.113.8"
    assert envelope["source_port"] == 43333
    fim = adapt_wazuh_event(load("fim.json"))
    assert fim["source_ip"] is None  # fim has no network fields: NULL, not faked
    vuln = adapt_wazuh_event(load("vulnerability.json"))
    assert vuln["severity"] == "HIGH"


def test_unknown_type_accepted_as_generic():
    envelope = adapt_wazuh_event(load("unknown.json"))
    assert envelope["event_type"] == "WAZUH_UNKNOWN"
    assert envelope["severity"] == "INFO"


@pytest.mark.parametrize(
    "bad", [[], "string", 42, None, {"no_type": True}, {"event_type": 7}, {"event_type": "  "}]
)
def test_malformed_input_rejected(bad):
    with pytest.raises(WazuhAdapterError):
        adapt_wazuh_event(bad)


def test_identity_deterministic_with_fallback():
    eve = load("alert.json")
    assert (
        adapt_wazuh_event(eve)["external_event_id"] == adapt_wazuh_event(eve)["external_event_id"]
    )
    changed = dict(eve, id="other-id")
    assert (
        adapt_wazuh_event(changed)["external_event_id"]
        != adapt_wazuh_event(eve)["external_event_id"]
    )
    stripped = {key: value for key, value in eve.items() if key not in ("id", "agent", "rule")}
    first = adapt_wazuh_event(stripped)["external_event_id"]
    assert first == adapt_wazuh_event(stripped)["external_event_id"] and first.startswith("wazuh:")


def test_security_regression_payloads_stay_data():
    envelope = adapt_wazuh_event(load("command.json"))
    assert "$(whoami)" in (envelope["raw_event"]["data"]["command"] or "")
    assert "<script>alert(1)</script>" in (envelope["description"] or "")
    assert "' OR 1=1 --" in (envelope["description"] or "")
    assert "{{7*7}}" in (envelope["description"] or "")
    assert envelope["source_type"] == "WAZUH"


def test_single_ingest_end_to_end(client, clean_db):
    response = client.post(
        "/api/v1/events/ingest/wazuh",
        json={"source_name": "test-manager", "event": load("fim.json")},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["source_type"] == "WAZUH"
    assert body["event_type"] == "WAZUH_FIM"
    assert body["severity"] == "MEDIUM"
    assert body["hostname"] == "test-agent-01"
    assert body["normalized_data"]["vendor"]["fim"]["path"] == "/etc/test.conf"
    assert body["normalized_data"]["vendor"]["rule"]["id"] == "552"

    replay = client.post(
        "/api/v1/events/ingest/wazuh",
        json={"source_name": "test-manager", "event": load("fim.json")},
    )
    assert replay.status_code == 200
    assert replay.json()["id"] == body["id"]
    assert client.get("/api/v1/events", params={"source_type": "WAZUH"}).json()["total"] == 1


def test_ingest_rejects_bad_input(client):
    assert (
        client.post(
            "/api/v1/events/ingest/wazuh", json={"event": load("malformed.json")}
        ).status_code
        == 422
    )
    assert client.post("/api/v1/events/ingest/wazuh", json={"event": [1]}).status_code == 422
    oversized = {"event_type": "alert", "blob": "x" * (70 * 1024)}
    assert client.post("/api/v1/events/ingest/wazuh", json={"event": oversized}).status_code == 413


def test_batch_partial_failure_counts(client, clean_db):
    response = client.post(
        "/api/v1/events/ingest/wazuh/batch",
        json={
            "source_name": "batch-manager",
            "events": [load("alert.json"), load("sca.json"), {"broken": True}, load("alert.json")],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 2
    assert body["duplicates"] == 1
    assert body["rejected"] == 1
    assert body["errors"][0]["index"] == 2
    assert body["errors"][0]["code"] == "INVALID_WAZUH"
    assert len(body["items"]) == 3


def test_batch_size_bounded(client):
    response = client.post(
        "/api/v1/events/ingest/wazuh/batch", json={"events": [{"event_type": "alert"}] * 101}
    )
    assert response.status_code == 422


def test_wazuh_events_visible_in_generic_api(client, clean_db):
    client.post("/api/v1/events/ingest/wazuh", json={"event": load("vulnerability.json")})
    filtered = client.get("/api/v1/events", params={"source_type": "WAZUH"}).json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["event_type"] == "WAZUH_VULNERABILITY"
