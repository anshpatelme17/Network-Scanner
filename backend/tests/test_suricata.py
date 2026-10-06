"""Suricata EVE adapter + ingest endpoint tests (synthetic fixtures only)."""

import json
from pathlib import Path

import pytest

from app.services.suricata_adapter import SuricataAdapterError, adapt_eve_event

FIXTURES = Path(__file__).parent / "fixtures" / "suricata"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_alert_parsing_and_mapping():
    envelope = adapt_eve_event(load("alert.json"), "test-sensor")
    assert envelope["source_type"] == "SURICATA"
    assert envelope["source_name"] == "test-sensor"
    assert envelope["event_type"] == "SURICATA_ALERT"
    assert envelope["severity"] == "CRITICAL"  # Suricata severity 1
    assert envelope["title"] == "TEST Suspicious HTTP Request"
    assert envelope["source_ip"] == "192.0.2.10"
    assert envelope["destination_ip"] == "198.51.100.23"
    assert envelope["destination_port"] == 80
    assert envelope["protocol"] == "tcp"
    assert envelope["action"] == "allowed"
    assert envelope["hostname"] == "test-sensor-01"
    assert envelope["event_time"] is not None and envelope["event_time"].year == 2026
    assert envelope["raw_event"]["alert"]["signature_id"] == 2000001
    assert envelope["external_event_id"].startswith("suricata:")
    assert envelope["correlation_key"] == "1122334455667788"


@pytest.mark.parametrize(
    ("fixture", "event_type", "severity"),
    [
        ("dns.json", "SURICATA_DNS", "INFO"),
        ("http.json", "SURICATA_HTTP", "INFO"),
        ("tls.json", "SURICATA_TLS", "INFO"),
        ("flow.json", "SURICATA_FLOW", "INFO"),
        ("fileinfo.json", "SURICATA_FILEINFO", "INFO"),
    ],
)
def test_network_event_types(fixture, event_type, severity):
    envelope = adapt_eve_event(load(fixture))
    assert envelope["event_type"] == event_type
    assert envelope["severity"] == severity  # platform default, no alert severity
    assert envelope["source_ip"] and envelope["destination_ip"]
    assert envelope["source_name"] == "suricata"  # declared default


def test_unknown_type_accepted_as_generic_suricata():
    envelope = adapt_eve_event(load("unknown.json"))
    assert envelope["event_type"] == "SURICATA_UNKNOWN"
    assert envelope["severity"] == "INFO"


def test_missing_optional_fields_tolerated():
    envelope = adapt_eve_event(load("missing_fields.json"))
    assert envelope["event_type"] == "SURICATA_ALERT"
    assert envelope["source_ip"] is None
    assert envelope["hostname"] is None
    assert envelope["title"] == "Suricata alert event (? → ?)"


def test_invalid_severity_falls_back_to_default():
    envelope = adapt_eve_event(load("invalid_severity.json"))
    assert envelope["severity"] == "INFO"  # 99 is not a real Suricata severity


@pytest.mark.parametrize("bad", [[], "string", 42, None, {"no_type": True}, {"event_type": 7}])
def test_malformed_input_rejected(bad):
    with pytest.raises(SuricataAdapterError):
        adapt_eve_event(bad)


def test_external_id_deterministic_not_time_based():
    eve = load("alert.json")
    first = adapt_eve_event(eve)["external_event_id"]
    second = adapt_eve_event(eve)["external_event_id"]
    assert first == second
    different = dict(eve, flow_id=999)
    assert adapt_eve_event(different)["external_event_id"] != first


def test_malicious_values_stay_inert_data():
    envelope = adapt_eve_event(load("malicious.json"))
    assert "$(whoami)" in envelope["title"]
    assert envelope["severity"] == "HIGH"  # severity 2 maps, payload does not execute
    assert envelope["raw_event"]["alert"]["category"] == "Test'; DROP TABLE security_events; --"


def test_single_ingest_end_to_end(client, clean_db):
    response = client.post(
        "/api/v1/events/ingest/suricata",
        json={"source_name": "test-sensor", "event": load("alert.json")},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["source_type"] == "SURICATA"
    assert body["event_type"] == "SURICATA_ALERT"
    assert body["severity"] == "CRITICAL"
    assert body["title"] == "TEST Suspicious HTTP Request"
    assert body["raw_event"]["alert"]["signature_id"] == 2000001
    assert body["normalized_data"]["vendor"]["alert"]["category"] == "Test Policy Violation"
    assert body["normalized_data"]["vendor"]["http"]["url"] == "/index.html"

    # Replay → 200, same row, no duplicate.
    replay = client.post(
        "/api/v1/events/ingest/suricata",
        json={"source_name": "test-sensor", "event": load("alert.json")},
    )
    assert replay.status_code == 200
    assert replay.json()["id"] == body["id"]
    assert client.get("/api/v1/events", params={"source_type": "SURICATA"}).json()["total"] == 1


def test_ingest_rejects_bad_input(client):
    assert (
        client.post("/api/v1/events/ingest/suricata", json={"event": {"nope": True}}).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/events/ingest/suricata", json={"source_name": "s", "event": [1, 2]}
        ).status_code
        == 422
    )
    oversized = {"event_type": "alert", "blob": "x" * (70 * 1024)}
    oversized_response = client.post("/api/v1/events/ingest/suricata", json={"event": oversized})
    assert oversized_response.status_code == 413


def test_batch_partial_failure_counts(client, clean_db):
    response = client.post(
        "/api/v1/events/ingest/suricata/batch",
        json={
            "source_name": "batch-sensor",
            "events": [
                load("alert.json"),
                load("dns.json"),
                {"broken": True},  # invalid: no event_type
                load("alert.json"),  # duplicate of the first
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 2
    assert body["duplicates"] == 1
    assert body["rejected"] == 1
    assert body["errors"][0]["index"] == 2
    assert body["errors"][0]["code"] == "INVALID_EVE"
    assert len(body["items"]) == 3


def test_batch_size_bounded(client):
    response = client.post(
        "/api/v1/events/ingest/suricata/batch",
        json={"events": [{"event_type": "flow"}] * 101},
    )
    assert response.status_code == 422


def test_suricata_events_visible_in_generic_api(client, clean_db):
    client.post("/api/v1/events/ingest/suricata", json={"event": load("http.json")})
    filtered = client.get("/api/v1/events", params={"source_type": "SURICATA"}).json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["event_type"] == "SURICATA_HTTP"
