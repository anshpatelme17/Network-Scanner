"""Defender adapter + ingest endpoint tests (synthetic fixtures only)."""

import json
from pathlib import Path

import pytest

from app.services.defender_adapter import DefenderAdapterError, adapt_defender_event

FIXTURES = Path(__file__).parent / "fixtures" / "defender"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_alert_mapping():
    envelope = adapt_defender_event(load("alert.json"), "test-source")
    assert envelope["source_type"] == "DEFENDER"
    assert envelope["source_name"] == "test-source"
    assert envelope["event_type"] == "DEFENDER_ALERT"
    assert envelope["severity"] == "HIGH"
    assert envelope["title"] == "Test malware was blocked on the endpoint."
    assert envelope["hostname"] == "TEST-WKS-01"
    assert envelope["username"] == "TESTDOM\\testuser"
    assert envelope["source_ip"] == "192.0.2.10"
    assert envelope["action"] == "quarantine"
    assert envelope["status"] == "Resolved"
    assert envelope["event_time"] is not None and envelope["event_time"].year == 2026
    assert envelope["external_event_id"].startswith("defender:")
    assert envelope["raw_event"]["threatName"] == "Test:Win32/Malware"


@pytest.mark.parametrize(
    ("fixture", "event_type"),
    [
        ("incident.json", "DEFENDER_INCIDENT"),
        ("device.json", "DEFENDER_DEVICE"),
        ("malware.json", "DEFENDER_MALWARE"),
        ("authentication.json", "DEFENDER_AUTHENTICATION"),
    ],
)
def test_supported_categories(fixture, event_type):
    envelope = adapt_defender_event(load(fixture))
    assert envelope["event_type"] == event_type
    assert envelope["source_type"] == "DEFENDER"
    assert envelope["source_name"] == "defender"  # declared default


def test_severity_text_numeric_and_boundaries():
    assert adapt_defender_event(load("device.json"))["severity"] == "INFO"  # informational
    assert adapt_defender_event(load("malware.json"))["severity"] == "MEDIUM"
    cases = {
        "CRITICAL": "CRITICAL",
        "critical": "CRITICAL",
        "High": "HIGH",
        "MEDIUM": "MEDIUM",
        "low": "LOW",
        "Info": "INFO",
        "unknown-word": "INFO",
        "": "INFO",
        95: "CRITICAL",
        80: "CRITICAL",
        79: "HIGH",
        50: "HIGH",
        49: "MEDIUM",
        20: "MEDIUM",
        19: "LOW",
        1: "LOW",
        0: "INFO",
        -3: "INFO",
        120: "CRITICAL",
    }
    for raw, expected in cases.items():
        envelope = adapt_defender_event({"event_type": "alert", "severity": raw})
        assert envelope["severity"] == expected, raw
    assert adapt_defender_event({"event_type": "alert"})["severity"] == "INFO"  # missing


def test_timestamps_iso_epoch_millis_and_fallback():
    assert adapt_defender_event(load("alert.json"))["event_time"].year == 2026
    assert adapt_defender_event(load("incident.json"))["event_time"] is not None  # epoch s
    assert adapt_defender_event(load("device.json"))["event_time"] is not None  # epoch ms
    assert (
        adapt_defender_event({"event_type": "alert", "timestamp": "garbage"})["event_time"]
        is not None
    )
    assert adapt_defender_event({"event_type": "alert"})["event_time"] is not None


def test_network_device_user_process_file_mappings():
    auth = adapt_defender_event(load("authentication.json"))
    assert auth["source_ip"] == "203.0.113.9"
    assert auth["destination_ip"] == "198.51.100.10"
    assert auth["source_port"] == 51234
    assert auth["destination_port"] == 3389
    assert auth["username"] == "TESTDOM\\testuser"
    malware = adapt_defender_event(load("malware.json"))
    assert malware["process_name"] == "runner.exe.test"
    incident = adapt_defender_event(load("incident.json"))
    assert incident["source_ip"] is None  # absent stays NULL, never faked


def test_unknown_type_accepted_as_generic():
    envelope = adapt_defender_event({"event_type": "weirdfuturekind"})
    assert envelope["event_type"] == "DEFENDER_UNKNOWN"
    assert envelope["severity"] == "INFO"


@pytest.mark.parametrize(
    "bad", [[], "s", 42, None, {"x": 1}, {"event_type": 7}, {"event_type": "  "}]
)
def test_malformed_input_rejected(bad):
    with pytest.raises(DefenderAdapterError):
        adapt_defender_event(bad)


def test_identity_deterministic_with_fallback():
    eve = load("alert.json")
    assert (
        adapt_defender_event(eve)["external_event_id"]
        == adapt_defender_event(eve)["external_event_id"]
    )
    changed = dict(eve, id="other-id")
    assert (
        adapt_defender_event(changed)["external_event_id"]
        != adapt_defender_event(eve)["external_event_id"]
    )
    stripped = {key: value for key, value in eve.items() if key not in ("id", "timestamp")}
    first = adapt_defender_event(stripped)["external_event_id"]
    assert first == adapt_defender_event(stripped)["external_event_id"] and first.startswith(
        "defender:"
    )


def test_security_regression_payloads_stay_data():
    envelope = adapt_defender_event(load("malware.json"))
    # description collapses into title when identical — assert on title.
    assert "<script>alert(1)</script>" in (envelope["title"] or "")
    assert "{{7*7}}" in (envelope["title"] or "")
    assert "' OR 1=1 --" in (envelope["title"] or "")
    assert "$(whoami)" in envelope["raw_event"]["commandLine"]
    assert "powershell" in envelope["raw_event"]["commandLine"]
    assert envelope["source_type"] == "DEFENDER"


def test_single_ingest_end_to_end(client, clean_db):
    response = client.post(
        "/api/v1/events/ingest/defender",
        json={"source_name": "test-src", "event": load("malware.json")},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["source_type"] == "DEFENDER"
    assert body["event_type"] == "DEFENDER_MALWARE"
    assert body["severity"] == "MEDIUM"
    assert body["hostname"] == "TEST-WKS-04"
    assert body["normalized_data"]["vendor"]["threat_name"] == "Test:Script/Downloader"
    assert body["normalized_data"]["vendor"]["file_hash"] == (
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a8"
    )

    replay = client.post(
        "/api/v1/events/ingest/defender",
        json={"source_name": "test-src", "event": load("malware.json")},
    )
    assert replay.status_code == 200
    assert replay.json()["id"] == body["id"]
    assert client.get("/api/v1/events", params={"source_type": "DEFENDER"}).json()["total"] == 1


def test_ingest_rejects_bad_input(client):
    assert (
        client.post(
            "/api/v1/events/ingest/defender", json={"event": load("malformed.json")}
        ).status_code
        == 422
    )
    assert client.post("/api/v1/events/ingest/defender", json={"event": [1]}).status_code == 422
    oversized = {"event_type": "alert", "blob": "x" * (70 * 1024)}
    assert (
        client.post("/api/v1/events/ingest/defender", json={"event": oversized}).status_code == 413
    )


def test_batch_partial_failure_counts(client, clean_db):
    response = client.post(
        "/api/v1/events/ingest/defender/batch",
        json={
            "source_name": "batch-src",
            "events": [
                load("alert.json"),
                load("device.json"),
                {"broken": True},
                load("alert.json"),
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 2
    assert body["duplicates"] == 1
    assert body["rejected"] == 1
    assert body["errors"][0]["index"] == 2
    assert body["errors"][0]["code"] == "INVALID_DEFENDER"
    assert len(body["items"]) == 3


def test_batch_size_bounded(client):
    response = client.post(
        "/api/v1/events/ingest/defender/batch", json={"events": [{"event_type": "alert"}] * 101}
    )
    assert response.status_code == 422


def test_defender_events_visible_in_generic_api(client, clean_db):
    client.post("/api/v1/events/ingest/defender", json={"event": load("authentication.json")})
    filtered = client.get("/api/v1/events", params={"source_type": "DEFENDER"}).json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["event_type"] == "DEFENDER_AUTHENTICATION"
