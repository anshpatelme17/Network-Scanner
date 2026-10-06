"""Zeek adapter + ingest endpoint tests (synthetic fixtures only)."""

import json
from pathlib import Path

import pytest

from app.services.zeek_adapter import ZeekAdapterError, adapt_zeek_event

FIXTURES = Path(__file__).parent / "fixtures" / "zeek"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_conn_mapping():
    envelope = adapt_zeek_event(load("conn.json"), "test-zeek")
    assert envelope["source_type"] == "ZEEK"
    assert envelope["source_name"] == "test-zeek"
    assert envelope["event_type"] == "ZEEK_CONN"
    assert envelope["severity"] == "INFO"  # no severity signal in conn logs
    assert envelope["source_ip"] == "192.0.2.10"
    assert envelope["destination_ip"] == "198.51.100.23"
    assert envelope["source_port"] == 41234
    assert envelope["destination_port"] == 80
    assert envelope["protocol"] == "tcp"
    assert envelope["event_time"] is not None and envelope["event_time"].year == 2025
    assert envelope["correlation_key"] == "CONN1234567890abcd"
    assert envelope["external_event_id"].startswith("zeek:")
    assert envelope["raw_event"]["uid"] == "CONN1234567890abcd"


def test_ipv6_dns_mapping():
    envelope = adapt_zeek_event(load("dns.json"))
    assert envelope["event_type"] == "ZEEK_DNS"
    assert envelope["source_ip"] == "2001:db8::10"
    assert envelope["destination_ip"] == "2001:db8::53"
    assert envelope["source_name"] == "zeek"


def test_http_action_and_hostname():
    envelope = adapt_zeek_event(load("http.json"))
    assert envelope["event_type"] == "ZEEK_HTTP"
    assert envelope["action"] == "POST"
    assert envelope["hostname"] == "files.test.invalid"


def test_ssl_tls_x509_ssh_types():
    assert adapt_zeek_event(load("ssl.json"))["event_type"] == "ZEEK_SSL"
    x509 = adapt_zeek_event(load("x509.json"))
    assert x509["event_type"] == "ZEEK_X509"
    assert x509["source_ip"] is None  # x509 has no addresses: NULL, not faked
    assert adapt_zeek_event(load("ssh.json"))["event_type"] == "ZEEK_SSH"


def test_notice_title_description_and_src_dst():
    envelope = adapt_zeek_event(load("notice.json"))
    assert envelope["event_type"] == "ZEEK_NOTICE"
    assert envelope["title"] == "Zeek notice: Scan::Sweep"
    assert envelope["description"] == "Test scan sweep detected in lab traffic"
    assert envelope["source_ip"] == "192.0.2.15"
    assert envelope["destination_ip"] == "198.51.100.99"


def test_explicit_notice_severity_mapped():
    eve = dict(load("notice.json"), severity=2)
    assert adapt_zeek_event(eve)["severity"] == "HIGH"
    assert adapt_zeek_event(load("notice.json"))["severity"] == "INFO"


def test_unknown_type_accepted_as_generic():
    envelope = adapt_zeek_event(load("unknown.json"))
    assert envelope["event_type"] == "ZEEK_UNKNOWN"
    assert envelope["severity"] == "INFO"


@pytest.mark.parametrize(
    "bad", [[], "string", 42, None, {"no_type": True}, {"event_type": 7}, {"event_type": "  "}]
)
def test_malformed_input_rejected(bad):
    with pytest.raises(ZeekAdapterError):
        adapt_zeek_event(bad)


def test_identity_deterministic_and_uid_free_fallback():
    eve = load("conn.json")
    assert adapt_zeek_event(eve)["external_event_id"] == adapt_zeek_event(eve)["external_event_id"]
    changed = dict(eve, uid="OTHER")
    assert (
        adapt_zeek_event(changed)["external_event_id"] != adapt_zeek_event(eve)["external_event_id"]
    )
    no_uid = {key: value for key, value in eve.items() if key != "uid"}
    first, second = (
        adapt_zeek_event(no_uid)["external_event_id"],
        adapt_zeek_event(no_uid)["external_event_id"],
    )
    assert first == second and first.startswith("zeek:")


def test_security_regression_payloads_stay_data():
    envelope = adapt_zeek_event(load("malicious.json"))
    assert "<script>alert(1)</script>" in (envelope["hostname"] or "")
    assert "$(whoami)" in (envelope["action"] or "")
    assert "rm -rf" in envelope["raw_event"]["uri"]
    assert envelope["source_type"] == "ZEEK"
    assert envelope["severity"] == "INFO"


def test_single_ingest_end_to_end(client, clean_db):
    response = client.post(
        "/api/v1/events/ingest/zeek",
        json={"source_name": "test-zeek", "event": load("notice.json")},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["source_type"] == "ZEEK"
    assert body["event_type"] == "ZEEK_NOTICE"
    assert body["title"] == "Zeek notice: Scan::Sweep"
    assert body["raw_event"]["uid"] == "NOTICE1234567890ab"

    replay = client.post(
        "/api/v1/events/ingest/zeek",
        json={"source_name": "test-zeek", "event": load("notice.json")},
    )
    assert replay.status_code == 200
    assert replay.json()["id"] == body["id"]
    assert client.get("/api/v1/events", params={"source_type": "ZEEK"}).json()["total"] == 1


def test_ingest_rejects_bad_input(client):
    assert (
        client.post("/api/v1/events/ingest/zeek", json={"event": {"nope": True}}).status_code == 422
    )
    assert client.post("/api/v1/events/ingest/zeek", json={"event": [1]}).status_code == 422
    oversized = {"event_type": "conn", "blob": "x" * (70 * 1024)}
    assert client.post("/api/v1/events/ingest/zeek", json={"event": oversized}).status_code == 413


def test_batch_partial_failure_counts(client, clean_db):
    response = client.post(
        "/api/v1/events/ingest/zeek/batch",
        json={
            "source_name": "batch-zeek",
            "events": [load("conn.json"), load("dns.json"), {"broken": True}, load("conn.json")],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 2
    assert body["duplicates"] == 1
    assert body["rejected"] == 1
    assert body["errors"][0] == {
        "index": 2,
        "code": "INVALID_ZEEK",
        "message": body["errors"][0]["message"],
    }
    assert len(body["items"]) == 3


def test_batch_size_bounded(client):
    response = client.post(
        "/api/v1/events/ingest/zeek/batch", json={"events": [{"event_type": "conn"}] * 101}
    )
    assert response.status_code == 422


def test_zeek_events_visible_in_generic_api(client, clean_db):
    client.post("/api/v1/events/ingest/zeek", json={"event": load("ssh.json")})
    filtered = client.get("/api/v1/events", params={"source_type": "ZEEK"}).json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["event_type"] == "ZEEK_SSH"
