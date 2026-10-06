"""Vulnerability finding adapter + ingest endpoint tests (synthetic only)."""

import json
from pathlib import Path

import pytest

from app.services.vulnerability_adapter import (
    VulnerabilityAdapterError,
    adapt_vulnerability_finding,
)

FIXTURES = Path(__file__).parent / "fixtures" / "vulnerabilities"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_critical_finding_mapping():
    envelope = adapt_vulnerability_finding(load("critical.json"), "test-scanner")
    assert envelope["source_type"] == "VULNERABILITY_SCANNER"
    assert envelope["source_name"] == "test-scanner"
    assert envelope["event_type"] == "VULNERABILITY_FINDING"
    assert envelope["severity"] == "CRITICAL"
    assert envelope["title"] == "Test Critical RCE"
    assert envelope["destination_ip"] == "192.0.2.10"
    assert envelope["destination_port"] == 443
    assert envelope["protocol"] == "tcp"
    assert envelope["hostname"] == "192.0.2.10"
    assert envelope["external_event_id"].startswith("vuln:")
    assert envelope["correlation_key"] == "FIND-0001"
    assert envelope["raw_event"]["finding_id"] == "FIND-0001"


def test_cvss_drives_severity_when_text_absent():
    assert adapt_vulnerability_finding(load("high_cvss.json"))["severity"] == "HIGH"  # 7.5
    assert adapt_vulnerability_finding(load("medium.json"))["severity"] == "MEDIUM"  # text
    assert adapt_vulnerability_finding(load("low.json"))["severity"] == "LOW"
    assert adapt_vulnerability_finding(load("info.json"))["severity"] == "INFO"


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (10, "CRITICAL"),
        (9.0, "CRITICAL"),
        (8.9, "HIGH"),
        (7.0, "HIGH"),
        (6.9, "MEDIUM"),
        (4.0, "MEDIUM"),
        (3.9, "LOW"),
        (0.1, "LOW"),
        (0, "INFO"),
        ("7.5", "HIGH"),
        ("junk", "INFO"),
    ],
)
def test_cvss_boundaries(score, expected):
    envelope = adapt_vulnerability_finding({"title": "t", "cvss_score": score})
    assert envelope["severity"] == expected, score


def test_explicit_severity_beats_cvss():
    envelope = adapt_vulnerability_finding({"title": "t", "severity": "low", "cvss_score": 9.9})
    assert envelope["severity"] == "LOW"
    assert adapt_vulnerability_finding({"title": "t"})["severity"] == "INFO"  # missing


def test_cve_normalization_and_multi():
    import json as _json

    from app.services import event_service

    multi = adapt_vulnerability_finding(load("multicve.json"))
    assert multi["severity"] == "HIGH"  # CVSS 8.2
    attributes = event_service.normalize_event({**multi, "source_name": "s"})
    stored_cves = _json.loads(attributes["normalized_data"])["vendor"].get("cves")
    # Upper-cased, de-duplicated; "not-a-cve" excluded from normalized list.
    assert stored_cves == ["CVE-2024-0010", "CVE-2024-0011"]


def test_host_port_protocol_service_product():
    envelope = adapt_vulnerability_finding(load("hostport.json"))
    assert envelope["destination_ip"] == "198.51.100.23"
    assert envelope["destination_port"] == 8443
    assert envelope["protocol"] == "tcp"
    assert envelope["hostname"] == "web.test.invalid"
    assert envelope["source_ip"] is None
    assert envelope["source_port"] is None


def test_evidence_solution_references_preserved():
    envelope = adapt_vulnerability_finding(load("evidence.json"))
    assert "probe pattern" in (envelope["description"] or "")
    assert envelope["source_ip"] is None


def test_unknown_fields_and_raw_preservation():
    envelope = adapt_vulnerability_finding(load("unknown_fields.json"))
    assert envelope["raw_event"]["custom_field"] == "kept in raw only"
    assert envelope["raw_event"]["nested"] == {"extra": True}


def test_ipv6_accepted():
    envelope = adapt_vulnerability_finding(load("low.json"))
    assert envelope["destination_ip"] == "2001:db8::20"


@pytest.mark.parametrize("bad", [[], "s", 42, None, {"severity": "high"}, {"name": 7}])
def test_malformed_input_rejected(bad):
    with pytest.raises(VulnerabilityAdapterError):
        adapt_vulnerability_finding(bad)


def test_identity_deterministic_with_fallback():
    eve = load("critical.json")
    assert (
        adapt_vulnerability_finding(eve)["external_event_id"]
        == adapt_vulnerability_finding(eve)["external_event_id"]
    )
    changed = dict(eve, finding_id="OTHER")
    assert (
        adapt_vulnerability_finding(changed)["external_event_id"]
        != adapt_vulnerability_finding(eve)["external_event_id"]
    )
    stripped = {"title": "Same title everywhere"}
    first = adapt_vulnerability_finding(stripped)["external_event_id"]
    assert first == adapt_vulnerability_finding(stripped)["external_event_id"] and first.startswith(
        "vuln:"
    )


def test_security_regression_payloads_stay_data():
    envelope = adapt_vulnerability_finding(load("evidence.json"))
    assert "$(whoami)" in (envelope["description"] or "")
    assert "<script>alert(1)</script>" in (envelope["description"] or "")
    assert "' OR 1=1 --" in (envelope["description"] or "")
    assert "{{7*7}}" in (envelope["description"] or "")
    assert envelope["source_type"] == "VULNERABILITY_SCANNER"


def test_no_execution_paths_in_adapter():
    """AST-level proof: no subprocess/eval/import/callable-from-data paths.

    Docstrings are excluded by parsing the AST (not raw text), so this
    test cannot false-positive on documentation.
    """
    import ast as _ast
    import inspect as _inspect

    import app.services.vulnerability_adapter as adapter

    tree = _ast.parse(_inspect.getsource(adapter))
    banned_builtin_calls = {"eval", "exec", "compile", "open", "__import__"}
    banned_method_calls = {"system", "popen"}
    banned_modules = {"subprocess", "os", "pty", "shutil", "importlib"}
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
            assert not (set(names) & banned_modules), names
        elif isinstance(node, _ast.ImportFrom):
            module = (node.module or "").split(".")[0]
            assert module not in banned_modules, module
        if isinstance(node, _ast.Call):
            func = node.func
            if isinstance(func, _ast.Name):
                assert func.id not in banned_builtin_calls, func.id
            elif isinstance(func, _ast.Attribute):
                assert func.attr not in banned_method_calls, func.attr


def test_single_ingest_end_to_end(client, clean_db):
    response = client.post(
        "/api/v1/events/ingest/vulnerabilities",
        json={"source_name": "test-scanner", "event": load("critical.json")},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["source_type"] == "VULNERABILITY_SCANNER"
    assert body["event_type"] == "VULNERABILITY_FINDING"
    assert body["severity"] == "CRITICAL"
    assert body["title"] == "Test Critical RCE"
    assert body["destination_ip"] == "192.0.2.10"
    assert body["normalized_data"]["vendor"]["cves"] == ["CVE-2024-0001"]
    assert body["normalized_data"]["vendor"]["cvss"] == 9.8
    assert body["normalized_data"]["vendor"]["solution"] == "Apply the test vendor patch."
    assert body["normalized_data"]["vendor"]["references"] == ["https://example.test/cve-2024-0001"]

    replay = client.post(
        "/api/v1/events/ingest/vulnerabilities",
        json={"source_name": "test-scanner", "event": load("critical.json")},
    )
    assert replay.status_code == 200
    assert replay.json()["id"] == body["id"]
    assert (
        client.get("/api/v1/events", params={"source_type": "VULNERABILITY_SCANNER"}).json()[
            "total"
        ]
        == 1
    )


def test_ingest_rejects_bad_input(client):
    assert (
        client.post(
            "/api/v1/events/ingest/vulnerabilities", json={"event": load("malformed.json")}
        ).status_code
        == 422
    )
    assert (
        client.post("/api/v1/events/ingest/vulnerabilities", json={"event": [1]}).status_code == 422
    )
    oversized = {"title": "t", "blob": "x" * (70 * 1024)}
    assert (
        client.post("/api/v1/events/ingest/vulnerabilities", json={"event": oversized}).status_code
        == 413
    )


def test_batch_partial_failure_counts(client, clean_db):
    response = client.post(
        "/api/v1/events/ingest/vulnerabilities/batch",
        json={
            "source_name": "batch-scanner",
            "events": [
                load("critical.json"),
                load("medium.json"),
                {"broken": True},
                load("critical.json"),
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 2
    assert body["duplicates"] == 1
    assert body["rejected"] == 1
    assert body["errors"][0]["index"] == 2
    assert body["errors"][0]["code"] == "INVALID_VULNERABILITY"
    assert len(body["items"]) == 3


def test_batch_size_bounded(client):
    response = client.post(
        "/api/v1/events/ingest/vulnerabilities/batch", json={"events": [{"title": "t"}] * 101}
    )
    assert response.status_code == 422


def test_findings_visible_in_generic_api(client, clean_db):
    client.post("/api/v1/events/ingest/vulnerabilities", json={"event": load("hostport.json")})
    filtered = client.get("/api/v1/events", params={"source_type": "VULNERABILITY_SCANNER"}).json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["event_type"] == "VULNERABILITY_FINDING"
