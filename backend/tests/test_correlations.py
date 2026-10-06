"""Deterministic correlation tests (synthetic TEST-NET fixtures only)."""

import hashlib
import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "correlation"

CHAIN_FILES = [
    "chain_a_1.json",
    "chain_a_2.json",
    "chain_a_3.json",
    "chain_b_1.json",
    "chain_b_2.json",
    "chain_b_3.json",
    "loner.json",
    "outside_window.json",
    "incompatible_1.json",
    "incompatible_2.json",
    "vuln.json",
    "vuln_activity.json",
    "chain_d_1.json",
    "chain_d_2.json",
]


def ingest_all(client):
    ids = {}
    for name in CHAIN_FILES:
        payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        response = client.post("/api/v1/events", json=payload)
        assert response.status_code == 201, name
        ids[name] = response.json()["id"]
    return ids


def recompute(client):
    response = client.post("/api/v1/correlations/recompute")
    assert response.status_code == 200
    return response.json()


def test_recompute_creates_documented_chains(client, clean_db):
    ids = ingest_all(client)
    result = recompute(client)
    assert result["events_scanned"] == len(CHAIN_FILES)
    assert result["rules_evaluated"] == 3
    assert result["created"] == 4
    assert result["refreshed"] == 0

    listed = client.get("/api/v1/correlations").json()
    assert listed["total"] == 4
    by_rule = {}
    for item in listed["items"]:
        by_rule.setdefault(item["rule_id"], []).append(item)
    assert sorted(by_rule) == ["multi-source-target", "repeated-source", "vuln-exposure"]
    assert len(by_rule["multi-source-target"]) == 2

    target_a = next(
        item for item in by_rule["multi-source-target"] if item["primary_ip"] == "198.51.100.23"
    )
    assert target_a["severity"] == "HIGH"  # inherited maximum, not invented
    assert target_a["confidence"] == 75
    assert target_a["event_count"] == 3
    target_a_detail = client.get(f"/api/v1/correlations/{target_a['id']}").json()
    assert "198.51.100.23" in target_a_detail["explanation"]

    vuln = by_rule["vuln-exposure"][0]
    assert vuln["primary_ip"] == "192.0.2.50"
    assert vuln["confidence"] == 70
    detail = client.get(f"/api/v1/correlations/{vuln['id']}").json()
    roles = {item["event_id"]: item["role"] for item in detail["evidence"]}
    assert roles[ids["vuln.json"]] == "vulnerability"
    assert roles[ids["vuln_activity.json"]] == "activity"
    assert "not proof of compromise" in detail["description"]

    src = by_rule["repeated-source"][0]
    assert src["primary_ip"] == "203.0.113.9"
    assert src["severity"] == "MEDIUM"
    assert src["confidence"] == 60

    loner_id = ids["loner.json"]
    for item in listed["items"]:
        detail = client.get(f"/api/v1/correlations/{item['id']}").json()
        assert loner_id not in {entry["event_id"] for entry in detail["evidence"]}
    # Outside-window + incompatible events never form their own correlation.
    assert listed["total"] == 4


def test_recompute_is_idempotent(client, clean_db):
    ingest_all(client)
    first = recompute(client)
    second = recompute(client)
    assert second["created"] == 0
    assert second["refreshed"] == first["created"]
    assert sorted(second["correlation_ids"]) == sorted(first["correlation_ids"])
    assert client.get("/api/v1/correlations").json()["total"] == 4


def test_deterministic_identity(client, clean_db):
    ids = ingest_all(client)
    recompute(client)
    listed = client.get("/api/v1/correlations").json()["items"]
    target_a = next(item for item in listed if item["primary_ip"] == "198.51.100.23")
    expected_events = sorted([ids["chain_a_1.json"], ids["chain_a_2.json"], ids["chain_a_3.json"]])
    canonical = json.dumps(
        ["correlation:v1", "multi-source-target", expected_events], separators=(",", ":")
    )
    assert target_a["id"] == hashlib.sha256(canonical.encode()).hexdigest()


def test_time_window_boundary(client, clean_db):
    base = {
        "source_type": "GENERIC",
        "source_name": "w",
        "event_type": "probe",
        "severity": "INFO",
        "title": "window probe",
        "destination_ip": "198.51.100.77",
    }
    client.post(
        "/api/v1/events",
        json={**base, "source_type": "SURICATA", "event_time": "2026-09-27T06:00:00Z"},
    )
    client.post(
        "/api/v1/events", json={**base, "source_type": "ZEEK", "event_time": "2026-09-27T06:59:00Z"}
    )
    assert recompute(client)["created"] == 1  # 59 minutes apart: one cluster
    client.post(
        "/api/v1/events",
        json={**base, "source_type": "WAZUH", "event_time": "2026-09-27T08:00:00Z"},
    )
    result = recompute(client)
    # 61-minute gap splits the window; the late event stands alone: no new rows.
    assert result["created"] == 0
    assert client.get("/api/v1/correlations").json()["total"] == 1


def test_attack_chain_ordering_and_evidence(client, clean_db):
    ids = ingest_all(client)
    recompute(client)
    listed = client.get("/api/v1/correlations").json()["items"]
    target_a = next(item for item in listed if item["primary_ip"] == "198.51.100.23")
    chain = client.get(f"/api/v1/correlations/{target_a['id']}/attack-chain").json()
    assert chain["correlation_id"] == target_a["id"]
    kinds = [node["kind"] for node in chain["nodes"]]
    assert kinds[0] == "correlation"
    assert "asset" in kinds
    event_nodes = [node for node in chain["nodes"] if node["kind"] == "event"]
    assert [node["id"] for node in event_nodes] == [
        f"event:{ids['chain_a_1.json']}",
        f"event:{ids['chain_a_2.json']}",
        f"event:{ids['chain_a_3.json']}",
    ]
    # Original evidence IDs preserved verbatim.
    assert {node["id"].removeprefix("event:") for node in event_nodes} == {
        ids["chain_a_1.json"],
        ids["chain_a_2.json"],
        ids["chain_a_3.json"],
    }
    assert all(edge["source"] and edge["target"] and edge["relation"] for edge in chain["edges"])


def test_identical_timestamps_order_deterministically(client, clean_db):
    """Tied event_time values break ties by event id, stably across recomputes."""
    base = {
        "source_name": "tie",
        "event_type": "probe",
        "severity": "INFO",
        "title": "tie probe",
        "event_time": "2026-09-27T06:00:00Z",
        "destination_ip": "198.51.100.88",
    }
    first = client.post(
        "/api/v1/events", json={**base, "source_type": "SURICATA", "external_event_id": "tie-1"}
    ).json()["id"]
    second = client.post(
        "/api/v1/events", json={**base, "source_type": "ZEEK", "external_event_id": "tie-2"}
    ).json()["id"]
    recompute(client)
    chain_one = client.get("/api/v1/correlations").json()["items"]
    assert len(chain_one) == 1
    nodes_one = client.get(f"/api/v1/correlations/{chain_one[0]['id']}/attack-chain").json()[
        "nodes"
    ]
    order_one = [node["id"] for node in nodes_one if node["kind"] == "event"]
    assert order_one == sorted(order_one)  # tie broken by event id
    assert {node.removeprefix("event:") for node in order_one} == {first, second}
    recompute(client)  # second pass must converge to the exact same order
    nodes_two = client.get(f"/api/v1/correlations/{chain_one[0]['id']}/attack-chain").json()[
        "nodes"
    ]
    assert [node["id"] for node in nodes_two if node["kind"] == "event"] == order_one


def test_malformed_and_missing_timestamps(client, clean_db):
    bad = {
        "source_type": "GENERIC",
        "source_name": "w",
        "event_type": "probe",
        "severity": "INFO",
        "title": "bad time",
        "event_time": "not-a-time",
    }
    assert client.post("/api/v1/events", json=bad).status_code == 422
    missing = dict(bad)
    del missing["event_time"]
    assert client.post("/api/v1/events", json=missing).status_code == 201  # defaults to now
    aware = dict(missing, event_time="2026-09-27T06:00:00+02:00", external_event_id="aware-1")
    assert client.post("/api/v1/events", json=aware).status_code == 201
    assert recompute(client)["created"] == 0  # loners stay loners


def test_api_validation_and_filters(client, clean_db):
    ingest_all(client)
    recompute(client)
    assert client.get("/api/v1/correlations", params={"status": "bogus"}).status_code == 422
    assert client.get("/api/v1/correlations", params={"severity": "NOPE"}).status_code == 422
    assert client.get("/api/v1/correlations", params={"status": "open"}).json()["total"] == 4
    assert client.get("/api/v1/correlations", params={"severity": "HIGH"}).json()["total"] == 2
    assert (
        client.get("/api/v1/correlations", params={"rule_id": "vuln-exposure"}).json()["total"] == 1
    )
    page = client.get("/api/v1/correlations", params={"limit": 2, "offset": 2}).json()
    assert page["total"] == 4 and len(page["items"]) == 2
    missing = client.get("/api/v1/correlations/does-not-exist")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "CORRELATION_NOT_FOUND"
    assert client.get("/api/v1/correlations/does-not-exist/attack-chain").status_code == 404


def test_security_regression_no_execution_paths():
    """AST-level proof for the new Step 9 modules (mirrors the vuln test)."""
    import ast as _ast
    import inspect as _inspect

    import app.services.correlation_rules as rules
    import app.services.correlation_service as service

    for module in (rules, service):
        tree = _ast.parse(_inspect.getsource(module))
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
                assert not (
                    set(names) & {"subprocess", "os", "pty", "shutil", "importlib", "socket"}
                ), names
            elif isinstance(node, _ast.ImportFrom):
                module_name = (node.module or "").split(".")[0]
                assert module_name not in {"subprocess", "os", "socket"}, module_name
            if isinstance(node, _ast.Call):
                func = node.func
                if isinstance(func, _ast.Name):
                    assert func.id not in {"eval", "exec", "compile", "open", "__import__"}, func.id
                elif isinstance(func, _ast.Attribute):
                    assert func.attr not in {"system", "popen"}, func.attr
