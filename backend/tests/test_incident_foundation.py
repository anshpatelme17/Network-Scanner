"""Incident foundation tests (Step 17, detection + evidence + audit).

Covers: creation, invalid input, retrieval, not-found, evidence,
timeline, valid/invalid status transitions, deduplication, repeat
processing, multi-evidence attachment, vulnerability-only input,
risk/confidence, empty-evidence behavior, missing assets, incident
updates, audit trail, and API error handling — without weakening any
Step 1–16 test.
"""

import json
import uuid
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "correlation"


def _fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _ingest(client, *names):
    for name in names:
        response = client.post("/api/v1/events", json=_fixture(name))
        assert response.status_code == 201, name


def _recompute(client):
    response = client.post("/api/v1/correlations/recompute")
    assert response.status_code == 200
    return response.json()


def _correlations(client, **params):
    return client.get("/api/v1/correlations", params=params).json()["items"]


def _seed_vuln_exposure(client):
    """Finding + observed activity on 192.0.2.50 (qualifies by construction)."""
    _ingest(client, "vuln.json", "vuln_activity.json")
    _recompute(client)
    matches = _correlations(client, rule_id="vuln-exposure")
    assert len(matches) == 1
    return matches[0]


def _insert_asset_finding(ip, hostname=None):
    """Direct Asset + Vulnerability rows sharing the incident host keys."""
    from app.database import session as session_module
    from app.models.assets import Asset
    from app.models.vulnerabilities import Vulnerability

    db = session_module.get_session_factory()()
    try:
        asset = Asset(ip_address=ip, hostname=hostname)
        db.add(asset)
        db.flush()
        finding = Vulnerability(
            asset_id=asset.id,
            scanner="fixture",
            scanner_finding_id=f"TEST-{uuid.uuid4().hex[:8]}",
            title="Test finding sharing the incident host",
            severity="HIGH",
            cvss_score=7.5,
            cve_id="CVE-2026-0001",
        )
        db.add(finding)
        db.commit()
        return asset.id, finding.id
    finally:
        db.close()


def test_detect_creates_vulnerability_activity_incident(client, clean_db):
    correlation = _seed_vuln_exposure(client)
    body = client.post(
        "/api/v1/incidents/detect", json={"correlation_id": correlation["id"]}
    ).json()
    assert body["evaluated"] == 1
    assert body["created"] == 1
    assert body["skipped"] == 0
    assert body["detector_version"] == "1.0.0"
    outcome = body["outcomes"][0]
    assert outcome["created"] is True
    assert outcome["incident_id"] is not None

    incident = client.get(f"/api/v1/incidents/{outcome['incident_id']}").json()
    assert incident["incident_type"] == "VULNERABILITY_ACTIVITY"
    assert incident["status"] == "OPEN"
    assert incident["confidence"] == correlation["confidence"] == 70
    assert incident["risk_score"] is None  # no assessment linked: no invented score
    assert incident["first_seen"] == correlation["window_start"]
    assert incident["last_seen"] == correlation["window_end"]
    assert incident["resolved_at"] is None
    assert "observed activity" in (incident["detection_reason"] or "")
    assert incident["incident_key"].startswith("INC-")
    # Missing asset row: referenced by IP, never manufactured.
    assert incident["primary_asset_id"] is None
    assert incident["primary_ip"] == "192.0.2.50"


def test_detect_invalid_input(client, clean_db):
    absent = client.post("/api/v1/incidents/detect", json={"correlation_id": "nope"})
    assert absent.status_code == 404
    assert absent.json()["error"]["code"] == "REFERENCE_NOT_FOUND"
    malformed = client.post("/api/v1/incidents/detect", json={"correlation_id": 123})
    assert malformed.status_code == 422
    bulk_with_risk = client.post(
        "/api/v1/incidents/detect", json={"risk_assessment_id": "whatever"}
    )
    assert bulk_with_risk.status_code == 422


def test_incident_not_found_everywhere(client, clean_db):
    for path in ("", "/evidence", "/timeline", "/audit"):
        response = client.get(f"/api/v1/incidents/nope{path}")
        assert response.status_code == 404, path
        assert response.json()["error"]["code"] == "INCIDENT_NOT_FOUND", path
    status_change = client.post("/api/v1/incidents/nope/status", json={"status": "CLOSED"})
    assert status_change.status_code == 404


def test_evidence_lists_references_not_copies(client, clean_db):
    correlation = _seed_vuln_exposure(client)
    incident_id = client.post(
        "/api/v1/incidents/detect", json={"correlation_id": correlation["id"]}
    ).json()["outcomes"][0]["incident_id"]

    evidence = client.get(f"/api/v1/incidents/{incident_id}/evidence").json()
    assert evidence["incident_type"] == "VULNERABILITY_ACTIVITY"
    assert evidence["detection_reason"]
    assert evidence["correlation"]["id"] == correlation["id"]
    assert evidence["correlation"]["rule_id"] == "vuln-exposure"
    roles = {event["id"]: event["role"] for event in evidence["events"]}
    assert len(roles) == 2
    assert set(roles.values()) == {"vulnerability", "activity"}
    for event in evidence["events"]:
        for key in ("event_type", "severity", "source_type", "title", "event_time"):
            assert event[key], key
    # No stored findings yet: honest empty, not invented links.
    assert evidence["vulnerabilities"] == []


def test_evidence_includes_related_findings(client, clean_db, _sqlite_engine):
    correlation = _seed_vuln_exposure(client)
    _, finding_id = _insert_asset_finding("192.0.2.50", "exposed-host")
    incident_id = client.post(
        "/api/v1/incidents/detect", json={"correlation_id": correlation["id"]}
    ).json()["outcomes"][0]["incident_id"]
    evidence = client.get(f"/api/v1/incidents/{incident_id}/evidence").json()
    refs = {item["id"]: item for item in evidence["vulnerabilities"]}
    assert finding_id in refs
    assert refs[finding_id]["severity"] == "HIGH"
    assert refs[finding_id]["cve_id"] == "CVE-2026-0001"
    assert "shares asset identifiers" in (refs[finding_id]["reason"] or "")


def test_timeline_orders_lifecycle(client, clean_db):
    correlation = _seed_vuln_exposure(client)
    incident_id = client.post(
        "/api/v1/incidents/detect", json={"correlation_id": correlation["id"]}
    ).json()["outcomes"][0]["incident_id"]
    client.post(f"/api/v1/incidents/{incident_id}/status", json={"status": "ACKNOWLEDGED"})
    client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "CLOSED"})

    timeline = client.get(f"/api/v1/incidents/{incident_id}/timeline").json()
    kinds = [entry["kind"] for entry in timeline["entries"]]
    assert kinds[0] == "observation"  # first-seen marker leads
    assert "opened" in kinds
    assert kinds.count("status") == 2
    assert kinds[-1] == "resolution"  # resolved marker trails
    stamps = [entry["at"] for entry in timeline["entries"] if entry["at"]]
    assert stamps == sorted(stamps)
    for entry in timeline["entries"]:
        assert entry["label"] and entry["kind"]


def test_status_post_alias_and_resolved_at(client, clean_db):
    correlation = _seed_vuln_exposure(client)
    incident_id = client.post(
        "/api/v1/incidents/detect", json={"correlation_id": correlation["id"]}
    ).json()["outcomes"][0]["incident_id"]
    moved = client.post(f"/api/v1/incidents/{incident_id}/status", json={"status": "CLOSED"})
    assert moved.status_code == 200
    assert moved.json()["status"] == "CLOSED"
    assert moved.json()["resolved_at"] is not None

    invalid = client.post(f"/api/v1/incidents/{incident_id}/status", json={"status": "OPEN"})
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "INVALID_TRANSITION"
    unknown = client.post("/api/v1/incidents/detect", json={"correlation_id": correlation["id"]})
    assert unknown.status_code == 200  # detect still resolves the same row
    bad_value = client.patch(f"/api/v1/incidents/{incident_id}", json={"status": "NOPE"})
    assert bad_value.status_code == 422


def test_repeat_detection_is_idempotent(client, clean_db):
    correlation = _seed_vuln_exposure(client)
    first = client.post(
        "/api/v1/incidents/detect", json={"correlation_id": correlation["id"]}
    ).json()
    second = client.post(
        "/api/v1/incidents/detect", json={"correlation_id": correlation["id"]}
    ).json()
    assert second["created"] == 0
    assert second["updated"] == 0
    assert second["outcomes"][0]["incident_id"] == first["outcomes"][0]["incident_id"]
    assert client.get("/api/v1/incidents").json()["total"] == 1
    audits = client.get(f"/api/v1/incidents/{first['outcomes'][0]['incident_id']}/audit").json()
    assert [entry["action"] for entry in audits["entries"]] == ["OPENED"]


def test_bulk_detect_updates_new_finding_evidence(client, clean_db, _sqlite_engine):
    _seed_vuln_exposure(client)
    first = client.post("/api/v1/incidents/detect", json={}).json()
    assert first["evaluated"] >= 1
    assert first["created"] == 1

    _insert_asset_finding("192.0.2.50")
    second = client.post("/api/v1/incidents/detect", json={}).json()
    assert second["created"] == 0
    assert second["updated"] == 1  # the later finding link is genuinely new
    third = client.post("/api/v1/incidents/detect", json={}).json()
    assert third["created"] == 0
    assert third["updated"] == 0  # steady state: same inputs, same outputs
    assert client.get("/api/v1/incidents").json()["total"] == 1

    audits = client.get(f"/api/v1/incidents/{first['outcomes'][0]['incident_id']}/audit").json()
    actions = [entry["action"] for entry in audits["entries"]]
    # Same-second ties order arbitrarily in SQLite: compare the multiset.
    assert sorted(actions) == ["EVIDENCE_ATTACHED", "OPENED"]


def test_vulnerability_only_creates_nothing(client, clean_db):
    _ingest(client, "vuln.json")  # a finding with no observed activity
    assert _recompute(client)["created"] == 0
    body = client.post("/api/v1/incidents/detect", json={}).json()
    assert body == {
        "evaluated": 0,
        "created": 0,
        "updated": 0,
        "skipped": 0,
        "detector_version": "1.0.0",
        "outcomes": [],
    }
    assert client.get("/api/v1/incidents").json()["total"] == 0


def test_assess_branches_are_conservative():
    from app.models.correlations import Correlation
    from app.services.incident_detection import assess, classify_type

    def row(rule_id, count, severity):
        return Correlation(
            id="c",
            rule_id=rule_id,
            rule_name=rule_id,
            title="t",
            severity=severity,
            confidence=0,
            explanation="",
            primary_ip="10.0.0.1",
            hostname=None,
            window_start=None,
            window_end=None,
            event_count=count,
        )

    qualifies, reason = assess(row("vuln-exposure", 2, "LOW"))
    assert qualifies and "observed activity" in reason
    qualifies, _ = assess(row("repeated-source", 3, "LOW"))
    assert qualifies
    qualifies, _ = assess(row("multi-source-target", 2, "CRITICAL"))
    assert qualifies
    qualifies, reason = assess(row("multi-source-target", 2, "LOW"))
    assert not qualifies and "investigation lead" in reason
    qualifies, _ = assess(row("multi-source-target", 1, "INFO"))
    assert not qualifies  # finding-only / lone observation never qualifies

    assert classify_type(row("vuln-exposure", 0, "INFO")) == "VULNERABILITY_ACTIVITY"
    assert classify_type(row("multi-source-target", 0, "INFO")) == "SUSPICIOUS_NETWORK_ACTIVITY"
    assert classify_type(row("repeated-source", 0, "INFO")) == "CORRELATED_SECURITY_EVENT"
    assert classify_type(row("future-rule", 0, "INFO")) == "OTHER"


def test_detect_skips_lone_observations_consistently(client, clean_db):
    _ingest(client, "chain_d_1.json", "chain_d_2.json")
    _recompute(client)
    correlations = _correlations(client)
    assert len(correlations) == 1
    correlation = correlations[0]
    expected = (
        correlation["rule_id"] == "vuln-exposure"
        or correlation["event_count"] >= 3
        or correlation["severity"] in ("HIGH", "CRITICAL")
    )
    body = client.post(
        "/api/v1/incidents/detect", json={"correlation_id": correlation["id"]}
    ).json()
    if expected:
        assert body["created"] == 1
    else:
        assert body["created"] == 0 and body["skipped"] == 1
        assert "investigation lead" in body["outcomes"][0]["reason"]
        assert client.get("/api/v1/incidents").json()["total"] == 0


def test_risk_link_sets_score_verbatim(client, clean_db):
    correlation = _seed_vuln_exposure(client)
    client.post("/api/v1/risk/recompute")
    risks = client.get("/api/v1/risk", params={"entity_type": "correlation"}).json()["items"]
    matches = [item for item in risks if item["entity_id"] == correlation["id"]]
    assert matches, "expected a stored risk assessment for the correlation"
    risk = matches[0]

    incident_id = client.post(
        "/api/v1/incidents/detect",
        json={"correlation_id": correlation["id"], "risk_assessment_id": risk["id"]},
    ).json()["outcomes"][0]["incident_id"]
    incident = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert incident["risk_assessment_id"] == risk["id"]
    assert incident["risk_score"] == risk["score"]  # verbatim Step 10 score
    assert incident["severity"] == risk["severity"]  # severity still from the assessment
    assert incident["confidence"] == correlation["confidence"]  # evidence strength


def test_audit_trail_records_lifecycle(client, clean_db):
    correlation = _seed_vuln_exposure(client)
    incident_id = client.post(
        "/api/v1/incidents/detect", json={"correlation_id": correlation["id"]}
    ).json()["outcomes"][0]["incident_id"]
    client.post(
        f"/api/v1/incidents/{incident_id}/status",
        json={"status": "ACKNOWLEDGED", "actor": "analyst"},
    )
    client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"title": "Renamed for the investigation"},
    )
    audits = client.get(f"/api/v1/incidents/{incident_id}/audit").json()
    actions = [entry["action"] for entry in audits["entries"]]
    # Same-second ties in SQLite make row order arbitrary, so assert the
    # multiset plus non-decreasing timestamps (Postgres keeps full precision).
    assert sorted(actions) == ["OPENED", "STATUS_CHANGED", "UPDATED"]
    by_action = {entry["action"]: entry for entry in audits["entries"]}
    assert by_action["STATUS_CHANGED"]["actor"] == "analyst"
    assert "ACKNOWLEDGED" in (by_action["STATUS_CHANGED"]["detail"] or "")
    stamps = [entry["created_at"] for entry in audits["entries"]]
    assert stamps == sorted(stamps)
    # Audit rows back the legacy detail view too (unchanged contract).
    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert len(detail["evidence_event_ids"]) == 2


def test_type_filter_and_invalid_filters(client, clean_db):
    correlation = _seed_vuln_exposure(client)
    client.post("/api/v1/incidents/detect", json={"correlation_id": correlation["id"]})
    filtered = client.get(
        "/api/v1/incidents", params={"incident_type": "VULNERABILITY_ACTIVITY"}
    ).json()
    assert filtered["total"] == 1
    assert client.get("/api/v1/incidents", params={"incident_type": "OTHER"}).json()["total"] == 0
    bad = client.get("/api/v1/incidents", params={"incident_type": "NOPE"})
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "INVALID_FILTER"
    bad_status = client.get("/api/v1/incidents", params={"status": "NEW"})
    assert bad_status.status_code == 422  # NEW is not a Step 11/17 status


def test_first_seen_preserved_across_reprocessing(client, clean_db):
    correlation = _seed_vuln_exposure(client)
    incident_id = client.post(
        "/api/v1/incidents/detect", json={"correlation_id": correlation["id"]}
    ).json()["outcomes"][0]["incident_id"]
    before = client.get(f"/api/v1/incidents/{incident_id}").json()
    client.post("/api/v1/incidents/detect", json={"correlation_id": correlation["id"]})
    after = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert after["first_seen"] == before["first_seen"] == correlation["window_start"]
    assert after["last_seen"] == correlation["window_end"]


def test_migration_includes_step17_objects(tmp_path, monkeypatch):
    from sqlalchemy import create_engine, inspect

    from alembic import command
    from alembic.config import Config

    db_file = tmp_path / "mig17.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    config = Config(str(Path(__file__).parent.parent / "alembic.ini"))
    config.set_main_option("script_location", str(Path(__file__).parent.parent / "alembic"))
    command.upgrade(config, "head")
    inspector = inspect(create_engine(f"sqlite:///{db_file}"))
    assert "incident_audits" in inspector.get_table_names()
    assert "incident_evidence" in inspector.get_table_names()
    columns = {column["name"] for column in inspector.get_columns("incidents")}
    assert {"incident_type", "risk_score", "resolved_at", "detection_reason"} <= columns


def test_security_regression_step17_modules():
    """AST-level proof for the Step 17 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.api.v1.endpoints.incidents as endpoints
    import app.services.incident_detection as detection

    for module in (detection, endpoints):
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
