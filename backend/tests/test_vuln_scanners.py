"""Vulnerability assessment foundation tests (Step 22, LIVE + MOCK).

Covers: authorized requests, 401/403 gating, scope/size rejection,
unknown scanners/profiles, flag/executable rejection, shell-proof
adapter construction, mock parsing, normalization, UNKNOWN severity,
CVE preservation + gating, dedup, first/last_seen, NOT_SEEN lifecycle,
transitions, duplicate jobs, audits, secret hygiene — without
weakening Steps 1–21.
"""

import json

NSE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="TestHTTP" version="1.0"/>
        <script id="http-vuln-test" output="VULNERABLE:&#10;  CVE-2014-6271&#10;  see details"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
        <script id="ssh-quiet" output="nothing interesting here"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _db():
    from app.database import session as session_module

    return session_module.get_session_factory()()


def _seed_asset_with_service(ip="127.0.0.1", port=80, service_name="http"):
    from app.models.assets import Asset, DiscoveredService

    db = _db()
    try:
        asset = Asset(ip_address=ip, hostname="test-host", state="up")
        db.add(asset)
        db.flush()
        service = DiscoveredService(
            asset_id=asset.id, port=port, protocol="tcp", state="open", service_name=service_name
        )
        db.add(service)
        db.commit()
        return asset.id, service.id
    finally:
        db.close()


def _mock_nmap_vuln(monkeypatch, xml=NSE_XML):
    from app.services import nmap_runner
    from app.services.nmap_vuln_scanner import NmapVulnScanner

    monkeypatch.setattr(nmap_runner, "is_available", lambda: True)
    monkeypatch.setattr(NmapVulnScanner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(NmapVulnScanner, "execute", lambda self, config, asset, services: xml)
    monkeypatch.setattr(NmapVulnScanner, "version_info", lambda self: "nmap 7.94")


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
    client.post(
        "/api/v1/users",
        json={
            "username": "viewer1",
            "password": "viewer-pass-1234",
            "display_name": "V",
            "roles": ["VIEWER"],
        },
        headers={"Authorization": f"Bearer {admin}"},
    )
    viewer = client.post(
        "/api/v1/auth/login", json={"username": "viewer1", "password": "viewer-pass-1234"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {admin}"}, {"Authorization": f"Bearer {viewer}"}


def test_authorized_basic_scan(client, clean_db, monkeypatch):
    _seed_asset_with_service()
    _mock_nmap_vuln(monkeypatch)
    created = client.post(
        "/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "BASIC"}
    )
    assert created.status_code == 202
    job = client.get(f"/api/v1/vulnerability-scans/{created.json()['id']}").json()
    assert job["status"] == "completed"
    assert job["scanner"] == "nmap-vuln"
    assert "1 new" in (job["result_summary"] or "")
    findings = client.get("/api/v1/vulnerabilities").json()["items"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["scanner"] == "nmap-vuln"
    assert finding["cve_id"] == "CVE-2014-6271"
    assert finding["severity"] == "UNKNOWN"  # scripts state none: never guessed
    assert finding["status"] == "OPEN"
    assert finding["detected_version"] == "1.0"
    assert finding["fixed_version"] is None  # missing stays missing
    assert finding["scanner_version"] == "nmap 7.94"
    assert finding["extra_data"]["scanner_severity"] == "UNKNOWN"


def test_unauthenticated_and_unauthorized_roles(client, clean_db, monkeypatch):
    _seed_asset_with_service()
    _mock_nmap_vuln(monkeypatch)
    admin_headers, viewer_headers = _tokens(client)
    assert (
        client.post(
            "/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "BASIC"}
        ).status_code
        == 401
    )
    denied = client.post(
        "/api/v1/vulnerability-scans",
        json={"target": "127.0.0.1", "profile": "BASIC"},
        headers=viewer_headers,
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
    assert client.get("/api/v1/vulnerabilities", headers=viewer_headers).status_code == 200
    ok = client.post(
        "/api/v1/vulnerability-scans",
        json={"target": "127.0.0.1", "profile": "BASIC"},
        headers=admin_headers,
    )
    assert ok.status_code == 202


def test_scope_and_size_rejected(client, clean_db):
    _seed_asset_with_service()
    outside = client.post(
        "/api/v1/vulnerability-scans", json={"target": "192.168.1.1", "profile": "BASIC"}
    )
    assert outside.status_code == 403
    assert outside.json()["error"]["code"] == "TARGET_NOT_AUTHORIZED"
    assert (
        client.post(
            "/api/v1/vulnerability-scans", json={"target": "10.0.0.0/16", "profile": "BASIC"}
        ).status_code
        == 422
    )


def test_unknown_scanner_profile_rejected(client, clean_db):
    _seed_asset_with_service()
    assert (
        client.post(
            "/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "--script vuln"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "NMAP_VULN"}
        ).status_code
        == 422
    )
    import pytest

    from app.services.vulnerability_scanners import get_scanner

    with pytest.raises(KeyError):
        get_scanner("openvas-remote")


def test_arbitrary_fields_rejected(client, clean_db):
    _seed_asset_with_service()
    base = {"target": "127.0.0.1", "profile": "BASIC", "command": "nmap -A 127.0.0.1"}
    assert client.post("/api/v1/vulnerability-scans", json=base).status_code == 422
    flags = {"target": "127.0.0.1", "profile": "BASIC", "nmap_flags": "-A"}
    assert client.post("/api/v1/vulnerability-scans", json=flags).status_code == 422
    from app.services.nmap_vuln_scanner import NMAP_EXECUTABLE

    assert NMAP_EXECUTABLE == "nmap"  # fixed literal, no path configuration surface


def test_fixed_argv_construction(monkeypatch):
    import subprocess as _subprocess

    from app.services.nmap_vuln_scanner import NMAP_EXECUTABLE, NmapVulnScanner

    seen = {}

    class _Completed:
        returncode = 0
        stdout = NSE_XML
        stderr = ""

    def _fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return _Completed()

    monkeypatch.setattr(_subprocess, "run", _fake_run)
    monkeypatch.setattr(NmapVulnScanner, "is_available", staticmethod(lambda: True))
    scanner = NmapVulnScanner()
    config = scanner.configure("BASIC")
    from app.services.vulnerability_scanners import AssetView, ServiceView

    scanner.execute(
        config, AssetView(ip_address="127.0.0.1"), [ServiceView(port=80, protocol="tcp")]
    )
    argv = seen["argv"]
    assert argv[0] == NMAP_EXECUTABLE
    assert argv[-3:-1] == ["-p", "80"]
    assert argv[-1] == "127.0.0.1"
    assert "--script" in argv and "vuln and not intrusive" in argv
    assert "-oX" in argv
    assert seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["timeout"] == 600
    for token in argv:
        assert not token.startswith("--script=") or token == "--script"


def test_parse_reports_cve_evidence_only():
    from app.services.nmap_vuln_scanner import NmapVulnError, NmapVulnScanner

    findings = NmapVulnScanner().parse(NSE_XML)
    assert len(findings) == 1  # the CVE-less ssh script output is dropped
    finding = findings[0]
    assert finding.scanner_finding_id == "http-vuln-test:80/tcp"
    assert finding.cves == ("CVE-2014-6271",)
    assert finding.severity == "UNKNOWN"
    assert finding.cvss_score is None
    assert "CVE-2014-6271" in (finding.evidence or "")
    import pytest

    with pytest.raises(NmapVulnError):
        NmapVulnScanner().parse("garbage <<<")
    with pytest.raises(NmapVulnError):
        NmapVulnScanner().parse("")


def test_dedup_and_seen_timestamps(monkeypatch, client, clean_db):
    _seed_asset_with_service()
    _mock_nmap_vuln(monkeypatch)
    first = client.post(
        "/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "BASIC"}
    ).json()
    second = client.post(
        "/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "BASIC"}
    ).json()
    assert first["id"] != second["id"]  # distinct jobs
    assert (
        "1 new" in client.get(f"/api/v1/vulnerability-scans/{first['id']}").json()["result_summary"]
    )
    assert (
        "1 refreshed"
        in client.get(f"/api/v1/vulnerability-scans/{second['id']}").json()["result_summary"]
    )
    items = client.get("/api/v1/vulnerabilities").json()["items"]
    assert len(items) == 1  # no duplicates
    assert (
        items[0]["first_seen"] < items[0]["last_seen"]
        or items[0]["first_seen"] == items[0]["last_seen"]
    )


def test_not_seen_lifecycle(monkeypatch, client, clean_db):
    from app.models.assets import DiscoveredService

    asset_id, service_id = _seed_asset_with_service()
    _mock_nmap_vuln(monkeypatch)
    client.post("/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "BASIC"})
    finding_id = client.get("/api/v1/vulnerabilities").json()["items"][0]["id"]
    # Script output goes quiet while the service still exists: NOT_SEEN + audit.
    empty_xml = NSE_XML.replace("CVE-2014-6271", "nothing here")
    _mock_nmap_vuln(monkeypatch, xml=empty_xml)
    client.post("/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "BASIC"})
    detail = client.get(f"/api/v1/vulnerabilities/{finding_id}").json()
    assert detail["status"] == "NOT_SEEN"
    assert any(
        entry["event"] == "VULNERABILITY_STATUS_CHANGED" and entry["new_status"] == "NOT_SEEN"
        for entry in detail["audit"]
    )
    # Re-observation reopens with history intact.
    _mock_nmap_vuln(monkeypatch, xml=NSE_XML)
    client.post("/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "BASIC"})
    reopened = client.get(f"/api/v1/vulnerabilities/{finding_id}").json()
    assert reopened["status"] == "OPEN"
    assert reopened["first_seen"] == detail["first_seen"]
    assert len(client.get("/api/v1/vulnerabilities").json()["items"]) == 1  # still no duplicates
    # A failed scan changes nothing: break execution, rescan, status preserved.
    from app.services.nmap_vuln_scanner import NmapVulnError

    def _boom(self, config, asset, services):
        raise NmapVulnError("Nmap did not produce usable XML output.")

    monkeypatch.setattr("app.services.nmap_vuln_scanner.NmapVulnScanner.execute", _boom)
    failed = client.post(
        "/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "BASIC"}
    ).json()
    assert client.get(f"/api/v1/vulnerability-scans/{failed['id']}").json()["status"] == "failed"
    assert client.get(f"/api/v1/vulnerabilities/{finding_id}").json()["status"] == "OPEN"
    # No discovered services at all: rejected up front, no job created.
    db = _db()
    try:
        row = db.get(DiscoveredService, service_id)
        db.delete(row)
        db.commit()
    finally:
        db.close()
    refused = client.post(
        "/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "BASIC"}
    )
    assert refused.status_code == 422
    # Invalid manual edges are still rejected.
    rehide = client.post(
        f"/api/v1/vulnerabilities/{finding_id}/status", json={"status": "NOT_SEEN"}
    )
    assert rehide.status_code == 200  # OPEN->NOT_SEEN is an allowed explicit edge
    resolved = client.post(
        f"/api/v1/vulnerabilities/{finding_id}/status", json={"status": "RESOLVED"}
    )
    assert resolved.status_code == 200
    illegal = client.post(
        f"/api/v1/vulnerabilities/{finding_id}/status", json={"status": "ACCEPTED_RISK"}
    )
    assert illegal.status_code == 409  # RESOLVED->ACCEPTED_RISK is not a valid edge


def test_audit_and_job_records(monkeypatch, client, clean_db):
    _seed_asset_with_service()
    _mock_nmap_vuln(monkeypatch)
    job_id = client.post(
        "/api/v1/vulnerability-scans", json={"target": "127.0.0.1", "profile": "BASIC"}
    ).json()["id"]
    job = client.get(f"/api/v1/vulnerability-scans/{job_id}").json()
    assert [entry["event"] for entry in job["audit"]] == [
        "SCAN_REQUESTED",
        "SCAN_STARTED",
        "SCAN_COMPLETED",
    ]
    assert job["scanner"] == "nmap-vuln"
    finding_id = client.get("/api/v1/vulnerabilities").json()["items"][0]["id"]
    detail = client.get(f"/api/v1/vulnerabilities/{finding_id}").json()
    assert detail["audit"][0]["event"] == "VULNERABILITY_OPENED"
    blob = json.dumps(job) + json.dumps(detail)
    assert "password" not in blob.lower()
    assert "access_token" not in blob
    assert "argv" not in blob


def test_no_shell_paths_in_live_adapter():
    import ast as _ast
    import inspect

    import app.services.nmap_vuln_scanner as live

    tree = _ast.parse(inspect.getsource(live))
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
            # os/shutil/subprocess are the fixed-execution trio (defpath
            # env, availability probe, argv-only spawn); everything else
            # network/os-adjacent is forbidden.
            assert not (
                set(names) & {"pty", "importlib", "socket", "requests", "httpx", "urllib"}
            ), names
        elif isinstance(node, _ast.ImportFrom):
            module_name = (node.module or "").split(".")[0]
            assert module_name not in {"subprocess", "os", "socket", "importlib"}, module_name
        if isinstance(node, _ast.Call):
            func = node.func
            if isinstance(func, _ast.Name):
                assert func.id not in {"eval", "exec", "compile", "open", "__import__", "system"}, (
                    func.id
                )
            elif isinstance(func, _ast.Attribute):
                assert func.attr not in {"system", "popen", "execv", "spawnl"}, func.attr
            for keyword in node.keywords:
                if keyword.arg == "shell":
                    assert isinstance(keyword.value, _ast.Constant) and keyword.value.value is False
    source = inspect.getsource(live)
    assert "shell=True" not in source.replace("no ``shell=True``", "")
    assert "os.system" not in source
    assert "importlib" not in source
