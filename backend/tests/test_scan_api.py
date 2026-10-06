"""Scan-job and asset API tests, including injection resistance."""

import app.services.nmap_runner as nmap_runner
from app.services import scan_service

MOCK_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="8000">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="TestServer" version="1.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _mock_run(monkeypatch, xml=MOCK_XML, version="7.94"):
    # Patch availability too: CI/dev machines may not have Nmap installed,
    # and these tests verify orchestration, not the binary.
    monkeypatch.setattr(scan_service.nmap_runner, "is_available", lambda: True)
    monkeypatch.setattr(
        scan_service.nmap_runner,
        "run_scan",
        lambda profile, target: (xml, version),
    )


def test_nmap_status_available(monkeypatch, client, clean_db):
    monkeypatch.setattr(nmap_runner, "is_available", lambda: True)
    monkeypatch.setattr(nmap_runner, "get_version", lambda: "7.94")
    body = client.get("/api/v1/network/nmap/status").json()
    assert body == {
        "available": True,
        "version": "7.94",
        "profiles": ["DISCOVERY_PING", "DISCOVERY_TCP_COMMON", "quick", "standard"],
    }


def test_nmap_status_unavailable(monkeypatch, client, clean_db):
    monkeypatch.setattr(nmap_runner, "is_available", lambda: False)
    body = client.get("/api/v1/network/nmap/status").json()
    assert body["available"] is False
    assert body["version"] is None


def test_scan_lifecycle_completed(monkeypatch, client, clean_db):
    _mock_run(monkeypatch)
    created = client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "quick"}
    )
    assert created.status_code == 202
    scan_id = created.json()["id"]
    # TestClient runs BackgroundTasks inline, so the job is already done.
    job = client.get(f"/api/v1/network/scans/{scan_id}").json()
    assert job["status"] == "completed"
    assert job["target"] == "127.0.0.1"
    assert job["profile"] == "quick"
    assert job["assets_found"] == 1
    assert job["services_found"] == 1
    assert job["nmap_version"] == "7.94"
    assert job["error"] is None

    listed = client.get("/api/v1/network/scans").json()
    assert any(item["id"] == scan_id for item in listed)

    assets = client.get("/api/v1/assets").json()
    assert assets["total"] == 1
    assert assets["items"][0]["ip_address"] == "127.0.0.1"
    assert assets["items"][0]["service_count"] == 1


def test_scan_failed_records_controlled_error(monkeypatch, client, clean_db):
    monkeypatch.setattr(scan_service.nmap_runner, "is_available", lambda: True)
    monkeypatch.setattr(
        scan_service.nmap_runner,
        "run_scan",
        lambda profile, target: (_ for _ in ()).throw(nmap_runner.NmapScanError("boom")),
    )
    created = client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "quick"}
    )
    assert created.status_code == 202
    job = client.get(f"/api/v1/network/scans/{created.json()['id']}").json()
    assert job["status"] == "failed"
    assert job["error"] == "boom"
    assert "Traceback" not in job["error"]


def test_scan_unavailable_nmap_returns_503(monkeypatch, client):
    monkeypatch.setattr(nmap_runner, "is_available", lambda: False)
    response = client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "quick"}
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "NMAP_UNAVAILABLE"


def test_scan_rejects_malicious_targets(client):
    for target in [
        "127.0.0.1; cat /etc/passwd",
        "127.0.0.1 && id",
        "$(reboot)",
        "-sS 127.0.0.1",
        "10.0.0.0/8",
        "not-a-target",
    ]:
        response = client.post(
            "/api/v1/network/scans", json={"target": target, "scan_profile": "quick"}
        )
        assert response.status_code == 422, target
        assert response.json()["error"]["code"] == "INVALID_TARGET"


def test_scan_rejects_unknown_profile_and_extra_fields(client):
    bad_profile = client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "aggressive"}
    )
    assert bad_profile.status_code == 422  # allow-list enforced by schema

    smuggled_flags = client.post(
        "/api/v1/network/scans",
        json={"target": "127.0.0.1", "scan_profile": "quick", "flags": "-sS -O"},
    )
    assert smuggled_flags.status_code == 422  # extra=forbid: no flag smuggling


def test_scan_lookup_404(client):
    response = client.get("/api/v1/network/scans/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_get_version_returns_number_only(monkeypatch):
    class _Completed:
        stdout = "Nmap version 7.95 ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu\n"

    monkeypatch.setattr(nmap_runner, "is_available", lambda: True)
    monkeypatch.setattr(nmap_runner.subprocess, "run", lambda *args, **kwargs: _Completed())
    assert nmap_runner.get_version() == "7.95"


def test_get_version_none_when_missing(monkeypatch):
    monkeypatch.setattr(nmap_runner, "is_available", lambda: False)
    assert nmap_runner.get_version() is None


def test_runner_builds_exact_allow_listed_argv():
    assert nmap_runner.build_argv("quick", "127.0.0.1") == [
        "nmap",
        "-oX",
        "-",
        "-sV",
        "-T4",
        "--top-ports",
        "100",
        "127.0.0.1",
    ]
    assert "-O" in nmap_runner.build_argv("standard", "10.0.0.0/24")


def test_runner_invokes_subprocess_without_shell(monkeypatch):
    calls: list[tuple[list, dict]] = []

    class _Completed:
        returncode = 0
        stdout = MOCK_XML
        stderr = ""

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return _Completed()

    monkeypatch.setattr(nmap_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(nmap_runner, "is_available", lambda: True)
    nmap_runner.run_scan("quick", "127.0.0.1")
    # run_scan spawns twice: the scan itself and `nmap --version`.
    scan_calls = [call for call in calls if "-oX" in call[0]]
    assert len(scan_calls) == 1
    argv, kwargs = scan_calls[0]
    assert kwargs.get("shell") is False
    assert isinstance(argv, list)
    assert argv[-1] == "127.0.0.1"
    assert "--top-ports" in argv
    # The validated target travels as one argv element — never concatenated.
    assert not any(";" in element or "&&" in element for element in argv)


def test_assets_filtering_summary_detail(monkeypatch, client, clean_db):
    _mock_run(monkeypatch)
    client.post("/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "quick"})

    summary = client.get("/api/v1/assets/summary").json()
    assert summary["total_assets"] == 1
    assert summary["active_assets"] == 1
    assert summary["total_services"] == 1
    assert summary["last_scan_status"] == "completed"

    filtered = client.get("/api/v1/assets", params={"ip": "127.0.0"}).json()
    assert filtered["total"] == 1
    assert client.get("/api/v1/assets", params={"ip": "10.9.9.9"}).json()["total"] == 0

    asset_id = filtered["items"][0]["id"]
    detail = client.get(f"/api/v1/assets/{asset_id}").json()
    assert detail["hostname"] == "localhost"
    assert detail["services"][0]["port"] == 8000
    assert detail["services"][0]["product"] == "TestServer"

    services = client.get(f"/api/v1/assets/{asset_id}/services").json()
    assert len(services) == 1

    assert client.get("/api/v1/assets/nope").status_code == 404
    assert client.get("/api/v1/assets/nope/services").status_code == 404
