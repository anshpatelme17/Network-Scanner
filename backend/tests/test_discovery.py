"""Asset discovery + controlled Nmap tests (Step 21, discovery only).

Covers: valid IPv4/CIDR targets, invalid targets, shell-metacharacter
and flag rejection, command/flag/NSE rejection, RBAC gating, preview
semantics, duplicate/update normalization, audit records, timeout and
failure handling, output parsing, scope limits, no-shell structural
proof, and secret hygiene — without weakening Steps 1–20.
"""

import app.services.nmap_runner as nmap_runner
from app.services import scan_service

PING_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost" type="PTR"/></hostnames>
  </host>
  <host><status state="down" reason="no-response"/>
    <address addr="127.0.0.2" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

TCP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port>
      <port protocol="tcp" portid="22"><state state="closed" reason="reset"/></port>
    </ports>
  </host>
</nmaprun>
"""


def _mock_nmap(monkeypatch, xml=PING_XML):
    monkeypatch.setattr(scan_service.nmap_runner, "is_available", lambda: True)
    monkeypatch.setattr(scan_service.nmap_runner, "run_scan", lambda profile, target: (xml, "7.94"))


def _authed(client, username, password, roles):
    client.post(
        "/api/v1/users",
        json={
            "username": "admin",
            "password": "admin-pass-word-1",
            "display_name": "A",
            "roles": ["ADMIN"],
        },
    )
    admin_token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "admin-pass-word-1"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = client.post(
        "/api/v1/users",
        json={
            "username": username,
            "password": password,
            "display_name": username,
            "roles": list(roles),
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    token = client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_valid_ipv4_and_cidr_targets(monkeypatch, client, clean_db):
    _mock_nmap(monkeypatch, TCP_XML)
    single = client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_PING"}
    )
    assert single.status_code == 202
    assert single.json()["target"] == "127.0.0.1"
    job = client.get(f"/api/v1/network/scans/{single.json()['id']}").json()
    assert job["status"] == "completed"
    assert job["assets_found"] == 1
    network = client.post(
        "/api/v1/network/scans",
        json={"target": "127.0.0.1/32", "scan_profile": "DISCOVERY_TCP_COMMON"},
    )
    assert network.status_code == 202
    job = client.get(f"/api/v1/network/scans/{network.json()['id']}").json()
    assert job["services_found"] == 2


def test_invalid_targets_rejected(client, clean_db):
    for bad in [
        "",
        "   ",
        "not-a-target",
        "http://127.0.0.1/",
        "256.1.1.1",
        "127.0.0.1/33",
        12345,
        None,
    ]:
        response = client.post(
            "/api/v1/network/scans", json={"target": bad, "scan_profile": "DISCOVERY_PING"}
        )
        assert response.status_code == 422, bad
        assert response.json()["error"]["code"] in ("INVALID_TARGET", "VALIDATION_ERROR")


def test_shell_metacharacters_rejected(client, clean_db):
    for bad in [
        "127.0.0.1; whoami",
        "127.0.0.1 && id",
        "$(id)",
        "`id`",
        "127.0.0.1|nc evil",
        "--script=vuln",
        "-oX /tmp/x",
        "127.0.0.1\n evil",
    ]:
        response = client.post(
            "/api/v1/network/scans", json={"target": bad, "scan_profile": "DISCOVERY_PING"}
        )
        assert response.status_code == 422, bad


def test_command_field_and_flags_rejected(client, clean_db):
    base = {"target": "127.0.0.1", "scan_profile": "DISCOVERY_PING", "command": "nmap -A 127.0.0.1"}
    assert client.post("/api/v1/network/scans", json=base).status_code == 422
    assert client.post("/api/v1/network/scans/preview", json=base).status_code == 422
    for profile in ["--script vuln", "-A", "quick --top-ports 10", "DISCOVERY_PING ", "nmap"]:
        response = client.post(
            "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": profile}
        )
        assert response.status_code == 422, profile


def test_out_of_scope_target_rejected(client, clean_db):
    response = client.post(
        "/api/v1/network/scans", json={"target": "192.168.1.0/24", "scan_profile": "DISCOVERY_PING"}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "TARGET_NOT_AUTHORIZED"


def test_rbac_gating(monkeypatch, client, clean_db):
    viewer = _authed(client, "viewer1", "viewer-pass-1234", ("VIEWER",))
    analyst = _authed(client, "analyst1", "analyst-pass-1234", ("SECURITY_ANALYST",))
    assert client.get("/api/v1/network/nmap/status", headers=viewer).status_code == 200
    denied = client.post(
        "/api/v1/network/scans",
        json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_PING"},
        headers=viewer,
    )
    assert denied.status_code == 403
    assert (
        client.post(
            "/api/v1/network/scans/preview",
            json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_PING"},
            headers=viewer,
        ).status_code
        == 403
    )
    # Analyst (authorized operator role) can initiate discovery.
    monkeypatch.setattr(scan_service.nmap_runner, "is_available", lambda: True)
    monkeypatch.setattr(
        scan_service.nmap_runner, "run_scan", lambda profile, target: (PING_XML, "7.94")
    )
    created = client.post(
        "/api/v1/network/scans",
        json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_PING"},
        headers=analyst,
    )
    assert created.status_code == 202
    job = client.get(f"/api/v1/network/scans/{created.json()['id']}", headers=analyst).json()
    assert job["status"] == "completed"


def test_preview_performs_no_scan(monkeypatch, client, clean_db):
    def _boom(*args, **kwargs):
        raise AssertionError("preview must never invoke Nmap")

    monkeypatch.setattr(scan_service.nmap_runner, "run_scan", _boom)
    monkeypatch.setattr(scan_service.nmap_runner, "is_available", lambda: True)
    body = client.post(
        "/api/v1/network/scans/preview",
        json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_PING"},
    ).json()
    assert body["target"] == "127.0.0.1"
    assert body["profile"] == "DISCOVERY_PING"
    assert body["probes_ports"] is False
    assert body["address_count"] == 1
    assert body["scope_authorized"] is True
    assert body["nmap_available"] is True
    assert "argv" not in body and "command" not in body
    assert client.get("/api/v1/network/scans").json() == []
    assert client.get("/api/v1/assets").json()["total"] == 0
    preview_tcp = client.post(
        "/api/v1/network/scans/preview",
        json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_TCP_COMMON"},
    ).json()
    assert preview_tcp["probes_ports"] is True
    assert "no port" not in preview_tcp["profile_description"].lower()


def test_preview_validates_like_create(client, clean_db):
    assert (
        client.post(
            "/api/v1/network/scans/preview",
            json={"target": "nope", "scan_profile": "DISCOVERY_PING"},
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/network/scans/preview",
            json={"target": "192.168.1.1", "scan_profile": "DISCOVERY_PING"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/network/scans/preview", json={"target": "127.0.0.1", "scan_profile": "NOPE"}
        ).status_code
        == 422
    )


def test_duplicate_assets_not_created(monkeypatch, client, clean_db):
    _mock_nmap(monkeypatch, TCP_XML)
    first_id = client.post(
        "/api/v1/network/scans",
        json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_TCP_COMMON"},
    ).json()["id"]
    second_id = client.post(
        "/api/v1/network/scans",
        json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_TCP_COMMON"},
    ).json()["id"]
    first = client.get(f"/api/v1/network/scans/{first_id}").json()
    second = client.get(f"/api/v1/network/scans/{second_id}").json()
    assert first["assets_found"] == second["assets_found"] == 1
    assets = client.get("/api/v1/assets").json()
    assert assets["total"] == 1
    assert assets["items"][0]["ip_address"] == "127.0.0.1"
    assert first["id"] != second["id"]  # distinct jobs, one asset row


def test_existing_asset_updated_first_seen_kept(monkeypatch, client, clean_db):
    _mock_nmap(monkeypatch, TCP_XML)
    client.post(
        "/api/v1/network/scans",
        json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_TCP_COMMON"},
    )
    before = client.get("/api/v1/assets").json()["items"][0]
    assert before["mac_address"] == "AA:BB:CC:DD:EE:FF"
    services_before = client.get(f"/api/v1/assets/{before['id']}/services").json()
    assert len(services_before) == 2
    # Ping-only follow-up: metadata refreshes, services are preserved, first_seen kept.
    _mock_nmap(monkeypatch, PING_XML)
    client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_PING"}
    )
    after = client.get("/api/v1/assets").json()["items"][0]
    assert after["first_seen"] == before["first_seen"]
    assert after["last_seen"] >= before["last_seen"]
    assert after["mac_address"] == "AA:BB:CC:DD:EE:FF"  # ping reported none: kept, not blanked
    services_after = client.get(f"/api/v1/assets/{after['id']}/services").json()
    assert len(services_after) == 2


def test_discovery_audit_records(monkeypatch, client, clean_db):
    _mock_nmap(monkeypatch, TCP_XML)
    job_id = client.post(
        "/api/v1/network/scans",
        json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_TCP_COMMON"},
    ).json()["id"]
    detail = client.get(f"/api/v1/network/scans/{job_id}").json()
    events = [entry["event"] for entry in detail["audit"]]
    assert events == ["SCAN_REQUESTED", "SCAN_STARTED", "SCAN_COMPLETED"]
    blob = str(detail["audit"])
    assert "password" not in blob.lower()
    assert "--script" not in blob
    assert "127.0.0.1" in blob  # target recorded, nothing else sensitive


def test_timeout_and_failure_handling(monkeypatch, client, clean_db):
    from app.services import nmap_runner as _runner_mod

    monkeypatch.setattr(scan_service.nmap_runner, "is_available", lambda: True)

    def _timeout(profile, target):
        raise _runner_mod.NmapScanError(
            "Scan timed out after 120 seconds (profile 'DISCOVERY_PING')."
        )

    monkeypatch.setattr(scan_service.nmap_runner, "run_scan", _timeout)
    job_id = client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_PING"}
    ).json()["id"]
    detail = client.get(f"/api/v1/network/scans/{job_id}").json()
    assert detail["status"] == "failed"
    assert "timed out" in (detail["error"] or "")

    monkeypatch.setattr(
        scan_service.nmap_runner, "run_scan", lambda profile, target: ("garbage", "7.94")
    )
    job_id = client.post(
        "/api/v1/network/scans", json={"target": "127.0.0.1", "scan_profile": "DISCOVERY_PING"}
    ).json()["id"]
    assert client.get(f"/api/v1/network/scans/{job_id}").json()["status"] == "failed"


def test_output_parsing_ping_and_tcp():
    from app.services.nmap_parser import NmapParseError, parse_nmap_xml

    hosts = parse_nmap_xml(PING_XML)
    assert len(hosts) == 1  # down host excluded
    assert hosts[0].ip_address == "127.0.0.1"
    assert hosts[0].hostname == "localhost"
    assert hosts[0].services == []
    hosts = parse_nmap_xml(TCP_XML)
    assert [service.port for service in hosts[0].services] == [80, 443]  # closed port excluded
    assert hosts[0].mac_address == "AA:BB:CC:DD:EE:FF"
    import pytest

    with pytest.raises(NmapParseError):
        parse_nmap_xml("not xml at all <<<")


def test_maximum_scope_enforced(client, clean_db):
    from app.services.target_validation import InvalidTargetError, validate_target

    assert (
        client.post(
            "/api/v1/network/scans",
            json={"target": "10.0.0.0/16", "scan_profile": "DISCOVERY_PING"},
        ).status_code
        == 422
    )  # size refused before scope is even considered
    import pytest

    with pytest.raises(InvalidTargetError):
        validate_target("10.0.0.0/16")
    assert validate_target("10.0.0.0/16", max_addresses=65536) == "10.0.0.0/16"
    assert validate_target("127.0.0.1/32") == "127.0.0.1/32"
    from app.core.config import get_settings

    assert get_settings().discovery_max_addresses == 256


def test_no_shell_construction():
    import ast as _ast
    import inspect

    import pytest

    import app.api.v1.endpoints.network as endpoints
    import app.services.scan_service as service

    for module in (nmap_runner, service, endpoints):
        tree = _ast.parse(inspect.getsource(module))
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Call):
                func = node.func
                if isinstance(func, _ast.Name):
                    assert func.id not in {
                        "eval",
                        "exec",
                        "compile",
                        "open",
                        "__import__",
                        "system",
                    }, func.id
                for keyword in node.keywords:
                    if keyword.arg == "shell":
                        assert (
                            isinstance(keyword.value, _ast.Constant)
                            and keyword.value.value is False
                        )
    source = inspect.getsource(nmap_runner)
    assert "shell=False" in source
    # "shell=True" appears exactly once: the module docstring prohibiting it.
    # Strip all docstrings first so the check covers executable code only.
    tree = _ast.parse(source)
    code_only = source
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Module | _ast.FunctionDef | _ast.ClassDef):
            doc = _ast.get_docstring(node, clean=False)
            if doc:
                code_only = code_only.replace(doc, "", 1)
    assert "shell=True" not in code_only
    assert "os.system" not in code_only

    with pytest.raises(KeyError):
        nmap_runner.build_argv("DO_ANYTHING", "127.0.0.1")
    argv = nmap_runner.build_argv("DISCOVERY_PING", "127.0.0.1")
    assert argv[:2] == ["nmap", "-oX"]
    assert argv[-1] == "127.0.0.1"
    assert "--script" not in argv
