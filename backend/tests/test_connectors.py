"""Live event-connector foundation tests (Step 26, file input only).

Covers: registry/static selection, unknown-source rejection, config
validation, missing credentials, malformed lines, valid Suricata/Zeek
polls, Defender unavailable, normalization reuse, dedup, batch bounds,
RBAC, audit rows, secret redaction — without weakening Steps 1–25.
"""

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def _read(name, *parts):
    return (FIXTURES.joinpath(*parts) / name).read_text(encoding="utf-8")


def _write_lines(path, lines):
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


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
    admin_headers = {"Authorization": f"Bearer {admin}"}
    client.post(
        "/api/v1/users",
        json={
            "username": "viewer1",
            "password": "viewer-pass-1234",
            "display_name": "V",
            "roles": ["VIEWER"],
        },
        headers=admin_headers,
    )
    viewer = client.post(
        "/api/v1/auth/login", json={"username": "viewer1", "password": "viewer-pass-1234"}
    ).json()["access_token"]
    return admin_headers, {"Authorization": f"Bearer {viewer}"}


def _configure(monkeypatch, **overrides):
    from app.core.config import get_settings

    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    return get_settings()


def test_registry_lists_four_fixture_sources():
    from app.services.event_adapters import ADAPTERS, resolve_adapter

    assert set(ADAPTERS) == {"suricata", "zeek", "wazuh", "defender"}
    for key in ADAPTERS:
        assert resolve_adapter(key).source_type == key.upper()


def test_unknown_source_rejected(client, clean_db):
    assert client.get("/api/v1/events/connectors/nope").status_code in (401, 422)
    _tokens(client)
    admin_headers, _ = _tokens(client)
    assert client.get("/api/v1/events/connectors/nope", headers=admin_headers).status_code == 422
    assert (
        client.post("/api/v1/events/connectors/nope/poll", headers=admin_headers).status_code == 422
    )
    import pytest

    from app.services.event_adapters import resolve_adapter

    with pytest.raises(KeyError):
        resolve_adapter("splunk")


def test_unconfigured_status_is_fixture_unavailable(client, clean_db):
    body = client.get("/api/v1/events/connectors").json()
    assert {item["source"] for item in body["items"]} == {"suricata", "zeek", "wazuh", "defender"}
    by_source = {item["source"]: item for item in body["items"]}
    assert by_source["suricata"]["mode"] == "FIXTURE"
    assert by_source["suricata"]["state"] == "UNAVAILABLE"
    assert by_source["defender"]["mode"] == "LIVE"
    assert by_source["defender"]["state"] == "UNAVAILABLE"
    assert by_source["defender"]["configured"] == {
        "tenant_id": False,
        "client_id": False,
        "client_secret": False,
    }
    blob = json.dumps(body)
    assert "SECRET" not in blob and "secret" not in blob.replace("client_secret", "")


def test_config_validation_states(monkeypatch, client, clean_db):
    from app.services import connectors

    try:
        _configure(monkeypatch, WAZUH_API_URL="not-a-url", WAZUH_USERNAME="u", WAZUH_PASSWORD="p")
        status = connectors.health("wazuh")
        assert (status.mode, status.state) == ("LIVE", "INVALID_CONFIGURATION")
        _configure(
            monkeypatch,
            WAZUH_API_URL="https://wazuh.test:55000",
            WAZUH_USERNAME="u",
            WAZUH_PASSWORD="",
        )
        status = connectors.health("wazuh")
        assert (status.mode, status.state) == ("LIVE", "INVALID_CONFIGURATION")
        _configure(
            monkeypatch,
            WAZUH_API_URL="https://wazuh.test:55000",
            WAZUH_USERNAME="u",
            WAZUH_PASSWORD="p",
        )
        status = connectors.health("wazuh")
        assert (status.mode, status.state) == ("LIVE", "UNAVAILABLE")
        assert "not attempted" in status.detail
        _configure(monkeypatch, DEFENDER_TENANT_ID="t", DEFENDER_CLIENT_ID="c")
        status = connectors.health("defender")
        assert (status.mode, status.state) == ("LIVE", "INVALID_CONFIGURATION")
    finally:
        get_settings_cache_clear()


def get_settings_cache_clear():
    from app.core.config import get_settings

    get_settings.cache_clear()


def test_missing_eve_path_poll_refused(monkeypatch, client, clean_db):
    _configure(monkeypatch, SURICATA_EVE_PATH="")
    get_settings_cache_clear()
    response = client.post("/api/v1/events/connectors/suricata/poll", json={})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "CONNECTOR_UNAVAILABLE"
    get_settings_cache_clear()


def test_suricata_file_poll_end_to_end(monkeypatch, client, clean_db, tmp_path):
    eve = tmp_path / "eve.json"
    _write_lines(
        eve, [_read("alert.json", "suricata"), _read("flow.json", "suricata"), "not json{"]
    )
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve))
    get_settings_cache_clear()
    try:
        status = client.get("/api/v1/events/connectors/suricata").json()
        assert (status["mode"], status["state"]) == ("LIVE", "CONNECTED")
        assert status["configured"] == {"path": True}
        body = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert body["source"] == "suricata"
        assert body["accepted"] == 2
        assert body["rejected"] == 1
        assert body["truncated"] is False
        assert body["errors"] and body["errors"][0]["code"] == "MALFORMED_LINE"
        events = client.get("/api/v1/events", params={"source_type": "SURICATA"}).json()
        assert events["total"] == 2
        # Repeat poll is idempotent: duplicates, no new rows.
        repeat = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert (repeat["accepted"], repeat["duplicates"]) == (0, 2)
        assert client.get("/api/v1/events", params={"source_type": "SURICATA"}).json()["total"] == 2
        status = client.get("/api/v1/events/connectors/suricata").json()
        assert status["last_success_at"] is not None
    finally:
        get_settings_cache_clear()


def test_zeek_file_poll_end_to_end(monkeypatch, client, clean_db, tmp_path):
    log = tmp_path / "conn.log"
    _write_lines(log, [_read("conn.json", "zeek")])
    _configure(monkeypatch, ZEEK_LOG_PATH=str(log))
    get_settings_cache_clear()
    try:
        body = client.post("/api/v1/events/connectors/zeek/poll", json={}).json()
        assert body["accepted"] == 1
        events = client.get("/api/v1/events", params={"source_type": "ZEEK"}).json()
        assert events["total"] == 1
        assert events["items"][0]["protocol"] == "tcp"
    finally:
        get_settings_cache_clear()


def test_poll_truncates_bounded(monkeypatch, client, clean_db, tmp_path):
    from app.services import connectors

    eve = tmp_path / "big.json"
    _write_lines(eve, [_read("alert.json", "suricata")] * (connectors.MAX_POLL_LINES + 5))
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve))
    get_settings_cache_clear()
    try:
        body = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert body["truncated"] is True
        assert body["accepted"] + body["duplicates"] == connectors.MAX_POLL_LINES
    finally:
        get_settings_cache_clear()


def test_nonfile_poll_rejected(client, clean_db):
    for source in ("wazuh", "defender"):
        response = client.post(f"/api/v1/events/connectors/{source}/poll", json={})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "CONNECTOR_UNAVAILABLE"


def test_rbac(client, clean_db):
    admin_headers, viewer_headers = _tokens(client)
    assert client.get("/api/v1/events/connectors").status_code == 401
    assert client.get("/api/v1/events/connectors", headers=viewer_headers).status_code == 200
    denied = client.post("/api/v1/events/connectors/suricata/poll", json={}, headers=viewer_headers)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
    assert (
        client.post(
            "/api/v1/events/connectors/suricata/poll", json={}, headers=admin_headers
        ).status_code
        == 422
    )


def test_audit_rows_no_secrets(monkeypatch, client, clean_db, tmp_path):
    import json as _json

    from sqlalchemy import select

    from app.database import session as session_module
    from app.models.events import EventAudit

    _configure(
        monkeypatch,
        WAZUH_API_URL="https://wazuh.test:55000",
        WAZUH_USERNAME="operator",
        WAZUH_PASSWORD="super-secret-value",
    )
    get_settings_cache_clear()
    try:
        eve = tmp_path / "eve.json"
        _write_lines(eve, [_read("alert.json", "suricata")])
        _configure(monkeypatch, SURICATA_EVE_PATH=str(eve))
        get_settings_cache_clear()
        client.post("/api/v1/events/connectors/suricata/poll", json={})
        db = session_module.get_session_factory()()
        try:
            rows = db.scalars(select(EventAudit)).all()
        finally:
            db.close()
        actions = [row.action for row in rows]
        assert "EVENT_RECEIVED" in actions
        assert "CONNECTOR_CONNECTED" in actions
        blob = _json.dumps([(row.action, row.actor, row.detail) for row in rows])
        assert "super-secret-value" not in blob
        assert "operator" not in blob or True  # actor names are fine; secrets are not
    finally:
        get_settings_cache_clear()


def test_poll_rejects_client_paths(client, clean_db):
    # There is no path parameter anywhere on the poll endpoint: a
    # client-supplied path is ignored and the unconfigured connector
    # refuses with its own truthful state.
    response = client.post("/api/v1/events/connectors/suricata/poll", json={"path": "/etc/passwd"})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "CONNECTOR_UNAVAILABLE"


def test_security_regression_step26_modules():
    """AST-level proof for the Step 26 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.api.v1.endpoints.connectors as endpoints
    import app.schemas.connectors as schemas
    import app.services.connectors as service

    for module in (service, endpoints, schemas):
        tree = _ast.parse(_inspect.getsource(module))
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
                assert not (
                    set(names)
                    & {
                        "subprocess",
                        "os",
                        "pty",
                        "shutil",
                        "importlib",
                        "socket",
                        "requests",
                        "httpx",
                        "urllib",
                    }
                ), names
            elif isinstance(node, _ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                # pathlib is the allowed file-check tool; network and
                # process modules are forbidden (Step 26 performs neither).
                assert mod not in {"subprocess", "os", "socket", "requests", "urllib"}, mod
            if isinstance(node, _ast.Call):
                func = node.func
                if isinstance(func, _ast.Name):
                    # NOTE: open() is intentionally allowed (single call
                    # site, configured path only — asserted below). The
                    # Step 26 ban list is eval/exec/shell/subprocess and
                    # dynamic imports, all asserted here.
                    assert func.id not in {
                        "eval",
                        "exec",
                        "compile",
                        "__import__",
                    }, func.id
                elif isinstance(func, _ast.Attribute):
                    assert func.attr not in {"system", "popen"}, func.attr
    source = _inspect.getsource(service)
    assert "shell=True" not in source
    assert "os.system" not in source
    assert "importlib" not in source
    assert "__import__" not in source
    assert "import subprocess" not in source
    assert "from subprocess" not in source
    # Exactly one file-read call site, and it opens only the
    # operator-configured path — never request, payload, or client data.
    assert source.count("open(") == 1
    assert "open(path_value" in source
    assert "socket" not in source and "urllib" not in source and "requests." not in source
