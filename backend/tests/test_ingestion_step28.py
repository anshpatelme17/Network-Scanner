"""Step 28 — bounded ingestion pipeline tests.

Covers, with **mocked HTTP only** (`httpx.MockTransport`; no real Wazuh,
Defender, or any other external service is ever contacted):

- the ingestion status/checkpoint observability endpoints (read-only,
  RBAC `READ_EVENTS`, zero network I/O, no secret material),
- bounded queue + bounded batches + backpressure (drops are reported and
  audited, and never advance a checkpoint),
- checkpoint creation, advancement, and *rejected* advancement (a failed
  poll never moves a stored cursor),
- bounded transient retry with audited attempts, and the cases that are
  deliberately never retried (authentication failures),
- file rotation/truncation/offset detection with a restart at offset 0,
  plus opt-in byte-offset resume,
- replay (same bounded pipeline, dedup absorbs repeats),
- streaming/worker architecture that exists but is not enabled,
- audit vocabulary bounds and Step 28 AST-level security regression.

Steps 1–27 behaviour is asserted in `test_connectors.py` and
`test_connectors_step27.py` and must keep passing unchanged.
"""

import ast
import inspect
import json
from pathlib import Path

import httpx
import pytest

FIXTURES = Path(__file__).parent / "fixtures"

FIXTURE_ALERT = {
    "id": "90011",
    "timestamp": "2026-01-05T10:00:00.000+0000",
    "rule": {"id": "5712", "level": 12, "description": "Step28 mock rule"},
    "agent": {"id": "001", "name": "agent-1", "ip": "10.0.0.5"},
    "data": {"srcip": "203.0.113.10", "dstip": "10.0.0.5"},
    "location": "/var/log/test",
}


def _read(name, *parts):
    return (FIXTURES.joinpath(*parts) / name).read_text(encoding="utf-8")


def _write_lines(path, lines):
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _suricata_lines(count, start=0):
    """Distinct synthetic Suricata events (unique flow_id + timestamp)."""
    base = json.loads(_read("alert.json", "suricata"))
    lines = []
    for index in range(start, start + count):
        record = dict(base)
        record["flow_id"] = 9000000000 + index
        record["timestamp"] = f"2026-09-27T06:00:00.{index % 1000000:06d}+0000"
        lines.append(json.dumps(record))
    return lines


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


def _clear_settings():
    from app.core.config import get_settings

    get_settings.cache_clear()


def _install(handler):
    from app.services import http_connector

    http_connector.install_test_transport(httpx.MockTransport(handler))
    return handler


def _session():
    from app.database import session as session_module

    return session_module.get_session_factory()()


def _audits():
    from sqlalchemy import select

    from app.models.events import EventAudit

    db = _session()
    try:
        rows = db.scalars(select(EventAudit)).all()
        return [(row.action, row.detail or "") for row in rows]
    finally:
        db.close()


def _audit_actions():
    return [action for action, _ in _audits()]


def _audit_blob():
    return json.dumps(_audits())


def _checkpoints():
    from sqlalchemy import select

    from app.models.ingestion import IngestionCheckpoint

    db = _session()
    try:
        return list(db.scalars(select(IngestionCheckpoint)).all())
    finally:
        db.close()


def _checkpoint_status(row):
    from app.services import checkpoints

    return checkpoints.to_status(row)


def _wazuh_pages(count, *, page_size=10):
    pages = {}
    for offset in range(0, count, page_size):
        end = min(offset + page_size, count)
        pages[offset] = {
            "data": {
                "totalItems": count,
                "alerts": [dict(FIXTURE_ALERT, id=str(i)) for i in range(offset, end)],
            },
            "error": 0,
        }
    return pages


def _pages_handler(pages: dict[int, dict], *, state=None, alerts_error=None, auth_status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        if state is not None:
            state.setdefault("calls", []).append(f"{request.method} {request.url.path}")
        if request.url.path.endswith("/security/user/authenticate"):
            if auth_status != 200:
                return httpx.Response(auth_status, json={"error": 4001})
            return httpx.Response(200, json={"token": "mock-jwt-token-value"})
        if request.url.path.endswith("/alerts"):
            if alerts_error is not None:
                raise alerts_error()
            offset = int(request.url.params.get("offset", "0"))
            page = pages.get(offset)
            if page is None:
                raise AssertionError(f"unexpected offset {offset}")
            return httpx.Response(200, json=page)
        raise AssertionError(f"unexpected path {request.url.path}")

    return handler


# --- observability endpoints ---------------------------------------------------


def test_ingestion_status_reports_bounds_pipeline_and_no_streaming(client, clean_db):
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={})

    _install(handler)
    response = client.get("/api/v1/events/ingestion/status")
    assert response.status_code == 200
    body = response.json()
    assert body["pipeline"] == [
        "SOURCE",
        "CONNECTOR",
        "FETCH",
        "VALIDATE",
        "NORMALIZE",
        "DEDUPLICATE",
        "CORRELATE",
        "STORE",
        "AUDIT",
    ]
    assert body["limits"]["max_pages"] >= 1
    assert body["limits"]["batch_size"] >= 1
    assert body["limits"]["queue_max"] >= 1
    assert body["limits"]["retry_max"] >= 0
    assert body["limits"]["file_resume"] is False
    assert body["queue"]["overflow"] == "REJECT_NEW"
    assert body["queue"]["dropped_total"] == 0
    # Streaming exists as an architecture and is deliberately inert.
    assert body["streaming"]["enabled"] is False
    assert body["streaming"]["mode"] == "MANUAL"
    assert {item["source"] for item in body["sources"]} == {
        "suricata",
        "zeek",
        "wazuh",
        "defender",
    }
    for item in body["sources"]:
        # No connectivity is ever claimed without a verified attempt.
        assert item["connector_state"] in {"NOT_CONFIGURED", "CONFIGURED"}
        assert item["checkpoint"] is None
        assert item["events_accepted"] == 0
    # Status is a pure read: nothing touched the network.
    assert calls == []
    blob = json.dumps(body)
    assert "super-secret" not in blob
    assert "password" not in blob
    assert "token" not in blob


def test_ingestion_limits_reflect_configured_bounds(monkeypatch, client, clean_db):
    try:
        _configure(
            monkeypatch,
            INGESTION_MAX_BATCH_SIZE="7",
            INGESTION_QUEUE_MAX="64",
            INGESTION_RETRY_MAX="2",
            CONNECTOR_MAX_PAGES="4",
            CONNECTOR_FILE_RESUME="true",
        )
        body = client.get("/api/v1/events/ingestion/status").json()
        assert body["limits"]["batch_size"] == 7
        assert body["limits"]["queue_max"] == 64
        assert body["limits"]["retry_max"] == 2
        assert body["limits"]["max_pages"] == 4
        assert body["limits"]["file_resume"] is True
        assert body["queue"]["max"] == 64
    finally:
        _clear_settings()


def test_ingestion_endpoints_enforce_read_events(client, clean_db):
    # Bootstrap mode passes through until the first user exists.
    assert client.get("/api/v1/events/ingestion/status").status_code == 200
    admin, viewer = _tokens(client)
    assert client.get("/api/v1/events/ingestion/status").status_code == 401
    assert client.get("/api/v1/events/ingestion/checkpoints").status_code == 401
    for path in ("/events/ingestion/status", "/events/ingestion/checkpoints"):
        assert client.get(f"/api/v1{path}", headers=viewer).status_code == 200
        assert client.get(f"/api/v1{path}", headers=admin).status_code == 200
    # Viewers may observe but never trigger ingestion (MANAGE_EVENTS).
    denied = client.post("/api/v1/events/connectors/suricata/poll", json={}, headers=viewer)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"


def test_checkpoints_endpoint_is_empty_until_a_poll_succeeds(
    monkeypatch, client, clean_db, tmp_path
):
    eve = tmp_path / "eve.json"
    _write_lines(eve, _suricata_lines(2))
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve))
    try:
        admin, _ = _tokens(client)
        assert client.get("/api/v1/events/ingestion/checkpoints", headers=admin).json() == {
            "items": []
        }
        poll = client.post("/api/v1/events/connectors/suricata/poll", json={}, headers=admin).json()
        assert poll["checkpoint_advanced"] is True
        items = client.get("/api/v1/events/ingestion/checkpoints", headers=admin).json()["items"]
        assert len(items) == 1
        checkpoint = items[0]
        assert checkpoint["source"] == "suricata"
        assert checkpoint["cursor"]["kind"] == "file"
        assert checkpoint["advance_count"] == 1
        assert checkpoint["cursor"]["offset"] > 0
        assert checkpoint["last_rejected_at"] is None
        assert checkpoint["last_external_event_id"]
    finally:
        _clear_settings()


# --- bounded queue / batches / backpressure ------------------------------------


def test_bounded_batches_split_records_and_are_audited(monkeypatch, client, clean_db, tmp_path):
    eve = tmp_path / "eve.json"
    _write_lines(eve, _suricata_lines(24))
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve), INGESTION_MAX_BATCH_SIZE="10")
    try:
        body = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert body["accepted"] == 24
        assert body["duplicates"] == 0
        assert body["batches"] == 3
        assert body["queue_dropped"] == 0
        assert body["checkpoint_advanced"] is True
        actions = _audit_actions()
        assert actions.count("INGESTION_BATCH_COMPLETED") == 3
        assert actions.count("INGESTION_BATCH_STARTED") == 3
        assert "INGESTION_STARTED" in actions
        assert "INGESTION_CHECKPOINT_ADVANCED" in actions
        started = [detail for action, detail in _audits() if action == "INGESTION_BATCH_STARTED"]
        assert started[0].startswith("suricata: batch 1/3")
        assert started[-1].startswith("suricata: batch 3/3")
        status = client.get("/api/v1/events/ingestion/status").json()
        suricata = {item["source"]: item for item in status["sources"]}["suricata"]
        assert suricata["events_accepted"] == 24
        assert suricata["batches"] == 3
        assert suricata["checkpoint"]["advance_count"] == 1
        assert status["totals"]["accepted"] == 24
        assert status["totals"]["batches"] == 3
    finally:
        _clear_settings()


def test_backpressure_is_reported_and_never_advances_checkpoint(
    monkeypatch, client, clean_db, tmp_path
):
    eve = tmp_path / "eve.json"
    _write_lines(eve, _suricata_lines(10))
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve), INGESTION_QUEUE_MAX="5")
    try:
        body = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert body["accepted"] == 5
        assert body["queue_dropped"] == 5
        assert body["checkpoint_advanced"] is False
        actions = _audit_actions()
        assert "INGESTION_BACKPRESSURE" in actions
        assert "INGESTION_CHECKPOINT_REJECTED" in actions
        assert "INGESTION_CHECKPOINT_ADVANCED" not in actions
        # No checkpoint row was created by a run that dropped records.
        assert _checkpoints() == []
        status = client.get("/api/v1/events/ingestion/status").json()
        assert status["queue"]["dropped_total"] == 5

        # With the default queue bound the next poll drains the window
        # and only then does the checkpoint advance.
        _configure(monkeypatch, SURICATA_EVE_PATH=str(eve), INGESTION_QUEUE_MAX="500")
        retry = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert retry["queue_dropped"] == 0
        assert retry["accepted"] == 5
        assert retry["duplicates"] == 5
        assert retry["checkpoint_advanced"] is True
        rows = _checkpoints()
        assert len(rows) == 1 and rows[0].advance_count == 1
    finally:
        _clear_settings()


def test_bounded_queue_policy_is_deterministic():
    from app.services import ingestion

    ingestion.reset_runtime()
    queue = ingestion.BoundedQueue(3)
    assert [queue.offer(i) for i in range(5)] == [True, True, True, False, False]
    assert queue.dropped == 2
    assert queue.depth == 3
    chunks = queue.drain(2)
    assert chunks == [[0, 1], [2]]
    assert queue.depth == 0
    assert ingestion._QUEUE["enqueued"] == 3
    assert ingestion._QUEUE["dropped"] == 2
    assert ingestion._QUEUE["dequeued"] == 3
    ingestion.reset_runtime()
    assert ingestion._QUEUE["dropped"] == 0
    ingestion.reset_runtime()


# --- checkpoints: create / advance / rejected advance --------------------------


def test_repeat_poll_deduplicates_and_still_advances_checkpoint(
    monkeypatch, client, clean_db, tmp_path
):
    eve = tmp_path / "eve.json"
    _write_lines(eve, _suricata_lines(6))
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve))
    try:
        first = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert (first["accepted"], first["duplicates"]) == (6, 0)
        second = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert (second["accepted"], second["duplicates"]) == (0, 6)
        assert second["checkpoint_advanced"] is True
        rows = _checkpoints()
        assert len(rows) == 1
        assert rows[0].advance_count == 2
        assert rows[0].last_rejected_at is None
        assert client.get("/api/v1/events", params={"source_type": "SURICATA"}).json()["total"] == 6
        # Reading the window again must not be misreported as rotation.
        assert "INGESTION_ROTATION_DETECTED" not in _audit_actions()
    finally:
        _clear_settings()


def test_failed_poll_never_moves_an_existing_checkpoint(monkeypatch, client, clean_db):
    state: dict = {}
    pages = _wazuh_pages(1)
    _install(_pages_handler(pages, state=state))
    try:
        _configure(
            monkeypatch,
            WAZUH_API_URL="https://wazuh.test:55000",
            WAZUH_USERNAME="u",
            WAZUH_PASSWORD="super-secret-value",
        )
        admin, _ = _tokens(client)
        ok = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert ok.status_code == 200
        rows = _checkpoints()
        assert len(rows) == 1
        before = (rows[0].cursor, rows[0].advance_count)
        assert before[1] == 1

        # Credentials are now incomplete: the poll fails before fetching.
        _configure(
            monkeypatch,
            WAZUH_API_URL="https://wazuh.test:55000",
            WAZUH_USERNAME="u",
            WAZUH_PASSWORD="",
        )
        failed = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert failed.status_code == 422
        assert failed.json()["error"]["code"] == "CONNECTOR_UNAVAILABLE"
        rows = _checkpoints()
        assert len(rows) == 1
        assert (rows[0].cursor, rows[0].advance_count) == before
        assert rows[0].last_rejected_at is not None
        actions = _audit_actions()
        assert actions.count("INGESTION_CHECKPOINT_ADVANCED") == 1
        assert "INGESTION_CHECKPOINT_REJECTED" in actions
        assert "super-secret-value" not in _audit_blob()
    finally:
        _clear_settings()


def test_batch_failure_fails_the_poll_without_advancing(clean_db, monkeypatch, tmp_path):
    from app.services import connectors, ingestion

    eve = tmp_path / "eve.json"
    _write_lines(eve, _suricata_lines(25))
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve), INGESTION_MAX_BATCH_SIZE="10")
    original = connectors.ingest_records
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated storage failure")
        return original(*args, **kwargs)

    db = _session()
    try:
        monkeypatch.setattr(connectors, "ingest_records", flaky)
        with pytest.raises(ingestion.IngestionFailedError):
            ingestion.poll_source(db, "suricata", "tester")
        actions = _audit_actions()
        assert "INGESTION_BATCH_FAILED" in actions
        assert actions.count("INGESTION_BATCH_COMPLETED") == 1
        assert "INGESTION_CHECKPOINT_ADVANCED" not in actions
        assert "INGESTION_CHECKPOINT_REJECTED" in actions
        assert _checkpoints() == []
        # First batch stayed committed; nothing was rolled back wholesale.

        # Replay through the same pipeline completes the window (dedup
        # absorbs the batch that already stored).
        monkeypatch.setattr(connectors, "ingest_records", original)
        result = ingestion.poll_source(db, "suricata", "tester")
        assert result["accepted"] == 15
        assert result["duplicates"] == 10
        assert result["checkpoint_advanced"] is True
        rows = _checkpoints()
        assert len(rows) == 1 and rows[0].advance_count == 1
    finally:
        _clear_settings()
        db.close()


def test_pipeline_refuses_to_store_a_secret_looking_cursor(clean_db, monkeypatch):
    from app.services import connectors, ingestion

    def fake_poll(db, source, actor, *, processor=None):
        return {
            "source": source,
            "accepted": 1,
            "duplicates": 0,
            "rejected": 0,
            "truncated": False,
            "errors": [],
            "pages": 1,
            "retrieved": 1,
            "termination": "COMPLETED",
            "cursor": {"v": 1, "kind": "file", "token": "hunter2-credential-value"},
            "fetch_attempts": 1,
        }

    monkeypatch.setattr(connectors, "poll_source", fake_poll)
    db = _session()
    try:
        with pytest.raises(ingestion.IngestionFailedError):
            ingestion.poll_source(db, "suricata", "tester")
        assert _checkpoints() == []
        actions = _audit_actions()
        assert "INGESTION_CHECKPOINT_REJECTED" in actions
        assert "INGESTION_CHECKPOINT_ADVANCED" not in actions
        # The audit names the offending key, never the value.
        blob = _audit_blob()
        assert "hunter2-credential-value" not in blob
        assert "token" in blob
    finally:
        db.close()


def test_cursor_sanitization_bounds_and_rejects_secret_material():
    from app.services import checkpoints

    with pytest.raises(checkpoints.CheckpointRejected):
        checkpoints.sanitize_cursor({"authorization": "Bearer abc"})
    with pytest.raises(checkpoints.CheckpointRejected):
        checkpoints.sanitize_cursor({"offset": 1, "note": "bearer abc"})
    with pytest.raises(checkpoints.CheckpointRejected):
        checkpoints.sanitize_cursor({"nested": {"a": 1}})
    with pytest.raises(checkpoints.CheckpointRejected):
        checkpoints.sanitize_cursor({"note": "x" * 513})
    with pytest.raises(checkpoints.CheckpointRejected):
        checkpoints.sanitize_cursor(dict.fromkeys("abcdefghij", "y" * 480))
    assert checkpoints.sanitize_cursor({"v": 1, "kind": "api", "pages": 2}) == {
        "v": 1,
        "kind": "api",
        "pages": 2,
    }
    assert checkpoints.sanitize_cursor(None) == {}


# --- API polling: bounded pagination, retry, replay ----------------------------


def test_api_poll_is_bounded_batched_and_checkpoints(monkeypatch, client, clean_db):
    state: dict = {}
    _install(_pages_handler(_wazuh_pages(20), state=state))
    try:
        _configure(
            monkeypatch,
            WAZUH_API_URL="https://wazuh.test:55000",
            WAZUH_USERNAME="u",
            WAZUH_PASSWORD="p",
            CONNECTOR_MAX_PAGES="3",
            CONNECTOR_MAX_EVENTS="100",
            INGESTION_MAX_BATCH_SIZE="7",
        )
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert response.status_code == 200
        body = response.json()
        assert body["pages"] == 2
        assert body["retrieved"] == 20
        assert body["termination"] == "COMPLETED"
        assert body["accepted"] == 20
        assert body["batches"] == 3
        assert body["queue_dropped"] == 0
        assert body["checkpoint_advanced"] is True
        # Bounded: auth + two pages, never a third.
        assert len(state["calls"]) == 3
        rows = _checkpoints()
        assert len(rows) == 1
        status = _checkpoint_status(rows[0])
        assert status["cursor"]["kind"] == "api"
        assert status["cursor"]["pages"] == 2
        assert status["cursor"]["termination"] == "COMPLETED"
        assert status["advance_count"] == 1
        # The cursor never appears in the poll response body.
        assert "cursor" not in body and "offset" not in json.dumps(body)
        events = client.get("/api/v1/events", params={"source_type": "WAZUH"}, headers=admin)
        assert events.json()["total"] == 20
        # Observability reflects the verified state (truthful CONNECTED).
        ingestion_status = client.get("/api/v1/events/ingestion/status", headers=admin).json()
        wazuh = {item["source"]: item for item in ingestion_status["sources"]}["wazuh"]
        assert wazuh["connector_state"] == "CONNECTED"
        assert wazuh["events_accepted"] == 20
        assert wazuh["batches"] == 3
        assert wazuh["checkpoint"]["advance_count"] == 1
        assert wazuh["retries"] == 0
    finally:
        _clear_settings()


def test_replay_runs_the_same_bounded_pipeline_and_stays_idempotent(monkeypatch, client, clean_db):
    state: dict = {}
    _install(_pages_handler(_wazuh_pages(5), state=state))
    try:
        _configure(
            monkeypatch,
            WAZUH_API_URL="https://wazuh.test:55000",
            WAZUH_USERNAME="u",
            WAZUH_PASSWORD="p",
        )
        admin, _ = _tokens(client)
        first = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert first.json()["accepted"] == 5
        replay = client.post(
            "/api/v1/events/connectors/wazuh/poll?replay=true", json={}, headers=admin
        )
        assert replay.status_code == 200
        body = replay.json()
        assert (body["accepted"], body["duplicates"]) == (0, 5)
        assert body["checkpoint_advanced"] is True
        actions = _audit_actions()
        assert "INGESTION_REPLAY" in actions
        assert (
            client.get("/api/v1/events", params={"source_type": "WAZUH"}, headers=admin).json()[
                "total"
            ]
            == 5
        )
        rows = _checkpoints()
        assert rows[0].advance_count == 2
    finally:
        _clear_settings()


def test_transient_timeout_is_retried_boundedly_then_succeeds(monkeypatch, client, clean_db):
    state: dict = {}
    pages = _wazuh_pages(1)
    attempts = {"alerts": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state.setdefault("calls", []).append(f"{request.method} {request.url.path}")
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": "mock-jwt-token-value"})
        if request.url.path.endswith("/alerts"):
            attempts["alerts"] += 1
            if attempts["alerts"] == 1:
                raise httpx.ReadTimeout("mock read timeout")
            return httpx.Response(200, json=pages[int(request.url.params.get("offset", "0"))])
        raise AssertionError(f"unexpected path {request.url.path}")

    _install(handler)
    try:
        _configure(
            monkeypatch,
            WAZUH_API_URL="https://wazuh.test:55000",
            WAZUH_USERNAME="u",
            WAZUH_PASSWORD="p",
            CONNECTOR_RETRY_MAX="0",
            INGESTION_RETRY_MAX="1",
            INGESTION_RETRY_BACKOFF_SECONDS="0",
        )
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert response.status_code == 200
        assert attempts["alerts"] == 2
        assert sum(1 for c in state["calls"] if c.endswith("/alerts")) == 2
        assert "INGESTION_RETRY" in _audit_actions()
        assert any(
            "bounded retry 2/2" in detail
            for action, detail in _audits()
            if action == "INGESTION_RETRY"
        )
        status = client.get("/api/v1/events/ingestion/status", headers=admin).json()
        wazuh = {item["source"]: item for item in status["sources"]}["wazuh"]
        assert wazuh["retries"] == 1
        assert wazuh["events_accepted"] == 1
        assert wazuh["checkpoint"]["advance_count"] == 1
    finally:
        _clear_settings()


def test_transient_retry_budget_is_bounded_and_fails_structured(monkeypatch, client, clean_db):
    state: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        state.setdefault("calls", []).append(f"{request.method} {request.url.path}")
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(200, json={"token": "mock-jwt-token-value"})
        if request.url.path.endswith("/alerts"):
            raise httpx.ReadTimeout("mock read timeout")
        raise AssertionError(f"unexpected path {request.url.path}")

    _install(handler)
    try:
        _configure(
            monkeypatch,
            WAZUH_API_URL="https://wazuh.test:55000",
            WAZUH_USERNAME="u",
            WAZUH_PASSWORD="p",
            CONNECTOR_RETRY_MAX="0",
            INGESTION_RETRY_MAX="2",
            INGESTION_RETRY_BACKOFF_SECONDS="0",
        )
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "CONNECTOR_UNAVAILABLE"
        # 1 initial + 2 bounded retries, then a structured stop.
        assert sum(1 for c in state["calls"] if c.endswith("/alerts")) == 3
        actions = _audit_actions()
        assert actions.count("INGESTION_RETRY") == 2
        assert "INGESTION_CHECKPOINT_REJECTED" in actions
        assert _checkpoints() == []
        status = client.get("/api/v1/events/ingestion/status", headers=admin).json()
        wazuh = {item["source"]: item for item in status["sources"]}["wazuh"]
        assert wazuh["events_failed"] == 1
        assert wazuh["retries"] == 2
        assert wazuh["last_failure_reason"] == "connector unavailable"
    finally:
        _clear_settings()


def test_authentication_failure_is_never_retried(monkeypatch, client, clean_db):
    state: dict = {}
    _install(_pages_handler({}, state=state, auth_status=401, alerts_error=AssertionError))
    try:
        _configure(
            monkeypatch,
            WAZUH_API_URL="https://wazuh.test:55000",
            WAZUH_USERNAME="u",
            WAZUH_PASSWORD="wrong-password-value",
            CONNECTOR_RETRY_MAX="0",
            INGESTION_RETRY_MAX="2",
            INGESTION_RETRY_BACKOFF_SECONDS="0",
        )
        admin, _ = _tokens(client)
        response = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "CONNECTOR_UNAVAILABLE"
        assert sum(1 for c in state["calls"] if c.endswith("/authenticate")) == 1
        assert sum(1 for c in state["calls"] if c.endswith("/alerts")) == 0
        assert "INGESTION_RETRY" not in _audit_actions()
        assert "wrong-password-value" not in _audit_blob()
        assert _checkpoints() == []
    finally:
        _clear_settings()


# --- file rotation / resume ----------------------------------------------------


def test_file_rotation_or_truncation_restarts_the_bounded_read(
    monkeypatch, client, clean_db, tmp_path
):
    eve = tmp_path / "eve.json"
    _write_lines(eve, _suricata_lines(5))
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve))
    try:
        first = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert first["accepted"] == 5
        assert first["checkpoint_advanced"] is True

        # The file is replaced underneath us and is now smaller than the
        # stored offset/size: identity/size checks must catch it.
        _write_lines(eve, _suricata_lines(3, start=500))
        second = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert second["accepted"] == 3
        assert second["duplicates"] == 0
        assert second["checkpoint_advanced"] is True
        actions = _audit_actions()
        assert "INGESTION_ROTATION_DETECTED" in actions
        detail = dict(_audits())["INGESTION_ROTATION_DETECTED"]
        assert any(code in detail for code in ("ROTATED", "OFFSET_INVALID", "TRUNCATED"))
        assert "restarted at offset 0" in detail
        assert client.get("/api/v1/events", params={"source_type": "SURICATA"}).json()["total"] == 8
    finally:
        _clear_settings()


def test_file_resume_is_opt_in_and_reads_only_new_bytes(monkeypatch, client, clean_db, tmp_path):
    eve = tmp_path / "eve.json"
    _write_lines(eve, _suricata_lines(5))
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve), CONNECTOR_FILE_RESUME="true")
    try:
        first = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert first["accepted"] == 5

        with eve.open("a", encoding="utf-8") as handle:
            for line in _suricata_lines(3, start=500):
                handle.write(line + "\n")

        second = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert second["accepted"] == 3
        assert second["duplicates"] == 0
        assert second["retrieved"] == 3
        assert second["truncated"] is False

        third = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert (third["accepted"], third["duplicates"]) == (0, 0)
        assert third["retrieved"] == 0
        rows = _checkpoints()
        assert rows[0].advance_count == 3
    finally:
        _clear_settings()


def test_file_poll_stays_bounded_and_reports_truncation(monkeypatch, client, clean_db, tmp_path):
    from app.services import connectors

    eve = tmp_path / "eve.json"
    _write_lines(eve, _suricata_lines(connectors.MAX_POLL_LINES + 5))
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve))
    try:
        body = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert body["truncated"] is True
        assert body["accepted"] + body["duplicates"] == connectors.MAX_POLL_LINES
        assert body["checkpoint_advanced"] is True
        rows = _checkpoints()
        cursor = json.loads(rows[0].cursor)
        assert cursor["offset"] < cursor["file_size"]
    finally:
        _clear_settings()


def test_malformed_file_lines_are_rejected_without_failing_the_run(
    monkeypatch, client, clean_db, tmp_path
):
    eve = tmp_path / "eve.json"
    _write_lines(eve, _suricata_lines(3) + ["not json{"])
    _configure(monkeypatch, SURICATA_EVE_PATH=str(eve))
    try:
        body = client.post("/api/v1/events/connectors/suricata/poll", json={}).json()
        assert body["accepted"] == 3
        assert body["rejected"] == 1
        assert body["errors"][0]["code"] == "MALFORMED_LINE"
        assert body["checkpoint_advanced"] is True
    finally:
        _clear_settings()


# --- streaming foundation ------------------------------------------------------


def test_streaming_architecture_exists_and_is_not_enabled():
    from app.services import ingestion, ingestion_stream

    assert ingestion.STREAMING_ENABLED is False
    assert ingestion_stream.STREAMING_ENABLED is False
    assert ingestion.STREAMING_MODE == "MANUAL"
    assert "not enabled" in ingestion_stream.STREAMING_DETAIL

    worker = ingestion_stream.PollWorker("wazuh")
    assert worker.status["enabled"] is False
    with pytest.raises(ingestion_stream.StreamingDisabledError):
        worker.start()

    stream = ingestion_stream.BoundedPollStream(
        "suricata", records=[(i, {"i": i}) for i in range(10)], max_items=4
    )
    yielded = list(stream)
    assert len(yielded) == 4
    stream.close()
    assert list(stream) == []
    assert isinstance(stream, ingestion_stream.ConnectorStream)


def test_step28_services_start_no_threads_timers_or_daemons():
    from app.services import connectors, ingestion, ingestion_stream

    forbidden = (
        "import threading",
        "Timer(",
        "Thread(",
        "start_new_thread",
        "create_task",
        "BackgroundScheduler",
        "add_job",
    )
    for module in (ingestion, ingestion_stream, connectors):
        source = inspect.getsource(module)
        for token in forbidden:
            assert token not in source, (module.__name__, token)


# --- audit vocabulary + security regression ------------------------------------


def test_ingestion_audit_actions_fit_the_column_and_carry_no_secrets():
    from app.services.ingestion_audits import INGESTION_AUDIT_ACTIONS

    assert len(INGESTION_AUDIT_ACTIONS) == len(set(INGESTION_AUDIT_ACTIONS))
    for action in INGESTION_AUDIT_ACTIONS:
        assert len(action) <= 32
        assert action.startswith("INGESTION_")


def test_audit_and_status_payloads_carry_no_secret_material(monkeypatch, client, clean_db):
    state: dict = {}
    _install(_pages_handler(_wazuh_pages(2), state=state))
    try:
        _configure(
            monkeypatch,
            WAZUH_API_URL="https://wazuh.test:55000",
            WAZUH_USERNAME="operator",
            WAZUH_PASSWORD="super-secret-value",
        )
        admin, _ = _tokens(client)
        body = client.post("/api/v1/events/connectors/wazuh/poll", json={}, headers=admin).json()
        assert body["accepted"] == 2
        blob = _audit_blob()
        assert "super-secret-value" not in blob
        assert "mock-jwt-token-value" not in blob
        status_text = client.get("/api/v1/events/ingestion/status", headers=admin).text
        assert "super-secret-value" not in status_text
        assert "password" not in status_text
        checkpoints_text = client.get("/api/v1/events/ingestion/checkpoints", headers=admin).text
        assert "super-secret-value" not in checkpoints_text
    finally:
        _clear_settings()


def test_security_regression_step28_modules():
    """AST-level proof for the Step 28 pipeline modules."""
    import app.api.v1.endpoints.ingestion as ingestion_endpoints
    import app.schemas.ingestion as ingestion_schemas
    import app.services.checkpoints as checkpoint_service
    import app.services.connectors as connector_service
    import app.services.ingestion as ingestion_service
    import app.services.ingestion_audits as audit_vocabulary
    import app.services.ingestion_stream as stream_service
    import app.services.log_file_reader as log_reader

    banned = {
        "subprocess",
        "os",
        "pty",
        "shutil",
        "importlib",
        "socket",
        "requests",
        "urllib",
        "httpx",
        "threading",
        "sched",
    }
    modules = (
        ingestion_service,
        stream_service,
        checkpoint_service,
        log_reader,
        audit_vocabulary,
        ingestion_schemas,
        ingestion_endpoints,
    )
    for module in modules:
        tree = ast.parse(inspect.getsource(module))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
                assert not (set(names) & banned), (module.__name__, names)
            elif isinstance(node, ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                assert mod not in banned, (module.__name__, mod)
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    assert func.id not in {"eval", "exec", "compile", "__import__"}, func.id
                elif isinstance(func, ast.Attribute):
                    assert func.attr not in {"system", "popen"}, func.attr

    # The pipeline never touches the filesystem itself; only the Step 26
    # connector module has its single bounded read site.
    for module in (ingestion_service, stream_service, ingestion_endpoints):
        assert "open(" not in inspect.getsource(module)
    service_source = inspect.getsource(connector_service)
    assert service_source.count("open(") == 1
    assert "open(path_value" in service_source
    assert "socket" not in service_source
    assert "urllib" not in service_source
    assert "requests." not in service_source
    assert "httpx.Client(" not in service_source
