"""Backend system-endpoint tests (real behavior, no fakes)."""

from app import __version__


def test_app_starts_and_root_reports_version(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == __version__
    assert body["status"] == "running"
    assert body["api_prefix"] == "/api/v1"
    # Root must not leak secrets.
    serialized = response.text.lower()
    assert "secret" not in serialized
    assert "password" not in serialized


def test_health_endpoint_and_version_path(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__
    assert "environment" in body

    version_response = client.get("/api/v1/version")
    assert version_response.status_code == 200
    assert version_response.json()["version"] == __version__


def test_readiness_reports_database_up_with_sqlite(client):
    response = client.get("/api/v1/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"]["database"] == "up"


def test_readiness_reports_down_when_database_unreachable(monkeypatch):
    from fastapi.testclient import TestClient

    import app.services.health as health_service
    from app.main import create_app

    monkeypatch.setattr(health_service, "ping_database", lambda: False)
    app = create_app()
    with TestClient(app) as test_client:
        response = test_client.get("/api/v1/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert body["checks"]["database"] == "down"


def test_invalid_route_returns_controlled_error_envelope(client):
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert "error" in body
    assert body["error"]["code"] == "NOT_FOUND"
    assert isinstance(body["error"]["message"], str)
    # No stack traces leak to clients.
    assert "traceback" not in response.text.lower()


def test_health_never_exposes_sensitive_config(client):
    body = client.get("/api/v1/health").text.lower()
    for forbidden in ("secret", "password", "database_url", "passwd", "api_key"):
        assert forbidden not in body
    ready_body = client.get("/api/v1/ready").text.lower()
    for forbidden in ("secret", "password", "database_url", "passwd", "api_key"):
        assert forbidden not in ready_body
