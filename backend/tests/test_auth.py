"""Authentication + RBAC foundation tests (Step 20).

Covers: bootstrap creation, login success/failure semantics,
token identity, logout revocation, role permission mapping,
endpoint enforcement (401/403), approval actor integrity,
last-admin guards, audit events, token tampering, REQUIRE_AUTH
mode, and structural security — without weakening Steps 1–19.
"""

ADMIN = {"username": "admin", "password": "correct-horse-12345", "display_name": "Admin"}


def _login(client, username=ADMIN["username"], password=ADMIN["password"]):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def _admin_headers(client):
    """Idempotent bootstrap: first ADMIN, then a fresh token.

    201 = just bootstrapped; 409 = duplicate in bootstrap mode;
    401 = enforcement already active (admin exists), log in directly.
    """
    created = client.post(
        "/api/v1/users",
        json={
            "username": ADMIN["username"],
            "password": ADMIN["password"],
            "display_name": ADMIN["display_name"],
            "roles": ["ADMIN"],
        },
    )
    assert created.status_code in (201, 409, 401), created.text
    token = _login(client).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _bootstrap_admin(client):
    headers = _admin_headers(client)
    me = client.get("/api/v1/auth/me", headers=headers).json()
    assert me["roles"] == ["ADMIN"]
    assert "MANAGE_USERS" in me["permissions"]
    assert "password_hash" not in me
    return me


def _auth_header(client, username, password, roles=("VIEWER",)):
    admin_headers = _admin_headers(client)
    created = client.post(
        "/api/v1/users",
        json={
            "username": username,
            "password": password,
            "display_name": username,
            "roles": list(roles),
        },
        headers=admin_headers,
    )
    assert created.status_code == 201, created.text
    token = _login(client, username, password).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _seed_incident_auth(client, headers):
    """One incident seeded with an authorized writer (Step 11/18 helper pattern)."""
    import json as _json
    from pathlib import Path as _Path

    fixtures = _Path(__file__).parent / "fixtures" / "correlation"
    for name in ("chain_a_1.json", "chain_a_2.json"):
        payload = _json.loads((fixtures / name).read_text(encoding="utf-8"))
        assert client.post("/api/v1/events", json=payload, headers=headers).status_code in (
            200,
            201,
        )
    assert client.post("/api/v1/correlations/recompute", headers=headers).status_code == 200
    correlation_id = client.get("/api/v1/correlations", headers=headers).json()["items"][0]["id"]
    incident = client.post(
        "/api/v1/incidents", json={"correlation_id": correlation_id}, headers=headers
    )
    assert incident.status_code in (200, 201)
    return incident.json()


def test_bootstrap_first_user_must_be_admin(client, clean_db):
    assert client.get("/api/v1/incidents").status_code == 200  # bootstrap: open
    bad_role = client.post(
        "/api/v1/users",
        json={
            "username": "sneaky",
            "password": "long-enough-123",
            "display_name": "S",
            "roles": ["VIEWER"],
        },
    )
    assert bad_role.status_code == 422
    admin = _bootstrap_admin(client)
    assert admin["roles"] == ["ADMIN"]
    assert "MANAGE_USERS" in admin["permissions"]
    assert "password_hash" not in admin


def test_login_semantics(client, clean_db):
    _bootstrap_admin(client)
    assert _login(client, "admin", "wrong-password-xyz").status_code == 401
    assert _login(client, "nobody-here", "whatever-long-pw").status_code == 401
    body = _login(client, "nobody-here", "whatever-long-pw").json()
    assert body["error"]["code"] == "INVALID_CREDENTIALS"
    # Generic fixed message: identical for unknown user, wrong password,
    # and inactive accounts, and never echoes the attempted username.
    assert body["error"]["message"] == "Invalid username or password."
    assert "nobody-here" not in body["error"]["message"]
    ok = _login(client)
    assert ok.status_code == 200
    assert ok.json()["token_type"] == "bearer"
    assert ok.json()["expires_in_minutes"] == 15
    me = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {ok.json()['access_token']}"}
    )
    assert me.status_code == 200
    assert me.json()["last_login_at"] is not None
    assert "password_hash" not in me.json()
    assert "access_token" not in me.json()


def test_inactive_user_rejected_generically(client, clean_db):
    admin = _bootstrap_admin(client)
    token = _login(client).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post(
        "/api/v1/users",
        json={
            "username": "temp",
            "password": "temporary-pass-1",
            "display_name": "T",
            "roles": ["VIEWER"],
        },
        headers=headers,
    ).json()
    client.patch(f"/api/v1/users/{created['id']}", json={"is_active": False}, headers=headers)
    assert _login(client, "temp", "temporary-pass-1").status_code == 401
    assert (
        _login(client, "temp", "temporary-pass-1").json()["error"]["code"] == "INVALID_CREDENTIALS"
    )
    assert admin["username"] == "admin"


def test_enforcement_after_bootstrap(client, clean_db):
    _bootstrap_admin(client)
    assert client.get("/api/v1/incidents").status_code == 401
    assert client.get("/api/v1/incidents").json()["error"]["code"] == "AUTH_REQUIRED"
    assert client.get("/api/v1/health").status_code == 200  # public stays public
    assert client.post("/api/v1/auth/login", json={"u": 1}).status_code == 422


def test_viewer_reads_but_cannot_write(client, clean_db):
    _bootstrap_admin(client)
    viewer = _auth_header(client, "viewer", "viewer-pass-1234", ("VIEWER",))
    assert client.get("/api/v1/incidents", headers=viewer).status_code == 200
    denied = client.post("/api/v1/incidents", json={"correlation_id": "x"}, headers=viewer)
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
    assert client.post("/api/v1/users", json={}, headers=viewer).status_code == 403


def test_role_ladder_for_response_workflow(client, clean_db):
    _bootstrap_admin(client)
    analyst = _auth_header(client, "analyst", "analyst-pass-123", ("SECURITY_ANALYST",))
    operator = _auth_header(client, "operator", "operator-pass-12", ("OPERATOR",))
    # Analyst proposes; operator approves/executes; viewer observes.
    assert client.get("/api/v1/responses", headers=analyst).status_code == 200
    forbidden = client.post(
        "/api/v1/responses/nope/approve", json={"actor": "analyst"}, headers=analyst
    )
    assert forbidden.status_code == 403  # permission checked before lookup
    assert forbidden.json()["error"]["code"] == "PERMISSION_DENIED"
    assert client.get("/api/v1/auth/audit", headers=analyst).status_code == 200
    viewer = _auth_header(client, "viewer2", "viewer2-pass-123", ("VIEWER",))
    assert client.get("/api/v1/auth/audit", headers=viewer).status_code == 403
    assert client.get("/api/v1/responses", headers=operator).status_code == 200
    assert client.get("/api/v1/responses", headers=viewer).status_code == 200


def test_approval_records_token_identity(client, clean_db):
    admin_headers = _admin_headers(client)
    analyst = _auth_header(client, "analyst", "analyst-pass-123", ("SECURITY_ANALYST",))
    operator = _auth_header(client, "operator", "operator-pass-12", ("OPERATOR",))
    assert client.get("/api/v1/incidents", headers=analyst).json()["total"] == 0
    incident = _seed_incident_auth(client, admin_headers)
    proposed = client.post(
        f"/api/v1/incidents/{incident['id']}/responses",
        json={"action_type": "REVIEW", "reason": "r", "requested_by": "analyst"},
        headers=analyst,
    )
    assert proposed.status_code == 201
    action_id = proposed.json()["id"]
    # Body claims someone else — the token identity must win server-side.
    approved = client.post(
        f"/api/v1/responses/{action_id}/approve", json={"actor": "mallory"}, headers=operator
    )
    assert approved.status_code == 200
    assert approved.json()["approved_by"] == "operator"
    detail = client.get(f"/api/v1/responses/{action_id}", headers=operator).json()
    assert detail["audit"][1]["actor"] == "operator"


def test_user_management_guards(client, clean_db):
    _bootstrap_admin(client)
    admin_headers = {"Authorization": f"Bearer {_login(client).json()['access_token']}"}
    dup = client.post(
        "/api/v1/users",
        json={
            "username": "ADMIN",
            "password": "another-long-pass",
            "display_name": "D",
            "roles": ["VIEWER"],
        },
        headers=admin_headers,
    )
    assert dup.status_code == 409  # case-insensitive duplicate
    short = client.post(
        "/api/v1/users",
        json={"username": "weak", "password": "short", "display_name": "W", "roles": ["VIEWER"]},
        headers=admin_headers,
    )
    assert short.status_code == 422
    bad_role = client.post(
        "/api/v1/users",
        json={
            "username": "nope",
            "password": "long-enough-123",
            "display_name": "N",
            "roles": ["ROOT"],
        },
        headers=admin_headers,
    )
    assert bad_role.status_code == 422
    admin_id = client.get("/api/v1/users", headers=admin_headers).json()["items"][0]["id"]
    assert (
        client.patch(
            f"/api/v1/users/{admin_id}", json={"is_active": False}, headers=admin_headers
        ).status_code
        == 422
    )
    assert (
        client.patch(
            f"/api/v1/users/{admin_id}", json={"roles": ["VIEWER"]}, headers=admin_headers
        ).status_code
        == 422
    )
    analyst_id = client.post(
        "/api/v1/users",
        json={
            "username": "analyst2",
            "password": "analyst-pass-999",
            "display_name": "A",
            "roles": ["SECURITY_ANALYST"],
        },
        headers=admin_headers,
    ).json()["id"]
    analyst = {
        "Authorization": f"Bearer {_login(client, 'analyst2', 'analyst-pass-999').json()['access_token']}"
    }
    assert client.post("/api/v1/users", json={}, headers=analyst).status_code == 403
    assert (
        client.patch(
            f"/api/v1/users/{analyst_id}", json={"roles": ["ADMIN"]}, headers=analyst
        ).status_code
        == 403
    )


def test_logout_revokes_token(client, clean_db):
    _bootstrap_admin(client)
    token = _login(client).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    fresh_admin = _admin_headers(client)  # password login still works; only the token died
    audits = client.get("/api/v1/auth/audit", headers=fresh_admin).json()
    events = [entry["event"] for entry in audits["items"]]
    assert "LOGOUT" in events
    assert "LOGIN_SUCCESS" in events


def test_audit_captures_lifecycle_without_secrets(client, clean_db):
    _bootstrap_admin(client)
    _login(client, "admin", "wrong-password-xyz")
    viewer_headers = _auth_header(client, "viewer3", "v3-pass-word-123", ("VIEWER",))
    client.post("/api/v1/incidents", json={"correlation_id": "x"}, headers=viewer_headers)
    admin_headers = {"Authorization": f"Bearer {_login(client).json()['access_token']}"}
    audits = client.get("/api/v1/auth/audit", headers=admin_headers).json()["items"]
    events = [entry["event"] for entry in audits]
    for expected in ("USER_CREATED", "LOGIN_SUCCESS", "LOGIN_FAILURE", "PERMISSION_DENIED"):
        assert expected in events, expected
    blob = str(audits).lower()
    assert "correct-horse" not in blob
    assert "password_hash" not in blob
    assert "access_token" not in blob
    assert "eyJ" not in str(audits)


def test_token_tampering_rejected(client, clean_db):
    _bootstrap_admin(client)
    token = _login(client).json()["access_token"]
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Token {token}"}).status_code
        == 401
    )
    assert client.get("/api/v1/auth/me", headers={"Authorization": token}).status_code == 401
    tampered = token[:-2] + ("AA" if not token.endswith("AA") else "BB")
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tampered}"}).status_code
        == 401
    )


def test_expired_token_rejected(client, clean_db):
    import time

    import jwt

    from app.core.config import get_settings

    _bootstrap_admin(client)
    secret = get_settings().secret_key
    stale = jwt.encode(
        {
            "sub": "nobody",
            "username": "nobody",
            "roles": ["ADMIN"],
            "jti": "stale",
            "iat": int(time.time()) - 3600,
            "exp": int(time.time()) - 60,
        },
        secret,
        algorithm="HS256",
    )
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {stale}"})
    assert response.status_code == 401


def test_require_auth_mode_disables_bootstrap(client, clean_db, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setenv("REQUIRE_AUTH", "true")
    get_settings.cache_clear()
    try:
        assert client.get("/api/v1/incidents").status_code == 401
        bootstrap = client.post(
            "/api/v1/users",
            json={
                "username": "admin",
                "password": "correct-horse-12345",
                "display_name": "A",
                "roles": ["ADMIN"],
            },
        )
        assert bootstrap.status_code == 401
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


def test_no_admin_command_permission_exists():
    from app.services import auth_service

    assert "EXECUTE_ARBITRARY_COMMAND" not in auth_service.PERMISSIONS
    admin_perms = auth_service.permissions_for_roles(["ADMIN"])
    assert set(admin_perms) == set(auth_service.PERMISSIONS)
    assert auth_service.permissions_for_roles(["VIEWER"]) <= auth_service.permissions_for_roles(
        ["SECURITY_ANALYST"]
    )
    assert auth_service.permissions_for_roles(
        ["SECURITY_ANALYST"]
    ) <= auth_service.permissions_for_roles(["OPERATOR"])
    assert "APPROVE_RESPONSE" not in auth_service.permissions_for_roles(["SECURITY_ANALYST"])
    assert "MANAGE_USERS" not in auth_service.permissions_for_roles(["OPERATOR"])


def test_passwords_hashed_and_verified():
    from app.services import auth_service

    hashed = auth_service.hash_password("a-very-long-passphrase-1")
    assert hashed != "a-very-long-passphrase-1"
    assert hashed.startswith("$argon2")
    assert auth_service.verify_password(hashed, "a-very-long-passphrase-1") is True
    assert auth_service.verify_password(hashed, "wrong") is False
    import pytest

    with pytest.raises(auth_service.AuthError):
        auth_service.hash_password("short")


def test_migration_includes_auth_tables(tmp_path, monkeypatch):
    from pathlib import Path

    from sqlalchemy import create_engine, inspect

    from alembic import command
    from alembic.config import Config

    db_file = tmp_path / "mig20.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    config = Config(str(Path(__file__).parent.parent / "alembic.ini"))
    config.set_main_option("script_location", str(Path(__file__).parent.parent / "alembic"))
    command.upgrade(config, "head")
    inspector = inspect(create_engine(f"sqlite:///{db_file}"))
    for table in ("users", "revoked_tokens", "auth_audits"):
        assert table in inspector.get_table_names(), table
    columns = {column["name"] for column in inspector.get_columns("users")}
    assert {
        "username",
        "password_hash",
        "display_name",
        "is_active",
        "roles",
        "last_login_at",
    } <= columns


def test_security_regression_step20_modules():
    """AST-level proof for the Step 20 modules (established pattern)."""
    import ast as _ast
    import inspect as _inspect

    import app.api.v1.auth_deps as deps
    import app.api.v1.endpoints.auth as auth_endpoints
    import app.api.v1.endpoints.users as user_endpoints
    import app.services.auth_service as service

    for module in (service, deps, auth_endpoints, user_endpoints):
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
