"""Rate-limit coverage for scan/discovery starts (Step 32 Remediation 2).

Finding: ``Settings.rate_limit_scan_start`` / ``RATE_LIMIT_SCAN_START``
existed in config, ``.env.example`` and ``docker-compose.yml`` but no
endpoint ever read it, so the documented 60-per-window budget for the
most resource-expensive action in the product was never enforced.

These tests pin the setting to the routes it documents, and add a guard so
the same class of bug -- a shipped, documented, unenforced budget -- cannot
reappear silently.
"""

import ast
from pathlib import Path

import pytest

from app.core.config import Settings

SCAN_START = "/api/v1/network/scans"
VULN_SCAN_START = "/api/v1/vulnerability-scans"

# Valid bodies for each route. ``/network/scans`` rejects this target
# before touching nmap (422), which keeps the test hermetic: no process is
# ever started and no scan is queued.
SCAN_BODY = {"target": "not-a-target", "scan_profile": "DISCOVERY_PING"}
VULN_BODY = {"target": "not-a-target", "profile": "SERVICE_BANNER_FINGERPRINT"}


def _settings() -> Settings:
    from app.core.config import get_settings

    return get_settings()


# ---------------------------------------------------------------------------
# The setting is enforced
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "body", "operation"),
    [
        (SCAN_START, SCAN_BODY, "scan start"),
        (VULN_SCAN_START, VULN_BODY, "vuln scan start"),
    ],
)
def test_scan_start_budget_is_enforced(client, clean_db, monkeypatch, url, body, operation):
    monkeypatch.setattr(_settings(), "rate_limit_scan_start", 2)
    client.app.state.limiter.reset()

    for index in range(2):
        response = client.post(url, json=body)
        assert response.status_code != 429, index

    limited = client.post(url, json=body)
    assert limited.status_code == 429
    error = limited.json()["error"]
    assert error["code"] == "RATE_LIMITED"
    assert operation in error["message"]
    assert int(limited.headers["Retry-After"]) >= 1


def test_both_scan_routes_share_the_one_configured_budget(client, clean_db, monkeypatch):
    """The setting governs both start routes, not just the network one."""
    monkeypatch.setattr(_settings(), "rate_limit_scan_start", 1)
    client.app.state.limiter.reset()

    client.post(SCAN_START, json=SCAN_BODY)
    client.post(VULN_SCAN_START, json=VULN_BODY)
    # Exhausting one route's budget does not exhaust the other's: they are
    # distinct operation keys reading the same setting.
    assert client.post(SCAN_START, json=SCAN_BODY).status_code == 429
    assert client.post(VULN_SCAN_START, json=VULN_BODY).status_code == 429


def test_a_limited_scan_start_queues_nothing(client, clean_db, monkeypatch):
    """A refused scan start must leave no job behind."""
    monkeypatch.setattr(_settings(), "rate_limit_scan_start", 1)
    client.app.state.limiter.reset()

    client.post(SCAN_START, json=SCAN_BODY)
    assert client.post(SCAN_START, json=SCAN_BODY).status_code == 429
    assert client.get("/api/v1/network/scans").json() == []


def test_zero_disables_the_scan_start_budget(client, clean_db, monkeypatch):
    monkeypatch.setattr(_settings(), "rate_limit_scan_start", 0)
    client.app.state.limiter.reset()

    for _ in range(5):
        assert client.post(SCAN_START, json=SCAN_BODY).status_code != 429


# ---------------------------------------------------------------------------
# Functionality preserved
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "url", "body"),
    [
        # Preview validates and plans; it starts no process and stores nothing.
        ("post", "/api/v1/network/scans/preview", {"target": "127.0.0.1", "scan_profile": "NOPE"}),
        # Listing is a read on the same path as the budgeted POST.
        ("get", "/api/v1/network/scans", None),
        ("get", "/api/v1/vulnerability-scans", None),
    ],
)
def test_only_scan_starts_are_budgeted(client, clean_db, monkeypatch, method, url, body):
    """Only *starting* work is budgeted; listing and previewing stay free."""
    monkeypatch.setattr(_settings(), "rate_limit_scan_start", 1)
    client.app.state.limiter.reset()

    call = getattr(client, method)
    for _ in range(4):
        kwargs = {"json": body} if body is not None else {}
        assert call(url, **kwargs).status_code != 429


def test_scan_budget_never_replaces_authorization(client, clean_db, monkeypatch):
    """An anonymous caller is refused before any budget is consumed."""
    from tests.test_auth import _admin_headers

    monkeypatch.setattr(_settings(), "rate_limit_scan_start", 1)
    client.app.state.limiter.reset()
    _admin_headers(client)  # makes require_auth active

    for _ in range(5):
        response = client.post(SCAN_START, json=SCAN_BODY)
        assert response.status_code in (401, 403, 429)
        if response.status_code in (401, 403):
            # Refused before the limiter ran, so the budget is untouched.
            assert client.post(SCAN_START, json=SCAN_BODY).status_code in (401, 403)
            return


# ---------------------------------------------------------------------------
# Guard: no shipped budget may be dead again
# ---------------------------------------------------------------------------

# Limiter plumbing, not per-operation budgets: they have no endpoint.
_LIMITER_PLUMBING = {"rate_limit_window_seconds", "rate_limit_max_buckets"}


def _settings_used_by_endpoints() -> set[str]:
    """Every ``Settings`` field an endpoint actually reads for rate limiting.

    Two shapes are recognised:

    * the ``rate_limit(operation, setting)`` dependency, whose second
      argument names the setting as a string literal;
    * a direct attribute read (``settings.rate_limit_login_failures``),
      used where a budget must be charged conditionally rather than on
      every request.

    Docstrings are excluded: a prose mention of a setting is not
    enforcement.
    """
    used: set[str] = set()
    endpoints = Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "endpoints"
    for path in sorted(endpoints.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr.startswith("rate_limit_"):
                used.add(node.attr)
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "id", None) or getattr(func, "attr", None)
            if name != "rate_limit" or len(node.args) < 2:
                continue
            for arg in node.args[1:2]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    used.add(arg.value)
    return used


def test_every_rate_limit_budget_setting_is_actually_used():
    """A budget that nothing reads is a documented control that does nothing."""
    budget_settings = {
        name
        for name in Settings.model_fields
        if name.startswith("rate_limit_") and name not in _LIMITER_PLUMBING
    }
    used = _settings_used_by_endpoints()

    dead = sorted(budget_settings - used)
    assert not dead, f"rate-limit settings declared but never enforced: {dead}"
    assert "rate_limit_scan_start" in used
    assert "rate_limit_login_failures" in used


def test_every_used_setting_actually_exists():
    """A typo would fail at call time; fail here instead."""
    unknown = sorted(_settings_used_by_endpoints() - set(Settings.model_fields))
    assert not unknown, f"rate_limit() references unknown settings: {unknown}"
