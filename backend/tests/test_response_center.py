"""Response Center summary tests (Step 40, read-only).

Covers the additive ``GET /api/v1/responses/summary`` contract without
weakening Steps 1-39: authorization, exact controlled-status counts, the
pending-approval queue, the bounded 72-hour expiry warning (and its
boundary behaviour), proof that a read cannot extend an expiry, exclusion
of legacy Step 12/13/18/19 proposal rows, bounded output with exact
``total``/``truncated`` semantics, a fixed query count as volume grows,
single-audit expiry handling, and the structural guards that no new
direct-action route or unsafe import was introduced.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event as sa_event

OBSERVED_IP = "198.51.100.23"

SUMMARY_URL = "/api/v1/responses/summary"

# The statuses the summary is documented to report, every one always present.
CANONICAL_STATUSES = {
    "PENDING_APPROVAL",
    "APPROVED",
    "REJECTED",
    "CANCELLED",
    "EXPIRED",
    "DRY_RUN_COMPLETED",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "ROLLED_BACK",
}


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------


def _seed_controlled(client, *, action_id, status, expires_at, requested_by="analyst-1"):
    """Insert one controlled-response row directly with a chosen state."""
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAction
    from app.services.response_providers import select_provider_name
    from app.services.response_service import action_id as compute_action_id

    # Deterministic identity, exactly as the governance layer computes it,
    # so the seeded row is indistinguishable from a real request.
    row_id = compute_action_id(
        f"inc-{action_id}", "BLOCK_INDICATOR", "IP", OBSERVED_IP, requested_by
    )
    db = get_session_factory()()
    try:
        db.add(
            ResponseAction(
                id=row_id,
                incident_id=f"inc-{action_id}",
                action_type="BLOCK_INDICATOR",
                target_type="IP",
                target_reference=OBSERVED_IP,
                reason="Deterministic Step 40 fixture row.",
                requested_by=requested_by,
                status=status,
                dry_run=True,
                policy_version="1.0.0",
                provider=select_provider_name("BLOCK_INDICATOR"),
                approval_required=True,
                expires_at=expires_at,
            )
        )
        db.commit()
    finally:
        db.close()
    return row_id


def _seed_legacy(client, *, suffix, action_type="REVIEW", status="PROPOSED"):
    """Insert a Step 12/18/19 proposal row that must never appear here."""
    from app.database.session import get_session_factory
    from app.models.responses import ResponseAction
    from app.services.response_service import action_id as compute_action_id

    row_id = compute_action_id(
        f"legacy-inc-{suffix}", action_type, "INCIDENT", f"legacy-inc-{suffix}", "operator"
    )
    db = get_session_factory()()
    try:
        db.add(
            ResponseAction(
                id=row_id,
                incident_id=f"legacy-inc-{suffix}",
                action_type=action_type,
                target_type="INCIDENT",
                target_reference=f"legacy-inc-{suffix}",
                reason="Legacy Step 18 proposal that must stay out of the summary.",
                requested_by="operator",
                status=status,
                dry_run=True,
                policy_version="1.0.0",
            )
        )
        db.commit()
    finally:
        db.close()
    return row_id


def _admin(client):
    from tests.test_auth import _admin_headers

    return _admin_headers(client)


def _principal(client, username, password, roles):
    from tests.test_auth import _auth_header

    return _auth_header(client, username, password, roles=roles)


def _naive(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _now() -> datetime:
    """Naive UTC, matching how the platform stores timestamps."""
    return datetime.now(UTC).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# 1. Authentication and authorization
# ---------------------------------------------------------------------------


def test_anonymous_summary_is_401(client, clean_db):
    _admin(client)  # enforcement active
    assert client.get(SUMMARY_URL).status_code == 401


def test_authenticated_principal_without_read_responses_is_403(client, clean_db, monkeypatch):
    """403 comes from the permission gate itself, not from a role lookup.

    Every role this platform defines already holds ``READ_RESPONSES``
    (see ``auth_service.ROLE_PERMISSIONS``), so no real account can be
    denied this particular read through role assignment alone. The
    denial path is therefore exercised directly against the endpoint's
    own dependency guard with a resolved context that lacks the
    permission, which is exactly the check the route performs.
    """
    from app.api.v1 import auth_deps
    from app.services.auth_service import AuthContext

    def _without_permission(_db, _authorization):
        return AuthContext(
            authenticated=True,
            enforcement=True,
            username="no-read-responses",
            user_id="no-read-responses",
            roles=("VIEWER",),
            permissions=frozenset({"READ_INCIDENTS"}),
        )

    monkeypatch.setattr(auth_deps.auth_service, "resolve_context", _without_permission)
    refused = client.get(SUMMARY_URL)
    assert refused.status_code == 403
    assert refused.json()["error"]["code"] == "PERMISSION_DENIED"
    assert "READ_RESPONSES" in refused.json()["error"]["message"]


@pytest.mark.parametrize(
    "roles", ["VIEWER", "SECURITY_ANALYST", "OPERATOR", "ADMIN"]
)
def test_every_defined_role_may_read_the_summary(client, clean_db, roles):
    """READ_RESPONSES is a read-permission gate held by every SOC role."""
    principal = _principal(
        client,
        f"rc-{roles.lower()}",
        f"{roles.lower()}-pass-1234",
        (roles,),
    )
    assert client.get(SUMMARY_URL, headers=principal).status_code == 200


def test_reader_with_read_responses_is_200(client, clean_db):
    assert client.get(SUMMARY_URL, headers=_admin(client)).status_code == 200


# ---------------------------------------------------------------------------
# 2-4. Counts, pending queue, expiry window
# ---------------------------------------------------------------------------


def test_counts_are_exact_and_always_complete(client, clean_db):
    now = _now()
    offsets = {
        "PENDING_APPROVAL": 30,
        "APPROVED": 120,
        "REJECTED": 200,
        "CANCELLED": 300,
        "EXPIRED": -300,
        "DRY_RUN_COMPLETED": 400,
        "RUNNING": 500,
        "COMPLETED": 600,
        "FAILED": 700,
        "ROLLED_BACK": 800,
    }
    for index, (status, minutes) in enumerate(offsets.items()):
        _seed_controlled(
            client,
            action_id=f"cnt-{index}",
            status=status,
            expires_at=now + timedelta(minutes=minutes),
        )
    # A legacy row in a status that is counted must not move any number.
    _seed_legacy(client, suffix="cnt", status="PROPOSED")

    body = client.get(SUMMARY_URL, headers=_admin(client)).json()
    assert set(body["counts"]) == CANONICAL_STATUSES, "every canonical status is reported"
    for status in offsets:
        assert body["counts"][status] == 1, status
    # Every canonical status is present, including the zeros.
    assert all(key in body["counts"] for key in CANONICAL_STATUSES)
    # total counts only controlled rows: the legacy proposal is excluded.
    assert body["total"] == len(offsets)


def test_pending_approval_contains_only_pending_controlled_actions(client, clean_db):
    now = _now()
    pending = _seed_controlled(
        client,
        action_id="pend-1",
        status="PENDING_APPROVAL",
        expires_at=now + timedelta(hours=1),
    )
    _seed_controlled(
        client,
        action_id="pend-2",
        status="APPROVED",
        expires_at=now + timedelta(hours=2),
    )
    _seed_legacy(client, suffix="pend", status="PROPOSED")

    body = client.get(SUMMARY_URL, headers=_admin(client)).json()
    ids = [row["id"] for row in body["pending_approval"]]
    assert ids == [pending], "only the pending controlled action is queued"
    row = body["pending_approval"][0]
    assert row["status"] == "PENDING_APPROVAL"
    assert row["target_reference"] == OBSERVED_IP
    assert row["target_evidence"] == []
    # The wire shape is the existing Step 30 controlled-action contract.
    for field in (
        "provider",
        "policy_decision",
        "approval_required",
        "rollback_supported",
        "expires_at",
        "created_at",
    ):
        assert field in row, field


def test_expiring_soon_window_boundaries_are_exact(client, clean_db):
    now = _now()
    inside = _seed_controlled(
        client,
        action_id="win-in",
        status="APPROVED",
        expires_at=now + timedelta(hours=1),
    )
    far = _seed_controlled(
        client,
        action_id="win-far",
        status="APPROVED",
        expires_at=now + timedelta(hours=73),
    )
    expired = _seed_controlled(
        client,
        action_id="win-expired",
        status="EXPIRED",
        expires_at=now - timedelta(hours=1),
    )
    _seed_controlled(
        client,
        action_id="win-none",
        status="PENDING_APPROVAL",
        expires_at=None,
    )
    _seed_legacy(client, suffix="win", status="PROPOSED")

    body = client.get(SUMMARY_URL, headers=_admin(client)).json()
    ids = [row["id"] for row in body["expiring_soon"]]
    assert inside in ids
    assert far not in ids, "beyond the 72-hour warning window"
    assert expired not in ids, "already expired"
    # Records with no expiry at all never fabricate one.
    assert all(row["expires_at"] for row in body["expiring_soon"])
    assert body["expiry_warning_hours"] == 72


def test_expiring_soon_horizon_is_inclusive_at_exactly_72_hours(client, clean_db, monkeypatch):
    """The window is ``now < expires_at <= now+72h``.

    The lower bound is strict (already-expired and exactly-now rows are
    out, because `expire_due` has just retired the latter); the horizon
    itself is inclusive, so "within the next 72 hours" means no more than
    that far away. A row one second past the horizon is out.
    """
    from app.services import response_governance

    frozen = datetime(2026, 1, 15, 12, 0, 0)
    monkeypatch.setattr(response_governance, "_utcnow_naive", lambda: frozen)
    at_horizon = _seed_controlled(
        client,
        action_id="bnd",
        status="APPROVED",
        expires_at=frozen + timedelta(hours=72),
    )
    just_inside = _seed_controlled(
        client,
        action_id="bnd-just-in",
        status="APPROVED",
        expires_at=frozen + timedelta(hours=72, seconds=-1),
    )
    just_past = _seed_controlled(
        client,
        action_id="bnd-past",
        status="APPROVED",
        expires_at=frozen + timedelta(hours=72, seconds=1),
    )
    exactly_now = _seed_controlled(
        client,
        action_id="bnd-now",
        status="APPROVED",
        expires_at=frozen,
    )

    body = client.get(SUMMARY_URL, headers=_admin(client)).json()
    ids = [row["id"] for row in body["expiring_soon"]]
    assert at_horizon in ids, "the 72-hour horizon is inclusive"
    assert just_inside in ids
    assert just_past not in ids, "one second past the horizon is outside"
    # An exactly-now deadline is not "strictly in the future": the shared
    # expiry sweep retires it on this same read.
    assert exactly_now not in ids


def test_expiry_uses_one_consistent_timestamp(client, clean_db, monkeypatch):
    """The horizon is computed once, not per row, so results cannot drift."""
    from app.services import response_governance

    calls = {"n": 0}
    frozen = datetime(2026, 1, 20, 9, 0, 0)

    def _clock():
        calls["n"] += 1
        return frozen

    monkeypatch.setattr(response_governance, "_utcnow_naive", _clock)
    _seed_controlled(
        client,
        action_id="clock-1",
        status="APPROVED",
        expires_at=frozen + timedelta(hours=10),
    )

    body = client.get(SUMMARY_URL, headers=_admin(client)).json()
    assert body["generated_at"] == frozen.isoformat()
    assert calls["n"] == 1, "the request captured a single timestamp"
    assert len(body["expiring_soon"]) == 1


def test_a_summary_request_cannot_extend_an_expiry(client, clean_db):
    before = _now() + timedelta(hours=2)
    action_id = _seed_controlled(
        client,
        action_id="no-extend",
        status="APPROVED",
        expires_at=before,
    )
    client.get(SUMMARY_URL, headers=_admin(client))
    client.get(SUMMARY_URL, headers=_admin(client))

    body = client.get(SUMMARY_URL, headers=_admin(client)).json()
    stored = [row for row in body["expiring_soon"] if row["id"] == action_id][0]["expires_at"]
    assert _naive(stored) == before, "a read must never alter the stored deadline"


def test_summary_read_retires_overdue_requests_once(client, clean_db):
    overdue = _seed_controlled(
        client,
        action_id="retire",
        status="PENDING_APPROVAL",
        expires_at=_now() - timedelta(hours=1),
    )
    admin = _admin(client)

    first = client.get(SUMMARY_URL, headers=admin).json()
    assert first["counts"]["EXPIRED"] == 1
    assert first["counts"]["PENDING_APPROVAL"] == 0
    assert [row["id"] for row in first["pending_approval"]] == []

    # A second read must not re-audit the same retirement.
    second = client.get(SUMMARY_URL, headers=admin).json()
    assert second["counts"]["EXPIRED"] == 1

    from app.database.session import get_session_factory
    from app.models.responses import ResponseAudit

    db = get_session_factory()()
    try:
        events = db.query(ResponseAudit).filter(ResponseAudit.action_id == overdue).all()
    finally:
        db.close()
    expired_events = [e for e in events if e.event == "RESPONSE_EXPIRED"]
    assert len(expired_events) == 1, "expiry is retired and audited exactly once"


# ---------------------------------------------------------------------------
# 6-7. Exclusion and bounded output
# ---------------------------------------------------------------------------


def test_legacy_proposals_are_never_summarized(client, clean_db):
    _seed_legacy(client, suffix="legacy-a", action_type="REVIEW", status="PROPOSED")
    _seed_legacy(client, suffix="legacy-b", action_type="REVIEW", status="APPROVED")
    # A Step 13 simulation-only action must also stay out.
    _seed_legacy(client, suffix="legacy-c", action_type="ISOLATE_ASSET", status="APPROVED")

    body = client.get(SUMMARY_URL, headers=_admin(client)).json()
    assert body["total"] == 0
    assert body["pending_approval"] == []
    assert body["expiring_soon"] == []
    assert body["truncated"] is False
    assert all(count == 0 for count in body["counts"].values())


def test_lists_are_bounded_and_truncation_is_honest(client, clean_db):
    now = _now()
    for index in range(4):
        _seed_controlled(
            client,
            action_id=f"bnd-{index}",
            status="PENDING_APPROVAL",
            expires_at=now + timedelta(hours=index + 1),
        )

    full = client.get(SUMMARY_URL, params={"limit": 10}, headers=_admin(client)).json()
    assert full["limit"] == 10
    assert full["total"] == 4
    assert full["truncated"] is False
    assert len(full["pending_approval"]) == 4

    bounded = client.get(SUMMARY_URL, params={"limit": 2}, headers=_admin(client)).json()
    assert bounded["limit"] == 2
    assert len(bounded["pending_approval"]) == 2
    # The aggregate stays complete even when the list is cut short.
    assert bounded["total"] == 4
    assert bounded["truncated"] is True


def test_offset_pages_the_lists_deterministically(client, clean_db):
    now = _now()
    made = [
        _seed_controlled(
            client,
            action_id=f"page-{index}",
            status="PENDING_APPROVAL",
            expires_at=now + timedelta(hours=index + 1),
        )
        for index in range(3)
    ]
    first = client.get(
        SUMMARY_URL, params={"limit": 2, "offset": 0}, headers=_admin(client)
    ).json()
    second = client.get(
        SUMMARY_URL, params={"limit": 2, "offset": 2}, headers=_admin(client)
    ).json()

    first_ids = [row["id"] for row in first["pending_approval"]]
    second_ids = [row["id"] for row in second["pending_approval"]]
    assert first_ids == made[:2]
    assert second_ids == [made[2]]
    # Reading page two still says page one had more rows.
    assert second["truncated"] is False
    assert first["truncated"] is True


def test_out_of_range_bounds_are_refused_by_the_contract(client, clean_db):
    """The bound cannot be widened or bypassed by a caller.

    ``limit``/``offset`` are validated at the route (``Query`` ge/le) and
    clamped again inside the service, exactly as the existing response
    list endpoint does. Out-of-range input is a 422, never a silently
    larger read.
    """
    assert client.get(SUMMARY_URL, params={"limit": 99999}, headers=_admin(client)).status_code == 422
    assert client.get(SUMMARY_URL, params={"limit": 0}, headers=_admin(client)).status_code == 422
    assert client.get(SUMMARY_URL, params={"offset": -1}, headers=_admin(client)).status_code == 422


def test_declared_bounds_match_the_service_ceiling(client, clean_db):
    """The echoed limit can never exceed the service's own ceiling."""
    from app.services import response_governance

    assert response_governance.RESPONSE_CENTER_DEFAULT_LIMIT <= (
        response_governance.RESPONSE_CENTER_MAX_LIMIT
    )
    body = client.get(
        SUMMARY_URL,
        params={"limit": response_governance.RESPONSE_CENTER_MAX_LIMIT},
        headers=_admin(client),
    ).json()
    assert body["limit"] == response_governance.RESPONSE_CENTER_MAX_LIMIT


def test_service_clamp_is_a_backstop_below_the_route_ceiling(client, clean_db):
    """Calling the service directly still cannot exceed its own ceiling."""
    from app.database.session import get_session_factory
    from app.services import response_governance

    db = get_session_factory()()
    try:
        body = response_governance.build_response_center_summary(db, limit=99999, offset=-5)
    finally:
        db.close()
    assert body["limit"] == response_governance.RESPONSE_CENTER_MAX_LIMIT
    assert body["offset"] == 0


# ---------------------------------------------------------------------------
# 8. Query count
# ---------------------------------------------------------------------------


def _count_queries(db, fn):  # noqa: ANN001, ANN201
    counter = {"n": 0}
    bind = db.get_bind()

    def _before(*_args, **_kwargs):
        counter["n"] += 1

    sa_event.listen(bind, "before_cursor_execute", _before)
    try:
        return fn(), counter["n"]
    finally:
        sa_event.remove(bind, "before_cursor_execute", _before)


def test_query_count_is_constant_as_volume_grows(client, clean_db):
    from app.database.session import get_session_factory
    from app.services import response_governance

    now = _now()

    def _run(volume: int):
        for index in range(volume):
            _seed_controlled(
                client,
                action_id=f"q-{volume}-{index}",
                status="PENDING_APPROVAL",
                expires_at=now + timedelta(hours=1),
            )
        db = get_session_factory()()
        try:
            (_result, queries) = _count_queries(
                db, lambda: response_governance.build_response_center_summary(db, limit=10)
            )
        finally:
            db.close()
        return queries

    small = _run(2)
    large = _run(60)
    assert small == large, f"query count grew with volume: {small} vs {large}"
    assert small <= 6, f"expected a handful of bounded queries, got {small}"


# ---------------------------------------------------------------------------
# 10. Structural guards
# ---------------------------------------------------------------------------


def test_no_new_direct_action_route_was_introduced(client, clean_db):
    paths = client.get("/openapi.json").json()["paths"]
    forbidden = ("/block", "/isolate", "/wipe", "/command", "/remediate", "/firewall", "/execute-raw")
    for path in paths:
        lowered = path.lower()
        for needle in forbidden:
            assert needle not in lowered, f"{path} exposes a forbidden response interface"
    # The summary is a read-only literal path.
    assert "/api/v1/responses/summary" in paths
    methods = paths["/api/v1/responses/summary"]
    assert set(methods) == {"get"}, "the summary route is GET-only"


def test_summary_service_has_no_unsafe_imports_or_calls():
    import ast as _ast
    import inspect as _inspect

    from app.services import response_governance as governance

    banned_imports = {
        "subprocess",
        "os",
        "pty",
        "shutil",
        "importlib",
        "socket",
        "requests",
        "httpx",
        "urllib",
        "http",
        "ctypes",
        "multiprocessing",
        "asyncio",
        "signal",
    }
    banned_names = {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr"}
    banned_attrs = {"system", "popen", "Popen", "check_output", "check_call", "connect", "urlopen"}

    # Scan the whole governance module: Step 40 must not have widened what
    # is importable or callable from it.
    tree = _ast.parse(_inspect.getsource(governance))
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in banned_imports, alias.name
        if isinstance(node, _ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root not in banned_imports, root
        if isinstance(node, _ast.Call):
            func = node.func
            if isinstance(func, _ast.Name):
                assert func.id not in banned_names, f"calls {func.id}()"
            if isinstance(func, _ast.Attribute):
                assert func.attr not in banned_attrs, f"calls .{func.attr}()"


def test_summary_documented_status_vocabulary_is_canonical():
    """The reported statuses are the model's own vocabulary, not invented ones."""
    from app.services import response_governance, response_service

    assert set(response_governance.RESPONSE_CENTER_STATUSES) <= set(response_service.STATUSES)
    # PROPOSED and READY_FOR_EXECUTION belong to the Step 12-19 flow.
    assert response_service.STATUS_PROPOSED not in response_governance.RESPONSE_CENTER_STATUSES
    assert response_service.STATUS_READY_FOR_EXECUTION not in (
        response_governance.RESPONSE_CENTER_STATUSES
    )
