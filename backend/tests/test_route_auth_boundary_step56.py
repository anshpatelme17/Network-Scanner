"""Step 56 - authorization boundary test (test-only).

Enumerates the routes of the *actual* application instance and proves that
every HTTP API endpoint is protected by the established authentication /
authorization dependency chain defined in ``app.api.v1.auth_deps``
(``require_authenticated`` / ``require_permission``), with the sole exception
of an explicit, closed allowlist of intentionally public endpoints.

Why this test exists
--------------------
There is no global authentication dependency on the application
(``create_app`` mounts the v1/v2 routers without a router-wide dependency), so
protection is applied per endpoint. Nothing previously asserted that *every*
endpoint carries that dependency: the existing suite checks individual
routes, and ``test_require_auth_forwarding_step32.py`` probes only three
paths. A future endpoint added without a dependency would therefore be
silently reachable without authentication. This test closes that gap.

Design notes
------------
* The guarded decision walks each route's FastAPI ``Dependant`` tree
  **recursively**, so a dependency inherited from an ``APIRouter`` or
  introduced through a nested dependency is detected - not only one declared
  directly on the endpoint function.
* The invariant is **fail-closed**: the set of routes that lack an
  ``auth_deps`` dependency must equal the public allowlist exactly. A new
  unguarded route grows the public set and fails; a removed/renamed route
  shrinks it and fails. Omitting a route from the allowlist can never make it
  public.
* Discovery is **order-independent** (comparisons are made on sets).
* Framework-generated routes (``/docs``, ``/redoc``, ``/openapi.json``) are
  Starlette ``Route`` objects, not ``APIRoute``; they are handled according
  to the actual production configuration rather than being assumed public.
* No production code, authentication dependency, security control or
  unrelated test is modified.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, FastAPI
from fastapi.routing import APIRoute

from app.api.v1 import auth_deps

# The module that owns every authentication/authorization dependency factory.
AUTH_DEPS_MODULE = auth_deps.__name__

# Endpoints that are deliberately reachable without an authenticated caller.
# Each entry matches a documented decision in the application configuration or
# the existing authentication tests (README §10 / §13, architecture §6):
#   * "/"                 - Step 1 service root: name, version, environment only.
#   * "/api/v1/auth/login" - how a bearer token is obtained.
#   * "/api/v1/health"     - liveness probe (no data).
#   * "/api/v1/ready"      - readiness probe (no data).
#   * "/api/v1/version"    - build/version metadata.
#   * "/api/v1/health/db"  - database connectivity probe.
PUBLIC_PATHS = frozenset(
    {
        "/",
        "/api/v1/auth/login",
        "/api/v1/health",
        "/api/v1/ready",
        "/api/v1/version",
        "/api/v1/health/db",
    }
)

# Framework-generated (Starlette) documentation routes. They are public only
# when documentation is enabled, which is outside production.
FRAMEWORK_DOCS_PATHS = ("/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc")


def _iter_dependency_calls(dependant):
    """Yield every callable in a ``Dependant`` tree.

    Recursive, so nested dependencies and dependencies inherited from an
    included router are reached - not only the endpoint's own dependencies.
    """
    call = getattr(dependant, "call", None)
    if call is not None:
        yield call
    for child in dependant.dependencies:
        yield from _iter_dependency_calls(child)


def _has_auth_dependency(route: APIRoute) -> bool:
    """True when the route's dependency tree contains an ``auth_deps`` callable."""
    return any(
        getattr(call, "__module__", None) == AUTH_DEPS_MODULE
        for call in _iter_dependency_calls(route.dependant)
    )


def _api_routes(app) -> list[APIRoute]:
    """HTTP API routes only.

    Framework-generated documentation/OpenAPI routes are ``starlette``
    ``Route`` objects and are intentionally excluded from the authorization
    requirement; they are asserted separately against the production config.
    """
    return [route for route in app.routes if isinstance(route, APIRoute)]


# ---------------------------------------------------------------------------
# Discovery sanity: the scan is real and not vacuously true
# ---------------------------------------------------------------------------


def test_route_discovery_and_auth_module_are_wired(client):
    """Guards against a broken discovery that would pass by finding nothing."""
    routes = _api_routes(client.app)
    # The application exposes well over a hundred routes today; require a
    # meaningful number so an empty/partial scan cannot pass silently.
    assert len(routes) >= 50
    # The callables we look for genuinely live in the module we scan for.
    assert callable(getattr(auth_deps, "require_permission", None))
    assert callable(getattr(auth_deps, "require_authenticated", None))
    paths = {route.path for route in routes}
    for known in ("/api/v1/incidents", "/api/v1/responses", "/api/v1/users"):
        assert known in paths


# ---------------------------------------------------------------------------
# Dependency-tree walk: recursive, router-inherited, and negative detection
# ---------------------------------------------------------------------------


def test_dependency_walk_detects_router_level_dependency():
    """A dependency inherited from an included router is detected."""
    guard = auth_deps.require_permission("READ_INCIDENTS")
    router = APIRouter(dependencies=[Depends(guard)])

    @router.get("/guarded")
    def guarded():  # noqa: ANN202 - test-only stub
        return {}

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    routes = _api_routes(app)
    assert len(routes) == 1
    # Nothing is declared on the endpoint itself; the router-level dependency
    # must still be found.
    assert _has_auth_dependency(routes[0]) is True


def test_dependency_walk_detects_nested_dependency():
    """A dependency introduced one level below the endpoint is detected."""

    def _inner(auth=Depends(auth_deps.require_authenticated)):  # noqa: ANN001, ANN202
        return auth

    router = APIRouter()

    @router.get("/nested")
    def nested(_: object = Depends(_inner)):  # noqa: ANN202 - test-only stub
        return {}

    app = FastAPI()
    app.include_router(router)

    route = _api_routes(app)[0]
    assert _has_auth_dependency(route) is True


def test_dependency_walk_reports_an_unguarded_route():
    """The walk does not invent protection where there is none."""
    router = APIRouter()

    @router.get("/open")
    def open_route():  # noqa: ANN202 - test-only stub
        return {}

    app = FastAPI()
    app.include_router(router)

    assert _has_auth_dependency(_api_routes(app)[0]) is False


# ---------------------------------------------------------------------------
# The invariant: every non-public endpoint is protected (fail-closed)
# ---------------------------------------------------------------------------


def test_every_non_public_route_has_an_authorization_dependency(client):
    """No endpoint outside the public allowlist may be reachable unauthenticated."""
    unguarded = [
        (sorted(route.methods), route.path)
        for route in _api_routes(client.app)
        if route.path not in PUBLIC_PATHS and not _has_auth_dependency(route)
    ]
    assert unguarded == [], f"Endpoints missing an authorization dependency: {unguarded}"


def test_only_intended_public_endpoints_lack_authorization(client):
    """The public surface is exactly the allowlist: new routes cannot hide here.

    Equality (not a subset) makes this fail-closed in both directions: an
    endpoint added without a dependency joins the public set and fails, and a
    stale allowlist entry that no longer exists also fails.
    """
    public = {route.path for route in _api_routes(client.app) if not _has_auth_dependency(route)}
    assert public == set(PUBLIC_PATHS), (
        "Public (unauthenticated) HTTP API endpoints changed.\n"
        f"  unexpected public: {sorted(public - set(PUBLIC_PATHS))}\n"
        f"  expected public but guarded/absent: {sorted(set(PUBLIC_PATHS) - public)}"
    )


def test_guard_discovery_is_independent_of_route_declaration_order(client):
    """The guarded set does not depend on the order routes were registered in."""
    routes = _api_routes(client.app)
    forward = {route.path for route in routes if _has_auth_dependency(route)}
    backward = {route.path for route in reversed(routes) if _has_auth_dependency(route)}
    assert forward == backward


# ---------------------------------------------------------------------------
# Framework-generated documentation routes follow the production configuration
# ---------------------------------------------------------------------------


def test_framework_docs_routes_follow_production_configuration(client):
    from app.core.config import get_settings

    paths = {getattr(route, "path", None) for route in client.app.routes}
    present = [path for path in FRAMEWORK_DOCS_PATHS if path in paths]
    if get_settings().is_production:
        # Production disables docs/OpenAPI entirely.
        assert present == []
    else:
        assert "/openapi.json" in paths
        assert "/docs" in paths
    # They are never counted as API routes subject to the authorization
    # requirement, whatever their presence.
    assert not (set(FRAMEWORK_DOCS_PATHS) & {route.path for route in _api_routes(client.app)})
