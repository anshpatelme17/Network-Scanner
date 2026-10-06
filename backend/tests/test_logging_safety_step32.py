"""Log-safety regression for validation failures (Step 32 Remediation 1).

Finding: the ``RequestValidationError`` handler logged ``exc.errors()``.
Pydantic includes an ``input`` key with the submitted value, and for a
``missing`` field that value is the *entire request body* — so a password
was written to the application log verbatim. The global redaction filter
did not help, because its pattern needs the field name immediately
followed by ``:``/``=`` while Pydantic renders ``'password': '…'``.

These tests pin the fix: the handler logs the failure *shape* (type and
field location) and never a submitted value.
"""

import logging
from contextlib import contextmanager

import pytest
from pydantic import BaseModel, Field, ValidationError

from app.core.errors import safe_validation_summary

SENTINEL = "step32-sentinel-not-a-real-secret"


class _UserCreate(BaseModel):
    """Mirrors the shape of the real user-creation schema.

    ``display_name`` has no default so omitting it produces a ``missing``
    error whose ``input`` is the whole submitted dict - the worst case
    that leaked a password.
    """

    username: str = Field(min_length=3, max_length=128)
    password: str = Field(min_length=1, max_length=256)
    display_name: str = Field(min_length=1, max_length=256)
    model_config = {"extra": "forbid"}


def _validation_error(payload: dict):
    """A real Pydantic error payload for ``payload``, via the real schema.

    ``safe_validation_summary`` only needs an object exposing ``errors()``,
    so this wrapper keeps the unit tests independent of how FastAPI
    constructs its own exception type.
    """
    try:
        _UserCreate(**payload)
    except ValidationError as exc:
        return _ValidationError(exc)
    raise AssertionError("payload was expected to fail validation")


class _ValidationError:
    def __init__(self, exc: ValidationError) -> None:
        self._exc = exc

    def errors(self) -> list[dict]:
        return self._exc.errors()


@contextmanager
def _capture_error_logs():
    """Collect records emitted by the errors logger.

    Attached directly to ``app.core.errors`` rather than via ``caplog``:
    ``create_app()`` calls ``setup_logging()``, which clears the root
    handlers, so a root-level capture handler installed by the plugin can
    be removed before the request is made. Propagation is disabled for
    the duration so the captured text is not also printed to stdout.

    The logger is explicitly re-enabled because Alembic's ``fileConfig()``
    (invoked in-process by the migration tests) sets ``disabled`` on
    existing loggers. That is a test-suite artefact, unrelated to the
    behaviour under test.
    """
    logger = logging.getLogger("app.core.errors")
    records: list[str] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.getMessage())

    handler = _Collector(level=logging.DEBUG)
    previous = (logger.disabled, logger.level, logger.propagate)
    logger.addHandler(handler)
    logger.disabled = False
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.disabled, logger.level, logger.propagate = previous


def _logged_text(records: list[str]) -> str:
    # Non-empty is asserted so a handler test can never pass vacuously by
    # capturing nothing at all.
    assert records, "no log record was captured; the capture setup is broken"
    return "\n".join(records)


# ---------------------------------------------------------------------------
# Unit level: the summary helper
# ---------------------------------------------------------------------------


def test_summary_keeps_type_and_location():
    exc = _validation_error({"username": "operator", "password": SENTINEL})
    summary = safe_validation_summary(exc)
    assert summary, "a validation failure must still produce a summary"
    types = {item["type"] for item in summary}
    locations = {tuple(item["loc"]) for item in summary}
    assert "missing" in types
    assert ("display_name",) in locations
    # Diagnostics retained: which field, and why.
    assert all(set(item) == {"type", "loc"} for item in summary)


def test_summary_never_carries_a_value_bearing_key():
    exc = _validation_error({"username": "operator", "password": SENTINEL})
    for item in safe_validation_summary(exc):
        assert "input" not in item
        assert "ctx" not in item
        assert "url" not in item


def test_summary_omits_missing_field_input_which_is_the_whole_body():
    """The worst case: a missing field carries the entire submitted body."""
    exc = _validation_error({"username": "operator", "password": SENTINEL})
    # Prove the raw payload really does contain the secret...
    assert SENTINEL in str(exc.errors()), "fixture no longer exercises the leak"
    # ...and that the safe summary does not.
    assert SENTINEL not in str(safe_validation_summary(exc))


def test_summary_omits_over_long_field_value():
    long_value = SENTINEL * 40
    exc = _validation_error({"username": "operator", "password": long_value, "display_name": "Op"})
    assert long_value in str(exc.errors()), "fixture no longer exercises the leak"
    assert SENTINEL not in str(safe_validation_summary(exc))


def test_summary_omits_extra_field_value():
    exc = _validation_error(
        {
            "username": "operator",
            "password": SENTINEL,
            "display_name": "Op",
            "role": SENTINEL,
        }
    )
    assert SENTINEL in str(exc.errors()), "fixture no longer exercises the leak"
    assert SENTINEL not in str(safe_validation_summary(exc))
    # The field name and reason are still reported.
    summary = safe_validation_summary(exc)
    assert summary == [{"type": "extra_forbidden", "loc": ("role",)}]


# ---------------------------------------------------------------------------
# End to end: what the handler actually writes to the log
# ---------------------------------------------------------------------------


def test_handler_does_not_log_submitted_password(client, clean_db):
    with _capture_error_logs() as records:
        response = client.post(
            "/api/v1/users",
            # display_name omitted on purpose -> the whole body is Pydantic's `input`
            json={"username": "operator", "password": SENTINEL},
        )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"

    logged = _logged_text(records)
    assert SENTINEL not in logged, "a submitted password reached the log"
    # The client response is unchanged and still generic.
    assert SENTINEL not in response.text
    # Diagnostics survive.
    assert "Validation error on /api/v1/users" in logged
    assert "display_name" in logged
    assert "missing" in logged


def test_handler_does_not_log_over_long_password(client, clean_db):
    long_password = SENTINEL * 40
    with _capture_error_logs() as records:
        response = client.post(
            "/api/v1/users",
            json={"username": "operator", "password": long_password, "display_name": "Op"},
        )
    assert response.status_code == 422
    logged = _logged_text(records)
    assert SENTINEL not in logged
    assert "password" in logged  # the field name is still reported
    assert "string_too_long" in logged  # so is the reason


def test_handler_does_not_log_login_credentials(client, clean_db):
    """The login endpoint is public: it must be safe from any caller."""
    with _capture_error_logs() as records:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": ["operator"], "password": {"nested": SENTINEL}},
        )
    assert response.status_code == 422
    logged = _logged_text(records)
    assert SENTINEL not in logged
    assert "password" in logged  # the field name is still reported


@pytest.mark.parametrize(
    "field",
    ["password", "access_token", "authorization", "api_key", "secret", "client_secret"],
)
def test_no_secret_named_field_value_is_logged(client, clean_db, field):
    """A missing sibling field must not drag any submitted value into the log.

    This is the original leak shape: ``display_name`` is missing, so
    Pydantic's ``input`` becomes the whole body -- including every value
    below, whatever the field happens to be called.
    """
    body = {"username": "operator", "password": SENTINEL, field: SENTINEL, "display_name": "Op"}
    body.pop("password")  # avoid a duplicate key when field == "password"
    with _capture_error_logs() as records:
        response = client.post("/api/v1/users", json={"username": "operator", field: SENTINEL})
    assert response.status_code == 422
    assert SENTINEL not in _logged_text(records)
    assert SENTINEL not in response.text


def test_no_handler_elsewhere_logs_a_validation_payload():
    """Guard the invariant: no logger in errors.py writes ``errors()`` raw."""
    import inspect

    from app.core import errors

    source = inspect.getsource(errors)
    # Comments explain *why* the raw payload is unsafe and quote it; they are
    # not executable log output.
    code = "\n".join(line for line in source.splitlines() if not line.strip().startswith("#"))
    assert "exc.errors()" not in code.replace("for error in exc.errors()", "")
    assert "safe_validation_summary" in code
