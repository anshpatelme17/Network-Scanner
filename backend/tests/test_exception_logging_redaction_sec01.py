"""SEC-01 regression tests for exception and traceback redaction."""

import io
import logging
import sys
from collections.abc import Iterator

import pytest

from app.core import logging as app_logging

SYNTHETIC_PASSWORD = "sec01-password-7f31"
SYNTHETIC_DB_PASSWORD = "sec01-db-password-a982"
SYNTHETIC_TOKEN = "sec01-token-f4c3"
SYNTHETIC_NESTED_SECRET = "sec01-nested-68b2"


class _CaptureHandler(logging.StreamHandler):
    def __init__(self) -> None:
        self.output = io.StringIO()
        self.records: list[logging.LogRecord] = []
        super().__init__(self.output)

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)
        super().emit(record)


@pytest.fixture
def configured_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[logging.Logger, io.StringIO, _CaptureHandler]]:
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)
    app_logging.setup_logging("INFO")
    handler = _CaptureHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s%(exc_text)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    logger = logging.getLogger("sec01.exception-test")
    logger.disabled = False
    logger.setLevel(logging.INFO)
    try:
        yield logger, stream, handler
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()


@pytest.mark.parametrize(
    "exception_message, secret",
    [
        (f"password={SYNTHETIC_PASSWORD}", SYNTHETIC_PASSWORD),
        (
            f"connection failed postgresql://test-user:{SYNTHETIC_DB_PASSWORD}@db:5432/testdb",
            SYNTHETIC_DB_PASSWORD,
        ),
        (f"request rejected token={SYNTHETIC_TOKEN}", SYNTHETIC_TOKEN),
    ],
)
def test_exception_messages_are_redacted_before_handlers(
    configured_capture: tuple[logging.Logger, io.StringIO, _CaptureHandler],
    exception_message: str,
    secret: str,
) -> None:
    logger, configured_output, capture = configured_capture
    try:
        raise RuntimeError(exception_message)
    except RuntimeError:
        logger.exception("operation failed")

    output = configured_output.getvalue() + capture.output.getvalue()
    assert secret not in output
    assert "RuntimeError" in output
    assert "Traceback (most recent call last)" in output
    assert capture.records and capture.records[0].exc_info is None


def test_nested_and_chained_exception_messages_are_redacted(
    configured_capture: tuple[logging.Logger, io.StringIO, _CaptureHandler],
) -> None:
    logger, configured_output, capture = configured_capture
    try:
        try:
            raise ValueError(f"nested secret={SYNTHETIC_NESTED_SECRET}")
        except ValueError as cause:
            raise RuntimeError(f"outer token={SYNTHETIC_TOKEN}") from cause
    except RuntimeError:
        logger.exception("nested operation failed")

    output = configured_output.getvalue() + capture.output.getvalue()
    for secret in (SYNTHETIC_NESTED_SECRET, SYNTHETIC_TOKEN):
        assert secret not in output
    assert "ValueError" in output
    assert "RuntimeError" in output
    assert "The above exception was the direct cause" in output
    assert capture.records[0].exc_info is None


def test_preformatted_exception_text_is_redacted(
    configured_capture: tuple[logging.Logger, io.StringIO, _CaptureHandler],
) -> None:
    logger, configured_output, capture = configured_capture
    record = logging.LogRecord(
        logger.name,
        logging.ERROR,
        __file__,
        1,
        "cached exception detail",
        (),
        None,
    )
    record.exc_text = f"ValueError: password={SYNTHETIC_PASSWORD}"
    logger.handle(record)

    output = configured_output.getvalue() + capture.output.getvalue()
    assert SYNTHETIC_PASSWORD not in output
    assert "ValueError" in output
    assert capture.records[0].exc_info is None


def test_traceback_format_failure_uses_safe_fallback(
    configured_capture: tuple[logging.Logger, io.StringIO, _CaptureHandler],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logger, configured_output, capture = configured_capture

    def fail_formatting(_formatter: logging.Formatter, _exc_info: object) -> str:
        raise RuntimeError(f"password={SYNTHETIC_PASSWORD}")

    monkeypatch.setattr(logging.Formatter, "formatException", fail_formatting)

    try:
        raise RuntimeError("synthetic formatting failure")
    except RuntimeError:
        logger.exception("operation failed")

    output = configured_output.getvalue() + capture.output.getvalue()
    assert SYNTHETIC_PASSWORD not in output
    assert "Exception details withheld (traceback formatting failed)." in output
    assert capture.records[0].exc_info is None


def test_safe_exception_diagnostics_and_message_redaction_are_preserved(
    configured_capture: tuple[logging.Logger, io.StringIO, _CaptureHandler],
) -> None:
    logger, configured_output, capture = configured_capture
    try:
        raise ValueError("asset scan failed for password=" + SYNTHETIC_PASSWORD)
    except ValueError:
        logger.exception("scan token=%s", SYNTHETIC_TOKEN)

    output = configured_output.getvalue() + capture.output.getvalue()
    assert SYNTHETIC_PASSWORD not in output
    assert SYNTHETIC_TOKEN not in output
    assert "ValueError" in output
    assert "asset scan failed" in output
    assert "Traceback (most recent call last)" in output
