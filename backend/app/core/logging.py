"""Centralized structured logging.

Design notes (Step 1):
- Standard-library logging only; no extra dependency.
- Every record carries timestamp, level, logger name and message.
- A redacting filter prevents accidental leakage of secrets.
- Application logs are deliberately separate from future *security event*
  pipelines (collectors / normalization / correlation). Security telemetry
  must never be confused with operational logs; it will live in the database
  and a dedicated event bus in later stages.
"""

from __future__ import annotations

import logging
import re
import sys

# Step 10: the credential-in-URL pattern uses a lookahead for the trailing "@"
# rather than capturing it, so a redacted DSN stays readable
# ("postgresql://user:***@db:5432") without a second replacement group.
_REDACT_PATTERNS = (
    re.compile(r"(?i)(password\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(passwd\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(secret\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(token\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-~+/=]+"),
    re.compile(r"(?i)(://[^:/@\s]+:)[^@\s]+(?=@)"),
)

_CONFIGURED = False
_PREVIOUS_RECORD_FACTORY = None


def _redact(text: str) -> str:
    """Replace every recognised secret in ``text`` with ``***``."""
    for pattern in _REDACT_PATTERNS:
        text = pattern.sub(r"\1***", text)
    return text


class _SecretRedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - logging must never crash the app
            return True
        redacted = _redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def _install_redacting_record_factory() -> None:
    """Redact every LogRecord at creation, whatever handler it later reaches.

    Step 10. The handler filter alone was not sufficient: ``uvicorn`` and
    ``uvicorn.access`` are configured by uvicorn's own ``dictConfig`` with
    ``propagate: False`` and private handlers, so records they emit never
    reach the root handler where the filter lived. uvicorn also rewrites
    those loggers *after* the application imports the app, so a filter
    attached during startup would be discarded anyway.

    A record factory runs before any handler, logger filter or formatter, so
    it is the only placement that cannot be bypassed by handler
    reconfiguration. The previous factory is preserved and chained, and the
    installation is idempotent, so this composes with any other factory
    rather than replacing it.
    """
    global _PREVIOUS_RECORD_FACTORY
    if getattr(logging.getLogRecordFactory(), "_securesecrets_redacting", False):
        return
    previous = logging.getLogRecordFactory()

    def factory(*args, **kwargs):
        record = previous(*args, **kwargs)
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - logging must never crash the app
            return record
        redacted = _redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return record

    factory._securesecrets_redacting = True  # type: ignore[attr-defined]
    _PREVIOUS_RECORD_FACTORY = previous
    logging.setLogRecordFactory(factory)


def setup_logging(level: str = "INFO") -> None:
    """Configure root logging once with a structured, secret-safe format."""
    global _CONFIGURED
    numeric = getattr(logging, level.strip().upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    handler.addFilter(_SecretRedactingFilter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(numeric)
    # Quiet down noisy third-party loggers without hiding warnings.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    # Step 10: guarantee redaction for every record in the process, including
    # records handled by uvicorn's own non-propagating handlers.
    _install_redacting_record_factory()
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a module logger, ensuring logging was configured."""
    if not _CONFIGURED:
        setup_logging()
    return logging.getLogger(name)
