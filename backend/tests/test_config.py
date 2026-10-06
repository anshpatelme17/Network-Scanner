"""Configuration safety tests."""

import pytest

from app.core.config import Settings


def test_production_refuses_placeholder_secret():
    with pytest.raises(RuntimeError):
        Settings(
            environment="production",
            secret_key="CHANGE_ME_dev_only",
            debug=False,
        ).validate_production()


def test_production_refuses_debug_enabled():
    with pytest.raises(RuntimeError):
        Settings(
            environment="production",
            secret_key="a" * 32,
            debug=True,
        ).validate_production()


def test_log_level_is_validated():
    with pytest.raises(ValueError):
        Settings(log_level="VERBOSE")
    assert Settings(log_level="debug").log_level == "DEBUG"
