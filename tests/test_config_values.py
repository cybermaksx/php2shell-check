import pytest

from php2shell_check.config import (
    normalise,
    parse_ini_bool,
    parse_ini_int,
    parse_ini_size,
    satisfies,
)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("1", True),
        ("On", True),
        ("on", True),
        ("YES", True),
        ("true", True),
        ('"On"', True),
        ("2", True),
        ("0", False),
        ("Off", False),
        ("no", False),
        ("false", False),
        ("none", False),
        ("", False),
        ("abc", False),  # zend_ini_parse_bool falls back to atoi()
        ("  1  ", True),
    ],
)
def test_parse_ini_bool(value, expected):
    assert parse_ini_bool(value) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("128M", 128 * 1024**2),
        ("8m", 8 * 1024**2),
        ("1G", 1024**3),
        ("512K", 512 * 1024),
        ("1048576", 1048576),
        ("-1", -1),
        ('"32M"', 32 * 1024**2),
        (" 64 M ", 64 * 1024**2),
    ],
)
def test_parse_ini_size(value, expected):
    assert parse_ini_size(value) == expected


@pytest.mark.parametrize("value", ["", "M", "12MB", "1.5G", "lots"])
def test_parse_ini_size_rejects(value):
    with pytest.raises(ValueError):
        parse_ini_size(value)


def test_parse_ini_int():
    assert parse_ini_int("1000") == 1000
    assert parse_ini_int(" -5 ") == -5
    with pytest.raises(ValueError):
        parse_ini_int("10k")


@pytest.mark.parametrize(
    "actual, op, expected, type_, result",
    [
        ("Off", "eq", "0", "bool", True),
        ("On", "eq", "0", "bool", False),
        ("-1", "eq", "-1", "size", True),
        ("128M", "eq", "-1", "size", False),
        ("8M", "lte", "32M", "size", True),
        ("32M", "lte", "32M", "size", True),
        ("33554433", "lte", "32M", "size", False),
        ("1G", "lte", "32M", "size", False),
        ("-1", "lte", "32M", "size", False),  # unlimited is never below a bound
        ("-1", "gte", "32M", "size", True),
        ("64", "lte", "64", "int", True),
    ],
)
def test_satisfies(actual, op, expected, type_, result):
    assert satisfies(actual, op, expected, type_) is result


def test_satisfies_rejects_ordering_bools():
    with pytest.raises(ValueError):
        satisfies("1", "lte", "0", "bool")


def test_normalise_unknown_type():
    with pytest.raises(ValueError):
        normalise("1", "float")
