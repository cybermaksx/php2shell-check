"""INI value parsing. Pure functions, no file or process access.

Phase 6 adds ini / FPM pool / .htaccess / .user.ini parsing here; for now
this holds the value parsers the advisory loader needs to validate
expected values.
"""

from __future__ import annotations

import re

from .models import ExpectOp, SettingType

_TRUE_WORDS = {"on", "yes", "true"}


def parse_ini_bool(value: str) -> bool:
    """Interpret a value the way zend_ini_parse_bool() does.

    "on", "yes" and "true" (any case) are true; anything else is true only
    if it starts with a non-zero integer, so "off", "", "none" and "abc"
    are all false.
    """
    text = value.strip().strip('"').strip()
    if text.lower() in _TRUE_WORDS:
        return True
    match = re.match(r"[+-]?\d+", text)
    return bool(match and int(match.group()) != 0)


_SIZE_RE = re.compile(r"^([+-]?\d+)\s*([kKmMgG]?)$")
_SIZE_FACTORS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}


def parse_ini_size(value: str) -> int:
    """Parse a quantity like "128M", "8m", "1G" or "-1" into bytes.

    -1 (unlimited) stays -1. Raises ValueError for anything PHP would
    reject or warn about.
    """
    text = value.strip().strip('"').strip()
    match = _SIZE_RE.match(text)
    if not match:
        raise ValueError(f"not a size: {value!r}")
    number, suffix = match.groups()
    return int(number) * _SIZE_FACTORS[suffix.lower()]


def parse_ini_int(value: str) -> int:
    text = value.strip().strip('"').strip()
    if not re.fullmatch(r"[+-]?\d+", text):
        raise ValueError(f"not an integer: {value!r}")
    return int(text)


def normalise(value: str, type_: SettingType) -> int | bool:
    if type_ == "bool":
        return parse_ini_bool(value)
    if type_ == "size":
        return parse_ini_size(value)
    if type_ == "int":
        return parse_ini_int(value)
    raise ValueError(f"unknown setting type: {type_!r}")


def satisfies(actual: str, op: ExpectOp, expected: str, type_: SettingType) -> bool:
    """True if the setting's actual value meets the expectation.

    For sizes, -1 means unlimited, so it never satisfies an upper bound.
    """
    a, e = normalise(actual, type_), normalise(expected, type_)
    if op == "eq":
        return a == e
    if type_ == "bool":
        raise ValueError(f"operator {op!r} makes no sense for a bool")
    if type_ == "size" and a == -1:
        return op == "gte"
    if op == "lte":
        return a <= e
    if op == "gte":
        return a >= e
    raise ValueError(f"unknown operator: {op!r}")
