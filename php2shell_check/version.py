"""Version parsing and comparison. Pure functions, no subprocess.

Three schemes:
- upstream PHP versions ("8.3.6", "8.5.0RC1")
- Debian package versions, following dpkg's verrevcmp()
- RPM package versions, following rpm's rpmvercmp()

Comparison functions return -1, 0 or 1.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from .models import Scheme


class VersionError(ValueError):
    pass


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


# --- upstream PHP -----------------------------------------------------------

# Matches what php -v prints, including distro suffixes we ignore:
# "8.3.6", "8.5.0RC1", "8.1.2-1ubuntu2.28", "7.4.33-nmm1".
_UPSTREAM_RE = re.compile(
    r"^(\d+)\.(\d+)(?:\.(\d+))?(?:(alpha|beta|RC|rc)(\d*))?(?:[-+~].*)?$"
)

# Pre-release order as in PHP's version_compare(); a final release sorts last.
_PRE_RANK = {"alpha": 0, "beta": 1, "rc": 2}
_FINAL_RANK = 3


class UpstreamVersion(NamedTuple):
    major: int
    minor: int
    patch: int
    pre_rank: int = _FINAL_RANK
    pre_num: int = 0

    @property
    def branch(self) -> str:
        return f"{self.major}.{self.minor}"

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.pre_rank == _FINAL_RANK:
            return base
        name = {0: "alpha", 1: "beta", 2: "RC"}[self.pre_rank]
        return f"{base}{name}{self.pre_num}"


def parse_upstream(text: str) -> UpstreamVersion:
    match = _UPSTREAM_RE.match(text.strip())
    if not match:
        raise VersionError(f"not a PHP version: {text!r}")
    major, minor, patch, pre, pre_num = match.groups()
    if pre is None:
        return UpstreamVersion(int(major), int(minor), int(patch or 0))
    return UpstreamVersion(
        int(major),
        int(minor),
        int(patch or 0),
        _PRE_RANK[pre.lower()],
        int(pre_num or 0),
    )


def branch_of(text: str) -> str:
    return parse_upstream(text).branch


def compare_upstream(a: str, b: str) -> int:
    pa, pb = parse_upstream(a), parse_upstream(b)
    return (pa > pb) - (pa < pb)


# --- dpkg -------------------------------------------------------------------


class DebVersion(NamedTuple):
    epoch: int
    upstream: str
    revision: str


def parse_dpkg(text: str) -> DebVersion:
    """Split [epoch:]upstream[-revision] the way dpkg does.

    The epoch ends at the first colon; the revision starts after the last
    hyphen, so hyphens inside the upstream part are allowed.
    """
    text = text.strip()
    if not text or any(c.isspace() for c in text):
        raise VersionError(f"invalid dpkg version: {text!r}")

    epoch = 0
    if ":" in text:
        epoch_text, text = text.split(":", 1)
        if not epoch_text.isdigit():
            raise VersionError(f"invalid dpkg epoch: {epoch_text!r}")
        epoch = int(epoch_text)

    upstream, sep, revision = text.rpartition("-")
    if not sep:
        upstream, revision = text, ""
    if not upstream:
        raise VersionError(f"empty dpkg upstream version: {text!r}")
    return DebVersion(epoch, upstream, revision)


def _dpkg_order(c: str) -> int:
    # Weight of one non-digit character. "" means end of string.
    # '~' sorts before everything, even the end of the string;
    # letters sort before all other punctuation.
    if c == "":
        return 0
    if c == "~":
        return -1
    if c.isascii() and c.isalpha():
        return ord(c)
    return ord(c) + 256


def _is_digit(c: str) -> bool:
    return c != "" and c in "0123456789"


def _dpkg_verrevcmp(a: str, b: str) -> int:
    """Port of verrevcmp() from dpkg's lib/dpkg/version.c."""
    i = j = 0

    def at(s: str, k: int) -> str:
        return s[k] if k < len(s) else ""

    while i < len(a) or j < len(b):
        # Non-digit prefix, compared character by character.
        while (at(a, i) and not _is_digit(at(a, i))) or (
            at(b, j) and not _is_digit(at(b, j))
        ):
            ac, bc = _dpkg_order(at(a, i)), _dpkg_order(at(b, j))
            if ac != bc:
                return _sign(ac - bc)
            i += 1
            j += 1

        # Digit run, compared numerically: skip leading zeros, then the
        # longer run wins, otherwise the first differing digit decides.
        while at(a, i) == "0":
            i += 1
        while at(b, j) == "0":
            j += 1
        first_diff = 0
        while _is_digit(at(a, i)) and _is_digit(at(b, j)):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if _is_digit(at(a, i)):
            return 1
        if _is_digit(at(b, j)):
            return -1
        if first_diff:
            return _sign(first_diff)
    return 0


def compare_dpkg(a: str, b: str) -> int:
    va, vb = parse_dpkg(a), parse_dpkg(b)
    if va.epoch != vb.epoch:
        return _sign(va.epoch - vb.epoch)
    result = _dpkg_verrevcmp(va.upstream, vb.upstream)
    if result:
        return result
    return _dpkg_verrevcmp(va.revision, vb.revision)


# --- rpm --------------------------------------------------------------------


class RpmVersion(NamedTuple):
    epoch: int
    version: str
    release: str


def parse_rpm(text: str) -> RpmVersion:
    """Split [epoch:]version[-release]. A missing epoch counts as 0."""
    text = text.strip()
    if not text or any(c.isspace() for c in text):
        raise VersionError(f"invalid rpm version: {text!r}")

    epoch = 0
    if ":" in text:
        epoch_text, text = text.split(":", 1)
        if not epoch_text.isdigit():
            raise VersionError(f"invalid rpm epoch: {epoch_text!r}")
        epoch = int(epoch_text)

    version, sep, release = text.rpartition("-")
    if not sep:
        version, release = text, ""
    if not version:
        raise VersionError(f"empty rpm version: {text!r}")
    return RpmVersion(epoch, version, release)


_ASCII_DIGITS = frozenset("0123456789")
_ASCII_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ASCII_ALNUM = _ASCII_DIGITS | _ASCII_ALPHA


def rpmvercmp(a: str, b: str) -> int:
    """Port of rpmvercmp() from rpm's rpmio/rpmvercmp.cc.

    Strings are split into alternating digit and letter segments; any other
    character is just a separator. '~' sorts before anything (pre-release),
    '^' sorts after the base version but before any further segment
    (post-release snapshot).
    """
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and a[i] not in _ASCII_ALNUM and a[i] not in "~^":
            i += 1
        while j < len(b) and b[j] not in _ASCII_ALNUM and b[j] not in "~^":
            j += 1

        ca = a[i] if i < len(a) else ""
        cb = b[j] if j < len(b) else ""

        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i += 1
            j += 1
            continue

        if ca == "^" or cb == "^":
            if ca == "":
                return -1
            if cb == "":
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i += 1
            j += 1
            continue

        if ca == "" or cb == "":
            break

        charset = _ASCII_DIGITS if ca in _ASCII_DIGITS else _ASCII_ALPHA
        is_num = charset is _ASCII_DIGITS
        si, sj = i, j
        while i < len(a) and a[i] in charset:
            i += 1
        while j < len(b) and b[j] in charset:
            j += 1
        seg_a, seg_b = a[si:i], b[sj:j]

        # Segments of different types: a numeric segment is always newer.
        if not seg_b:
            return 1 if is_num else -1

        if is_num:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1

    a_done, b_done = i >= len(a), j >= len(b)
    if a_done and b_done:
        return 0
    return -1 if a_done else 1


def compare_rpm(a: str, b: str) -> int:
    """Compare full EVR strings like rpm's labelCompare()."""
    va, vb = parse_rpm(a), parse_rpm(b)
    if va.epoch != vb.epoch:
        return _sign(va.epoch - vb.epoch)
    result = rpmvercmp(va.version, vb.version)
    if result:
        return result
    return rpmvercmp(va.release, vb.release)


# --- dispatch ---------------------------------------------------------------


def compare_package(a: str, b: str, scheme: Scheme) -> int:
    if scheme == "dpkg":
        return compare_dpkg(a, b)
    if scheme == "rpm":
        return compare_rpm(a, b)
    raise VersionError(f"unknown version scheme: {scheme!r}")


def is_at_least(installed: str, fixed: str, scheme: Scheme) -> bool:
    return compare_package(installed, fixed, scheme) >= 0
