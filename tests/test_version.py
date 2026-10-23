import itertools
import shutil
import subprocess

import pytest

from php2shell_check.version import (
    DebVersion,
    RpmVersion,
    UpstreamVersion,
    VersionError,
    branch_of,
    compare_dpkg,
    compare_package,
    compare_rpm,
    compare_upstream,
    is_at_least,
    parse_dpkg,
    parse_rpm,
    parse_upstream,
    rpmvercmp,
)

# --- upstream ---------------------------------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        ("8.3.6", UpstreamVersion(8, 3, 6)),
        ("8.5.12", UpstreamVersion(8, 5, 12)),
        ("5.4", UpstreamVersion(5, 4, 0)),
        ("8.5.0RC1", UpstreamVersion(8, 5, 0, 2, 1)),
        ("8.5.0beta2", UpstreamVersion(8, 5, 0, 1, 2)),
        ("8.5.0alpha1", UpstreamVersion(8, 5, 0, 0, 1)),
        # php -v on Debian/Ubuntu appends the package revision
        ("8.1.2-1ubuntu2.28", UpstreamVersion(8, 1, 2)),
        ("8.3.6-0ubuntu0.24.04.13", UpstreamVersion(8, 3, 6)),
        ("7.4.33-nmm1", UpstreamVersion(7, 4, 33)),
        ("8.2.35+deb12u1", UpstreamVersion(8, 2, 35)),
        ("  8.4.27\n", UpstreamVersion(8, 4, 27)),
    ],
)
def test_parse_upstream(text, expected):
    assert parse_upstream(text) == expected


@pytest.mark.parametrize("text", ["", "8", "php 8.3.6", "8.x.1", "v8.3.6", "8.3.6 (cli)"])
def test_parse_upstream_rejects_garbage(text):
    with pytest.raises(VersionError):
        parse_upstream(text)


def test_upstream_str_roundtrip():
    assert str(parse_upstream("8.5.0RC1")) == "8.5.0RC1"
    assert str(parse_upstream("8.3.6-0ubuntu1")) == "8.3.6"


def test_branch_of():
    assert branch_of("8.3.6-0ubuntu0.24.04.13") == "8.3"
    assert branch_of("8.10.1") == "8.10"


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("8.5.11", "8.5.12", -1),
        ("8.5.12", "8.5.12", 0),
        ("8.5.13", "8.5.12", 1),
        ("8.3.9", "8.3.36", -1),  # numeric, not lexical
        ("8.10.0", "8.9.0", 1),
        ("8.5.0RC1", "8.5.0", -1),
        ("8.5.0alpha3", "8.5.0beta1", -1),
        ("8.5.0beta3", "8.5.0RC1", -1),
        ("8.5.0RC2", "8.5.0RC10", -1),
        ("8.5.0", "8.5.0-1ubuntu1", 0),  # suffix ignored
    ],
)
def test_compare_upstream(a, b, expected):
    assert compare_upstream(a, b) == expected
    assert compare_upstream(b, a) == -expected


# --- dpkg -------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        ("1.0", DebVersion(0, "1.0", "")),
        ("1.0-1", DebVersion(0, "1.0", "1")),
        ("2:1.0-1", DebVersion(2, "1.0", "1")),
        ("1.0-beta-1", DebVersion(0, "1.0-beta", "1")),
        ("1:2.0:3-4", DebVersion(1, "2.0:3", "4")),
        ("8.3.6-0ubuntu0.24.04.13", DebVersion(0, "8.3.6", "0ubuntu0.24.04.13")),
        ("8.2.35-1~deb12u1", DebVersion(0, "8.2.35", "1~deb12u1")),
    ],
)
def test_parse_dpkg(text, expected):
    assert parse_dpkg(text) == expected


@pytest.mark.parametrize("text", ["", " ", "a:1.0", "-1", "1.0 1", ":1.0"])
def test_parse_dpkg_rejects(text):
    with pytest.raises(VersionError):
        parse_dpkg(text)


# (a, b, expected). Generic cases follow dpkg's own t-version.c and
# deb-version(7); the php ones are real versions from the advisories.
DPKG_CASES = [
    ("1.0", "1.0", 0),
    ("1.0", "1.0-0", 0),  # empty revision equals "0"
    ("0:1.0", "1.0", 0),  # missing epoch is 0
    ("1.001", "1.1", 0),  # leading zeros are insignificant
    ("1.0", "1.1", -1),
    ("1.9", "1.10", -1),
    ("1:0.1", "0:10.0", 1),  # epoch wins
    ("2:1.0", "10:0.1", -1),
    ("1.0-1", "1.0-2", -1),
    ("1.0-9", "1.0-10", -1),
    # tilde sorts before everything, even the end of the string
    ("1.0~~", "1.0~~a", -1),
    ("1.0~~a", "1.0~", -1),
    ("1.0~", "1.0", -1),
    ("1.0", "1.0a", -1),
    ("1.0~rc1", "1.0", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    # letters sort before non-letters
    ("1.0a", "1.0+", -1),
    ("1.0a", "1.0.", -1),
    ("1.0+", "1.0.", -1),  # '+' (43) < '.' (46)
    ("1.0", "1.0+b1", -1),
    ("1.0-1", "1.0-1+deb12u1", -1),
    ("1.0-1", "1.0-1.1", -1),
    # real php packages
    ("8.2.32-1~deb12u1", "8.2.35-1~deb12u1", -1),
    ("8.2.35-1~deb12u1", "8.2.35-1~deb12u1", 0),
    ("8.2.35-1~deb12u1", "8.2.35-1", -1),  # backport sorts below sid
    ("8.4.24-1~deb13u1", "8.4.27-1~deb13u1", -1),
    ("8.4.27-1~deb13u1", "8.4.27-1", -1),
    ("8.3.6-0ubuntu0.24.04.9", "8.3.6-0ubuntu0.24.04.13", -1),  # numeric
    ("8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13", -1),
    ("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.13", 0),
    ("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.13.1", -1),
    ("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.13+esm1", -1),
    ("8.1.2-1ubuntu2.27", "8.1.2-1ubuntu2.28", -1),
    ("8.5.4-0ubuntu1.5", "8.5.4-0ubuntu1.4", 1),
    ("8.5.9-0ubuntu2.1", "8.5.9-0ubuntu2", 1),
    ("8.3.36-1+ubuntu24.04.1+deb.sury.org+1", "8.3.6-0ubuntu0.24.04.13", 1),
    ("1:8.3+93ubuntu2", "8.3.36-1", 1),  # metapackage with an epoch
]


@pytest.mark.parametrize("a, b, expected", DPKG_CASES)
def test_compare_dpkg(a, b, expected):
    assert compare_dpkg(a, b) == expected
    assert compare_dpkg(b, a) == -expected


def test_dpkg_tilde_chain_is_totally_ordered():
    chain = ["1.0~~", "1.0~~a", "1.0~", "1.0", "1.0a", "1.0+", "1.0.1"]
    for lower, higher in itertools.combinations(chain, 2):
        assert compare_dpkg(lower, higher) == -1, (lower, higher)


# --- rpm --------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        ("1.0", RpmVersion(0, "1.0", "")),
        ("1.0-1.el9", RpmVersion(0, "1.0", "1.el9")),
        ("1:8.2.13-1.el9_4", RpmVersion(1, "8.2.13", "1.el9_4")),
        (
            "8.2.13-1.module+el8.10.0+1234+abcd",
            RpmVersion(0, "8.2.13", "1.module+el8.10.0+1234+abcd"),
        ),
    ],
)
def test_parse_rpm(text, expected):
    assert parse_rpm(text) == expected


@pytest.mark.parametrize("text", ["", "x:1.0", "-1", "1.0 -1"])
def test_parse_rpm_rejects(text):
    with pytest.raises(VersionError):
        parse_rpm(text)


# (a, b, expected) for the bare segment comparison. Taken from rpm's
# tests/rpmvercmp.at.
RPMVERCMP_CASES = [
    ("1.0", "1.0", 0),
    ("1.0", "2.0", -1),
    ("2.0.1", "2.0.1", 0),
    ("2.0", "2.0.1", -1),
    ("2.0.1a", "2.0.1a", 0),
    ("2.0.1a", "2.0.1", 1),
    ("5.5p1", "5.5p1", 0),
    ("5.5p1", "5.5p2", -1),
    ("5.5p10", "5.5p10", 0),
    ("5.5p1", "5.5p10", -1),
    ("10xyz", "10.1xyz", -1),
    ("xyz10", "xyz10.1", -1),
    ("xyz.4", "xyz.4", 0),
    ("xyz.4", "8", -1),  # letters sort below digits
    ("xyz.4", "2", -1),
    ("5.5p2", "5.6p1", -1),
    ("5.6p1", "6.5p1", -1),
    ("6.0.rc1", "6.0", 1),  # no tilde: rc1 is an extra segment
    ("10b2", "10a1", 1),
    ("1.0aa", "1.0a", 1),
    ("10.0001", "10.1", 0),
    ("10.0001", "10.0039", -1),
    ("4.999.9", "5.0", -1),
    ("20101121", "20101122", -1),
    ("2_0", "2.0", 0),  # separators are equivalent
    ("2.0", "2_0", 0),
    ("a", "a", 0),
    ("a+", "a_", 0),
    ("+a", "_a", 0),
    ("+", "_", 0),
    ("+_", "_+", 0),
    ("1b.fc17", "1.fc17", -1),
    ("1b.fc17", "1b.fc17", 0),
    # tilde: pre-release
    ("1.0~rc1", "1.0~rc1", 0),
    ("1.0~rc1", "1.0", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~rc1~git123", "1.0~rc1", -1),
    ("~", "~~", 1),
    ("~1", "~~1", 1),
    # caret: post-release snapshot
    ("1.0^", "1.0^", 0),
    ("1.0^", "1.0", 1),
    ("1.0^git1", "1.0", 1),
    ("1.0^git1", "1.0^git2", -1),
    ("1.0^git1", "1.01", -1),
    ("1.0^20160101", "1.0.1", -1),
    ("1.0^20160101^git1", "1.0^20160101", 1),
    ("1.0~rc1^git1", "1.0~rc1", 1),
    ("1.0^git1~pre", "1.0^git1", -1),
]


@pytest.mark.parametrize("a, b, expected", RPMVERCMP_CASES)
def test_rpmvercmp(a, b, expected):
    assert rpmvercmp(a, b) == expected


RPM_EVR_CASES = [
    ("8.2.13-1.el9", "8.2.13-1.el9", 0),
    ("8.2.13-1.el9", "8.2.13-2.el9", -1),
    ("8.2.13-1.el9_4", "8.2.13-1.el9_4.1", -1),
    ("8.2.13-1.el9_4", "8.2.13-1.el9_3", 1),
    ("8.0.30-1.el9_2", "8.2.13-1.el9", -1),
    ("1:7.4.0-1.el8", "8.5.12-1.el8", 1),  # epoch wins
    ("0:8.4.27-1.el9", "8.4.27-1.el9", 0),
    ("8.4.27-1.el9.remi", "8.4.26-1.el9.remi", 1),
    ("8.4.27-1.el9.remi", "8.4.27-1.el9", 1),
    ("8.2.13-1.module+el8.10.0+1234+abcd", "8.2.13-1.module+el8.9.0+999+ffff", 1),
    ("8.5.0~RC1-1.fc43", "8.5.0-1.fc43", -1),
]


@pytest.mark.parametrize("a, b, expected", RPM_EVR_CASES)
def test_compare_rpm(a, b, expected):
    assert compare_rpm(a, b) == expected
    assert compare_rpm(b, a) == -expected


# --- properties over every case we know -------------------------------------


def _all_versions(cases):
    return sorted({v for a, b, _ in cases for v in (a, b)})


@pytest.mark.parametrize(
    "compare, versions",
    [
        (compare_dpkg, _all_versions(DPKG_CASES)),
        (compare_rpm, _all_versions(RPM_EVR_CASES)),
        (rpmvercmp, _all_versions(RPMVERCMP_CASES)),
    ],
    ids=["dpkg", "rpm-evr", "rpmvercmp"],
)
def test_antisymmetric_and_transitive(compare, versions):
    for a, b in itertools.product(versions, repeat=2):
        assert compare(a, b) == -compare(b, a), (a, b)
    for a, b, c in itertools.product(versions, repeat=3):
        if compare(a, b) <= 0 and compare(b, c) <= 0:
            assert compare(a, c) <= 0, (a, b, c)


# --- dispatch ---------------------------------------------------------------


def test_compare_package_dispatch():
    # "1.0a" vs "1.0.1": dpkg compares 'a' < '.', rpm compares "a" < "1"
    assert compare_package("1.0a", "1.0.1", "dpkg") == -1
    assert compare_package("1.0a", "1.0.1", "rpm") == -1
    # schemes really differ: rpm ignores separators, dpkg does not
    assert compare_package("2_0", "2.0", "rpm") == 0
    assert compare_package("2_0", "2.0", "dpkg") != 0


def test_compare_package_unknown_scheme():
    with pytest.raises(VersionError):
        compare_package("1", "1", "pacman")


def test_is_at_least():
    assert is_at_least("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.13", "dpkg")
    assert is_at_least("8.3.6-0ubuntu0.24.04.14", "8.3.6-0ubuntu0.24.04.13", "dpkg")
    assert not is_at_least("8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13", "dpkg")
    assert not is_at_least("8.2.13-1.el9", "8.2.13-1.el9_4", "rpm")


# --- oracle: check against the real tools when they exist -------------------
# Skipped on hosts without dpkg/rpm; the docker lab runs them.


def _dpkg_says(a: str, b: str) -> int:
    for op, result in (("lt", -1), ("eq", 0), ("gt", 1)):
        proc = subprocess.run(["dpkg", "--compare-versions", a, op, b], check=False)
        if proc.returncode == 0:
            return result
    raise AssertionError(f"dpkg gave no answer for {a} vs {b}")


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg not installed")
@pytest.mark.parametrize("a, b, _expected", DPKG_CASES)
def test_dpkg_matches_real_dpkg(a, b, _expected):
    assert compare_dpkg(a, b) == _dpkg_says(a, b)


def _rpm_says(a: str, b: str) -> int:
    proc = subprocess.run(
        ["rpm", "--eval", f"%{{lua: print(rpm.vercmp('{a}', '{b}'))}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return int(proc.stdout.strip())


@pytest.mark.skipif(shutil.which("rpm") is None, reason="rpm not installed")
@pytest.mark.parametrize("a, b, _expected", RPM_EVR_CASES)
def test_rpm_matches_real_rpm(a, b, _expected):
    assert compare_rpm(a, b) == _rpm_says(a, b)


@pytest.mark.skipif(shutil.which("rpm") is None, reason="rpm not installed")
@pytest.mark.parametrize("a, b, _expected", RPMVERCMP_CASES)
def test_rpmvercmp_matches_real_rpm(a, b, _expected):
    # No ':' or '-' in these, so rpm.vercmp compares them as bare versions.
    assert rpmvercmp(a, b) == _rpm_says(a, b)
