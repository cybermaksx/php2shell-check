import copy
import json

import pytest

from php2shell_check import advisories
from php2shell_check.advisories import (
    AdvisoryError,
    find_distro_fix,
    find_upstream_fix,
    load,
    loads,
    mitigations_for,
    version_id_matches,
)
from php2shell_check.models import Distro


@pytest.fixture(scope="module")
def raw():
    return json.loads(advisories.DEFAULT_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def db():
    return load()


def errors_for(raw_data) -> list[str]:
    with pytest.raises(AdvisoryError) as info:
        loads(json.dumps(raw_data))
    return info.value.errors


def by_id(db, cve):
    return next(a for a in db.advisories if a.id == cve)


# --- the shipped file -------------------------------------------------------


def test_shipped_file_loads(db):
    assert {a.id for a in db.advisories} == {
        "CVE-2026-109618",
        "CVE-2026-109619",
        "CVE-2026-115560",
    }


def test_shipped_fixed_releases(db):
    expected = {"8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35"}
    for cve in ("CVE-2026-109618", "CVE-2026-109619"):
        adv = by_id(db, cve)
        assert {f.branch: f.version for f in adv.upstream_fixed} == expected


def test_shipped_placeholder_has_no_version_data(db):
    placeholder = by_id(db, "CVE-2026-115560")
    assert placeholder.status == "unconfirmed"
    assert not placeholder.has_version_data
    assert "TODO" in placeholder.note
    assert placeholder.mitigations == ("session-upload-progress-off",)


def test_shipped_unconfirmed_facts_are_marked(db):
    for adv in db.advisories[:2]:
        assert adv.affected_since.status == "unconfirmed"
        # only secondary sources back the 5.4 lower bound
        assert all(db.sources[s].tier == "secondary" for s in adv.affected_since.sources)


def test_shipped_eol_branches(db):
    assert [b for b, info in db.branches.items() if not info.eol] == ["8.5", "8.4", "8.3", "8.2"]
    assert db.branches["8.1"].source_backport == "PHP-8.1-CVE-2026-109618-109619"


# --- validation -------------------------------------------------------------


def test_rejects_wrong_schema_version(raw):
    data = copy.deepcopy(raw)
    data["schema_version"] = 2
    assert any("schema_version" in e for e in errors_for(data))


def test_rejects_unknown_source_reference(raw):
    data = copy.deepcopy(raw)
    data["advisories"][0]["sources"].append("nope")
    assert any("unknown source 'nope'" in e for e in errors_for(data))


def test_rejects_unknown_key_typo(raw):
    data = copy.deepcopy(raw)
    data["advisories"][0]["distros"][0]["fixd"] = "1.0"
    errors = errors_for(data)
    assert any("unknown key 'fixd'" in e for e in errors)


def test_rejects_fixed_version_on_wrong_branch(raw):
    data = copy.deepcopy(raw)
    data["advisories"][0]["upstream"]["fixed"][0]["version"] = "8.4.99"
    assert any("not on branch 8.5" in e for e in errors_for(data))


def test_rejects_bad_dpkg_version(raw):
    data = copy.deepcopy(raw)
    data["advisories"][0]["distros"][0]["fixed"] = "x:1.0"
    assert any("invalid dpkg epoch" in e for e in errors_for(data))


def test_rejects_fixed_and_not_affected_together(raw):
    data = copy.deepcopy(raw)
    data["advisories"][0]["distros"][0]["not_affected"] = True
    assert any("exactly one of" in e for e in errors_for(data))


def test_rejects_row_with_neither_fixed_nor_not_affected(raw):
    data = copy.deepcopy(raw)
    del data["advisories"][0]["distros"][0]["fixed"]
    assert any("exactly one of" in e for e in errors_for(data))


def test_rejects_unknown_mitigation_reference(raw):
    data = copy.deepcopy(raw)
    data["advisories"][0]["mitigations"].append("pray")
    assert any("unknown mitigation 'pray'" in e for e in errors_for(data))


def test_rejects_bad_expect_value(raw):
    data = copy.deepcopy(raw)
    data["mitigations"]["post-max-size-low"]["expect"]["value"] = "lots"
    assert any("not a size" in e for e in errors_for(data))


def test_rejects_ordering_operator_on_bool(raw):
    data = copy.deepcopy(raw)
    data["mitigations"]["session-upload-progress-off"]["expect"]["op"] = "lte"
    assert any("makes no sense for a bool" in e for e in errors_for(data))


def test_rejects_unconfirmed_without_todo(raw):
    data = copy.deepcopy(raw)
    data["advisories"][0]["upstream"]["affected_since"]["note"] = "trust me"
    assert any("TODO" in e for e in errors_for(data))


def test_rejects_duplicate_distro_rows(raw):
    data = copy.deepcopy(raw)
    rows = data["advisories"][0]["distros"]
    rows.append(copy.deepcopy(rows[0]))
    assert any("duplicate row" in e for e in errors_for(data))


def test_rejects_http_source(raw):
    data = copy.deepcopy(raw)
    data["sources"]["wiz"]["url"] = "http://www.wiz.io/blog/php2shell-php-rce"
    assert any("https://" in e for e in errors_for(data))


def test_collects_all_errors_at_once(raw):
    data = copy.deepcopy(raw)
    data["schema_version"] = 99
    data["advisories"][0]["sources"].append("nope")
    data["mitigations"]["post-max-size-low"]["coverage"] = "total"
    assert len(errors_for(data)) >= 3


def test_rejects_invalid_json():
    with pytest.raises(AdvisoryError, match="not valid JSON"):
        loads("{nope")


def test_missing_file_is_an_advisory_error(tmp_path):
    with pytest.raises(AdvisoryError, match="cannot read"):
        load(tmp_path / "missing.json")


# --- filling in the placeholder needs no code ------------------------------


def test_placeholder_can_be_filled_in_with_data_only(raw):
    data = copy.deepcopy(raw)
    placeholder = next(a for a in data["advisories"] if a["id"] == "CVE-2026-115560")
    placeholder["status"] = "confirmed"
    placeholder["upstream"] = {
        "fixed": [{"branch": "8.5", "version": "8.5.13", "sources": ["php-net"]}]
    }
    placeholder["distros"] = [
        {
            "os_id": "ubuntu",
            "version_id": "24.04",
            "scheme": "dpkg",
            "source_package": "php8.3",
            "fixed": "8.3.6-0ubuntu0.24.04.14",
            "sources": ["usn-8948-1"],
        }
    ]
    db = loads(json.dumps(data))
    adv = by_id(db, "CVE-2026-115560")
    assert adv.has_version_data
    assert find_upstream_fix(adv, "8.5").version == "8.5.13"


# --- queries ----------------------------------------------------------------


@pytest.mark.parametrize(
    "row, host, expected",
    [
        ("24.04", "24.04", True),
        ("7", "7.9", True),
        ("9", "9.4", True),
        ("9.4", "9.4", True),
        ("9.4", "9.6", False),
        ("9", "10.0", False),
        ("1", "10", False),  # no accidental prefix match
        ("12", "", False),
    ],
)
def test_version_id_matches(row, host, expected):
    assert version_id_matches(row, host) is expected


def test_find_distro_fix_ubuntu(db):
    adv = by_id(db, "CVE-2026-109619")
    row = find_distro_fix(adv, Distro("ubuntu", "24.04"), "php8.3")
    assert row.fixed == "8.3.6-0ubuntu0.24.04.13"
    assert find_distro_fix(adv, Distro("ubuntu", "24.04"), "php8.4") is None


def test_find_distro_fix_rhel7_minor_release(db):
    row = find_distro_fix(by_id(db, "CVE-2026-109618"), Distro("rhel", "7.9"), "php")
    assert row.not_affected
    assert find_distro_fix(by_id(db, "CVE-2026-109619"), Distro("rhel", "7.9"), "php") is None


def test_find_distro_fix_ignores_id_like(db):
    rocky = Distro("rocky", "7.9", id_like=("rhel", "centos", "fedora"))
    assert find_distro_fix(by_id(db, "CVE-2026-109618"), rocky, "php") is None


def test_find_distro_fix_prefers_most_specific(raw):
    data = copy.deepcopy(raw)
    rows = data["advisories"][1]["distros"]
    base = {"os_id": "rhel", "scheme": "rpm", "source_package": "php", "sources": ["rhsb-2026-013"]}
    rows.append({**base, "version_id": "9", "fixed": "8.0.30-3.el9_6"})
    rows.append({**base, "version_id": "9.2", "fixed": "8.0.30-1.el9_2.1"})
    adv = by_id(loads(json.dumps(data)), "CVE-2026-109619")
    assert find_distro_fix(adv, Distro("rhel", "9.2"), "php").fixed == "8.0.30-1.el9_2.1"
    assert find_distro_fix(adv, Distro("rhel", "9.6"), "php").fixed == "8.0.30-3.el9_6"


def test_mitigations_for_filters_by_branch(db):
    adv = by_id(db, "CVE-2026-109619")
    on_85 = [m.id for m in mitigations_for(db, adv, "8.5")]
    on_83 = [m.id for m in mitigations_for(db, adv, "8.3")]
    assert on_85 == ["session-upload-progress-off", "fatal-error-backtraces-off"]
    assert on_83 == ["session-upload-progress-off"]
