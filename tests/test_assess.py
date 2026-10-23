import copy
import json

import pytest

from php2shell_check import advisories
from php2shell_check.advisories import load, loads
from php2shell_check.assess import (
    EXIT_EOL,
    EXIT_EXPOSED,
    EXIT_OK,
    EXIT_UNKNOWN,
    assess,
    exit_code,
    finding_exit_code,
    judge_advisory,
    mitigation_status,
)
from php2shell_check.config import ConfigReport, ContextValue, SettingResult
from php2shell_check.models import (
    Distro,
    Finding,
    InstallStatus,
    MitigationStatus,
    Package,
    PhpInstall,
    SettingCheck,
)

UBUNTU_2404 = Distro("ubuntu", "24.04", ("debian",))
UBUNTU_2204 = Distro("ubuntu", "22.04", ("debian",))
DEBIAN_12 = Distro("debian", "12")
RHEL_7 = Distro("rhel", "7.9", ("fedora",))
ROCKY_9 = Distro("rocky", "9.3", ("rhel", "centos", "fedora"))


@pytest.fixture(scope="module")
def db():
    return load()


def install(version, sapi="fpm-fcgi", package=None, distro=None):
    return PhpInstall(binary="/usr/sbin/php-fpm", sapi=sapi, version=version, package=package, distro=distro)


def deb(source, version, name=None):
    return Package(name or f"{source}-fpm", version, source, "dpkg")


def rpm(source, version):
    return Package(f"{source}-fpm", version, source, "rpm")


def verdicts(finding):
    return {v.advisory_id: (v.status, v.basis) for v in finding.verdicts}


# --- version verdicts -------------------------------------------------------


def test_ubuntu_backport_is_patched_despite_old_upstream(db):
    # php -v says 8.3.6, far below 8.3.36: a version-only check would be wrong.
    f = assess(install("8.3.6", package=deb("php8.3", "8.3.6-0ubuntu0.24.04.13"), distro=UBUNTU_2404), db, None)
    assert f.status is InstallStatus.PATCHED
    assert verdicts(f)["CVE-2026-109618"] == (InstallStatus.PATCHED, "distro")


def test_ubuntu_package_below_fix_is_vulnerable(db):
    f = assess(install("8.3.6", package=deb("php8.3", "8.3.6-0ubuntu0.24.04.12"), distro=UBUNTU_2404), db, None)
    assert f.status is InstallStatus.VULNERABLE
    assert "8.3.6-0ubuntu0.24.04.12 < 8.3.6-0ubuntu0.24.04.13 (USN-8948-1)" in f.verdicts[0].reason


def test_ubuntu_2204_patched_eol_branch(db):
    # 8.1 is EOL upstream, but Ubuntu backported the fix: PATCHED, not EOL.
    f = assess(install("8.1.2-1ubuntu2.28", package=deb("php8.1", "8.1.2-1ubuntu2.28"), distro=UBUNTU_2204), db, None)
    assert f.status is InstallStatus.PATCHED


def test_ubuntu_2204_unpatched_eol_branch_is_vulnerable(db):
    f = assess(install("8.1.2-1ubuntu2.27", package=deb("php8.1", "8.1.2-1ubuntu2.27"), distro=UBUNTU_2204), db, None)
    assert f.status is InstallStatus.VULNERABLE


def test_debian_binnmu_counts_as_patched(db):
    f = assess(install("8.2.35", package=deb("php8.2", "8.2.35-1~deb12u1+b1"), distro=DEBIAN_12), db, None)
    assert f.status is InstallStatus.PATCHED


def test_upstream_fixed_release_is_patched_anywhere(db):
    f = assess(install("8.4.27", distro=Distro("arch", "")), db, None)
    assert f.status is InstallStatus.PATCHED
    assert verdicts(f)["CVE-2026-109619"] == (InstallStatus.PATCHED, "upstream")


def test_source_build_below_fix_is_unknown_not_vulnerable(db):
    f = assess(install("8.3.20", distro=UBUNTU_2404), db, None)
    assert f.status is InstallStatus.UNKNOWN
    assert "not owned by a package" in f.verdicts[0].reason


def test_rocky_does_not_inherit_rhel_rows(db):
    f = assess(install("8.0.30", package=rpm("php", "8.0.30-8.el9_8.1"), distro=ROCKY_9), db, None)
    # 8.0 is EOL upstream and Rocky has no row: EOL, not PATCHED via RHEL.
    assert f.status is InstallStatus.EOL


def test_remi_package_below_fix_is_unknown(db):
    f = assess(install("8.3.30", package=rpm("php", "8.3.30-1.el9.remi"), distro=Distro("almalinux", "9.4")), db, None)
    assert f.status is InstallStatus.UNKNOWN
    assert "may carry a backport" in f.verdicts[0].reason


def test_remi_package_at_fixed_release_is_patched(db):
    f = assess(install("8.4.27", package=rpm("php", "8.4.27-1.el9.remi"), distro=Distro("almalinux", "9.4")), db, None)
    assert f.status is InstallStatus.PATCHED


def test_rhel7_not_affected_by_109618_but_eol_for_109619(db):
    f = assess(install("5.4.16", package=rpm("php", "5.4.16-48.el7"), distro=RHEL_7), db, None)
    v = verdicts(f)
    assert v["CVE-2026-109618"] == (None, "distro")
    assert v["CVE-2026-109619"] == (InstallStatus.EOL, "eol")
    assert f.status is InstallStatus.EOL
    assert f.advisories == ["CVE-2026-109619"]


def test_eol_mentions_source_backport(db):
    f = assess(install("7.4.33"), db, None)
    assert f.status is InstallStatus.EOL
    assert "PHP-7.4-CVE-2026-109618-109619" in f.verdicts[0].reason


def test_unknown_version(db):
    f = assess(install(""), db, None)
    assert f.status is InstallStatus.UNKNOWN


def test_branch_missing_from_data(db):
    f = assess(install("9.0.1"), db, None)
    assert f.status is InstallStatus.UNKNOWN
    assert "no fix data for PHP branch 9.0" in f.verdicts[0].reason


def test_placeholder_never_affects_status(db):
    f = assess(install("8.4.27"), db, None)
    placeholder = next(v for v in f.verdicts if v.advisory_id == "CVE-2026-115560")
    assert placeholder.status is None
    assert f.status is InstallStatus.PATCHED


def test_scheme_mismatch_is_unknown(db):
    # An rpm-managed php on Ubuntu matches the row by name but not by scheme.
    f = assess(install("8.3.6", package=rpm("php8.3", "8.3.6-1"), distro=UBUNTU_2404), db, None)
    assert verdicts(f)["CVE-2026-109618"] == (InstallStatus.UNKNOWN, "distro")


def test_filled_placeholder_changes_verdict_without_code(db):
    raw = json.loads(advisories.DEFAULT_PATH.read_text())
    entry = next(a for a in raw["advisories"] if a["id"] == "CVE-2026-115560")
    entry["upstream"] = {"fixed": [{"branch": "8.4", "version": "8.4.28", "sources": ["php-net"]}]}
    filled = loads(json.dumps(raw))
    f = assess(install("8.4.27"), filled, None)
    assert verdicts(f)["CVE-2026-115560"] == (InstallStatus.UNKNOWN, "upstream")
    assert f.status is InstallStatus.UNKNOWN


# --- mitigations ------------------------------------------------------------


def config_with(**satisfied):
    """ConfigReport where each check id maps to satisfied True/False/None."""
    report = ConfigReport()
    settings = load().mitigations
    for check_id, state in satisfied.items():
        setting = settings[check_id].setting
        report.results[check_id] = SettingResult(
            check_id, setting, [ContextValue("pool www", "x", "php.ini:1", False, state)]
        )
    return report


ALL = ("session-upload-progress-off", "fatal-error-backtraces-off", "memory-limit-unlimited", "post-max-size-low")


def all_checks(state):
    return config_with(**{k.replace("_", "-"): state for k in ALL})


def test_patched_skips_mitigation(db):
    f = assess(install("8.4.27"), db, all_checks(False))
    assert f.mitigation is None
    assert f.mitigations == []


def test_mitigations_filtered_by_branch(db):
    f = assess(install("8.3.20"), db, all_checks(True))
    ids = [m.id for m in f.mitigations]
    assert "fatal-error-backtraces-off" not in ids  # 8.5 only
    assert ids == ["memory-limit-unlimited", "post-max-size-low", "session-upload-progress-off"]
    assert f.mitigation is MitigationStatus.MITIGATED


def test_branch_85_includes_fatal_error_backtraces(db):
    f = assess(install("8.5.11"), db, all_checks(True))
    assert "fatal-error-backtraces-off" in [m.id for m in f.mitigations]


def test_rhel7_skips_109618_mitigations(db):
    f = assess(install("5.4.16", package=rpm("php", "5.4.16-48.el7"), distro=RHEL_7), db, all_checks(True))
    assert [m.id for m in f.mitigations] == ["session-upload-progress-off"]


def test_partial_and_exposed(db):
    partial = assess(
        install("8.3.20"),
        db,
        config_with(**{"session-upload-progress-off": True, "memory-limit-unlimited": False, "post-max-size-low": None}),
    )
    assert partial.mitigation is MitigationStatus.PARTIAL
    exposed = assess(install("8.3.20"), db, all_checks(False))
    assert exposed.mitigation is MitigationStatus.EXPOSED
    assert exposed.mitigations[0].failing[0].origin == "php.ini:1"


def test_cli_gets_no_mitigation_verdict(db):
    f = assess(install("8.3.20", sapi="cli"), db, all_checks(False))
    assert f.mitigation is None
    assert any("does not serve web requests" in r for r in f.reasons)


def test_sapi_exposure_reason(db):
    f = assess(install("8.3.20", sapi="apache2handler"), db, None)
    assert any("CVE-2026-109618: apache2handler is confirmed" in r for r in f.reasons)


def test_patched_host_still_hears_about_unfixed_advisory(db):
    f = assess(install("8.4.27"), db, all_checks(False))
    assert f.status is InstallStatus.PATCHED
    assert f.mitigation is None
    assert any(
        r.startswith("CVE-2026-115560 has no fix yet") and "session.upload_progress.enabled" in r for r in f.reasons
    )
    assert finding_exit_code(f) == EXIT_OK  # informational only


def test_no_pending_advice_when_mitigated(db):
    f = assess(install("8.4.27"), db, all_checks(True))
    assert not any("no fix yet" in r for r in f.reasons)


def test_no_pending_advice_for_cli(db):
    f = assess(install("8.4.27", sapi="cli"), db, all_checks(False))
    assert not any("no fix yet" in r for r in f.reasons)


def test_mitigation_status_empty_is_exposed():
    assert mitigation_status([]) is MitigationStatus.EXPOSED
    assert mitigation_status([SettingCheck("a", "a", True)]) is MitigationStatus.MITIGATED


# --- exit codes -------------------------------------------------------------


def F(status, mitigation=None):
    return Finding(install=install("8.3.6"), status=status, mitigation=mitigation)


@pytest.mark.parametrize(
    "finding, code",
    [
        (F(InstallStatus.PATCHED), EXIT_OK),
        (F(InstallStatus.VULNERABLE, MitigationStatus.MITIGATED), EXIT_EXPOSED),
        (F(InstallStatus.UNKNOWN, MitigationStatus.EXPOSED), EXIT_EXPOSED),
        (F(InstallStatus.EOL, MitigationStatus.EXPOSED), EXIT_EXPOSED),
        (F(InstallStatus.EOL, MitigationStatus.PARTIAL), EXIT_EOL),
        (F(InstallStatus.EOL, None), EXIT_EOL),
        (F(InstallStatus.EOL, MitigationStatus.MITIGATED), EXIT_OK),
        (F(InstallStatus.UNKNOWN, MitigationStatus.PARTIAL), EXIT_UNKNOWN),
        (F(InstallStatus.UNKNOWN, MitigationStatus.MITIGATED), EXIT_OK),
    ],
)
def test_finding_exit_code(finding, code):
    assert finding_exit_code(finding) == code


def test_cli_findings_do_not_set_the_exit_code():
    cli = Finding(install=install("7.4.33", sapi="cli"), status=InstallStatus.EOL)
    fpm = Finding(install=install("7.4.33"), status=InstallStatus.EOL, mitigation=MitigationStatus.MITIGATED)
    assert exit_code([cli, fpm]) == EXIT_OK


def test_exit_code_priority():
    assert exit_code([]) == EXIT_OK
    assert exit_code([F(InstallStatus.UNKNOWN), F(InstallStatus.EOL)]) == EXIT_EOL
    assert exit_code([F(InstallStatus.UNKNOWN), F(InstallStatus.VULNERABLE)]) == EXIT_EXPOSED
    assert exit_code([F(InstallStatus.PATCHED), F(InstallStatus.UNKNOWN)]) == EXIT_UNKNOWN
