import json
import os
import shutil
from pathlib import Path

import pytest

from php2shell_check import cli, remediate
from php2shell_check.advisories import load
from php2shell_check.assess import assess
from php2shell_check.config import check_install, load_web_config
from php2shell_check.discovery import DiscoveryResult, HostFileSystem
from php2shell_check.distro import CommandResult
from php2shell_check.models import Distro, Package, PhpInstall
from php2shell_check.remediate import (
    DROPIN_NAME,
    Plan,
    Target,
    apply_plan,
    build_plan,
    recheck_targets,
    render_plan,
    service_units,
)

CONFIG = Path(__file__).parent / "fixtures" / "config"
TODAY = "2026-10-23"


@pytest.fixture(scope="module")
def db():
    return load()


@pytest.fixture
def fpm_root(tmp_path):
    root = tmp_path / "root"
    shutil.copytree(CONFIG / "debian-fpm", root)
    return root


@pytest.fixture
def modphp_root(tmp_path):
    root = tmp_path / "root"
    shutil.copytree(CONFIG / "apache-modphp", root)
    (root / "etc/php/8.3/apache2/conf.d").mkdir(exist_ok=True)  # git does not keep empty dirs
    return root


def fpm_install():
    return PhpInstall(
        binary="/usr/sbin/php-fpm8.3",
        sapi="fpm-fcgi",
        version="8.3.20",
        ini_files=["/etc/php/8.3/fpm/php.ini", "/etc/php/8.3/fpm/conf.d/10-opcache.ini", "/etc/php/8.3/fpm/conf.d/99-php2shell.ini"],
        ini_scan_dir="/etc/php/8.3/fpm/conf.d",
        fpm_config="/etc/php/8.3/fpm/php-fpm.conf",
        package=Package("php8.3-fpm", "8.3.20-1+deb.sury.org+1", "php8.3", "dpkg"),
        distro=Distro("ubuntu", "24.10"),
    )


def modphp_install():
    return PhpInstall(
        binary="/usr/lib/apache2/modules/libphp8.3.so",
        sapi="apache2handler",
        version="8.3.20",
        ini_files=["/etc/php/8.3/apache2/php.ini"],
        ini_scan_dir="/etc/php/8.3/apache2/conf.d",
        enabled=True,
    )


def findings_for(root, installs, db):
    fs = HostFileSystem(str(root))
    web = load_web_config(fs)
    checks = [*db.mitigations.values(), *db.hardening]
    return [assess(i, db, check_install(i, checks, fs, web)) for i in installs], fs


# --- planning ---------------------------------------------------------------


def test_fpm_plan_edits_only_the_failing_pool(fpm_root, db):
    findings, fs = findings_for(fpm_root, [fpm_install()], db)
    plan = build_plan(findings, db, fs, TODAY)

    assert set(plan.changes) == {"/etc/php/8.3/fpm/pool.d/legacy.conf"}
    after = plan.changes["/etc/php/8.3/fpm/pool.d/legacy.conf"].after
    assert "php_admin_flag[session.upload_progress.enabled] = off" in after
    assert "php_admin_value[memory_limit] = -1" in after
    assert after.count("; php2shell-check 2026-10-23") == 2
    # the existing pool lines stay; the admin lines win because FPM applies them last
    assert "php_value[session.upload_progress.enabled] = 1" in after


def test_fpm_plan_lists_what_it_cannot_fix(fpm_root, db):
    findings, fs = findings_for(fpm_root, [fpm_install()], db)
    plan = build_plan(findings, db, fs, TODAY)
    manual = "\n".join(plan.manual)
    assert "/etc/nginx/sites-enabled/a.conf:8: the web server sends this setting" in manual
    assert "set inside a php.ini [PATH=/var/www/b] section" in manual


def test_fpm_plan_targets_are_only_auto_fixed_contexts(fpm_root, db):
    findings, fs = findings_for(fpm_root, [fpm_install()], db)
    plan = build_plan(findings, db, fs, TODAY)
    contexts = {t.context for t in plan.targets}
    assert contexts == {"pool legacy"}


def test_plan_replaces_existing_admin_line(fpm_root, db):
    www = fpm_root / "etc/php/8.3/fpm/pool.d/www.conf"
    www.write_text(www.read_text().replace("php_admin_value[memory_limit] = -1", "php_admin_value[memory_limit] = 512M"))
    findings, fs = findings_for(fpm_root, [fpm_install()], db)
    plan = build_plan(findings, db, fs, TODAY, only={"memory-limit-unlimited"})
    after = plan.changes["/etc/php/8.3/fpm/pool.d/www.conf"].after
    assert "php_admin_value[memory_limit] = 512M" not in after
    assert after.count("php_admin_value[memory_limit] = -1") == 1


def test_plan_only_filter(fpm_root, db):
    findings, fs = findings_for(fpm_root, [fpm_install()], db)
    plan = build_plan(findings, db, fs, TODAY, only={"session-upload-progress-off"})
    after = plan.changes["/etc/php/8.3/fpm/pool.d/legacy.conf"].after
    assert "memory_limit" not in after


def test_modphp_plan_writes_a_dropin(modphp_root, db):
    findings, fs = findings_for(modphp_root, [modphp_install()], db)
    plan = build_plan(findings, db, fs, TODAY)
    path = f"/etc/php/8.3/apache2/conf.d/{DROPIN_NAME}"
    assert set(plan.changes) == {path}
    change = plan.changes[path]
    assert change.before is None
    assert "session.upload_progress.enabled = Off" in change.after
    assert change.after.startswith("; Written by php2shell-check on 2026-10-23.")
    # memory_limit is already -1 via php_admin_value in apache2.conf: untouched
    assert "memory_limit" not in change.after
    assert any("/var/www/site/sub/.htaccess:1" in m for m in plan.manual)


def test_patched_install_gets_no_plan(fpm_root, db):
    install = fpm_install()
    install.version = "8.3.36"
    findings, fs = findings_for(fpm_root, [install], db)
    assert build_plan(findings, db, fs, TODAY).empty


def test_render_plan_shows_diff_side_effects_and_manual(modphp_root, db):
    findings, fs = findings_for(modphp_root, [modphp_install()], db)
    text = render_plan(build_plan(findings, db, fs, TODAY))
    assert f"create /etc/php/8.3/apache2/conf.d/{DROPIN_NAME}" in text
    assert "+session.upload_progress.enabled = Off" in text
    assert "--- /dev/null" in text
    assert "Side effects:" in text and "Manual steps" in text


def _i(binary, sapi, version="8.3.6", manager=None, distro=None, enabled=None):
    package = Package("p", "1", "p", manager) if manager else None
    return PhpInstall(binary, sapi, version, package=package, distro=distro, enabled=enabled)


SLES = Distro("sles", "15.6")


@pytest.mark.parametrize(
    "install, expected",
    [
        (_i("/usr/sbin/php-fpm8.3", "fpm-fcgi", manager="dpkg"), ["php8.3-fpm"]),
        (_i("/usr/sbin/php-fpm", "fpm-fcgi", "8.0.30", manager="rpm"), ["php-fpm"]),
        (_i("/usr/sbin/php-fpm", "fpm-fcgi", "8.2.20", manager="rpm", distro=SLES), ["php-fpm"]),
        (_i("/opt/remi/php83/root/usr/sbin/php-fpm", "fpm-fcgi", manager="rpm"), ["php83-php-fpm"]),
        (_i("/opt/cpanel/ea-php83/root/usr/sbin/php-fpm", "fpm-fcgi", manager="rpm"), ["ea-php83-php-fpm"]),
        # review finding 3: Plesk and Red Hat SCL
        (_i("/opt/plesk/php/8.3/sbin/php-fpm", "fpm-fcgi", manager="dpkg"), ["plesk-php83-fpm"]),
        (_i("/opt/rh/rh-php73/root/usr/sbin/php-fpm", "fpm-fcgi", "7.3.33", manager="rpm"), ["rh-php73-php-fpm"]),
        # review finding 4: unreadable version on Debian, branch from the binary name
        (_i("/usr/sbin/php-fpm8.3", "fpm-fcgi", "", manager="dpkg"), ["php8.3-fpm"]),
        (_i("/usr/sbin/php-fpm", "fpm-fcgi", "", manager="dpkg"), []),
        (_i("/usr/local/sbin/php-fpm", "fpm-fcgi", "8.3.20"), ["php8.3-fpm", "php-fpm"]),
        (_i("/usr/lib/apache2/modules/libphp8.3.so", "apache2handler", manager="dpkg"), ["apache2"]),
        (_i("/usr/lib64/httpd/modules/libphp.so", "apache2handler", manager="rpm"), ["httpd"]),
        # review finding 2: SUSE calls it apache2
        (_i("/usr/lib64/apache2/mod_php8.so", "apache2handler", manager="rpm", distro=SLES), ["apache2"]),
        # review finding 8: a module Apache does not load needs no restart
        (_i("/usr/lib/apache2/modules/libphp8.3.so", "apache2handler", manager="dpkg", enabled=False), []),
        (_i("/usr/bin/php", "cli"), []),
    ],
)
def test_service_units(install, expected):
    assert service_units(install) == expected


# --- applying ---------------------------------------------------------------


class Runner:
    def __init__(self, active=("php8.3-fpm",), fail=()):
        self.active = set(active)
        self.fail = set(fail)
        self.calls = []

    def __call__(self, argv):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[0] == "systemctl" and argv[1] == "is-active":
            return CommandResult(argv, 0 if argv[-1] in self.active else 3, "", "")
        if argv in self.fail or argv[:2] in self.fail:
            return CommandResult(argv, 1, "", "ERROR: [pool legacy] invalid value\n")
        return CommandResult(argv, 0, "", "")


def which(name):
    return f"/usr/bin/{name}"


@pytest.fixture
def fpm_plan(fpm_root, db):
    findings, fs = findings_for(fpm_root, [fpm_install()], db)
    return build_plan(findings, db, fs, TODAY)


def test_apply_writes_backs_up_validates_restarts(fpm_root, fpm_plan):
    run = Runner()
    result = apply_plan(fpm_plan, lambda: [], backup_root="/backups", root=str(fpm_root), run=run, which=which, timestamp="T")
    assert result.ok, result.messages
    legacy = fpm_root / "etc/php/8.3/fpm/pool.d/legacy.conf"
    assert "php_admin_flag[session.upload_progress.enabled] = off" in legacy.read_text()

    backup = fpm_root / "backups/T/etc/php/8.3/fpm/pool.d/legacy.conf"
    assert "php_admin_flag" not in backup.read_text()
    assert json.loads((fpm_root / "backups/T/manifest.json").read_text()) == {
        "/etc/php/8.3/fpm/pool.d/legacy.conf": "modified"
    }
    assert ("/usr/sbin/php-fpm8.3", "-t", "-y", "/etc/php/8.3/fpm/php-fpm.conf") in run.calls
    assert ("systemctl", "restart", "php8.3-fpm") in run.calls
    assert "restarted php8.3-fpm" in result.messages


def test_apply_keeps_file_mode(fpm_root, fpm_plan):
    legacy = fpm_root / "etc/php/8.3/fpm/pool.d/legacy.conf"
    legacy.chmod(0o640)
    apply_plan(fpm_plan, lambda: [], backup_root="/backups", root=str(fpm_root), run=Runner(), which=which, timestamp="T")
    assert (legacy.stat().st_mode & 0o777) == 0o640


def test_validation_failure_rolls_back_without_restart(fpm_root, fpm_plan):
    legacy = fpm_root / "etc/php/8.3/fpm/pool.d/legacy.conf"
    original = legacy.read_text()
    run = Runner(fail={("/usr/sbin/php-fpm8.3", "-t")})
    result = apply_plan(fpm_plan, lambda: [], backup_root="/backups", root=str(fpm_root), run=run, which=which, timestamp="T")
    assert not result.ok and result.rolled_back
    assert legacy.read_text() == original
    assert not any(c[:2] == ("systemctl", "restart") for c in run.calls)
    assert any("invalid value" in m for m in result.messages)


def test_recheck_failure_rolls_back_and_restarts_again(fpm_root, fpm_plan):
    legacy = fpm_root / "etc/php/8.3/fpm/pool.d/legacy.conf"
    original = legacy.read_text()
    run = Runner()
    result = apply_plan(
        fpm_plan, lambda: ["still not set"], backup_root="/backups", root=str(fpm_root), run=run, which=which, timestamp="T"
    )
    assert result.rolled_back
    assert legacy.read_text() == original
    assert sum(1 for c in run.calls if c[:2] == ("systemctl", "restart")) == 2
    assert "failed: still not set" in result.messages


def test_restart_failure_rolls_back(fpm_root, fpm_plan):
    run = Runner(fail={("systemctl", "restart")})
    result = apply_plan(fpm_plan, lambda: [], backup_root="/backups", root=str(fpm_root), run=run, which=which, timestamp="T")
    assert result.rolled_back


def test_created_file_is_removed_on_rollback(modphp_root, db):
    findings, fs = findings_for(modphp_root, [modphp_install()], db)
    plan = build_plan(findings, db, fs, TODAY)
    run = Runner(active={"apache2"})
    result = apply_plan(plan, lambda: ["nope"], backup_root="/backups", root=str(modphp_root), run=run, which=which, timestamp="T")
    assert result.rolled_back
    assert not (modphp_root / "etc/php/8.3/apache2/conf.d" / DROPIN_NAME).exists()
    assert ("apache2ctl", "-t") in run.calls


def test_file_changed_since_plan_writes_nothing(fpm_root, fpm_plan):
    legacy = fpm_root / "etc/php/8.3/fpm/pool.d/legacy.conf"
    legacy.write_text(legacy.read_text() + "; edited by someone else\n")
    result = apply_plan(fpm_plan, lambda: [], backup_root="/backups", root=str(fpm_root), run=Runner(), which=which)
    assert not result.ok and not result.rolled_back
    assert "changed since the plan was made" in result.messages[0]
    assert not (fpm_root / "backups").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_unwritable_directory_rolls_back(fpm_root, fpm_plan):
    pool_dir = fpm_root / "etc/php/8.3/fpm/pool.d"
    pool_dir.chmod(0o555)
    try:
        result = apply_plan(fpm_plan, lambda: [], backup_root="/backups", root=str(fpm_root), run=Runner(), which=which, timestamp="T")
    finally:
        pool_dir.chmod(0o755)
    assert result.rolled_back
    assert any("cannot write" in m for m in result.messages)


def test_no_restart_option(fpm_root, fpm_plan):
    run = Runner()
    result = apply_plan(
        fpm_plan, lambda: [], backup_root="/backups", root=str(fpm_root), run=run, which=which, restart=False, timestamp="T"
    )
    assert result.ok
    assert not any(c[0] == "systemctl" for c in run.calls)


def test_second_run_is_a_no_op(fpm_root, db):
    findings, fs = findings_for(fpm_root, [fpm_install()], db)
    plan = build_plan(findings, db, fs, TODAY)
    apply_plan(plan, lambda: [], backup_root="/backups", root=str(fpm_root), run=Runner(), which=which, timestamp="T")
    findings, fs = findings_for(fpm_root, [fpm_install()], db)
    assert build_plan(findings, db, fs, TODAY).empty


def test_recheck_targets(fpm_root, db):
    findings, fs = findings_for(fpm_root, [fpm_install()], db)
    plan = Plan(targets=[Target("/usr/sbin/php-fpm8.3", "session-upload-progress-off", "pool legacy")])
    assert "still not set in pool legacy" in recheck_targets(plan, findings)[0]
    apply_plan(build_plan(findings, db, fs, TODAY), lambda: [], backup_root="/b", root=str(fpm_root), run=Runner(), which=which)
    findings, _ = findings_for(fpm_root, [fpm_install()], db)
    assert recheck_targets(plan, findings) == []


# --- cli --------------------------------------------------------------------


@pytest.fixture
def fix_host(monkeypatch, fpm_root):
    monkeypatch.setattr(cli, "discover", lambda: DiscoveryResult(Distro("ubuntu", "24.10"), [fpm_install()]))
    monkeypatch.setattr(cli, "HostFileSystem", lambda max_files: HostFileSystem(str(fpm_root)))
    return fpm_root


def test_cli_fix_flags_need_fix(capsys):
    assert cli.main(["--dry-run"]) == 4
    assert "need --fix" in capsys.readouterr().err


def test_cli_fix_and_json_conflict(capsys):
    assert cli.main(["--fix", "--json"]) == 4


def test_cli_dry_run_changes_nothing(fix_host, capsys):
    legacy = fix_host / "etc/php/8.3/fpm/pool.d/legacy.conf"
    before = legacy.read_text()
    code = cli.main(["--fix", "--dry-run"])
    out = capsys.readouterr().out
    assert "+php_admin_flag[session.upload_progress.enabled] = off" in out
    assert "Dry run: nothing was changed." in out
    assert legacy.read_text() == before
    assert code == 3  # the assessment exit code: UNKNOWN and only PARTIAL


def test_cli_unknown_only_id(fix_host, capsys):
    assert cli.main(["--fix", "--only", "pray"]) == 4
    assert "unknown mitigation id" in capsys.readouterr().err


@pytest.mark.skipif(os.geteuid() == 0, reason="checks the non-root guard")
def test_cli_fix_refuses_without_root(fix_host, capsys):
    assert cli.main(["--fix", "--yes"]) == 4
    assert "--fix needs root" in capsys.readouterr().err
