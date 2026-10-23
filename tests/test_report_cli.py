import json
from pathlib import Path

import pytest

from php2shell_check import cli
from php2shell_check.advisories import load
from php2shell_check.assess import assess
from php2shell_check.config import check_install, load_web_config
from php2shell_check.discovery import DiscoveryResult, HostFileSystem
from php2shell_check.models import Distro, Package, PhpInstall
from php2shell_check.report import DISCLAIMER, render_json, render_text

CONFIG = Path(__file__).parent / "fixtures" / "config"


@pytest.fixture(scope="module")
def db():
    return load()


@pytest.fixture
def findings(db):
    fs = HostFileSystem(str(CONFIG / "debian-fpm"))
    web = load_web_config(fs)
    checks = [*db.mitigations.values(), *db.hardening]
    exposed = PhpInstall(
        binary="/usr/sbin/php-fpm8.3",
        sapi="fpm-fcgi",
        version="8.3.20",
        ini_files=["/etc/php/8.3/fpm/php.ini", "/etc/php/8.3/fpm/conf.d/99-php2shell.ini"],
        fpm_config="/etc/php/8.3/fpm/php-fpm.conf",
        package=Package("php8.3-fpm", "8.3.20-1+ubuntu24.04.1+deb.sury.org+1", "php8.3", "dpkg"),
        distro=Distro("ubuntu", "24.10"),
    )
    patched = PhpInstall(
        binary="/usr/bin/php8.3",
        sapi="cli",
        version="8.3.6",
        package=Package("php8.3-cli", "8.3.6-0ubuntu0.24.04.13", "php8.3", "dpkg"),
        distro=Distro("ubuntu", "24.04"),
    )
    return [
        assess(exposed, db, check_install(exposed, checks, fs, web)),
        assess(patched, db, check_install(patched, checks, fs, web)),
    ]


def test_text_report(findings, db):
    text = render_text(findings, db, warnings=["something odd"])
    assert "SAPI" in text.splitlines()[2]
    assert "UNKNOWN" in text and "PATCHED" in text
    assert "[NOT SET] session.upload_progress.enabled" in text
    assert "pool legacy: '1' from /etc/php/8.3/fpm/pool.d/legacy.conf:3" in text
    assert "Warnings:\n  something odd" in text
    assert DISCLAIMER in text


def test_text_report_verbose_shows_hardening(findings, db):
    assert "hardening (informational)" not in render_text(findings, db)
    assert "hardening (informational)" in render_text(findings, db, verbose=True)


def test_text_report_empty(db):
    assert "No PHP installation found." in render_text([], db)


def test_json_report(findings, db):
    doc = json.loads(render_json(findings, db, 1, ["w"], [("/usr/bin/php83", "wrapper")], {"id": "ubuntu"}))
    assert doc["exit_code"] == 1
    assert doc["summary"]["UNKNOWN"] == 1 and doc["summary"]["PATCHED"] == 1
    fpm = doc["installs"][0]
    assert fpm["status"] == "UNKNOWN"
    assert fpm["mitigation"] in ("PARTIAL", "EXPOSED")
    upload = next(m for m in fpm["mitigations"] if m["id"] == "session-upload-progress-off")
    assert upload["satisfied"] is False
    assert {"context": "pool legacy", "value": "1", "origin": "/etc/php/8.3/fpm/pool.d/legacy.conf:3"} in upload["failing"]
    assert doc["skipped"] == [{"path": "/usr/bin/php83", "reason": "wrapper"}]
    assert doc["sources"]["ghsa-w8hw"].startswith("https://github.com/php/php-src/")


# --- cli --------------------------------------------------------------------


@pytest.fixture
def fake_host(monkeypatch):
    installs = [
        PhpInstall(
            binary="/usr/sbin/php-fpm8.4",
            sapi="fpm-fcgi",
            version="8.4.27",
            distro=Distro("debian", "13"),
        )
    ]
    monkeypatch.setattr(cli, "discover", lambda: DiscoveryResult(Distro("debian", "13"), installs))
    monkeypatch.setattr(cli, "HostFileSystem", lambda max_files: HostFileSystem("/nonexistent-root"))
    return installs


def test_cli_text_exit_0(fake_host, capsys):
    assert cli.main([]) == 0
    assert "PATCHED" in capsys.readouterr().out


def test_cli_json(fake_host, capsys):
    assert cli.main(["--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["installs"][0]["status"] == "PATCHED"
    assert doc["distro"]["id"] == "debian"


def test_cli_exit_3_for_unknown(fake_host, capsys):
    fake_host[0].version = "8.4.20"
    assert cli.main([]) == 3


def test_cli_bad_advisories_file(tmp_path, capsys):
    bad = tmp_path / "a.json"
    bad.write_text("{}")
    assert cli.main(["--advisories", str(bad)]) == 4
    assert "invalid advisories file" in capsys.readouterr().err


def test_cli_unexpected_error_exit_4(monkeypatch, capsys):
    def boom():
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(cli, "discover", boom)
    assert cli.main([]) == 4
    assert "disk on fire" in capsys.readouterr().err


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as info:
        cli.main(["--version"])
    assert info.value.code == 0
    assert "php2shell-check" in capsys.readouterr().out
