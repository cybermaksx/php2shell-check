import os

import pytest

from php2shell_check.discovery import (
    apache_conf_loads_php,
    branch_from_module_name,
    configure_option,
    discover,
    expected_sapi,
    fpm_config_candidates,
    parse_frankenphp_version,
    parse_phpinfo,
    parse_version_output,
    sapi_from_server_api,
    version_from_package,
)
from php2shell_check.distro import CommandError, CommandResult

# --- phpinfo parsing, against real captured output --------------------------


def test_phpinfo_ubuntu_cli(fixture_text):
    info = parse_phpinfo(fixture_text("php", "ubuntu-24.04-cli-i.txt"))
    assert info.version == "8.3.6"
    assert info.server_api == "Command Line Interface"
    assert info.ini_files[0] == "/etc/php/8.3/cli/php.ini"
    assert info.ini_files[1] == "/etc/php/8.3/cli/conf.d/10-opcache.ini"
    assert all(p.endswith(".ini") for p in info.ini_files)
    assert info.directives["session.upload_progress.enabled"] == "On"
    assert info.directives["memory_limit"] == "-1"  # Debian CLI default


def test_phpinfo_ubuntu_fpm(fixture_text):
    info = parse_phpinfo(fixture_text("php", "ubuntu-24.04-fpm-i.txt"))
    assert info.server_api == "FPM/FastCGI"
    assert info.ini_files[0] == "/etc/php/8.3/fpm/php.ini"
    assert all(p.startswith("/etc/php/8.3/fpm/") for p in info.ini_files)
    assert info.directives["memory_limit"] == "128M"


def test_phpinfo_ubuntu_cgi_html(fixture_text):
    info = parse_phpinfo(fixture_text("php", "ubuntu-24.04-cgi-i.html"))
    assert info.version == "8.3.6"
    assert info.server_api == "CGI/FastCGI"
    assert info.ini_files[0] == "/etc/php/8.3/cgi/php.ini"
    assert len(info.ini_files) > 5
    assert info.directives["session.upload_progress.enabled"] == "On"


def test_phpinfo_rocky_fpm(fixture_text):
    info = parse_phpinfo(fixture_text("php", "rocky-9-fpm-i.txt"))
    assert info.version == "8.0.30"
    # The credits contain "Server API (SAPI) Abstraction Layer => ..."; the
    # exact key must still be the real one.
    assert info.server_api == "FPM/FastCGI"
    assert info.ini_files[0] == "/etc/php.ini"
    assert all(p.startswith(("/etc/php.ini", "/etc/php.d/")) for p in info.ini_files)
    # Distro builds leave Configure Command out of phpinfo; only source
    # builds have it, so FPM config lookup must not depend on it.
    assert info.configure_command == ""


def test_phpinfo_no_ini_loaded():
    info = parse_phpinfo(
        "PHP Version => 8.4.27\n"
        "Server API => Command Line Interface\n"
        "Loaded Configuration File => (none)\n"
        "Additional .ini files parsed => (none)\n"
    )
    assert info.ini_files == []


@pytest.mark.parametrize(
    "name, expected",
    [
        ("ubuntu-24.04-cli-v.txt", ("8.3.6", "cli")),
        ("ubuntu-24.04-fpm-v.txt", ("8.3.6", "fpm-fcgi")),
        ("rocky-9-cli-v.txt", ("8.0.30", "cli")),
    ],
)
def test_parse_version_output(fixture_text, name, expected):
    assert parse_version_output(fixture_text("php", name)) == expected


def test_parse_version_output_with_distro_suffix():
    text = "PHP 8.1.2-1ubuntu2.28 (cli) (built: Oct 21 2026 10:00:00) (NTS)\n"
    assert parse_version_output(text) == ("8.1.2-1ubuntu2.28", "cli")


def test_parse_version_output_garbage():
    assert parse_version_output("Segmentation fault\n") is None


def test_parse_frankenphp_version():
    # Output shape of `frankenphp version`; not captured from a real binary.
    text = "FrankenPHP v1.9.0 PHP 8.4.11 Caddy v2.10.2 h1:abc=\n"
    assert parse_frankenphp_version(text) == "8.4.11"
    assert parse_frankenphp_version("nothing here") is None


@pytest.mark.parametrize(
    "value, expected",
    [
        ("Command Line Interface", "cli"),
        ("FPM/FastCGI", "fpm-fcgi"),
        ("CGI/FastCGI", "cgi-fcgi"),
        ("Apache 2.0 Handler", "apache2handler"),
        ("LiteSpeed V8.2", "litespeed"),
        ("Something New", None),
    ],
)
def test_sapi_from_server_api(value, expected):
    assert sapi_from_server_api(value) == expected


@pytest.mark.parametrize(
    "name, expected",
    [
        ("php", "cli"),
        ("php8.3", "cli"),
        ("php83", "cli"),
        ("php-fpm", "fpm-fcgi"),
        ("php-fpm8.3", "fpm-fcgi"),
        ("php-cgi8.3", "cgi-fcgi"),
        ("lsphp", "litespeed"),
        ("lsphp83", "litespeed"),
        ("frankenphp", "frankenphp"),
        ("php-config8.3", None),
        ("phpize", None),
        ("phpdbg8.3", None),
        ("php.bak", None),
        ("phpunit", None),
    ],
)
def test_expected_sapi(name, expected):
    assert expected_sapi(name) == expected


def test_configure_option():
    cmd = "'./configure'  '--build=x86_64-redhat-linux-gnu' '--sysconfdir=/etc' '--prefix=/usr'"
    assert configure_option(cmd, "sysconfdir") == "/etc"
    assert configure_option(cmd, "localstatedir") is None


@pytest.mark.parametrize(
    "text, expected",
    [
        ("LoadModule php_module /usr/lib/apache2/modules/libphp8.3.so\n", True),
        ("LoadModule php7_module modules/libphp7.so\n", True),
        ("  loadmodule PHP_MODULE modules/libphp.so\n", True),
        ("# LoadModule php_module modules/libphp.so\n", False),
        ("LoadModule rewrite_module modules/mod_rewrite.so\n", False),
    ],
)
def test_apache_conf_loads_php(text, expected):
    assert apache_conf_loads_php(text) is expected


def test_branch_from_module_name():
    assert branch_from_module_name("libphp8.3.so") == "8.3"
    assert branch_from_module_name("libphp.so") is None
    assert branch_from_module_name("libphp7.so") is None


@pytest.mark.parametrize(
    "package_version, expected",
    [
        ("8.3.6-0ubuntu0.24.04.13", "8.3.6"),
        ("1:8.3.6-1", "8.3.6"),
        ("8.0.30-8.el9_8.1", "8.0.30"),
        ("2:93", None),
    ],
)
def test_version_from_package(package_version, expected):
    assert version_from_package(package_version) == expected


def test_fpm_config_candidates_debian():
    candidates = fpm_config_candidates("/usr/sbin/php-fpm8.3", "8.3", "--sysconfdir=/etc")
    assert candidates[0] == "/etc/php-fpm.conf"
    assert "/etc/php/8.3/fpm/php-fpm.conf" in candidates


def test_fpm_config_candidates_remi_scl():
    candidates = fpm_config_candidates("/opt/remi/php83/root/usr/sbin/php-fpm", "8.3", "")
    assert candidates[0] == "/etc/opt/remi/php83/php-fpm.conf"


def test_fpm_config_candidates_cpanel():
    candidates = fpm_config_candidates("/opt/cpanel/ea-php83/root/usr/sbin/php-fpm", "8.3", "")
    assert candidates[0] == "/opt/cpanel/ea-php83/root/etc/php-fpm.conf"


# --- end to end on a fake filesystem ----------------------------------------

ELF = b"\x7fELF" + b"\0" * 60


def make_file(root, rel, content=b"", mode=0o644):
    path = root / rel.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode())
    path.chmod(mode)
    return path


class ScriptedRunner:
    """Answers by argv; unknown dpkg-query -S lookups mean "not owned"."""

    def __init__(self, answers):
        self.answers = {tuple(k): v for k, v in answers.items()}
        self.calls = []

    def __call__(self, argv):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv in self.answers:
            answer = self.answers[argv]
            if isinstance(answer, Exception):
                raise answer
            return CommandResult(argv, *answer)
        if argv[:2] == ("dpkg-query", "-S"):
            return CommandResult(argv, 1, "", f"dpkg-query: no path found matching pattern {argv[2]}\n")
        raise AssertionError(f"unexpected command: {argv}")


DPKG_SHOW = "-f=${Package}\\t${Version}\\t${Source}\\n"


@pytest.fixture
def ubuntu_host(tmp_path, fixture_text):
    root = tmp_path
    make_file(root, "/etc/os-release", fixture_text("os-release", "ubuntu-24.04"))
    cli = make_file(root, "/usr/bin/php8.3", ELF, 0o755)
    os.symlink(cli, root / "usr/bin/php")
    fpm = make_file(root, "/usr/sbin/php-fpm8.3", ELF, 0o755)
    make_file(root, "/usr/bin/php83", "#!/bin/sh\nexec php8.3 \"$@\"\n", 0o755)
    make_file(root, "/usr/bin/php-config8.3", "#!/bin/sh\n", 0o755)
    make_file(root, "/usr/bin/php8.2", ELF, 0o644)
    make_file(root, "/etc/php/8.3/fpm/php-fpm.conf", "[global]\n")
    module = make_file(root, "/usr/lib/apache2/modules/libphp8.3.so", ELF)
    make_file(root, "/etc/apache2/mods-enabled/php8.3.load", "LoadModule php_module /usr/lib/apache2/modules/libphp8.3.so\n")
    make_file(root, "/etc/php/8.3/apache2/php.ini", "")
    make_file(root, "/etc/php/8.3/apache2/conf.d/20-zz.ini", "")
    make_file(root, "/etc/php/8.3/apache2/conf.d/10-opcache.ini", "")

    runner = ScriptedRunner(
        {
            (str(cli), "-i"): (0, fixture_text("php", "ubuntu-24.04-cli-i.txt"), ""),
            (str(fpm), "-i"): (0, fixture_text("php", "ubuntu-24.04-fpm-i.txt"), ""),
            ("dpkg-query", "-S", str(cli)): (0, f"php8.3-cli: {cli}\n", ""),
            ("dpkg-query", "-S", str(fpm)): (0, f"php8.3-fpm: {fpm}\n", ""),
            ("dpkg-query", "-S", str(module)): (0, f"libapache2-mod-php8.3: {module}\n", ""),
            ("dpkg-query", "-W", DPKG_SHOW, "php8.3-cli"): (0, "php8.3-cli\t8.3.6-0ubuntu0.24.04.13\tphp8.3\n", ""),
            ("dpkg-query", "-W", DPKG_SHOW, "php8.3-fpm"): (0, "php8.3-fpm\t8.3.6-0ubuntu0.24.04.13\tphp8.3\n", ""),
            ("dpkg-query", "-W", DPKG_SHOW, "libapache2-mod-php8.3"): (
                0,
                "libapache2-mod-php8.3\t8.3.6-0ubuntu0.24.04.13\tphp8.3\n",
                "",
            ),
        }
    )
    return root, runner


def run_discovery(root, runner):
    return discover(
        run=runner,
        which=lambda name: "/usr/bin/" + name if name == "dpkg-query" else None,
        root=str(root),
        binary_dirs=["/usr/bin", "/usr/sbin"],
    )


def test_discover_ubuntu_host(ubuntu_host):
    root, runner = ubuntu_host
    result = run_discovery(root, runner)

    assert result.distro.os_id == "ubuntu"
    by_sapi = {i.sapi: i for i in result.installs}
    assert set(by_sapi) == {"cli", "fpm-fcgi", "apache2handler"}

    cli = by_sapi["cli"]
    assert cli.version == "8.3.6"
    assert cli.aliases == [str(root / "usr/bin/php")]
    assert cli.package.source_name == "php8.3"
    assert cli.ini_files[0] == "/etc/php/8.3/cli/php.ini"

    fpm = by_sapi["fpm-fcgi"]
    assert fpm.fpm_config == "/etc/php/8.3/fpm/php-fpm.conf"
    assert fpm.package.version == "8.3.6-0ubuntu0.24.04.13"

    mod = by_sapi["apache2handler"]
    assert mod.enabled is True
    assert mod.version == "8.3.6"  # from the package
    assert mod.ini_files == [
        "/etc/php/8.3/apache2/php.ini",
        "/etc/php/8.3/apache2/conf.d/10-opcache.ini",
        "/etc/php/8.3/apache2/conf.d/20-zz.ini",
    ]
    assert any("inferred from the distro layout" in w for w in mod.warnings)


def test_discover_skips_wrappers_and_non_executables(ubuntu_host):
    root, runner = ubuntu_host
    result = run_discovery(root, runner)
    skipped = dict(result.skipped)
    assert "wrapper script" in skipped[str(root / "usr/bin/php83")]
    assert skipped[str(root / "usr/bin/php8.2")] == "not an executable file"
    assert not any("php-config" in path for path, _ in result.skipped)  # never a candidate


def test_discover_never_runs_anything_but_info_commands(ubuntu_host):
    root, runner = ubuntu_host
    run_discovery(root, runner)
    for argv in runner.calls:
        if argv[0] == "dpkg-query":
            assert argv[1] in ("-S", "-W")
        else:
            assert argv[1:] in (("-i",), ("-v",), ("version",)), argv


def test_discover_phpinfo_failure_falls_back_to_v(tmp_path, fixture_text):
    make_file(tmp_path, "/etc/os-release", fixture_text("os-release", "debian-12"))
    php = make_file(tmp_path, "/usr/bin/php", ELF, 0o755)
    runner = ScriptedRunner(
        {
            (str(php), "-i"): (255, "", "PHP Fatal error: something\n"),
            (str(php), "-v"): (0, "PHP 8.2.35 (cli) (built: Oct 21 2026)\n", ""),
        }
    )
    result = run_discovery(tmp_path, runner)
    [install] = result.installs
    assert install.version == "8.2.35"
    assert any("exited 255" in w for w in install.warnings)
    assert any("ini files unknown" in w for w in install.warnings)
    assert install.package is None  # not owned, and that is not a warning
    assert not any("dpkg" in w for w in install.warnings)


def test_discover_binary_that_hangs(tmp_path, fixture_text):
    make_file(tmp_path, "/etc/os-release", fixture_text("os-release", "debian-12"))
    php = make_file(tmp_path, "/usr/bin/php", ELF, 0o755)
    runner = ScriptedRunner(
        {
            (str(php), "-i"): CommandError(f"{php} -i: timed out after 15s"),
            (str(php), "-v"): CommandError(f"{php} -v: timed out after 15s"),
        }
    )
    [install] = run_discovery(tmp_path, runner).installs
    assert install.version == ""
    assert any("timed out" in w for w in install.warnings)
    assert any("could not read the PHP version" in w for w in install.warnings)


def test_discover_fpm_without_config(tmp_path, fixture_text):
    make_file(tmp_path, "/etc/os-release", fixture_text("os-release", "rocky-9.4"))
    fpm = make_file(tmp_path, "/usr/sbin/php-fpm", ELF, 0o755)
    runner = ScriptedRunner({(str(fpm), "-i"): (0, fixture_text("php", "rocky-9-fpm-i.txt"), "")})
    [install] = run_discovery(tmp_path, runner).installs
    assert install.sapi == "fpm-fcgi"
    assert install.fpm_config is None
    assert any("php-fpm.conf not found" in w for w in install.warnings)


def test_discover_unpackaged_module_has_unknown_version(tmp_path, fixture_text):
    make_file(tmp_path, "/etc/os-release", fixture_text("os-release", "debian-12"))
    make_file(tmp_path, "/usr/lib/apache2/modules/libphp8.2.so", ELF)
    [install] = run_discovery(tmp_path, ScriptedRunner({})).installs
    assert install.sapi == "apache2handler"
    assert install.enabled is False
    assert install.version == ""
    assert any("mod_php version unknown" in w for w in install.warnings)


def test_discover_nothing(tmp_path, fixture_text):
    make_file(tmp_path, "/etc/os-release", fixture_text("os-release", "arch"))
    result = run_discovery(tmp_path, ScriptedRunner({}))
    assert result.installs == []
    assert "no PHP installation found" in result.warnings


def test_discover_unreadable_dir_is_a_warning(tmp_path, fixture_text):
    if os.geteuid() == 0:
        pytest.skip("root can read any directory")
    make_file(tmp_path, "/etc/os-release", fixture_text("os-release", "debian-12"))
    locked = tmp_path / "usr/bin"
    locked.mkdir(parents=True)
    locked.chmod(0o000)
    try:
        result = run_discovery(tmp_path, ScriptedRunner({}))
    finally:
        locked.chmod(0o755)
    assert any("permission denied" in w for w in result.warnings)
