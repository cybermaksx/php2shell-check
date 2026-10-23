"""Find every PHP installation on the host.

An installation is one real binary (CLI, FPM, CGI, LiteSpeed, FrankenPHP)
or one Apache module (mod_php). Symlinks such as /usr/bin/php ->
/etc/alternatives/php -> /usr/bin/php8.3 collapse into one install with
aliases.

For binaries the facts come from PHP itself: `<bin> -i` reports the SAPI,
the version, the php.ini it really loaded and the conf.d files it really
parsed. Apache modules cannot be run, so their version comes from the
owning package and their ini files from the distro's layout, with a
warning saying so.

This module only reads files and runs PHP binaries with -i / -v (or
`frankenphp version`). It never starts a server or sends a request.
"""

from __future__ import annotations

import glob
import html
import os
import re
import shutil
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from . import distro as distro_mod
from .distro import CommandError, Runner, Which, describe_failure, run_command
from .models import Distro, PhpInstall
from .version import VersionError, parse_upstream

# Directories searched for PHP binaries. Globs cover side-by-side installs:
# Remi SCL, cPanel EasyApache, Plesk, LiteSpeed.
BINARY_DIRS = (
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
    "/usr/lib/cgi-bin",
    "/opt/remi/php*/root/usr/bin",
    "/opt/remi/php*/root/usr/sbin",
    "/opt/cpanel/ea-php*/root/usr/bin",
    "/opt/cpanel/ea-php*/root/usr/sbin",
    "/opt/plesk/php/*/bin",
    "/opt/plesk/php/*/sbin",
    "/usr/local/lsws/lsphp*/bin",
    "/usr/local/lsws/fcgi-bin",
    "/usr/local/php*/bin",
    "/usr/local/php*/sbin",
)

APACHE_MODULE_GLOBS = (
    "/usr/lib/apache2/modules/libphp*.so",
    "/usr/lib64/httpd/modules/libphp*.so",
    "/usr/lib/httpd/modules/libphp*.so",
    "/usr/local/apache2/modules/libphp*.so",
)

# Where Apache configs that may LoadModule php live.
APACHE_CONF_GLOBS = (
    "/etc/apache2/mods-enabled/*.load",
    "/etc/httpd/conf.modules.d/*.conf",
    "/etc/httpd/conf/httpd.conf",
    "/usr/local/apache2/conf/httpd.conf",
)

# Binary name -> SAPI we expect. Matches php, php8.3, php83, php-fpm8.3 ...
# and deliberately not php-config, phpize or phpdbg.
_NAME_PATTERNS = (
    (re.compile(r"^php(\d+(\.\d+)?)?$"), "cli"),
    (re.compile(r"^php-fpm(\d+(\.\d+)?)?$"), "fpm-fcgi"),
    (re.compile(r"^php-cgi(\d+(\.\d+)?)?$"), "cgi-fcgi"),
    (re.compile(r"^lsphp(\d+)?$"), "litespeed"),
    (re.compile(r"^frankenphp$"), "frankenphp"),
)

# "Server API" line in phpinfo -> SAPI name used in advisories.json.
_SERVER_API = {
    "Command Line Interface": "cli",
    "FPM/FastCGI": "fpm-fcgi",
    "CGI/FastCGI": "cgi-fcgi",
    "Apache 2.0 Handler": "apache2handler",
    "FrankenPHP": "frankenphp",
}


@dataclass
class DiscoveryResult:
    distro: Distro | None
    installs: list[PhpInstall] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)
    warnings: list[str] = field(default_factory=list)


# --- pure parsing -----------------------------------------------------------


def expected_sapi(name: str) -> str | None:
    for pattern, sapi in _NAME_PATTERNS:
        if pattern.match(name):
            return sapi
    return None


def sapi_from_server_api(value: str) -> str | None:
    if value in _SERVER_API:
        return _SERVER_API[value]
    if value.startswith("LiteSpeed"):
        return "litespeed"
    return None


@dataclass
class PhpInfo:
    """What we need from phpinfo output, text (-i on the CLI and FPM) or HTML
    (-i on php-cgi)."""

    info: dict[str, str] = field(default_factory=dict)  # "key => value"
    directives: dict[str, str] = field(default_factory=dict)  # master values
    ini_files: list[str] = field(default_factory=list)

    @property
    def version(self) -> str:
        return self.info.get("PHP Version", "")

    @property
    def server_api(self) -> str:
        return self.info.get("Server API", "")

    @property
    def configure_command(self) -> str:
        return self.info.get("Configure Command", "")


def _html_rows(text: str) -> list[list[str]]:
    """Cells of every <tr> in phpinfo HTML, tags stripped and unescaped."""
    rows = []
    for row in re.findall(r"<tr>(.*?)</tr>", text, flags=re.S):
        cells = re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, flags=re.S)
        rows.append([html.unescape(re.sub(r"<[^>]+>", "", c)).strip() for c in cells])
    return rows


def _text_rows(text: str) -> list[list[str]]:
    """Split "a => b => c" lines. Continuation lines of the comma-separated
    "Additional .ini files parsed" value are folded into the previous row."""
    rows: list[list[str]] = []
    for line in text.splitlines():
        if rows and rows[-1] and rows[-1][-1].endswith(",") and " => " not in line:
            rows[-1][-1] += line.strip()
            continue
        if " => " in line:
            rows.append([part.strip() for part in line.split(" => ")])
    return rows


def parse_phpinfo(text: str) -> PhpInfo:
    rows = _html_rows(text) if "<table" in text else _text_rows(text)
    result = PhpInfo()
    for cells in rows:
        if len(cells) == 2:
            key, value = cells
            # First occurrence wins: "PHP Version" appears again in the Core
            # section, and the credits have "Server API (SAPI) Abstraction Layer".
            result.info.setdefault(key, value)
        elif len(cells) == 3 and cells[0] != "Directive":
            key, _local, master = cells
            result.directives.setdefault(key, master)

    loaded = result.info.get("Loaded Configuration File", "(none)")
    if loaded and loaded != "(none)":
        result.ini_files.append(loaded)
    extra = result.info.get("Additional .ini files parsed", "(none)")
    if extra and extra != "(none)":
        result.ini_files.extend(p.strip() for p in extra.split(",") if p.strip())
    return result


_VERSION_LINE = re.compile(r"^PHP (\S+) \(([\w-]+)\)", re.M)


def parse_version_output(text: str) -> tuple[str, str] | None:
    """`php -v` first line: "PHP 8.3.6 (fpm-fcgi) (built: ...)" -> ("8.3.6", "fpm-fcgi")."""
    match = _VERSION_LINE.search(text)
    return (match.group(1), match.group(2)) if match else None


def parse_frankenphp_version(text: str) -> str | None:
    """`frankenphp version`: "FrankenPHP v1.9.0 PHP 8.4.11 Caddy v2.10.2 ..."."""
    match = re.search(r"\bPHP (\d+\.\d+\.\d+\S*)", text)
    return match.group(1) if match else None


def configure_option(configure_command: str, option: str) -> str | None:
    """Value of --option=VALUE in phpinfo's Configure Command, quotes removed."""
    match = re.search(rf"--{re.escape(option)}=['\"]?([^'\"\s]+)", configure_command)
    return match.group(1) if match else None


def apache_conf_loads_php(text: str) -> bool:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        if re.match(r"LoadModule\s+php\w*_module\s+\S*libphp", line, flags=re.I):
            return True
    return False


def branch_from_module_name(name: str) -> str | None:
    """libphp8.3.so -> 8.3; libphp.so / libphp7.so -> None."""
    match = re.match(r"^libphp(\d+\.\d+)\.so$", name)
    return match.group(1) if match else None


# --- filesystem helpers -----------------------------------------------------


def _expand(patterns: Iterable[str], root: str) -> list[str]:
    """Expand directory/file globs under `root` (normally "/")."""
    paths: list[str] = []
    for pattern in patterns:
        rooted = os.path.join(root, pattern.lstrip("/"))
        for path in sorted(glob.glob(rooted)) if glob.has_magic(rooted) else [rooted]:
            if path not in paths:
                paths.append(path)
    return paths


def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def _scan_dir(directory: str, warnings: list[str]) -> list[str]:
    try:
        with os.scandir(directory) as entries:
            return sorted(e.path for e in entries)
    except FileNotFoundError:
        return []
    except NotADirectoryError:
        return []
    except PermissionError:
        warnings.append(f"cannot list {directory}: permission denied")
        return []


def _read_text(path: str, warnings: list[str]) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        warnings.append(f"cannot read {path}: {exc.strerror}")
        return None


# --- finding candidates -----------------------------------------------------


@dataclass
class Candidate:
    real: str
    expected_sapi: str
    aliases: list[str] = field(default_factory=list)


def find_binaries(
    dirs: Sequence[str],
    root: str,
    warnings: list[str],
    skipped: list[tuple[str, str]],
) -> list[Candidate]:
    """Every executable with a PHP binary name, grouped by resolved path."""
    by_real: dict[str, Candidate] = {}
    for directory in _expand(dirs, root):
        for path in _scan_dir(directory, warnings):
            sapi = expected_sapi(os.path.basename(path))
            if sapi is None:
                continue
            real = os.path.realpath(path)
            if real in by_real:
                if path != real and path not in by_real[real].aliases:
                    by_real[real].aliases.append(path)
                continue
            if not os.path.isfile(real) or not os.access(real, os.X_OK):
                skipped.append((path, "not an executable file"))
                continue
            if not _is_elf(real):
                # e.g. Remi's /usr/bin/php83 wrapper scripts; the real binary
                # under /opt/remi is found on its own.
                skipped.append((path, "not an ELF binary (wrapper script?)"))
                continue
            by_real[real] = Candidate(real, sapi, [path] if path != real else [])
    return list(by_real.values())


def find_apache_modules(root: str) -> list[str]:
    seen: list[str] = []
    for path in _expand(APACHE_MODULE_GLOBS, root):
        real = os.path.realpath(path)
        if os.path.isfile(real) and real not in seen:
            seen.append(real)
    return seen


def apache_php_enabled(root: str, warnings: list[str]) -> bool:
    for path in _expand(APACHE_CONF_GLOBS, root):
        text = _read_text(path, warnings)
        if text and apache_conf_loads_php(text):
            return True
    return False


# --- per-install inspection -------------------------------------------------


def _run(argv: list[str], run: Runner, warnings: list[str]) -> str | None:
    try:
        result = run(argv)
    except CommandError as exc:
        warnings.append(str(exc))
        return None
    if result.returncode != 0:
        warnings.append(describe_failure(result))
        return None
    return result.stdout


def inspect_binary(candidate: Candidate, run: Runner) -> tuple[PhpInstall, str]:
    """Describe one binary. Returns the install and phpinfo's Configure
    Command, which only FPM config lookup needs."""
    configure_command = ""
    install = PhpInstall(
        binary=candidate.real,
        sapi=candidate.expected_sapi,
        version="",
        aliases=list(candidate.aliases),
    )

    if candidate.expected_sapi == "frankenphp":
        output = _run([candidate.real, "version"], run, install.warnings)
        version = parse_frankenphp_version(output or "")
        if version:
            install.version = version
        else:
            install.warnings.append(f"{candidate.real}: could not read the PHP version")
        install.warnings.append(
            "FrankenPHP embeds PHP; loaded ini files are not discovered yet"
        )
        return install, configure_command

    output = _run([candidate.real, "-i"], run, install.warnings)
    if output:
        info = parse_phpinfo(output)
        install.version = info.version
        install.ini_files = info.ini_files
        install.ini_values = info.directives
        configure_command = info.configure_command
        reported = sapi_from_server_api(info.server_api)
        if reported:
            install.sapi = reported
        elif info.server_api:
            install.warnings.append(f"unrecognised Server API {info.server_api!r}")

    if not install.version:
        output = _run([candidate.real, "-v"], run, install.warnings)
        parsed = parse_version_output(output or "")
        if parsed:
            install.version, sapi = parsed
            install.sapi = sapi
            install.warnings.append("phpinfo unavailable; ini files unknown")
        else:
            install.warnings.append(f"{candidate.real}: could not read the PHP version")

    if install.version:
        try:
            parse_upstream(install.version)
        except VersionError:
            install.warnings.append(f"unparseable PHP version {install.version!r}")
    return install, configure_command


def fpm_config_candidates(binary: str, branch: str | None, configure_command: str) -> list[str]:
    """Likely locations of php-fpm.conf, most specific first."""
    candidates = []
    sysconfdir = configure_option(configure_command, "sysconfdir")
    if sysconfdir:
        candidates.append(os.path.join(sysconfdir, "php-fpm.conf"))
        if branch:
            candidates.append(os.path.join(sysconfdir, "php", branch, "fpm", "php-fpm.conf"))

    # SCL-style roots: /opt/remi/php83/root/usr/sbin/php-fpm
    match = re.match(r"^(/opt/remi/(php\d+))/root/", binary)
    if match:
        candidates.append(f"/etc/opt/remi/{match.group(2)}/php-fpm.conf")
    match = re.match(r"^(/opt/cpanel/ea-php\d+/root)/", binary)
    if match:
        candidates.append(f"{match.group(1)}/etc/php-fpm.conf")

    if branch:
        candidates.append(f"/etc/php/{branch}/fpm/php-fpm.conf")  # Debian/Ubuntu
    candidates.append("/etc/php-fpm.conf")  # RHEL family
    candidates.append("/usr/local/etc/php-fpm.conf")  # source builds
    return list(dict.fromkeys(candidates))


def _rooted(path: str, root: str) -> str:
    return os.path.join(root, path.lstrip("/"))


def find_fpm_config(install: PhpInstall, configure_command: str, root: str) -> None:
    branch = _branch(install.version)
    for candidate in fpm_config_candidates(install.binary, branch, configure_command):
        if os.path.isfile(_rooted(candidate, root)):
            install.fpm_config = candidate
            return
    install.warnings.append("php-fpm.conf not found in any known location; pools not checked")


def _branch(version: str) -> str | None:
    try:
        return parse_upstream(version).branch
    except VersionError:
        return None


def module_ini_files(branch: str | None, root: str) -> list[str]:
    """ini files mod_php would load, inferred from the distro layout."""
    layouts = []
    if branch:
        layouts.append((f"/etc/php/{branch}/apache2/php.ini", f"/etc/php/{branch}/apache2/conf.d"))
    layouts.append(("/etc/php.ini", "/etc/php.d"))
    for ini, scan_dir in layouts:
        if os.path.isfile(_rooted(ini, root)):
            # PHP parses the scan dir alphabetically, as sorted() does.
            names = sorted(os.path.basename(p) for p in glob.glob(_rooted(scan_dir, root) + "/*.ini"))
            return [ini, *(f"{scan_dir}/{name}" for name in names)]
    return []


def inspect_module(path: str, enabled: bool, root: str) -> PhpInstall:
    install = PhpInstall(binary=path, sapi="apache2handler", version="", enabled=enabled)
    branch = branch_from_module_name(os.path.basename(path))
    install.ini_files = module_ini_files(branch, root)
    if install.ini_files:
        install.warnings.append("mod_php ini files inferred from the distro layout, not reported by PHP")
    else:
        install.warnings.append("mod_php ini files not found in any known layout")
    return install


def version_from_package(package_version: str) -> str | None:
    """Upstream PHP version from a package version:
    "1:8.3.6-0ubuntu0.24.04.13" -> "8.3.6", "8.0.30-8.el9_8.1" -> "8.0.30"."""
    text = package_version.split(":", 1)[-1]
    match = re.match(r"^(\d+\.\d+\.\d+)", text)
    return match.group(1) if match else None


# --- entry point ------------------------------------------------------------


def discover(
    run: Runner = run_command,
    which: Which | None = None,
    root: str = "/",
    binary_dirs: Sequence[str] | None = None,
    os_release_paths: Sequence[Path] | None = None,
) -> DiscoveryResult:
    """Find and describe every PHP install. `root` and the path arguments
    exist so tests can point discovery at a fake filesystem."""
    which = which or shutil.which
    release_paths = os_release_paths or [Path(root, p.relative_to("/")) for p in distro_mod.OS_RELEASE_PATHS]
    host_distro, distro_warnings = distro_mod.read_distro(release_paths)
    result = DiscoveryResult(distro=host_distro, warnings=list(distro_warnings))

    dirs = list(binary_dirs or BINARY_DIRS)
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if entry and entry not in dirs and binary_dirs is None:
            dirs.append(entry)

    for candidate in find_binaries(dirs, root, result.warnings, result.skipped):
        install, configure_command = inspect_binary(candidate, run)
        if install.sapi == "fpm-fcgi":
            find_fpm_config(install, configure_command, root)
        result.installs.append(install)

    modules = find_apache_modules(root)
    if modules:
        enabled = apache_php_enabled(root, result.warnings)
        for path in modules:
            result.installs.append(inspect_module(path, enabled, root))

    for install in result.installs:
        install.distro = host_distro
        package, warnings = distro_mod.lookup_package(install.binary, host_distro, run=run, which=which)
        install.package = package
        install.warnings.extend(warnings)
        if install.sapi == "apache2handler" and not install.version:
            from_package = version_from_package(package.version) if package else None
            if from_package:
                install.version = from_package
            else:
                install.warnings.append("mod_php version unknown: module is not owned by a package")

    if not result.installs:
        result.warnings.append("no PHP installation found")
    return result
