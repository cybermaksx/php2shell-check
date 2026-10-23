"""Identify the distribution and the package that owns a file.

Parsing is pure and lives in the parse_* functions. The functions that read
files or run dpkg-query / rpm take the runner as an argument, so tests can
feed recorded output instead of touching the host.

Every failure becomes a warning string; nothing is swallowed.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .models import Distro, Package, Scheme

OS_RELEASE_PATHS = (Path("/etc/os-release"), Path("/usr/lib/os-release"))
COMMAND_TIMEOUT = 15  # seconds

DEBIAN_FAMILY = {"debian", "ubuntu"}
RPM_FAMILY = {"rhel", "fedora", "centos", "suse", "opensuse", "sles", "almalinux", "rocky", "ol", "amzn"}


# --- running commands -------------------------------------------------------


class CommandError(Exception):
    pass


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str]], CommandResult]
Which = Callable[[str], "str | None"]


# PHPRC and PHP_INI_SCAN_DIR make php read a different php.ini / conf.d than
# the web server does; if they leak in from the caller's shell, `php -i`
# describes a configuration no request ever sees.
_DROPPED_ENV = ("PHPRC", "PHP_INI_SCAN_DIR")


def run_command(argv: Sequence[str]) -> CommandResult:
    """Run a command with a C locale so output is parseable.

    Raises CommandError when the command cannot be started or times out;
    a non-zero exit is returned, not raised, because callers often expect it.
    """
    env = {k: v for k, v in os.environ.items() if k not in _DROPPED_ENV}
    env.update(LC_ALL="C", LANG="C")
    try:
        proc = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=COMMAND_TIMEOUT,
            env=env,
            check=False,
        )
    except FileNotFoundError as exc:
        raise CommandError(f"{argv[0]}: not found") from exc
    except PermissionError as exc:
        raise CommandError(f"{argv[0]}: permission denied") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"{shlex.join(argv)}: timed out after {COMMAND_TIMEOUT}s") from exc
    return CommandResult(tuple(argv), proc.returncode, proc.stdout, proc.stderr)


def describe_failure(result: CommandResult) -> str:
    detail = result.stderr.strip() or result.stdout.strip() or "no output"
    return f"{shlex.join(result.argv)} exited {result.returncode}: {detail.splitlines()[0]}"


# --- /etc/os-release --------------------------------------------------------


def _unquote_os_release(raw: str) -> str | None:
    """Unquote one os-release value as os-release(5) describes it.

    Values may be bare, single-quoted or double-quoted; inside double quotes
    a backslash escapes $, `, " and \\. Returns None for unbalanced quotes.
    """
    if not raw or raw[0] not in "\"'":
        return raw
    quote = raw[0]
    if len(raw) < 2 or raw[-1] != quote:
        return None
    body = raw[1:-1]
    if quote == "'":
        return body
    out, i = [], 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body) and body[i + 1] in '$`"\\':
            out.append(body[i + 1])
            i += 2
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


def parse_os_release(text: str) -> dict[str, str]:
    """Parse os-release(5): KEY=value lines, values optionally quoted."""
    fields = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        value = _unquote_os_release(raw.strip())
        if value is None:
            continue  # unbalanced quotes; skip the line like systemd does
        fields[key.strip()] = value
    return fields


def distro_from_fields(fields: dict[str, str]) -> Distro | None:
    os_id = fields.get("ID", "").lower()
    if not os_id:
        return None
    return Distro(
        os_id=os_id,
        version_id=fields.get("VERSION_ID", ""),
        id_like=tuple(fields.get("ID_LIKE", "").lower().split()),
        pretty_name=fields.get("PRETTY_NAME", ""),
    )


def read_distro(paths: Sequence[Path] = OS_RELEASE_PATHS) -> tuple[Distro | None, list[str]]:
    warnings = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            continue
        except OSError as exc:
            warnings.append(f"cannot read {path}: {exc.strerror}")
            continue
        distro = distro_from_fields(parse_os_release(text))
        if distro is None:
            warnings.append(f"{path} has no ID field")
            continue
        if not distro.version_id:
            warnings.append(f"{path} has no VERSION_ID (rolling or testing release?)")
        return distro, warnings
    warnings.append("no os-release file found; distribution unknown")
    return None, warnings


# --- package manager output parsing -----------------------------------------


def parse_dpkg_search(output: str) -> list[str]:
    """Package names from `dpkg-query -S <path>` output.

    Lines look like "php8.3-cli:amd64: /usr/bin/php8.3" or
    "pkg-a, pkg-b: /path". Diversion lines are skipped.
    """
    names: list[str] = []
    for line in output.splitlines():
        if line.startswith(("diversion by", "local diversion")) or ": " not in line:
            continue
        packages, _, _path = line.partition(": ")
        for name in packages.split(","):
            name = name.strip()
            if name and name not in names:
                names.append(name)
    return names


def parse_dpkg_show(output: str, manager: Scheme = "dpkg") -> Package | None:
    """Parse one line of `dpkg-query -W -f='${Package}\\t${Version}\\t${Source}\\n'`.

    ${Source} is empty when the source package has the binary's name, and may
    carry its own version in parentheses: "php8.3 (8.3.6-0ubuntu0.24.04.13)".
    """
    # Only strip newlines: an empty ${Source} leaves a trailing tab that
    # .strip() would eat, losing the third column.
    lines = [line for line in output.splitlines() if line.strip()]
    parts = lines[0].split("\t") if lines else []
    if len(parts) != 3 or not parts[0] or not parts[1]:
        return None
    name, ver, source = parts
    source_name = source.split(" ", 1)[0] if source.strip() else name.split(":", 1)[0]
    return Package(name=name, version=ver, source_name=source_name, manager=manager)


RPM_QUERY_FORMAT = "%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{SOURCERPM}\\n"


def source_name_from_srpm(srpm: str) -> str | None:
    """"php-8.3.19-1.el10_0.src.rpm" -> "php"."""
    if not srpm.endswith(".src.rpm"):
        return None
    nvr = srpm[: -len(".src.rpm")]
    name, sep1, rest = nvr.rpartition("-")  # strip release
    name, sep2, _ = name.rpartition("-")  # strip version
    if not (sep1 and sep2 and name):
        return None
    return name


def parse_rpm_query(output: str) -> list[Package]:
    """Parse `rpm -qf --qf RPM_QUERY_FORMAT` output; one package per line."""
    packages = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 5:
            continue
        name, epoch, ver, release, srpm = parts
        evr = f"{ver}-{release}"
        if epoch not in ("", "(none)"):
            evr = f"{epoch}:{evr}"
        packages.append(
            Package(
                name=name,
                version=evr,
                source_name=source_name_from_srpm(srpm) or name,
                manager="rpm",
            )
        )
    return packages


# --- package lookup ---------------------------------------------------------


def manager_order(distro: Distro | None) -> list[Scheme]:
    """Which package database to ask first. Both may be installed (rpm is
    available on Debian, for instance), so the distro family decides."""
    family = set()
    if distro is not None:
        family = {distro.os_id, *distro.id_like}
    if family & RPM_FAMILY and not family & DEBIAN_FAMILY:
        return ["rpm", "dpkg"]
    return ["dpkg", "rpm"]


def candidate_paths(path: str) -> list[str]:
    """The resolved path first (/usr/bin/php is usually an alternatives
    symlink), then the path as given."""
    resolved = os.path.realpath(path)
    return [resolved] if resolved == path else [resolved, path]


def _dpkg_lookup(path: str, run: Runner) -> tuple[Package | None, bool, list[str]]:
    """Returns (package, owned, warnings). owned=False means dpkg said no."""
    search = run(["dpkg-query", "-S", path])
    if search.returncode != 0:
        if "no path found" in search.stderr:
            return None, False, []
        return None, False, [describe_failure(search)]
    names = parse_dpkg_search(search.stdout)
    if not names:
        return None, False, [f"dpkg-query -S {path}: unexpected output: {search.stdout.strip()!r}"]

    warnings = []
    if len(names) > 1:
        warnings.append(f"{path} is owned by several packages ({', '.join(names)}); using {names[0]}")
    show = run(["dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${Source}\\n", names[0]])
    if show.returncode != 0:
        return None, True, warnings + [describe_failure(show)]
    package = parse_dpkg_show(show.stdout)
    if package is None:
        return None, True, warnings + [f"dpkg-query -W {names[0]}: unexpected output: {show.stdout.strip()!r}"]
    return package, True, warnings


def _rpm_lookup(path: str, run: Runner) -> tuple[Package | None, bool, list[str]]:
    result = run(["rpm", "-qf", "--qf", RPM_QUERY_FORMAT, path])
    if result.returncode != 0:
        if "is not owned by any package" in result.stdout + result.stderr:
            return None, False, []
        return None, False, [describe_failure(result)]
    packages = parse_rpm_query(result.stdout)
    if not packages:
        return None, False, [f"rpm -qf {path}: unexpected output: {result.stdout.strip()!r}"]
    warnings = []
    if len({p.name for p in packages}) > 1:
        names = ", ".join(sorted({p.name for p in packages}))
        warnings.append(f"{path} is owned by several packages ({names}); using {packages[0].name}")
    return packages[0], True, warnings


_QUERY_BINARY = {"dpkg": "dpkg-query", "rpm": "rpm"}
_LOOKUPS = {"dpkg": _dpkg_lookup, "rpm": _rpm_lookup}


def lookup_package(
    path: str,
    distro: Distro | None,
    run: Runner = run_command,
    which: Which = shutil.which,
) -> tuple[Package | None, list[str]]:
    """Find the package that owns `path`.

    Returns (None, []) when no package owns it (a source build, for example)
    and (None, [warnings]) when a lookup failed, so the caller can tell
    "unpackaged" from "could not find out".
    """
    warnings: list[str] = []
    managers = [m for m in manager_order(distro) if which(_QUERY_BINARY[m])]
    if not managers:
        return None, ["neither dpkg-query nor rpm is available; package ownership unknown"]

    for manager in managers:
        for candidate in candidate_paths(path):
            try:
                package, owned, found_warnings = _LOOKUPS[manager](candidate, run)
            except CommandError as exc:
                warnings.append(str(exc))
                break
            warnings.extend(found_warnings)
            if package is not None:
                return package, warnings
            if owned:
                break  # owned, but details failed; another path won't help
    return None, warnings
