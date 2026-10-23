"""--fix: apply the interim mitigations to PHP configuration.

    plan (pure) -> show diff -> confirm -> backup -> write -> validate
    -> restart active services -> re-check -> roll back on any failure

What it changes:
- php.ini-level values: one drop-in, conf.d/99-php2shell-check.ini, in the
  install's scan directory.
- FPM pools: php_admin_value / php_admin_flag lines in the pool (an
  existing admin line for the same setting is replaced). Admin values also
  stop .user.ini from overriding them.

What it never changes: packages, nginx or Apache configuration, .htaccess,
.user.ini or [PATH=]/[HOST=] sections. Failures that live there become
manual steps in the plan. It also never starts a service that was not
already running.
"""

from __future__ import annotations

import datetime
import difflib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .advisories import AdvisoryDB
from .config import FileSystem, ParseResult, Pool, fpm_prefix, parse_fpm
from .distro import CommandError, Runner, Which, describe_failure, run_command
from .models import FailingContext, Finding, InstallStatus, Mitigation, PhpInstall
from .version import VersionError, parse_upstream

DROPIN_NAME = "99-php2shell-check.ini"
DEFAULT_BACKUP_ROOT = "/var/backups/php2shell-check"


# --- the plan ---------------------------------------------------------------


@dataclass
class FileChange:
    path: str
    before: str | None  # None: the file is created
    after: str
    reasons: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Target:
    """A (install, check, context) that must be satisfied after the fix."""

    binary: str
    check_id: str
    context: str


@dataclass
class Plan:
    changes: dict[str, FileChange] = field(default_factory=dict)
    targets: list[Target] = field(default_factory=list)
    installs: list[PhpInstall] = field(default_factory=list)  # whose config changes
    manual: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # side effects of each mitigation

    @property
    def empty(self) -> bool:
        return not self.changes


def ini_line(m: Mitigation) -> str:
    value = m.expect.value
    if m.type == "bool":
        value = "On" if value not in ("0", "", "off", "Off") else "Off"
    return f"{m.setting} = {value}"


def fpm_line(m: Mitigation) -> str:
    if m.type == "bool":
        flag = "on" if m.expect.value not in ("0", "", "off", "Off") else "off"
        return f"php_admin_flag[{m.setting}] = {flag}"
    return f"php_admin_value[{m.setting}] = {m.expect.value}"


def _origin_path(origin: str) -> str:
    return origin.rsplit(":", 1)[0] if re.search(r":\d+$", origin) else origin


def _origin_line(origin: str) -> int | None:
    match = re.search(r":(\d+)$", origin)
    return int(match.group(1)) if match else None


def classify(install: PhpInstall, ctx: FailingContext) -> tuple[str, str]:
    """How a failing context can be fixed: ("pool", name), ("dropin", ""),
    or ("manual", explanation)."""
    if install.sapi == "fpm-fcgi" and ctx.context.startswith("pool "):
        if " after a request from " in ctx.context:
            source = ctx.context.split(" after a request from ", 1)[1].removesuffix(" (target unknown, assumed)")
            return ("manual", f"{source}: the web server sends this setting with PHP_VALUE/PHP_ADMIN_VALUE; "
                              "remove it there or send the safe value")
        return ("pool", ctx.context[len("pool "):])
    if ctx.context.startswith("php.ini ["):
        return ("manual", f"{ctx.origin}: set inside a php.ini {ctx.context[len('php.ini '):]} section; edit it there")

    path = _origin_path(ctx.origin)
    if ctx.origin == "PHP default" or path in install.ini_files:
        if install.ini_scan_dir is None:
            return ("manual", f"no conf.d directory is scanned; set it in {install.ini_files[0] if install.ini_files else 'php.ini'}")
        if (
            os.path.dirname(path) == install.ini_scan_dir.rstrip("/")
            and os.path.basename(path) > DROPIN_NAME
        ):
            return ("manual", f"{ctx.origin} sorts after {DROPIN_NAME} and would override it; edit it there")
        return ("dropin", "")
    return ("manual", f"{ctx.origin}: set in {ctx.context}; edit it there")


def _set_dropin_value(text: str | None, m: Mitigation, header: str) -> str:
    """Add or replace one setting in our drop-in."""
    lines = text.splitlines() if text else header.splitlines()
    pattern = re.compile(rf"^\s*{re.escape(m.setting)}\s*=")
    for i, line in enumerate(lines):
        if pattern.match(line):
            lines[i] = ini_line(m)
            return "\n".join(lines) + "\n"
    lines.append(ini_line(m))
    return "\n".join(lines) + "\n"


def _insert_into_pool(text: str, pool: str, line: str, comment: str) -> str | None:
    """Append `line` at the end of the [pool] section; None if not found."""
    lines = text.splitlines()
    header = next((i for i, l in enumerate(lines) if l.strip() == f"[{pool}]"), None)
    if header is None:
        return None
    end = next((i for i in range(header + 1, len(lines)) if lines[i].strip().startswith("[")), len(lines))
    while end > header + 1 and not lines[end - 1].strip():
        end -= 1
    lines[end:end] = [comment, line]
    return "\n".join(lines) + "\n"


def _replace_line(text: str, number: int, line: str, comment: str) -> str:
    lines = text.splitlines()
    lines[number - 1 : number] = [comment, line]
    return "\n".join(lines) + "\n"


def build_plan(
    findings: Sequence[Finding],
    db: AdvisoryDB,
    fs: FileSystem,
    today: str,
    only: set[str] | None = None,
) -> Plan:
    """Work out every file change, without touching anything."""
    plan = Plan()
    header = (
        f"; Written by php2shell-check on {today}.\n"
        "; Interim mitigations for CVE-2026-109618 / CVE-2026-109619 (PHP2Shell).\n"
        "; They reduce exposure but do not fix the bugs: update PHP, then remove this file.\n"
    )
    comment = f"; php2shell-check {today}: interim mitigation, remove after updating PHP"
    pools_by_conf: dict[str, dict[str, Pool]] = {}
    # (path, line number) -> new line, and (path, pool) -> lines to append.
    replacements: dict[str, dict[int, str]] = {}
    insertions: dict[str, list[tuple[str, str]]] = {}
    used: set[str] = set()

    def text_of(path: str) -> str | None:
        if path in plan.changes:
            return plan.changes[path].after
        return fs.read(path)

    def change(path: str, after: str, reason: str) -> None:
        if path not in plan.changes:
            plan.changes[path] = FileChange(path, fs.read(path), after)
        plan.changes[path].after = after
        if reason not in plan.changes[path].reasons:
            plan.changes[path].reasons.append(reason)

    for finding in findings:
        if finding.status is InstallStatus.PATCHED:
            continue
        install = finding.install
        for check in finding.mitigations:
            if check.satisfied is True or (only and check.id not in only):
                continue
            mitigation = db.mitigations[check.id]
            for ctx in check.failing:
                kind, detail = classify(install, ctx)
                reason = f"{check.id} for {install.sapi} {install.binary}"
                if kind == "manual":
                    item = f"{mitigation.setting} ({install.sapi} {install.binary}): {detail}"
                    if item not in plan.manual:
                        plan.manual.append(item)
                    continue

                if kind == "dropin":
                    path = os.path.join(install.ini_scan_dir or "", DROPIN_NAME)
                    change(path, _set_dropin_value(text_of(path), mitigation, header), reason)
                else:
                    conf = install.fpm_config or ""
                    if conf not in pools_by_conf:
                        pools = parse_fpm(fs, conf, ParseResult(), prefix=fpm_prefix(install.binary))
                        pools_by_conf[conf] = {p.name: p for p in pools}
                    pool = pools_by_conf[conf].get(detail)
                    if pool is None:
                        plan.manual.append(f"{mitigation.setting}: pool {detail} not found in {conf}; edit it by hand")
                        continue
                    existing = next((a for a in pool.admin_values if a.setting == mitigation.setting), None)
                    if existing is not None and _origin_line(existing.origin):
                        path = _origin_path(existing.origin)
                        replacements.setdefault(path, {})[_origin_line(existing.origin)] = fpm_line(mitigation)
                    else:
                        path = _origin_path(pool.origin)
                        entry = (pool.name, fpm_line(mitigation))
                        if entry not in insertions.setdefault(path, []):
                            insertions[path].append(entry)
                    plan.changes.setdefault(path, FileChange(path, fs.read(path), fs.read(path) or ""))
                    if reason not in plan.changes[path].reasons:
                        plan.changes[path].reasons.append(reason)

                plan.targets.append(Target(install.binary, check.id, ctx.context))
                if install not in plan.installs:
                    plan.installs.append(install)
                if mitigation.id not in used:
                    used.add(mitigation.id)
                    plan.notes.append(f"{mitigation.setting}: {mitigation.note}")

    # Pool edits: replacements first (original line numbers), then appends.
    for path, by_line in replacements.items():
        text = plan.changes[path].before or ""
        for number in sorted(by_line, reverse=True):
            text = _replace_line(text, number, by_line[number], comment)
        plan.changes[path].after = text
    for path, entries in insertions.items():
        text = plan.changes[path].after
        for pool_name, line in entries:
            updated = _insert_into_pool(text, pool_name, line, comment)
            if updated is None:
                plan.manual.append(f"[{pool_name}] header not found in {path}; add `{line}` by hand")
                continue
            text = updated
        plan.changes[path].after = text

    plan.changes = {p: c for p, c in plan.changes.items() if c.after != c.before}
    return plan


def render_plan(plan: Plan) -> str:
    out: list[str] = []
    if plan.empty:
        out.append("Nothing to change automatically.")
    for change in plan.changes.values():
        action = "create" if change.before is None else "modify"
        out.append(f"{action} {change.path}")
        for reason in change.reasons:
            out.append(f"  for {reason}")
        diff = difflib.unified_diff(
            (change.before or "").splitlines(keepends=True),
            change.after.splitlines(keepends=True),
            fromfile=change.path if change.before is not None else "/dev/null",
            tofile=change.path,
        )
        out.extend("  " + line.rstrip("\n") for line in diff)
        out.append("")
    if plan.notes:
        out.append("Side effects:")
        out.extend(f"  - {n}" for n in plan.notes)
        out.append("")
    if plan.manual:
        out.append("Manual steps (not changed automatically):")
        out.extend(f"  - {m}" for m in plan.manual)
        out.append("")
    return "\n".join(out)


# --- applying it ------------------------------------------------------------


@dataclass
class ApplyResult:
    ok: bool
    messages: list[str] = field(default_factory=list)
    backup_dir: str | None = None
    rolled_back: bool = False


def _host(path: str, root: str) -> str:
    return os.path.join(root, path.lstrip("/"))


def _write_atomic(host_path: str, text: str, like: str | None) -> None:
    """Write via a temp file in the same directory, keeping owner and mode."""
    directory = os.path.dirname(host_path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".php2shell-check.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        if like and os.path.exists(like):
            st = os.stat(like)
            os.chmod(tmp, st.st_mode & 0o7777)
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except PermissionError:
                pass  # not root: keep our ownership; only happens in tests
        else:
            os.chmod(tmp, 0o644)
        os.replace(tmp, host_path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def validation_commands(installs: Sequence[PhpInstall], which: Which) -> list[list[str]]:
    commands: list[list[str]] = []
    for install in installs:
        if install.sapi == "fpm-fcgi":
            cmd = [install.binary, "-t"]
            if install.fpm_config:
                cmd += ["-y", install.fpm_config]
        elif install.sapi == "apache2handler":
            tool = next((t for t in ("apache2ctl", "apachectl", "httpd") if which(t)), None)
            if tool is None:
                continue
            cmd = [tool, "-t"]
        elif install.sapi == "frankenphp":
            continue
        else:
            cmd = [install.binary, "-v"]
        if cmd not in commands:
            commands.append(cmd)
    return commands


_INI_PROBLEM = re.compile(r"(PHP (Warning|Parse error|Fatal error)|syntax error)", re.I)


def validate(commands: Sequence[list[str]], run: Runner) -> list[str]:
    problems = []
    for cmd in commands:
        try:
            result = run(cmd)
        except CommandError as exc:
            problems.append(str(exc))
            continue
        if result.returncode != 0:
            problems.append(describe_failure(result))
        elif _INI_PROBLEM.search(result.stdout + result.stderr):
            line = next(l for l in (result.stdout + result.stderr).splitlines() if _INI_PROBLEM.search(l))
            problems.append(f"{' '.join(cmd)}: {line.strip()}")
    return problems


def service_units(install: PhpInstall) -> list[str]:
    """systemd units that may run this install, most specific first."""
    try:
        branch = parse_upstream(install.version).branch
    except VersionError:
        branch = ""
    flat = branch.replace(".", "")
    if install.sapi == "fpm-fcgi":
        units = []
        match = re.match(r"^/opt/remi/(php\d+)/", install.binary)
        if match:
            units.append(f"{match.group(1)}-php-fpm")
        match = re.match(r"^/opt/cpanel/(ea-php\d+)/", install.binary)
        if match:
            units.append(f"{match.group(1)}-php-fpm")
        if branch:
            units.append(f"php{branch}-fpm")
        units.append("php-fpm")
        if flat:
            units.append(f"php{flat}-php-fpm")
        return list(dict.fromkeys(units))
    if install.sapi == "apache2handler":
        return ["apache2", "httpd"]
    if install.sapi == "litespeed":
        return ["lsws", "lshttpd"]
    return []


def restart_services(installs: Sequence[PhpInstall], run: Runner, which: Which) -> tuple[list[str], list[str], list[str]]:
    """Restart every *active* unit serving these installs.

    Returns (restarted, messages, failures). A full restart, because a
    reload keeps old workers and Red Hat's bulletin says it is not enough.
    """
    restarted: list[str] = []
    messages: list[str] = []
    failures: list[str] = []
    if not which("systemctl"):
        messages.append("systemctl not found: restart PHP-FPM and the web server yourself")
        return restarted, messages, failures
    for install in installs:
        if install.sapi == "cli":
            continue
        if install.sapi == "cgi-fcgi":
            messages.append(
                f"{install.binary}: CGI reads php.ini per request; if it runs as a persistent "
                "FastCGI process (mod_fcgid, spawn-fcgi), restart that yourself"
            )
            continue
        found = False
        for unit in service_units(install):
            if unit in restarted:
                found = True
                break
            try:
                active = run(["systemctl", "is-active", "--quiet", unit]).returncode == 0
            except CommandError as exc:
                failures.append(str(exc))
                continue
            if not active:
                continue
            found = True
            try:
                result = run(["systemctl", "restart", unit])
            except CommandError as exc:
                failures.append(str(exc))
                break
            if result.returncode != 0:
                failures.append(describe_failure(result))
            else:
                restarted.append(unit)
                messages.append(f"restarted {unit}")
            break
        if not found:
            messages.append(f"no running service found for {install.sapi} {install.binary}; restart it yourself")
    return restarted, messages, failures


def apply_plan(
    plan: Plan,
    recheck: Callable[[], list[str]],
    backup_root: str = DEFAULT_BACKUP_ROOT,
    root: str = "/",
    run: Runner = run_command,
    which: Which = shutil.which,
    restart: bool = True,
    timestamp: str = "",
) -> ApplyResult:
    result = ApplyResult(ok=False)
    stamp = timestamp or datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = _host(os.path.join(backup_root, stamp), root)
    result.backup_dir = os.path.join(backup_root, stamp)

    # 1. Nothing changed since planning?
    for change in plan.changes.values():
        host = _host(change.path, root)
        current = Path(host).read_text(encoding="utf-8") if os.path.exists(host) else None
        if current != change.before:
            result.messages.append(f"{change.path} changed since the plan was made; nothing was written")
            return result

    # 2. Backups and manifest, before any write.
    manifest: dict[str, str] = {}
    try:
        os.makedirs(backup_dir, exist_ok=False)
        for change in plan.changes.values():
            if change.before is None:
                manifest[change.path] = "created"
                continue
            target = os.path.join(backup_dir, change.path.lstrip("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(_host(change.path, root), target)
            manifest[change.path] = "modified"
        with open(os.path.join(backup_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
    except OSError as exc:
        result.messages.append(f"cannot write backups to {result.backup_dir}: {exc.strerror}; nothing was changed")
        return result
    result.messages.append(f"backups in {result.backup_dir}")

    written: list[str] = []
    restart_attempted = False

    def rollback(why: list[str]) -> ApplyResult:
        result.messages.extend(f"failed: {w}" for w in why)
        for path in reversed(written):
            host = _host(path, root)
            try:
                if manifest[path] == "created":
                    os.unlink(host)
                else:
                    backup = os.path.join(backup_dir, path.lstrip("/"))
                    _write_atomic(host, Path(backup).read_text(encoding="utf-8"), backup)
                result.messages.append(f"restored {path}")
            except OSError as exc:
                result.messages.append(f"could not restore {path}: {exc.strerror}; the backup is in {result.backup_dir}")
        if restart_attempted:
            # Restart again so workers drop the values we just removed, or
            # come back up if the first restart failed.
            _, messages, failures = restart_services(plan.installs, run, which)
            result.messages.extend(messages)
            result.messages.extend(f"failed: {f}" for f in failures)
        result.rolled_back = True
        return result

    # 3. Write.
    for change in plan.changes.values():
        host = _host(change.path, root)
        try:
            _write_atomic(host, change.after, host if change.before is not None else None)
        except OSError as exc:
            return rollback([f"cannot write {change.path}: {exc.strerror}"])
        written.append(change.path)
        result.messages.append(f"wrote {change.path}")

    # 4. Validate.
    problems = validate(validation_commands(plan.installs, which), run)
    if problems:
        return rollback(problems)

    # 5. Restart.
    if restart:
        restart_attempted = True
        _, messages, failures = restart_services(plan.installs, run, which)
        result.messages.extend(messages)
        if failures:
            return rollback(failures)
    else:
        result.messages.append("not restarting (--no-restart): restart PHP-FPM and the web server yourself")

    # 6. Re-check.
    failures = recheck()
    if failures:
        return rollback(failures)

    result.ok = True
    return result


def recheck_targets(plan: Plan, findings: Sequence[Finding]) -> list[str]:
    """Targets from the plan that a fresh assessment still finds unmet."""
    failures = []
    by_binary = {f.install.binary: f for f in findings}
    for target in plan.targets:
        finding = by_binary.get(target.binary)
        if finding is None:
            failures.append(f"{target.binary} disappeared after the change")
            continue
        check = next((c for c in finding.mitigations if c.id == target.check_id), None)
        if check is None:
            continue  # no longer needed, e.g. the install now counts as patched
        if any(ctx.context == target.context for ctx in check.failing):
            value = next(c for c in check.failing if c.context == target.context)
            failures.append(
                f"{target.check_id} still not set in {target.context} for {target.binary} "
                f"({value.value!r} from {value.origin})"
            )
    return failures
