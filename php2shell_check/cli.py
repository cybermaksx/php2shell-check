"""Command line entry point."""

from __future__ import annotations

import argparse
import datetime
import os
import sys
import traceback
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from . import __version__, remediate
from .advisories import DEFAULT_PATH, AdvisoryDB, AdvisoryError, load
from .assess import EXIT_ERROR, assess, exit_code, upgrade_advice
from .config import WebConfig, check_install, load_web_config
from .discovery import DiscoveryResult, HostFileSystem, discover
from .models import Finding
from .report import render_json, render_text

DESCRIPTION = """\
Audit this server for exposure to the PHP2Shell vulnerabilities
(CVE-2026-109618, CVE-2026-109619) and related advisories.

Read-only by default: it runs PHP binaries with -i / -v, queries dpkg or
rpm, and reads configuration files. It never sends requests. Only --fix
changes anything, and only PHP configuration, after showing a diff.
"""

EPILOG = """\
exit codes:
  0  every install is patched or mitigated
  1  an install is VULNERABLE, or its mitigations are EXPOSED
  2  an EOL install without full mitigation
  3  an UNKNOWN install without full mitigation
  4  runtime error
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell-check",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    parser.add_argument("-v", "--verbose", action="store_true", help="show hardening values, aliases and skipped files")
    parser.add_argument(
        "--advisories",
        type=Path,
        default=DEFAULT_PATH,
        metavar="FILE",
        help=f"advisory data to use (default: {DEFAULT_PATH})",
    )
    parser.add_argument(
        "--scan-dir",
        action="append",
        default=[],
        metavar="DIR",
        help="also look for .htaccess and .user.ini under DIR (repeatable)",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=200_000,
        metavar="N",
        help="stop walking web roots after N entries (default: 200000)",
    )
    fix = parser.add_argument_group("remediation")
    fix.add_argument("--fix", action="store_true", help="apply the interim mitigations to PHP configuration")
    fix.add_argument("--dry-run", action="store_true", help="with --fix: show the plan and diff, change nothing")
    fix.add_argument("-y", "--yes", action="store_true", help="with --fix: do not ask for confirmation")
    fix.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="ID",
        help="with --fix: apply only this mitigation id, e.g. session-upload-progress-off (repeatable)",
    )
    fix.add_argument("--no-restart", action="store_true", help="with --fix: do not restart services")
    fix.add_argument(
        "--backup-dir",
        default=remediate.DEFAULT_BACKUP_ROOT,
        metavar="DIR",
        help=f"with --fix: where backups go (default: {remediate.DEFAULT_BACKUP_ROOT})",
    )
    parser.add_argument("--debug", action="store_true", help="show a traceback on errors")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


@dataclass
class HostAssessment:
    discovery: DiscoveryResult
    web: WebConfig
    fs: HostFileSystem
    findings: list[Finding]
    warnings: list[str]


def assess_host(args: argparse.Namespace, db: AdvisoryDB) -> HostAssessment:
    result = discover()
    fs = HostFileSystem(max_files=args.max_files)
    web = load_web_config(fs)
    checks = [*db.mitigations.values(), *db.hardening]

    findings = []
    for install in result.installs:
        report = check_install(install, checks, fs, web, extra_roots=args.scan_dir)
        findings.append(assess(install, db, report))

    warnings = [*result.warnings, *web.warnings, *dict.fromkeys(fs.warnings)]
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        warnings.append("not running as root: some config files and package data may be unreadable")
    return HostAssessment(result, web, fs, findings, warnings)


def print_report(args: argparse.Namespace, db: AdvisoryDB, host: HostAssessment) -> int:
    code = exit_code(host.findings)
    advice = upgrade_advice(host.findings, db)
    if args.json:
        distro = None
        if host.discovery.distro:
            d = host.discovery.distro
            distro = {"id": d.os_id, "version_id": d.version_id, "name": d.pretty_name}
        sys.stdout.write(render_json(host.findings, db, code, host.warnings, host.discovery.skipped, distro, advice))
    else:
        sys.stdout.write(render_text(host.findings, db, host.warnings, host.discovery.skipped, args.verbose, advice))
    return code


def confirm(question: str, ask: Callable[[str], str] = input) -> bool:
    try:
        return ask(f"{question} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def run_fix(args: argparse.Namespace, db: AdvisoryDB, host: HostAssessment) -> int:
    unknown = set(args.only) - set(db.mitigations)
    if unknown:
        print(f"php2shell-check: unknown mitigation id(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return EXIT_ERROR
    today = datetime.date.today().isoformat()
    plan = remediate.build_plan(host.findings, db, host.fs, today, only=set(args.only) or None)

    print("Planned changes:\n")
    print(remediate.render_plan(plan))
    if plan.empty or args.dry_run:
        if args.dry_run:
            print("Dry run: nothing was changed.")
        return exit_code(host.findings)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("php2shell-check: --fix needs root to write configuration and restart services", file=sys.stderr)
        return EXIT_ERROR
    if not args.yes:
        if not sys.stdin.isatty():
            print("php2shell-check: not a terminal; pass --yes to apply without confirmation", file=sys.stderr)
            return EXIT_ERROR
        if not confirm("Apply these changes?"):
            print("Nothing was changed.")
            return exit_code(host.findings)

    after: list[HostAssessment] = []

    def recheck() -> list[str]:
        after.append(assess_host(args, db))
        return remediate.recheck_targets(plan, after[-1].findings)

    result = remediate.apply_plan(
        plan, recheck, backup_root=args.backup_dir, restart=not args.no_restart
    )
    for message in result.messages:
        print(message)
    if not result.ok:
        print("\nThe change was rolled back." if result.rolled_back else "\nNothing was changed.")
        return EXIT_ERROR

    print("\nDone. Current state:\n")
    return print_report(args, db, after[-1])


def run(args: argparse.Namespace) -> int:
    try:
        db = load(args.advisories)
    except AdvisoryError as exc:
        print(f"php2shell-check: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if (args.dry_run or args.yes or args.only or args.no_restart) and not args.fix:
        print("php2shell-check: --dry-run, --yes, --only and --no-restart need --fix", file=sys.stderr)
        return EXIT_ERROR
    if args.fix and args.json:
        print("php2shell-check: --fix cannot be combined with --json", file=sys.stderr)
        return EXIT_ERROR

    host = assess_host(args, db)
    if args.fix:
        return run_fix(args, db, host)
    return print_report(args, db, host)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        print("php2shell-check: interrupted", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # report, never crash with a bare traceback
        if args.debug:
            traceback.print_exc()
        print(f"php2shell-check: unexpected error: {exc!r} (run with --debug for details)", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
