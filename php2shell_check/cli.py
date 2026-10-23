"""Command line entry point."""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .advisories import DEFAULT_PATH, AdvisoryError, load
from .assess import EXIT_ERROR, assess, exit_code
from .config import check_install, load_web_config
from .discovery import HostFileSystem, discover
from .report import render_json, render_text

DESCRIPTION = """\
Audit this server for exposure to the PHP2Shell vulnerabilities
(CVE-2026-109618, CVE-2026-109619) and related advisories.

Read-only: it runs PHP binaries with -i / -v, queries dpkg or rpm, and reads
configuration files. It never sends requests or changes anything.
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
    parser.add_argument("--debug", action="store_true", help="show a traceback on errors")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def run(args: argparse.Namespace) -> int:
    try:
        db = load(args.advisories)
    except AdvisoryError as exc:
        print(f"php2shell-check: {exc}", file=sys.stderr)
        return EXIT_ERROR

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

    code = exit_code(findings)
    if args.json:
        distro = None
        if result.distro:
            distro = {"id": result.distro.os_id, "version_id": result.distro.version_id, "name": result.distro.pretty_name}
        sys.stdout.write(render_json(findings, db, code, warnings, result.skipped, distro))
    else:
        sys.stdout.write(render_text(findings, db, warnings, result.skipped, args.verbose))
    return code


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
