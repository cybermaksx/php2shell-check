"""Render findings as a terminal table or as JSON. Pure: returns strings."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from . import __version__
from .advisories import AdvisoryDB
from .models import Finding, InstallStatus, MitigationStatus, SettingCheck

DISCLAIMER = (
    "Mitigations reduce exposure to specific attack paths; they do not make an "
    "install safe. Only a patched PHP fixes these vulnerabilities."
)


def _package(finding: Finding) -> str:
    p = finding.install.package
    return f"{p.name} {p.version}" if p else "-"


def _mitigation(finding: Finding) -> str:
    return finding.mitigation.value if finding.mitigation else "-"


def _table(rows: list[list[str]]) -> list[str]:
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = []
    for n, row in enumerate(rows):
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
        if n == 0:
            lines.append("  ".join("-" * w for w in widths))
    return lines


def _check_lines(check: SettingCheck, verbose: bool) -> list[str]:
    if check.satisfied is True:
        state = "ok"
    elif check.satisfied is None:
        state = "undecided"
    else:
        state = "NOT SET"
    lines = [f"    [{state}] {check.setting}  ({check.id})"]
    for ctx in check.failing:
        lines.append(f"        {ctx.context}: {ctx.value!r} from {ctx.origin}")
    for note in check.notes:
        lines.append(f"        note: {note}")
    for warning in check.warnings:
        lines.append(f"        warning: {warning}")
    if verbose and check.note:
        lines.append(f"        why: {check.note}")
    return lines


def render_text(
    findings: Sequence[Finding],
    db: AdvisoryDB,
    warnings: Sequence[str] = (),
    skipped: Sequence[tuple[str, str]] = (),
    verbose: bool = False,
) -> str:
    out: list[str] = [f"php2shell-check {__version__}  (advisory data {db.updated})", ""]
    if not findings:
        out.append("No PHP installation found.")
    else:
        rows = [["SAPI", "BINARY", "VERSION", "PACKAGE", "STATUS", "MITIGATION"]]
        for f in findings:
            rows.append(
                [f.install.sapi, f.install.binary, f.install.version or "?", _package(f), f.status.value, _mitigation(f)]
            )
        out.extend(_table(rows))

    for f in findings:
        out += ["", f"{f.install.sapi} {f.install.binary}: {f.status.value}"]
        if f.install.aliases and verbose:
            out.append(f"  aliases: {', '.join(f.install.aliases)}")
        for v in f.verdicts:
            label = v.status.value if v.status else "n/a"
            out.append(f"  {v.advisory_id}: {label} - {v.reason}")
        for reason in f.reasons:
            out.append(f"  - {reason}")
        if f.mitigations:
            out.append(f"  mitigations: {_mitigation(f)}")
            for check in f.mitigations:
                out.extend(_check_lines(check, verbose))
        if verbose and f.hardening:
            out.append("  hardening (informational):")
            for check in f.hardening:
                values = ", ".join(sorted({c.value or "''" for c in check.values}))
                state = "" if check.satisfied is not False else "  <- consider changing"
                out.append(f"    {check.setting} = {values}{state}")
        for warning in f.warnings:
            out.append(f"  warning: {warning}")

    if skipped and verbose:
        out += ["", "Skipped:"]
        out += [f"  {path}: {why}" for path, why in skipped]
    if warnings:
        out += ["", "Warnings:"]
        out += [f"  {w}" for w in warnings]
    if any(f.mitigation is not None for f in findings):
        out += ["", DISCLAIMER]
    return "\n".join(out) + "\n"


# --- JSON -------------------------------------------------------------------


def _check_dict(check: SettingCheck) -> dict[str, Any]:
    return {
        "id": check.id,
        "setting": check.setting,
        "satisfied": check.satisfied,
        "contexts": [{"context": c.context, "value": c.value, "origin": c.origin} for c in check.values],
        "failing": [{"context": c.context, "value": c.value, "origin": c.origin} for c in check.failing],
        "notes": check.notes,
        "warnings": check.warnings,
    }


def finding_dict(f: Finding) -> dict[str, Any]:
    i = f.install
    return {
        "binary": i.binary,
        "aliases": i.aliases,
        "sapi": i.sapi,
        "version": i.version or None,
        "package": (
            {"name": i.package.name, "version": i.package.version, "source": i.package.source_name, "manager": i.package.manager}
            if i.package
            else None
        ),
        "ini_files": i.ini_files,
        "fpm_config": i.fpm_config,
        "status": f.status.value,
        "mitigation": f.mitigation.value if f.mitigation else None,
        "advisories": [
            {"id": v.advisory_id, "status": v.status.value if v.status else None, "basis": v.basis, "reason": v.reason}
            for v in f.verdicts
        ],
        "mitigations": [_check_dict(c) for c in f.mitigations],
        "hardening": [_check_dict(c) for c in f.hardening],
        "reasons": f.reasons,
        "warnings": f.warnings,
    }


def render_json(
    findings: Sequence[Finding],
    db: AdvisoryDB,
    exit_code: int,
    warnings: Sequence[str] = (),
    skipped: Sequence[tuple[str, str]] = (),
    distro: dict[str, str] | None = None,
) -> str:
    document = {
        "tool": "php2shell-check",
        "version": __version__,
        "advisory_data": db.updated,
        "exit_code": exit_code,
        "distro": distro,
        "summary": {
            status.value: sum(1 for f in findings if f.status is status) for status in InstallStatus
        }
        | {status.value: sum(1 for f in findings if f.mitigation is status) for status in MitigationStatus},
        "installs": [finding_dict(f) for f in findings],
        "skipped": [{"path": p, "reason": r} for p, r in skipped],
        "warnings": list(warnings),
        "sources": {s.id: s.url for s in db.sources.values()},
        "disclaimer": DISCLAIMER,
    }
    return json.dumps(document, indent=2) + "\n"
