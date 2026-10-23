"""Turn an install, the advisory data and its config results into a Finding.

Pure: no files, no processes. The rules, in order:

1. A distro row for (os ID, VERSION_ID, source package) decides alone:
   package >= fixed -> PATCHED, below -> VULNERABLE, not_affected -> skip.
   Distros backport without changing the upstream version, so this is the
   only way to call a distro package VULNERABLE.
2. Without a row, an upstream version at or above the fixed release is
   PATCHED: the release itself contains the fix.
3. Without a row and below the fixed release: EOL branch -> EOL, otherwise
   UNKNOWN, because the package may carry a backport we cannot see.
4. The install's status is the worst across advisories:
   VULNERABLE > EOL > UNKNOWN > PATCHED.

Mitigations are checked for anything not PATCHED. upgrade_advice() says
what to run to get a fixed PHP; nothing here runs it.
"""

from __future__ import annotations

from collections.abc import Sequence

from .advisories import AdvisoryDB, find_distro_fix, find_upstream_fix, mitigations_for
from .config import ConfigReport, SettingResult
from .models import (
    Advisory,
    AdvisoryVerdict,
    Distro,
    FailingContext,
    Finding,
    InstallStatus,
    MitigationStatus,
    PhpInstall,
    SettingCheck,
    UpgradeAdvice,
)
from .remediate import SUSE_FAMILY, service_units
from .version import VersionError, branch_or_none, compare_package, compare_upstream, is_at_least, parse_upstream

_SEVERITY = {
    InstallStatus.VULNERABLE: 3,
    InstallStatus.EOL: 2,
    InstallStatus.UNKNOWN: 1,
    InstallStatus.PATCHED: 0,
}

# SAPIs that do not serve web requests; the advisories cover web SAPIs only.
NON_WEB_SAPIS = {"cli", "phpdbg", "embed"}


def worst(statuses: Sequence[InstallStatus]) -> InstallStatus:
    return max(statuses, key=lambda s: _SEVERITY[s])


def judge_advisory(advisory: Advisory, install: PhpInstall, db: AdvisoryDB) -> AdvisoryVerdict:
    adv = advisory.id
    if not advisory.has_version_data:
        return AdvisoryVerdict(adv, None, "none", "no affected or fixed versions published yet")

    try:
        version = parse_upstream(install.version)
    except VersionError:
        return AdvisoryVerdict(adv, InstallStatus.UNKNOWN, "none", f"PHP version {install.version!r} is unknown")

    package, distro = install.package, install.distro
    if package is not None and distro is not None:
        row = find_distro_fix(advisory, distro, package.source_name)
        if row is not None:
            where = f"{distro.os_id} {distro.version_id} {row.source_package}"
            if row.not_affected:
                return AdvisoryVerdict(adv, None, "distro", f"{where}: not affected per {', '.join(row.sources)}")
            if row.scheme != package.manager:
                return AdvisoryVerdict(
                    adv,
                    InstallStatus.UNKNOWN,
                    "distro",
                    f"{where}: advisory row uses {row.scheme} versions but the package is from {package.manager}",
                )
            try:
                patched = is_at_least(package.version, row.fixed or "", row.scheme)
            except VersionError as exc:
                return AdvisoryVerdict(adv, InstallStatus.UNKNOWN, "distro", f"{where}: {exc}")
            fixed_by = f"{row.fixed} ({row.advisory})" if row.advisory else row.fixed
            if patched:
                return AdvisoryVerdict(adv, InstallStatus.PATCHED, "distro", f"package {package.version} >= {fixed_by}")
            return AdvisoryVerdict(adv, InstallStatus.VULNERABLE, "distro", f"package {package.version} < {fixed_by}")

    branch = version.branch
    fix = find_upstream_fix(advisory, branch)
    if fix is not None and compare_upstream(install.version, fix.version) >= 0:
        return AdvisoryVerdict(adv, InstallStatus.PATCHED, "upstream", f"PHP {version} >= {fix.version}")

    info = db.branches.get(branch)
    if info is not None and info.eol:
        backport = f"; source backport branch {info.source_backport} exists" if info.source_backport else ""
        return AdvisoryVerdict(
            adv, InstallStatus.EOL, "eol", f"PHP {branch} is end-of-life upstream with no fixed release{backport}"
        )
    if fix is None:
        return AdvisoryVerdict(adv, InstallStatus.UNKNOWN, "none", f"no fix data for PHP branch {branch}")

    if package is None and install.package_lookup_failed:
        why = "the owning package could not be determined (see warnings), so a distro backport cannot be checked"
    elif package is None:
        why = "not owned by a package (source build?); a manual patch cannot be detected"
    elif distro is None:
        why = "distribution unknown"
    else:
        why = f"no advisory data for {distro.os_id} {distro.version_id} {package.source_name}; the package may carry a backport"
    return AdvisoryVerdict(adv, InstallStatus.UNKNOWN, "upstream", f"PHP {version} < {fix.version}, but {why}")


def to_check(result: SettingResult, note: str = "") -> SettingCheck:
    values = [FailingContext(c.context, c.value, c.origin) for c in result.contexts]
    failing = [FailingContext(c.context, c.value, c.origin) for c in result.contexts if c.satisfied is not True]
    return SettingCheck(
        id=result.check_id,
        setting=result.setting,
        satisfied=result.satisfied,
        values=values,
        failing=failing,
        notes=list(result.notes),
        warnings=list(result.warnings),
        note=note,
    )


def mitigation_status(checks: Sequence[SettingCheck]) -> MitigationStatus:
    active = sum(1 for c in checks if c.satisfied is True)
    if checks and active == len(checks):
        return MitigationStatus.MITIGATED
    if active:
        return MitigationStatus.PARTIAL
    return MitigationStatus.EXPOSED


def pending_advice(db: AdvisoryDB, verdicts: Sequence[AdvisoryVerdict], config: ConfigReport) -> list[str]:
    """Advice for advisories that have no version data yet (no fix exists),
    such as CVE-2026-115560. Informational: it never changes the status or
    the exit code, but a patched host should still hear about it."""
    lines = []
    for adv in db.advisories:
        verdict = next(v for v in verdicts if v.advisory_id == adv.id)
        if verdict.status is not None or verdict.basis != "none":
            continue
        for mid in adv.mitigations:
            result = config.results.get(mid)
            if result is None or result.satisfied is True:
                continue
            where = ", ".join(sorted({c.context for c in result.contexts if c.satisfied is not True}))
            lines.append(
                f"{adv.id} has no fix yet; its recommended mitigation {result.setting} is not in place ({where})"
            )
    return lines


def assess(install: PhpInstall, db: AdvisoryDB, config: ConfigReport | None) -> Finding:
    verdicts = [judge_advisory(adv, install, db) for adv in db.advisories]
    applicable = [v for v in verdicts if v.status is not None]
    status = worst([v.status for v in applicable]) if applicable else InstallStatus.PATCHED
    finding = Finding(install=install, status=status, verdicts=verdicts, warnings=list(install.warnings))

    if not applicable:
        finding.reasons.append("no advisory with version data applies to this install")

    for adv in db.advisories:
        exposure = adv.sapis.get(install.sapi)
        verdict = next(v for v in verdicts if v.advisory_id == adv.id)
        if exposure and verdict.status not in (None, InstallStatus.PATCHED):
            note = f" ({exposure.note})" if exposure.note else ""
            finding.reasons.append(f"{adv.id}: {install.sapi} is {exposure.status.replace('_', ' ')}{note}")

    if install.sapi in NON_WEB_SAPIS:
        finding.reasons.append(f"{install.sapi} does not serve web requests; mitigations do not apply to it")
    elif install.sapi == "apache2handler" and install.enabled is False:
        finding.reasons.append("mod_php is installed but no LoadModule line was found; Apache may not load it")

    if config is not None:
        finding.warnings.extend(config.warnings)
        finding.reasons.extend(config.notes)
        finding.hardening = [to_check(config.results[h.id], h.note) for h in db.hardening if h.id in config.results]

    if config is not None and install.sapi not in NON_WEB_SAPIS:
        finding.reasons.extend(pending_advice(db, verdicts, config))

    if status is InstallStatus.PATCHED or install.sapi in NON_WEB_SAPIS:
        return finding

    branch = branch_or_none(install.version) or ""
    wanted: dict[str, None] = {}
    for adv in db.advisories:
        verdict = next(v for v in verdicts if v.advisory_id == adv.id)
        # Patched or confirmed not affected: its mitigations are not needed.
        # "No data yet" (status None, basis none) keeps them: unknown is not safe.
        if verdict.status is InstallStatus.PATCHED or (verdict.status is None and verdict.basis == "distro"):
            continue
        for mitigation in mitigations_for(db, adv, branch):
            wanted.setdefault(mitigation.id)

    if config is None:
        finding.reasons.append("configuration was not checked")
        return finding
    finding.mitigations = [
        to_check(config.results[mid], db.mitigations[mid].note) for mid in wanted if mid in config.results
    ]
    finding.mitigation = mitigation_status(finding.mitigations)
    return finding


# --- how to get a fixed PHP -------------------------------------------------

# rpm distributions whose release still ships yum but not dnf.
_YUM_ONLY = {("amzn", "2")}
_YUM_ONLY_RHEL_MAJOR = 7  # RHEL, CentOS, Oracle, CloudLinux 7 and older
_RHEL_FAMILY = {"rhel", "centos", "ol", "cloudlinux", "scientific"}


def upgrade_command(manager: str, distro: Distro | None, names: Sequence[str]) -> str:
    packages = " ".join(names)
    if manager == "dpkg":
        return f"apt-get update && apt-get install --only-upgrade {packages}"
    family = {distro.os_id, *distro.id_like} if distro else set()
    if family & SUSE_FAMILY:
        return f"zypper update {packages}"
    if distro is not None:
        major = distro.version_id.split(".")[0]
        yum_only = (distro.os_id, distro.version_id) in _YUM_ONLY or (
            family & _RHEL_FAMILY and major.isdigit() and int(major) <= _YUM_ONLY_RHEL_MAJOR
        )
        if yum_only:
            return f"yum update {packages}"
    return f"dnf upgrade --refresh {packages}"


def _distro_fix(db: AdvisoryDB, install: PhpInstall) -> tuple[str, str] | None:
    """The newest distro fixed version (and advisory) across advisories."""
    if install.package is None or install.distro is None:
        return None
    best: tuple[str, str] | None = None
    for adv in db.advisories:
        row = find_distro_fix(adv, install.distro, install.package.source_name)
        if row is None or not row.fixed:
            continue
        if best is None or compare_package(row.fixed, best[0], row.scheme) > 0:
            best = (row.fixed, row.advisory or ", ".join(row.sources))
    return best


def _upstream_fix(db: AdvisoryDB, branch: str | None) -> str | None:
    """The release on this branch that fixes every advisory with data."""
    if branch is None:
        return None
    versions = [f.version for adv in db.advisories if (f := find_upstream_fix(adv, branch))]
    return max(versions, key=parse_upstream) if versions else None


def migration_target(db: AdvisoryDB) -> str:
    """Oldest supported branch that has a fixed release for every advisory
    with version data, e.g. "PHP 8.2 (8.2.35 or newer)"."""
    with_data = [adv for adv in db.advisories if adv.upstream_fixed]
    supported = sorted(
        (b for b, info in db.branches.items() if not info.eol), key=lambda b: tuple(map(int, b.split(".")))
    )
    for branch in supported:
        if all(find_upstream_fix(adv, branch) for adv in with_data):
            return f"PHP {branch} ({_upstream_fix(db, branch)} or newer)"
    return "a supported PHP branch with a fixed release"


def _first_unknown_reason(group: Sequence[Finding]) -> str:
    for f in group:
        for v in f.verdicts:
            if v.status is InstallStatus.UNKNOWN:
                return v.reason
    return "status unknown"


def upgrade_advice(findings: Sequence[Finding], db: AdvisoryDB) -> list[UpgradeAdvice]:
    """One piece of advice per source package (or per source build) that is
    not PATCHED. Shown to the user, never run."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        if f.status is InstallStatus.PATCHED:
            continue
        i = f.install
        if i.package:
            key = (i.package.manager, i.package.source_name)
        elif i.package_lookup_failed:
            key = ("?", i.binary)
        else:
            # One source build installs php and php-fpm under different
            # directories but with the same version: one piece of advice.
            key = ("", i.version)
        groups.setdefault(key, []).append(f)

    advice = []
    for (manager, version), group in groups.items():
        status = worst([f.status for f in group])
        first = group[0].install
        branch = branch_or_none(first.version)
        binaries = [f.install.binary for f in group]
        web_facing = any(f.install.sapi not in NON_WEB_SAPIS for f in group)

        if manager == "?":
            note = (
                "Could not determine which package owns this PHP (see warnings). Update it with the tool "
                "that installed it, then run this check again."
            )
            advice.append(UpgradeAdvice(note, binaries))
            continue

        if not manager:  # not installed from a package
            info = db.branches.get(branch or "")
            fixed = _upstream_fix(db, branch)
            if not version:
                note = (
                    "Not owned by a package and its PHP version is unknown (mod_php cannot be run). "
                    "Rebuild it together with the PHP build it belongs to."
                )
            elif status is InstallStatus.EOL:
                backport = f" or apply the {info.source_backport} branch" if info and info.source_backport else ""
                note = f"PHP {branch} built from source and end-of-life: move to {migration_target(db)}{backport}, then rebuild."
            elif fixed:
                note = f"Not installed from a package: rebuild PHP {fixed} or newer from source."
            else:
                note = "Not installed from a package and no fixed release is known for this branch."
            if web_facing:
                # No package means no known unit name; do not invent one.
                note += " Then restart PHP-FPM or the web server that runs it."
            advice.append(UpgradeAdvice(note, binaries))
            continue

        names = sorted({f.install.package.name for f in group})
        command = upgrade_command(manager, first.distro, names)
        units = list(dict.fromkeys(u for f in group for u in service_units(f.install)[:1]))
        restart = f"systemctl restart {' '.join(units)}" if units else None
        where = f"{first.distro.os_id} {first.distro.version_id}" if first.distro else "this system"
        source = first.package.source_name
        if status is InstallStatus.VULNERABLE:
            fix = _distro_fix(db, first)
            note = f"{where} has a fix: {source} {fix[0]} ({fix[1]})." if fix else f"{where} has a fix for {source}."
        elif status is InstallStatus.EOL:
            note = (
                f"PHP {branch} is end-of-life upstream. Updating helps only if your vendor backports "
                f"the fix; otherwise move to {migration_target(db)}."
            )
        else:
            note = f"{_first_unknown_reason(group)}. Update, then check your vendor's advisory for the fixed version."
        advice.append(UpgradeAdvice(note, binaries, command, restart))
    return advice


# --- exit code --------------------------------------------------------------

EXIT_OK = 0
EXIT_EXPOSED = 1
EXIT_EOL = 2
EXIT_UNKNOWN = 3
EXIT_ERROR = 4


def finding_exit_code(finding: Finding) -> int:
    mitigated = finding.mitigation is MitigationStatus.MITIGATED
    # The advisories cover installs serving web requests. A CLI binary is
    # still reported with its status, but cannot be mitigated and must not
    # keep a fully mitigated server from exiting 0.
    if finding.install.sapi in NON_WEB_SAPIS:
        return EXIT_OK
    if finding.status is InstallStatus.PATCHED:
        return EXIT_OK
    if finding.status is InstallStatus.VULNERABLE or finding.mitigation is MitigationStatus.EXPOSED:
        return EXIT_EXPOSED
    if mitigated:
        return EXIT_OK
    if finding.status is InstallStatus.EOL:
        return EXIT_EOL
    return EXIT_UNKNOWN


def exit_code(findings: Sequence[Finding]) -> int:
    """1 beats 2 beats 3 beats 0."""
    codes = {finding_exit_code(f) for f in findings}
    for code in (EXIT_EXPOSED, EXIT_EOL, EXIT_UNKNOWN):
        if code in codes:
            return code
    return EXIT_OK
