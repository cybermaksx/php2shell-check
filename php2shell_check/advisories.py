"""Load and validate data/advisories.json.

Validation is strict: unknown keys, unknown source ids, bad enum values and
unparseable versions are all errors. The loader collects every problem and
raises them together, so one run of the tool shows everything wrong with an
edited file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import config, version
from .models import (
    Advisory,
    AffectedSince,
    Branch,
    Distro,
    DistroFix,
    Expectation,
    HardeningCheck,
    Mitigation,
    SapiExposure,
    Severity,
    Source,
    UpstreamFix,
)

SCHEMA_VERSION = 1
DEFAULT_PATH = Path(__file__).resolve().parent.parent / "data" / "advisories.json"

FACT_STATUSES = {"confirmed", "unconfirmed"}
SOURCE_TIERS = {"primary", "secondary"}
SCHEMES = {"dpkg", "rpm"}
SETTING_TYPES = {"bool", "size", "int"}
EXPECT_OPS = {"eq", "lte", "gte"}
COVERAGES = {"partial", "full"}
SAPI_STATUSES = {
    "confirmed",
    "susceptible",
    "likely",
    "conditional",
    "not_established",
    "listed",
}


class AdvisoryError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("invalid advisories file:\n  " + "\n  ".join(errors))


@dataclass(frozen=True)
class AdvisoryDB:
    updated: str
    sources: dict[str, Source]
    branches: dict[str, Branch]
    advisories: tuple[Advisory, ...]
    mitigations: dict[str, Mitigation]
    hardening: tuple[HardeningCheck, ...]


# --- loading ----------------------------------------------------------------


def load(path: Path = DEFAULT_PATH) -> AdvisoryDB:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AdvisoryError([f"{path}: cannot read: {exc.strerror}"]) from exc
    return loads(text, origin=str(path))


def loads(text: str, origin: str = "<string>") -> AdvisoryDB:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AdvisoryError([f"{origin}: not valid JSON: {exc}"]) from exc
    reader = _Reader()
    db = reader.database(raw)
    if reader.errors:
        raise AdvisoryError(reader.errors)
    return db


class _Reader:
    """Turns the raw JSON into models, recording errors with a JSON path."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.source_ids: set[str] = set()

    def error(self, where: str, message: str) -> None:
        self.errors.append(f"{where}: {message}")

    # -- generic field access --

    def obj(self, value: Any, where: str, required: set[str], optional: set[str]) -> dict:
        if not isinstance(value, dict):
            self.error(where, "expected an object")
            return {}
        for key in sorted(required - value.keys()):
            self.error(where, f"missing key {key!r}")
        for key in sorted(value.keys() - required - optional):
            self.error(where, f"unknown key {key!r}")
        return value

    def string(self, value: Any, where: str, default: str = "") -> str:
        if value is None:
            return default
        if not isinstance(value, str) or not value:
            self.error(where, "expected a non-empty string")
            return default
        return value

    def boolean(self, value: Any, where: str) -> bool:
        if value is None:
            return False
        if not isinstance(value, bool):
            self.error(where, "expected true or false")
            return False
        return value

    def choice(self, value: Any, where: str, allowed: set[str]) -> str:
        if value not in allowed:
            self.error(where, f"must be one of {sorted(allowed)}, got {value!r}")
        return value if isinstance(value, str) else ""

    def strings(self, value: Any, where: str) -> tuple[str, ...]:
        if value is None:
            return ()
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            self.error(where, "expected a list of strings")
            return ()
        return tuple(value)

    def items(self, value: Any, where: str) -> list:
        if value is None:
            return []
        if not isinstance(value, list):
            self.error(where, "expected a list")
            return []
        return value

    def source_refs(self, value: Any, where: str, allow_empty: bool = False) -> tuple[str, ...]:
        refs = self.strings(value, where)
        if not refs and not allow_empty:
            self.error(where, "at least one source is required")
        for ref in refs:
            if ref not in self.source_ids:
                self.error(where, f"unknown source {ref!r}")
        return refs

    # -- sections --

    def database(self, raw: Any) -> AdvisoryDB:
        top = self.obj(
            raw,
            "$",
            required={"schema_version", "updated", "sources", "branches", "advisories", "mitigations"},
            optional={"hardening"},
        )
        if top.get("schema_version") != SCHEMA_VERSION:
            self.error("$.schema_version", f"expected {SCHEMA_VERSION}, got {top.get('schema_version')!r}")

        sources = self.sources(top.get("sources", {}))
        self.source_ids = set(sources)
        branches = self.branches(top.get("branches", {}))
        mitigations = {
            mid: self.mitigation(mid, m, branches)
            for mid, m in self._mapping(top.get("mitigations", {}), "$.mitigations").items()
        }
        advisories = tuple(
            self.advisory(a, f"$.advisories[{i}]", branches, mitigations)
            for i, a in enumerate(self.items(top.get("advisories"), "$.advisories"))
        )
        seen: set[str] = set()
        for adv in advisories:
            if adv.id in seen:
                self.error("$.advisories", f"duplicate advisory {adv.id!r}")
            seen.add(adv.id)

        hardening = tuple(
            self.hardening(h, f"$.hardening[{i}]")
            for i, h in enumerate(self.items(top.get("hardening"), "$.hardening"))
        )
        return AdvisoryDB(
            updated=self.string(top.get("updated"), "$.updated"),
            sources=sources,
            branches=branches,
            advisories=advisories,
            mitigations=mitigations,
            hardening=hardening,
        )

    def _mapping(self, value: Any, where: str) -> dict:
        if not isinstance(value, dict):
            self.error(where, "expected an object")
            return {}
        return value

    def sources(self, raw: Any) -> dict[str, Source]:
        result = {}
        for sid, entry in self._mapping(raw, "$.sources").items():
            where = f"$.sources.{sid}"
            entry = self.obj(entry, where, required={"url", "tier"}, optional=set())
            url = self.string(entry.get("url"), f"{where}.url")
            if url and not url.startswith("https://"):
                self.error(f"{where}.url", "must be an https:// URL")
            tier = self.choice(entry.get("tier"), f"{where}.tier", SOURCE_TIERS)
            result[sid] = Source(sid, url, tier)  # type: ignore[arg-type]
        return result

    def branches(self, raw: Any) -> dict[str, Branch]:
        result = {}
        for name, entry in self._mapping(raw, "$.branches").items():
            where = f"$.branches.{name}"
            if not _is_branch_name(name):
                self.error(where, "branch must look like '8.3'")
            entry = self.obj(entry, where, required={"eol", "sources"}, optional={"eol_date", "source_backport"})
            result[name] = Branch(
                name=name,
                eol=self.boolean(entry.get("eol"), f"{where}.eol"),
                sources=self.source_refs(entry.get("sources"), f"{where}.sources"),
                eol_date=entry.get("eol_date") and self.string(entry.get("eol_date"), f"{where}.eol_date"),
                source_backport=entry.get("source_backport")
                and self.string(entry.get("source_backport"), f"{where}.source_backport"),
            )
        return result

    def expectation(self, raw: Any, where: str, type_: str) -> Expectation:
        raw = self.obj(raw, where, required={"op", "value"}, optional=set())
        op = self.choice(raw.get("op"), f"{where}.op", EXPECT_OPS)
        value = self.string(raw.get("value"), f"{where}.value")
        if op and value and type_ in SETTING_TYPES:
            try:
                config.satisfies(value, op, value, type_)  # type: ignore[arg-type]
            except ValueError as exc:
                self.error(where, str(exc))
        return Expectation(op, value)  # type: ignore[arg-type]

    def mitigation(self, mid: str, raw: Any, branches: dict[str, Branch]) -> Mitigation:
        where = f"$.mitigations.{mid}"
        raw = self.obj(
            raw,
            where,
            required={"setting", "type", "php_default", "expect", "coverage", "status", "sources"},
            optional={"early_only", "prefer_admin", "branches", "note"},
        )
        type_ = self.choice(raw.get("type"), f"{where}.type", SETTING_TYPES)
        php_default = self.string(raw.get("php_default"), f"{where}.php_default")
        if php_default and type_ in SETTING_TYPES:
            try:
                config.normalise(php_default, type_)  # type: ignore[arg-type]
            except ValueError as exc:
                self.error(f"{where}.php_default", str(exc))

        only_branches = None
        if raw.get("branches") is not None:
            only_branches = self.strings(raw["branches"], f"{where}.branches")
            for b in only_branches:
                if b not in branches:
                    self.error(f"{where}.branches", f"unknown branch {b!r}")

        return Mitigation(
            id=mid,
            setting=self.string(raw.get("setting"), f"{where}.setting"),
            type=type_,  # type: ignore[arg-type]
            php_default=php_default,
            expect=self.expectation(raw.get("expect"), f"{where}.expect", type_),
            coverage=self.choice(raw.get("coverage"), f"{where}.coverage", COVERAGES),  # type: ignore[arg-type]
            status=self.choice(raw.get("status"), f"{where}.status", FACT_STATUSES),  # type: ignore[arg-type]
            sources=self.source_refs(raw.get("sources"), f"{where}.sources"),
            early_only=self.boolean(raw.get("early_only"), f"{where}.early_only"),
            prefer_admin=self.boolean(raw.get("prefer_admin"), f"{where}.prefer_admin"),
            branches=only_branches,
            note=self.string(raw.get("note"), f"{where}.note"),
        )

    def hardening(self, raw: Any, where: str) -> HardeningCheck:
        raw = self.obj(raw, where, required={"id", "setting", "type", "sources"}, optional={"expect", "note"})
        type_ = self.choice(raw.get("type"), f"{where}.type", SETTING_TYPES)
        expect = None
        if raw.get("expect") is not None:
            expect = self.expectation(raw["expect"], f"{where}.expect", type_)
        return HardeningCheck(
            id=self.string(raw.get("id"), f"{where}.id"),
            setting=self.string(raw.get("setting"), f"{where}.setting"),
            type=type_,  # type: ignore[arg-type]
            # General hardening may have no advisory behind it; the note says so.
            sources=self.source_refs(raw.get("sources"), f"{where}.sources", allow_empty=True),
            expect=expect,
            note=self.string(raw.get("note"), f"{where}.note"),
        )

    def advisory(
        self,
        raw: Any,
        where: str,
        branches: dict[str, Branch],
        mitigations: dict[str, Mitigation],
    ) -> Advisory:
        raw = self.obj(
            raw,
            where,
            required={"id", "title", "published", "status", "sources"},
            optional={"aliases", "severity", "upstream", "sapis", "distros", "mitigations", "note"},
        )
        adv_id = self.string(raw.get("id"), f"{where}.id")
        where = f"$.advisories[{adv_id or where}]"

        upstream = self.obj(raw.get("upstream", {}), f"{where}.upstream", required=set(), optional={"fixed", "affected_since"})
        fixed = tuple(
            self.upstream_fix(f, f"{where}.upstream.fixed[{i}]", branches)
            for i, f in enumerate(self.items(upstream.get("fixed"), f"{where}.upstream.fixed"))
        )
        fixed_branches = [f.branch for f in fixed]
        if len(fixed_branches) != len(set(fixed_branches)):
            self.error(f"{where}.upstream.fixed", "a branch is listed more than once")

        affected_since = None
        if upstream.get("affected_since") is not None:
            affected_since = self.affected_since(upstream["affected_since"], f"{where}.upstream.affected_since")

        mitigation_ids = self.strings(raw.get("mitigations"), f"{where}.mitigations")
        for mid in mitigation_ids:
            if mid not in mitigations:
                self.error(f"{where}.mitigations", f"unknown mitigation {mid!r}")

        return Advisory(
            id=adv_id,
            title=self.string(raw.get("title"), f"{where}.title"),
            published=self.string(raw.get("published"), f"{where}.published"),
            status=self.choice(raw.get("status"), f"{where}.status", FACT_STATUSES),  # type: ignore[arg-type]
            sources=self.source_refs(raw.get("sources"), f"{where}.sources"),
            aliases=self.strings(raw.get("aliases"), f"{where}.aliases"),
            severity=tuple(
                self.severity(s, f"{where}.severity[{i}]")
                for i, s in enumerate(self.items(raw.get("severity"), f"{where}.severity"))
            ),
            upstream_fixed=fixed,
            affected_since=affected_since,
            sapis={
                name: self.sapi(s, f"{where}.sapis.{name}")
                for name, s in self._mapping(raw.get("sapis", {}), f"{where}.sapis").items()
            },
            distros=self.distro_fixes(raw.get("distros"), f"{where}.distros"),
            mitigations=mitigation_ids,
            note=self.string(raw.get("note"), f"{where}.note"),
        )

    def severity(self, raw: Any, where: str) -> Severity:
        raw = self.obj(raw, where, required={"system", "score", "sources"}, optional={"vector"})
        score = raw.get("score")
        if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 <= score <= 10:
            self.error(f"{where}.score", "expected a number from 0 to 10")
            score = 0.0
        return Severity(
            system=self.string(raw.get("system"), f"{where}.system"),
            score=float(score),
            sources=self.source_refs(raw.get("sources"), f"{where}.sources"),
            vector=raw.get("vector") and self.string(raw.get("vector"), f"{where}.vector"),
        )

    def upstream_fix(self, raw: Any, where: str, branches: dict[str, Branch]) -> UpstreamFix:
        raw = self.obj(raw, where, required={"branch", "version", "sources"}, optional=set())
        branch = self.string(raw.get("branch"), f"{where}.branch")
        ver = self.string(raw.get("version"), f"{where}.version")
        if branch and branch not in branches:
            self.error(f"{where}.branch", f"unknown branch {branch!r}")
        if ver:
            try:
                if version.branch_of(ver) != branch:
                    self.error(f"{where}.version", f"{ver} is not on branch {branch}")
            except version.VersionError as exc:
                self.error(f"{where}.version", str(exc))
        return UpstreamFix(branch, ver, self.source_refs(raw.get("sources"), f"{where}.sources"))

    def affected_since(self, raw: Any, where: str) -> AffectedSince:
        raw = self.obj(raw, where, required={"version", "status", "sources"}, optional={"note"})
        ver = self.string(raw.get("version"), f"{where}.version")
        if ver:
            try:
                version.parse_upstream(ver)
            except version.VersionError as exc:
                self.error(f"{where}.version", str(exc))
        status = self.choice(raw.get("status"), f"{where}.status", FACT_STATUSES)
        note = self.string(raw.get("note"), f"{where}.note")
        if status == "unconfirmed" and "TODO" not in note:
            self.error(f"{where}.note", "unconfirmed facts need a TODO note")
        return AffectedSince(ver, status, self.source_refs(raw.get("sources"), f"{where}.sources"), note)  # type: ignore[arg-type]

    def sapi(self, raw: Any, where: str) -> SapiExposure:
        raw = self.obj(raw, where, required={"status", "sources"}, optional={"note"})
        return SapiExposure(
            status=self.choice(raw.get("status"), f"{where}.status", SAPI_STATUSES),
            sources=self.source_refs(raw.get("sources"), f"{where}.sources"),
            note=self.string(raw.get("note"), f"{where}.note"),
        )

    def distro_fixes(self, raw: Any, where: str) -> tuple[DistroFix, ...]:
        rows = []
        seen: set[tuple[str, str, str]] = set()
        for i, entry in enumerate(self.items(raw, where)):
            row = self.distro_fix(entry, f"{where}[{i}]")
            key = (row.os_id, row.version_id, row.source_package)
            if key in seen:
                self.error(f"{where}[{i}]", f"duplicate row for {key}")
            seen.add(key)
            rows.append(row)
        return tuple(rows)

    def distro_fix(self, raw: Any, where: str) -> DistroFix:
        raw = self.obj(
            raw,
            where,
            required={"os_id", "version_id", "scheme", "source_package", "sources"},
            optional={"fixed", "not_affected", "advisory"},
        )
        scheme = self.choice(raw.get("scheme"), f"{where}.scheme", SCHEMES)
        fixed = raw.get("fixed") and self.string(raw.get("fixed"), f"{where}.fixed")
        not_affected = self.boolean(raw.get("not_affected"), f"{where}.not_affected")
        if bool(fixed) == not_affected:
            self.error(where, "set exactly one of 'fixed' or 'not_affected'")
        if fixed and scheme in SCHEMES:
            try:
                # Comparing with itself is the cheapest full parse.
                version.compare_package(fixed, fixed, scheme)  # type: ignore[arg-type]
            except version.VersionError as exc:
                self.error(f"{where}.fixed", str(exc))
        return DistroFix(
            os_id=self.string(raw.get("os_id"), f"{where}.os_id"),
            version_id=self.string(raw.get("version_id"), f"{where}.version_id"),
            scheme=scheme,  # type: ignore[arg-type]
            source_package=self.string(raw.get("source_package"), f"{where}.source_package"),
            sources=self.source_refs(raw.get("sources"), f"{where}.sources"),
            fixed=fixed or None,
            not_affected=not_affected,
            advisory=raw.get("advisory") and self.string(raw.get("advisory"), f"{where}.advisory"),
        )


def _is_branch_name(name: str) -> bool:
    major, dot, minor = name.partition(".")
    return bool(dot) and major.isdigit() and minor.isdigit()


# --- queries used by assess -------------------------------------------------


def version_id_matches(row_version: str, host_version: str) -> bool:
    """A row for "9" covers hosts reporting "9.4"; a row for "9.4" covers
    only "9.4". RHEL-family VERSION_ID includes the minor release, Debian
    and Ubuntu do not."""
    return host_version == row_version or host_version.startswith(row_version + ".")


def find_distro_fix(advisory: Advisory, distro: Distro, source_package: str) -> DistroFix | None:
    """Match on os-release ID, VERSION_ID and source package.

    The most specific VERSION_ID wins, so a row for an EUS minor release
    ("9.2") beats the general one ("9").

    ID_LIKE is deliberately not used: a Rocky or Alma host never inherits a
    RHEL row, because their package versions are not guaranteed to match.
    """
    matches = [
        row
        for row in advisory.distros
        if row.os_id == distro.os_id
        and row.source_package == source_package
        and version_id_matches(row.version_id, distro.version_id)
    ]
    if not matches:
        return None
    return max(matches, key=lambda row: len(row.version_id))


def find_upstream_fix(advisory: Advisory, branch: str) -> UpstreamFix | None:
    for fix in advisory.upstream_fixed:
        if fix.branch == branch:
            return fix
    return None


def mitigations_for(db: AdvisoryDB, advisory: Advisory, branch: str) -> list[Mitigation]:
    """Mitigations listed for an advisory that apply to this PHP branch."""
    result = []
    for mid in advisory.mitigations:
        mitigation = db.mitigations[mid]
        if mitigation.branches is None or branch in mitigation.branches:
            result.append(mitigation)
    return result
