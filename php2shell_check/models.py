"""Plain data types shared by every module.

Nothing here touches the system or does any assessment. Advisory-side types
mirror data/advisories.json one to one; install-side types hold what
discovery found on the host.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

Scheme = Literal["dpkg", "rpm"]
FactStatus = Literal["confirmed", "unconfirmed"]
SourceTier = Literal["primary", "secondary"]
SettingType = Literal["bool", "size", "int"]
ExpectOp = Literal["eq", "lte", "gte"]
Coverage = Literal["partial", "full"]


class InstallStatus(str, Enum):
    PATCHED = "PATCHED"
    VULNERABLE = "VULNERABLE"
    EOL = "EOL"
    UNKNOWN = "UNKNOWN"


class MitigationStatus(str, Enum):
    MITIGATED = "MITIGATED"
    PARTIAL = "PARTIAL"
    EXPOSED = "EXPOSED"


# --- advisory data (loaded from data/advisories.json) -----------------------


@dataclass(frozen=True)
class Source:
    id: str
    url: str
    tier: SourceTier


@dataclass(frozen=True)
class Branch:
    name: str  # "8.3"
    eol: bool
    sources: tuple[str, ...]
    eol_date: str | None = None
    source_backport: str | None = None  # upstream branch name with the fix


@dataclass(frozen=True)
class Severity:
    system: str  # "cvss_v4", "cvss_v3.1"
    score: float
    sources: tuple[str, ...]
    vector: str | None = None


@dataclass(frozen=True)
class UpstreamFix:
    branch: str
    version: str
    sources: tuple[str, ...]


@dataclass(frozen=True)
class AffectedSince:
    version: str
    status: FactStatus
    sources: tuple[str, ...]
    note: str = ""


@dataclass(frozen=True)
class SapiExposure:
    status: str  # one of advisories.SAPI_STATUSES
    sources: tuple[str, ...]
    note: str = ""


@dataclass(frozen=True)
class DistroFix:
    os_id: str
    version_id: str
    scheme: Scheme
    source_package: str
    sources: tuple[str, ...]
    fixed: str | None = None
    not_affected: bool = False
    advisory: str | None = None


@dataclass(frozen=True)
class Advisory:
    id: str
    title: str
    published: str
    status: FactStatus
    sources: tuple[str, ...]
    aliases: tuple[str, ...] = ()
    severity: tuple[Severity, ...] = ()
    upstream_fixed: tuple[UpstreamFix, ...] = ()
    affected_since: AffectedSince | None = None
    sapis: dict[str, SapiExposure] = field(default_factory=dict)
    distros: tuple[DistroFix, ...] = ()
    mitigations: tuple[str, ...] = ()
    note: str = ""

    @property
    def has_version_data(self) -> bool:
        return bool(self.upstream_fixed or self.distros)


@dataclass(frozen=True)
class Expectation:
    op: ExpectOp
    value: str


@dataclass(frozen=True)
class Mitigation:
    id: str
    setting: str
    type: SettingType
    php_default: str
    expect: Expectation
    coverage: Coverage
    status: FactStatus
    sources: tuple[str, ...]
    early_only: bool = False  # .user.ini / ini_set() values do not count
    prefer_admin: bool = False  # warn when set with an overridable directive
    branches: tuple[str, ...] | None = None  # None = every branch
    note: str = ""


@dataclass(frozen=True)
class HardeningCheck:
    id: str
    setting: str
    type: SettingType
    sources: tuple[str, ...]
    expect: Expectation | None = None  # None = report the value only
    note: str = ""


# --- what discovery found on the host ---------------------------------------


@dataclass(frozen=True)
class Distro:
    os_id: str  # os-release ID
    version_id: str  # os-release VERSION_ID
    id_like: tuple[str, ...] = ()
    pretty_name: str = ""


@dataclass(frozen=True)
class Package:
    name: str  # binary package, e.g. php8.3-fpm
    version: str  # full package version, epoch included
    source_name: str  # source package, e.g. php8.3
    manager: Scheme


@dataclass
class PhpInstall:
    binary: str
    sapi: str  # PHP's own SAPI name: cli, fpm-fcgi, apache2handler, ...
    version: str  # upstream version as PHP reports it
    ini_files: list[str] = field(default_factory=list)
    package: Package | None = None
    distro: Distro | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class Finding:
    install: PhpInstall
    status: InstallStatus
    mitigation: MitigationStatus | None = None
    advisories: list[str] = field(default_factory=list)  # CVE ids that apply
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
