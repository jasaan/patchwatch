"""Data shared by the inventory, matching and triage steps."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Asset:
    """Something software is installed on: a laptop, a server, a pod or a cluster."""

    id: str
    name: str
    type: str  # endpoint | server | container | cluster
    exposed: bool = False
    exposure: str = ""  # why it counts as internet-facing, e.g. "Ingress shop.contoso.com"


@dataclass
class Software:
    """One product at one version, and every asset it's installed on.

    `purl` is set for packages (SBOMs, container images) and is matched through OSV.
    `cpe` (vendor:product) is set for desktop apps and is matched through NVD.
    """

    name: str
    version: str
    purl: str = ""
    cpe: str = ""
    eol: str = ""  # endoflife.date product slug
    watch_releases: bool = False
    kev_names: tuple[str, ...] = ()  # "vendor|product" strings as written in the KEV catalog
    source: str = ""
    assets: list[Asset] = field(default_factory=list)

    @property
    def key(self) -> str:
        ident = self.purl.split("@")[0] if self.purl else f"cpe:{self.cpe}" if self.cpe else self.name
        return f"{ident}@{self.version}"

    @property
    def exposed(self) -> bool:
        return any(a.exposed for a in self.assets)

    def asset_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for a in self.assets:
            counts[a.type] = counts.get(a.type, 0) + 1
        return counts


@dataclass
class Vuln:
    """A vulnerability that affects a Software item, merged across feeds."""

    id: str  # CVE id when there is one, otherwise the OSV/GHSA id
    summary: str = ""
    aliases: set[str] = field(default_factory=set)
    score: float | None = None
    vector: str = ""
    severity: str = ""  # CRITICAL/HIGH/... when there is no CVSS score
    cwes: set[str] = field(default_factory=set)
    published: str = ""
    fixed: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    kev: dict | None = None
    epss: float | None = None

    def metric(self, name: str) -> str:
        """Value of one CVSS metric, e.g. metric('AV') -> 'N'."""
        for part in self.vector.split("/"):
            if part.startswith(name + ":"):
                return part.split(":", 1)[1]
        return ""


@dataclass
class Finding:
    software: Software
    tier: str  # urgent | digest | weekly | log
    reasons: list[str]
    vuln: Vuln | None = None  # None for release and end-of-support findings
    kind: str = "vuln"  # vuln | eol | release
    detail: str = ""
    notes: dict[str, str] = field(default_factory=dict)  # reason -> short note, e.g. "added 12d ago"

    @property
    def key(self) -> str:
        return f"{self.software.key}|{self.vuln.id if self.vuln else self.kind}"
