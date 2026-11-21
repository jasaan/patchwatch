"""Group findings into alerts (one per product version and tier) and render them."""

from __future__ import annotations

from dataclasses import dataclass, field

from .match import next_fix
from .models import Finding, Software
from .versions import sort_key

TIER_ORDER = ["urgent", "digest", "weekly", "log"]
TIER_TITLE = {"urgent": "Urgent", "digest": "Daily digest", "weekly": "Weekly planning", "log": "Logged only"}
TIER_ICON = {"urgent": "🔴", "digest": "🟠", "weekly": "⚪", "log": "·"}
TYPE_LABEL = {"endpoint": "endpoint", "server": "server", "container": "workload", "cluster": "cluster"}


_PRIORITY = [
    "Zero-day",
    "On CISA KEV",
    "Used in ransomware",
    "Advisory says",
    "Unauthenticated",
    "Critical",
    "Likely",
    "End of support",
    "New release",
]


def _priority(reason: str) -> int:
    return next((i for i, p in enumerate(_PRIORITY) if reason.startswith(p)), len(_PRIORITY))


@dataclass
class Alert:
    software: Software
    tier: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def title(self) -> str:
        return f"{self.software.name} {self.software.version}"

    @property
    def reasons(self) -> list[str]:
        seen: list[str] = []
        for f in self.findings:
            for r in f.reasons:
                if r not in seen:
                    seen.append(r)
        return seen

    def reason_lines(self, ids_per_line: int = 3) -> list[str]:
        """One line per reason, naming the vulnerabilities behind it: 'On CISA KEV: CVE-1 (added …)'."""
        lines = []
        for reason in sorted(self.reasons, key=_priority):
            hits = [f for f in self.findings if reason in f.reasons]
            if not any(f.vuln for f in hits):
                lines.append(reason)
                continue
            hits.sort(
                key=lambda f: (
                    -(f.vuln.epss or 0) if "EPSS" in reason or "likely" in reason.lower() else 0,
                    -(f.vuln.score or 0),
                    f.vuln.id,
                )
            )
            refs = [
                f"{f.vuln.id} ({f.notes[reason]})" if f.notes.get(reason) else f.vuln.id for f in hits[:ids_per_line]
            ]
            more = f" and {len(hits) - ids_per_line} more" if len(hits) > ids_per_line else ""
            lines.append(f"{reason}: {', '.join(refs)}{more}")
        return lines

    @property
    def vuln_ids(self) -> list[str]:  # most important first
        vulns = [f.vuln for f in self.findings if f.vuln]
        vulns.sort(key=lambda v: (not v.kev, -(v.score or 0), v.id))
        return [v.id for v in vulns]

    @property
    def fix(self) -> str:
        """Lowest version that fixes every vulnerability in this alert, when the feeds say."""
        needed = [next_fix(self.software.version, f.vuln.fixed) for f in self.findings if f.vuln]
        needed = [n for n in needed if n]
        return max(needed, key=sort_key) if needed else ""

    @property
    def where(self) -> str:
        parts = []
        for t, n in sorted(self.software.asset_counts().items()):
            label = TYPE_LABEL.get(t, t)
            parts.append(f"{n} {label}{'s' if n != 1 else ''}")
        exposed = [a for a in self.software.assets if a.exposed]
        if exposed:
            names = ", ".join(f"{a.name} ({a.exposure})" for a in exposed[:3])
            parts.append(f"internet-facing: {names}" + (f" and {len(exposed) - 3} more" if len(exposed) > 3 else ""))
        return " · ".join(parts)

    def summary_line(self) -> str:
        n = len(self.vuln_ids)
        parts = [f"{n} vulnerabilit{'y' if n == 1 else 'ies'}"] if n else []
        if self.fix:
            parts.append(f"fix: upgrade to {self.fix} or later")
        return " · ".join(parts)


def group(findings: list[Finding]) -> list[Alert]:
    """One vulnerability alert per product version, at its most severe tier, plus a separate
    weekly alert for end-of-support and new releases. Logged-only findings stay apart."""
    rank = {"urgent": 0, "digest": 1}
    top: dict[str, str] = {}
    for f in findings:
        if f.vuln and f.tier in rank and rank[f.tier] < rank.get(top.get(f.software.key, ""), 9):
            top[f.software.key] = f.tier
    alerts: dict[tuple[str, str], Alert] = {}
    for f in findings:
        tier = top[f.software.key] if f.vuln and f.tier in rank else f.tier
        a = alerts.setdefault((f.software.key, tier), Alert(f.software, tier))
        a.findings.append(f)
    return sorted(alerts.values(), key=lambda a: (TIER_ORDER.index(a.tier), -len(a.software.assets), a.title.lower()))


def markdown(findings: list[Finding], gaps: list[str], today: str, products: int, acked: int = 0) -> str:
    alerts = group(findings)
    lines = [f"# patchwatch report: {today}", ""]
    counts = {t: sum(1 for a in alerts if a.tier == t) for t in TIER_ORDER}
    lines.append(
        f"{products} products checked. **{counts['urgent']} urgent**, {counts['digest']} for the daily "
        f"digest, {counts['weekly']} for weekly planning, and {sum(1 for f in findings if f.tier == 'log')} "
        f"lower-risk findings logged without a notification." + (f" {acked} acknowledged." if acked else "")
    )
    for tier in ("urgent", "digest", "weekly"):
        group_alerts = [a for a in alerts if a.tier == tier]
        if not group_alerts:
            continue
        lines += ["", f"## {TIER_ICON[tier]} {TIER_TITLE[tier]}", ""]
        for a in group_alerts:
            lines.append(f"### {a.title}")
            lines.append(f"*{a.where}*")
            lines.append("")
            for r in a.reason_lines(4):
                lines.append(f"- {r}")
            if line := a.summary_line():
                lines.append(f"- {line}")
            lines.append("")
    logged = [a for a in alerts if a.tier == "log"]
    if logged:
        lines += ["## Logged only", "", "| Product | Findings |", "|---|---|"]
        for a in logged:
            lines.append(f"| {a.title} | {len(a.findings)} |")
        lines.append("")
    if gaps:
        lines += ["## Gaps (not assessed)", ""] + [f"- {g}" for g in gaps] + [""]
    return "\n".join(lines).rstrip() + "\n"
