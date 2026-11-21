"""SQLite state: what has been alerted on already, and what the team has acknowledged.

Notifications only go out for findings that are new, or that moved up a tier (for example
a CVE that was in the digest and has just been added to KEV). An acknowledgement
("not affected because…") silences a vulnerability for one product at any version, and
is kept with who made it and why, so it doubles as an audit record.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding

RANK = {"log": 0, "weekly": 1, "digest": 2, "urgent": 3}


def _ident(software_key: str) -> str:
    return software_key.rsplit("@", 1)[0]


class State:
    def __init__(self, path: str | Path):
        self.db = sqlite3.connect(str(path))
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS seen (
                key TEXT PRIMARY KEY, tier TEXT, first_seen TEXT, last_seen TEXT,
                notified_tier TEXT, notified_at TEXT);
            CREATE TABLE IF NOT EXISTS acks (
                vuln_id TEXT, product TEXT, reason TEXT, acked_by TEXT, acked_at TEXT,
                PRIMARY KEY (vuln_id, product));
        """)

    def close(self) -> None:
        self.db.commit()
        self.db.close()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def record(self, findings: list[Finding]) -> None:
        now = self._now()
        for f in findings:
            self.db.execute(
                "INSERT INTO seen (key, tier, first_seen, last_seen) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET tier = excluded.tier, last_seen = excluded.last_seen",
                (f.key, f.tier, now, now),
            )
        self.db.commit()

    def acked(self, f: Finding) -> tuple[str, str] | None:
        if not f.vuln:
            return None
        return self.db.execute(
            "SELECT reason, acked_by FROM acks WHERE vuln_id = ? AND (product = ? OR product = lower(?))",
            (f.vuln.id, _ident(f.software.key), f.software.name),
        ).fetchone()

    def ack(self, vuln_id: str, product: str, reason: str, by: str) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO acks VALUES (?, ?, ?, ?, ?)",
            (vuln_id, _ident(product) if "@" in product else product.lower(), reason, by, self._now()),
        )
        self.db.commit()

    def to_notify(self, findings: list[Finding], tiers: set[str]) -> list[Finding]:
        out = []
        for f in findings:
            if f.tier not in tiers or self.acked(f):
                continue
            row = self.db.execute("SELECT notified_tier FROM seen WHERE key = ?", (f.key,)).fetchone()
            if not row or not row[0] or RANK[f.tier] > RANK[row[0]]:
                out.append(f)
        return out

    def mark_notified(self, findings: list[Finding]) -> None:
        now = self._now()
        for f in findings:
            self.db.execute("UPDATE seen SET notified_tier = ?, notified_at = ? WHERE key = ?", (f.tier, now, f.key))
        self.db.commit()
