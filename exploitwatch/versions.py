"""Loose version comparison and CVSS v3 scoring, with no third-party dependencies."""

from __future__ import annotations

import math
import re
from functools import cmp_to_key

_TOKEN = re.compile(r"\d+|[a-z]+")


def _tokens(v: str) -> list[int | str]:
    v = v.lower().lstrip("v")
    if ":" in v and v.split(":", 1)[0].isdigit():  # Debian epoch, e.g. 1:9.6p1
        v = v.split(":", 1)[1]
    return [int(t) if t.isdigit() else t for t in _TOKEN.findall(v)]


def compare(a: str, b: str) -> int:
    """Compare two version strings: -1, 0 or 1.

    Works for the dotted versions desktop apps use (131.0.6778.86, 8.8.1, 10.6p1).
    Numbers compare as numbers, letters as text, and a number beats letters. Package
    ecosystems with their own rules (Debian, Alpine) are compared by OSV, not here.
    """
    ta, tb = _tokens(a), _tokens(b)
    for x, y in zip(ta, tb, strict=False):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            return -1 if x < y else 1
        return 1 if isinstance(x, int) else -1
    return (len(ta) > len(tb)) - (len(ta) < len(tb))


sort_key = cmp_to_key(compare)


def in_range(version: str, match: dict) -> bool:
    """Is `version` inside an NVD cpeMatch range (versionStart/EndIncluding/Excluding)?"""
    if (s := match.get("versionStartIncluding")) and compare(version, s) < 0:
        return False
    if (s := match.get("versionStartExcluding")) and compare(version, s) <= 0:
        return False
    if (e := match.get("versionEndIncluding")) and compare(version, e) > 0:
        return False
    return not ((e := match.get("versionEndExcluding")) and compare(version, e) >= 0)


# ---- CVSS v3.x base score (FIRST specification, section 7) ----
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """Base score for a CVSS:3.0 or CVSS:3.1 vector; None for anything else."""
    if not vector.startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if changed else 1) * (impact + expl), 10))
