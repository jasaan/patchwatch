"""Find the vulnerabilities that affect each installed product and version.

Two routes, chosen per item:
  packages (purl)      OSV does the version matching, including Debian/Ubuntu/Alpine rules
  desktop apps (cpe)   NVD CVEs for the product, checked locally against each CVE's affected
                       version ranges. Candidates are CVEs published in the lookback window
                       plus every KEV entry for the product, whatever its age.

Results are merged by CVE, then enriched with KEV status, EPSS and (when OSV lacks them)
the CVSS vector and CWE from NVD.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

from .feeds import Feeds
from .models import Software, Vuln
from .versions import compare, cvss3_score, in_range, sort_key

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")


# ---------------------------------------------------------------- purls -> OSV queries
def parse_purl(purl: str) -> dict:
    rest = purl[4:] if purl.startswith("pkg:") else purl
    rest, _, quals = rest.partition("?")
    rest, _, version = rest.partition("@")
    ptype, _, path = rest.partition("/")
    namespace, _, name = path.rpartition("/")
    q = dict(p.split("=", 1) for p in quals.split("&") if "=" in p)
    return {
        "type": ptype,
        "namespace": unquote(namespace),
        "name": unquote(name),
        "version": unquote(version),
        "qualifiers": {k: unquote(v) for k, v in q.items()},
    }


def osv_query_for(purl: str) -> dict:
    """OSV /v1/query body for a purl.

    OS packages are queried by ecosystem and *source* package name (syft's `upstream`
    qualifier), because that's how Debian, Ubuntu and Alpine publish advisories.
    """
    p = parse_purl(purl)
    q = p["qualifiers"]
    name = q.get("upstream", p["name"]).split(" ")[0].split("@")[0]
    distro = q.get("distro", "")
    if p["type"] == "deb":
        m = re.match(r"(ubuntu|debian)-(\d+(?:\.\d+)?)", distro)
        if m:
            osname, ver = m.groups()
            if osname == "ubuntu":
                lts = ver.endswith(".04") and int(ver.split(".")[0]) % 2 == 0
                eco = f"Ubuntu:{ver}" + (":LTS" if lts else "")
            else:
                eco = f"Debian:{ver.split('.')[0]}"
            return {"package": {"name": name, "ecosystem": eco}, "version": p["version"]}
    if p["type"] == "apk":
        m = re.search(r"(\d+\.\d+)", distro)
        if m:
            return {"package": {"name": name, "ecosystem": f"Alpine:v{m.group(1)}"}, "version": p["version"]}
    return {"package": {"purl": purl.split("?")[0]}}


def osv_package_name(purl: str) -> str:
    """Package name as OSV writes it in `affected[].package.name`."""
    p = parse_purl(purl)
    if p["type"] == "maven" and p["namespace"]:
        return f"{p['namespace']}:{p['name']}"
    if p["type"] in ("golang", "npm") and p["namespace"]:
        return f"{p['namespace']}/{p['name']}"
    return p["name"]


# ---------------------------------------------------------------- OSV records -> Vulns
def _cves_in(rec: dict) -> list[str]:
    found = {a for a in rec.get("aliases", []) + rec.get("upstream", []) if _CVE.fullmatch(a)}
    if m := _CVE.search(rec["id"]):
        found.add(m.group(0))
    return sorted(found)


def vuln_from_osv(rec: dict, package_name: str) -> Vuln | None:
    cves = _cves_in(rec)
    if len(cves) > 1 and not rec["id"].startswith(("CVE-", "GHSA-", "GO-", "PYSEC-")):
        return None  # distro notices (USN-…, DSA-…) bundle CVEs that have their own per-CVE records
    v = Vuln(id=cves[0] if len(cves) == 1 else rec["id"], aliases={rec["id"], *cves} - {""}, sources={"OSV"})
    v.summary = " ".join((rec.get("summary") or rec.get("details", "")).split())[:400]
    v.published = rec.get("published", "")
    for sev in rec.get("severity", []):
        if sev["type"] == "CVSS_V3" and not v.vector:
            v.vector, v.score = sev["score"], cvss3_score(sev["score"])
        elif sev["type"] == "CVSS_V4" and not v.vector:
            v.vector = sev["score"]
        elif sev["type"] == "Ubuntu":
            v.severity = sev["score"].upper()
    ds = rec.get("database_specific") or {}
    v.cwes |= set(ds.get("cwe_ids", []))
    if isinstance(ds.get("severity"), str):
        v.severity = v.severity or ds["severity"].upper()
    for aff in rec.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() not in (package_name.lower(), ""):
            continue
        for rng in aff.get("ranges", []):
            v.fixed |= {e["fixed"] for e in rng.get("events", []) if "fixed" in e}
    return v


# ---------------------------------------------------------------- NVD records -> Vulns
def nvd_affects(rec: dict, cpe: str, version: str) -> tuple[bool, set[str]]:
    """Does this CVE list `cpe` (vendor:product) at `version`? Also returns fixed versions."""
    vendor, product = (x.lower() for x in cpe.split(":", 1))
    hit, fixed = False, set()
    for conf in rec.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) < 7 or not m.get("vulnerable", True):
                    continue
                if parts[3].lower() != vendor or parts[4].lower() != product:
                    continue
                if m.get("versionEndExcluding"):
                    fixed.add(m["versionEndExcluding"])
                cpe_ver, update = parts[5], parts[6]
                if cpe_ver not in ("*", "-", ""):
                    full = cpe_ver + (update if update not in ("*", "-", "") else "")
                    if version in (cpe_ver, full):
                        hit = True
                elif in_range(version, m):
                    hit = True
    return hit, fixed


def apply_nvd(v: Vuln, rec: dict) -> None:
    v.sources.add("NVD")
    v.summary = v.summary or " ".join(rec.get("description", "").split())[:400]
    v.published = v.published or rec.get("published", "")
    v.cwes |= set(rec.get("cwes", []))
    best = rec.get("cvss3") or rec.get("cvss4")
    if best and (not v.vector or v.score is None):
        v.vector, v.score = best["vector"], best["score"]


def kev_matches(sw: Software, entry: dict) -> bool:
    label = f"{entry['vendorProject']}|{entry['product']}"
    if sw.kev_names:
        return any(re.search(p, label, re.I) for p in sw.kev_names)
    vendor, product = (x.replace("_", " ").replace("\\", "") for x in sw.cpe.lower().split(":", 1))
    return vendor in entry["vendorProject"].lower() and product in entry["product"].lower()


# ---------------------------------------------------------------- main entry
def match_software(sw: Software, feeds: Feeds, lookback_days: int) -> list[Vuln]:
    found: dict[str, Vuln] = {}

    def merge(v: Vuln) -> None:
        if v.id in found:
            old = found[v.id]
            old.aliases |= v.aliases
            old.sources |= v.sources
            old.cwes |= v.cwes
            old.fixed |= v.fixed
            if not old.vector and v.vector:
                old.vector, old.score = v.vector, v.score
            old.severity = old.severity or v.severity
            old.summary = old.summary or v.summary
        else:
            found[v.id] = v

    if sw.purl:
        query = osv_query_for(sw.purl)
        name = query["package"].get("name") or osv_package_name(sw.purl)
        for osv_id in feeds.osv_query(query):
            rec = feeds.osv_vuln(osv_id)
            if rec and not rec.get("withdrawn") and (v := vuln_from_osv(rec, name)):
                merge(v)
    elif sw.cpe and sw.version:
        candidates = {r["id"]: r for r in feeds.nvd_product(sw.cpe, lookback_days)}
        for cve, entry in feeds.kev().items():
            if cve not in candidates and kev_matches(sw, entry) and (rec := feeds.nvd_cve(cve)):
                candidates[cve] = rec
        for rec in candidates.values():
            hit, fixed = nvd_affects(rec, sw.cpe, sw.version)
            if hit:
                v = Vuln(id=rec["id"], aliases={rec["id"]}, fixed=fixed)
                apply_nvd(v, rec)
                merge(v)

    kev = feeds.kev()
    for v in found.values():
        v.kev = kev.get(v.id)
        needs_nvd = v.id.startswith("CVE-") and "NVD" not in v.sources and (not v.vector or not v.cwes or v.kev)
        if needs_nvd and (rec := feeds.nvd_cve(v.id)):
            apply_nvd(v, rec)
    return sorted(found.values(), key=lambda v: v.id)


def add_epss(results: dict[str, list[Vuln]], feeds: Feeds) -> None:
    cves = sorted({v.id for vs in results.values() for v in vs if v.id.startswith("CVE-")})
    scores = feeds.epss(cves)
    for vs in results.values():
        for v in vs:
            v.epss = scores.get(v.id)


def next_fix(installed: str, fixed: set[str]) -> str:
    """The lowest fixed version above the installed one (loose comparison)."""
    above = sorted((f for f in fixed if compare(f, installed) > 0), key=sort_key)
    return above[0] if above else ""
