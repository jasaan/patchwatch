"""Build the software catalog from Intune, SBOM files and Kubernetes.

Every source ends up as a list of `Software` items, each with the assets it's installed
on. The same product and version seen in several places is merged into one item.

Intune names apps loosely ("Google Chrome", "Google Chrome (x64)"), so desktop apps are
mapped to an NVD product (vendor:product) by the rules in mappings.yaml. Apps that no
rule matches are listed as gaps, never silently dropped.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import Asset, Software

GRAPH = "https://graph.microsoft.com/v1.0"

# Cluster add-ons recognised by controller image, matched through OSV as Go modules.
ADDONS = {
    "registry.k8s.io/ingress-nginx/controller": ("ingress-nginx", "pkg:golang/k8s.io/ingress-nginx"),
    "quay.io/jetstack/cert-manager-controller": ("cert-manager", "pkg:golang/github.com/cert-manager/cert-manager"),
    "quay.io/argoproj/argocd": ("Argo CD", "pkg:golang/github.com/argoproj/argo-cd/v2"),
}


@dataclass
class Rule:
    match: re.Pattern
    cpe: str = ""
    eol: str = ""
    watch_releases: bool = False
    kev: re.Pattern | None = None
    ignore: bool = False
    name: str = ""


@dataclass
class Catalog:
    software: list[Software] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)  # things we couldn't assess, shown in the report

    def add(self, sw: Software, asset: Asset) -> None:
        for existing in self.software:
            if existing.key == sw.key:
                if asset not in existing.assets:
                    existing.assets.append(asset)
                return
        sw.assets.append(asset)
        self.software.append(sw)


def load_rules(path: Path) -> list[Rule]:
    rules = []
    for r in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
        rules.append(
            Rule(
                match=re.compile(r["match"], re.I),
                cpe=r.get("cpe", ""),
                eol=r.get("eol", ""),
                watch_releases=bool(r.get("watch_releases", False)),
                kev=re.compile(r["kev"], re.I) if r.get("kev") else None,
                ignore=bool(r.get("ignore", False)),
                name=r.get("name", ""),
            )
        )
    return rules


def find_rule(rules: list[Rule], text: str) -> Rule | None:
    return next((r for r in rules if r.match.search(text)), None)


def _apply(rule: Rule | None, sw: Software) -> Software:
    if rule:
        sw.cpe = sw.cpe or rule.cpe
        sw.eol = sw.eol or rule.eol
        sw.watch_releases = rule.watch_releases
        sw.kev_names = (rule.kev.pattern,) if rule.kev else ()
        sw.name = rule.name or sw.name
    return sw


# ---------------------------------------------------------------- Intune
def intune_apps_live() -> list[dict]:
    """detectedApps from Microsoft Graph, with each app's devices.

    Needs an app registration with DeviceManagementManagedDevices.Read.All (application)
    and AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET in the environment.
    """
    import requests
    from azure.identity import DefaultAzureCredential

    token = DefaultAzureCredential().get_token("https://graph.microsoft.com/.default").token
    http = requests.Session()
    http.headers["Authorization"] = f"Bearer {token}"

    def pages(url: str):
        while url:
            data = http.get(url, timeout=60).json()
            if "error" in data:
                raise RuntimeError(f"Graph error: {data['error'].get('message')}")
            yield from data.get("value", [])
            url = data.get("@odata.nextLink")

    apps = list(pages(f"{GRAPH}/deviceManagement/detectedApps?$top=1000"))
    for app in apps:
        app["managedDevices"] = list(
            pages(
                f"{GRAPH}/deviceManagement/detectedApps/{app['id']}/managedDevices?$select=id,deviceName,operatingSystem"
            )
        )
    return apps


def add_intune(catalog: Catalog, apps: list[dict], rules: list[Rule]) -> None:
    unmapped = []
    for app in apps:
        rule = find_rule(rules, app["displayName"])
        if rule and rule.ignore:
            continue
        if not rule or not (rule.cpe or rule.eol):
            unmapped.append(f"{app['displayName']} {app.get('version', '')} ({app.get('deviceCount', 0)} devices)")
            continue
        devices = app.get("managedDevices") or [
            {"id": f"{app['id']}-{i}", "deviceName": "(device not listed)"} for i in range(app.get("deviceCount", 0))
        ]
        for d in devices:
            sw = _apply(rule, Software(name=app["displayName"], version=app.get("version", ""), source="intune"))
            catalog.add(sw, Asset(id=f"intune:{d['id']}", name=d.get("deviceName", d["id"]), type="endpoint"))
    for u in unmapped:
        catalog.gaps.append(f"Intune app not mapped to a product: {u}. Add a rule to mappings.yaml.")


# ---------------------------------------------------------------- SBOMs (CycloneDX JSON)
def read_sbom(path: Path) -> tuple[dict, list[dict]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{path}: only CycloneDX JSON SBOMs are supported")
    comps = [c for c in doc.get("components", []) if c.get("purl") and c.get("version")]
    return doc.get("metadata", {}).get("component", {}), comps


def _sbom_software(comp: dict, rules: list[Rule], source: str) -> Software:
    sw = Software(name=comp.get("name", ""), version=comp["version"], purl=comp["purl"], source=source)
    return _apply(find_rule(rules, comp["purl"].split("@")[0]), sw)


def add_server_sboms(catalog: Catalog, folder: Path, rules: list[Rule], internet_facing: set[str]) -> None:
    for path in sorted(folder.glob("*.json")):
        meta, comps = read_sbom(path)
        host = meta.get("name", path.stem)
        asset = Asset(
            id=f"server:{host}",
            name=host,
            type="server",
            exposed=host in internet_facing,
            exposure="listed as internet-facing in config" if host in internet_facing else "",
        )
        for c in comps:
            catalog.add(_sbom_software(c, rules, "sbom"), asset)


# ---------------------------------------------------------------- Kubernetes
def cluster_live() -> dict:
    """Pods, services and ingresses from the current kubectl context (read-only)."""
    items = json.loads(
        subprocess.run(
            ["kubectl", "get", "pods,services,ingresses", "-A", "-o", "json"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )["items"]
    version = json.loads(
        subprocess.run(["kubectl", "version", "-o", "json"], check=True, capture_output=True, text=True).stdout
    )["serverVersion"]
    ctx = subprocess.run(["kubectl", "config", "current-context"], capture_output=True, text=True).stdout.strip()
    return {"name": ctx or "cluster", "serverVersion": version, "items": items}


def _workload(pod: dict) -> str:
    owner = (pod["metadata"].get("ownerReferences") or [{}])[0]
    name = owner.get("name", pod["metadata"]["name"])
    if owner.get("kind") == "ReplicaSet":
        name = re.sub(r"-[a-z0-9]{6,10}$", "", name)
    return f"{pod['metadata'].get('namespace', 'default')}/{name}"


def _split_image(image: str) -> tuple[str, str]:
    image = image.split("@")[0]
    repo, _, tag = image.rpartition(":")
    if not repo or "/" in tag:  # no tag, or the colon was a registry port
        return image, "latest"
    return repo, tag


def exposed_services(items: list[dict]) -> dict[tuple[str, str], str]:
    """(namespace, service) -> why it's reachable from outside the cluster."""
    out = {}
    for it in items:
        ns = it["metadata"].get("namespace", "default")
        if it["kind"] == "Service" and it["spec"].get("type") in ("LoadBalancer", "NodePort"):
            out[(ns, it["metadata"]["name"])] = f"Service type {it['spec']['type']}"
        if it["kind"] == "Ingress":
            for rule in it["spec"].get("rules", []):
                for p in rule.get("http", {}).get("paths", []):
                    svc = p.get("backend", {}).get("service", {}).get("name")
                    if svc:
                        out.setdefault((ns, svc), f"Ingress {rule.get('host', '*')}")
    return out


def add_cluster(catalog: Catalog, cluster: dict, sbom_dir: Path | None, rules: list[Rule]) -> None:
    items = cluster.get("items", [])
    name = cluster.get("name", "cluster")
    services = {
        (i["metadata"].get("namespace", "default"), i["metadata"]["name"]): i for i in items if i["kind"] == "Service"
    }
    exposed = exposed_services(items)

    sboms = {}
    if sbom_dir and sbom_dir.exists():
        for path in sorted(sbom_dir.glob("*.json")):
            meta, comps = read_sbom(path)
            sboms[(meta.get("name", ""), meta.get("version", ""))] = comps
            sboms.setdefault((meta.get("name", ""), ""), comps)

    version = cluster.get("serverVersion", {}).get("gitVersion", "")
    if version:
        clean = re.match(r"v?(\d+\.\d+\.\d+)", version).group(1)
        catalog.add(
            Software(
                name="Kubernetes", version=clean, cpe="kubernetes:kubernetes", eol="kubernetes", source="kubernetes"
            ),
            Asset(id=f"cluster:{name}", name=name, type="cluster"),
        )

    missing = set()
    for pod in (i for i in items if i["kind"] == "Pod"):
        ns = pod["metadata"].get("namespace", "default")
        labels = pod["metadata"].get("labels", {})
        why = ""
        for (sns, sname), reason in exposed.items():
            sel = services.get((sns, sname), {}).get("spec", {}).get("selector") or {}
            if sns == ns and sel and all(labels.get(k) == v for k, v in sel.items()):
                why = reason
                break
        workload = _workload(pod)
        asset = Asset(
            id=f"k8s:{name}/{workload}", name=f"{name}/{workload}", type="container", exposed=bool(why), exposure=why
        )
        for c in pod["spec"].get("containers", []) + pod["spec"].get("initContainers", []):
            repo, tag = _split_image(c["image"])
            if repo in ADDONS:
                label, purl = ADDONS[repo]
                ver = tag.lstrip("v")
                catalog.add(
                    _apply(
                        find_rule(rules, purl),
                        Software(name=label, version=ver, purl=f"{purl}@{ver}", source="kubernetes"),
                    ),
                    asset,
                )
            comps = sboms.get((repo, tag)) or sboms.get((repo, ""))
            if comps is None:
                if repo not in ADDONS:
                    missing.add(f"{repo}:{tag}")
                continue
            for comp in comps:
                catalog.add(_sbom_software(comp, rules, "kubernetes"), asset)
    for image in sorted(missing):
        catalog.gaps.append(f"No SBOM for image {image}. Generate one with: syft {image} -o cyclonedx-json")


# ---------------------------------------------------------------- everything
def build(config: dict, base: Path, live_intune: bool = False, live_cluster: bool = False) -> Catalog:
    inv = config.get("inventory", {})
    rules = load_rules(base / config.get("mappings", "mappings.yaml"))
    internet_facing = set(config.get("exposure", {}).get("internet_facing", []))
    catalog = Catalog()

    if "intune" in inv:
        if live_intune:
            apps = intune_apps_live()
        else:
            apps = json.loads((base / inv["intune"]["file"]).read_text(encoding="utf-8"))["value"]
        add_intune(catalog, apps, rules)
    for folder in inv.get("server_sboms", []):
        add_server_sboms(catalog, base / folder, rules, internet_facing)
    if "kubernetes" in inv:
        k = inv["kubernetes"]
        cluster = cluster_live() if live_cluster else json.loads((base / k["file"]).read_text(encoding="utf-8"))
        add_cluster(catalog, cluster, base / k["sbom_dir"] if k.get("sbom_dir") else None, rules)
    return catalog
