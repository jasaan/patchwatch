"""Write the fictional demo inventory under demo/inventory/.

Contoso has ~470 Intune-managed laptops, two Ubuntu servers and one AKS cluster. The
versions are chosen to be realistic for late 2026: mostly current, with a few apps and
images that fell behind. Re-run after editing; the output is committed.
"""

import json
import random
from pathlib import Path

random.seed(7)
OUT = Path(__file__).resolve().parent.parent / "demo" / "inventory"


def write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- Intune detectedApps
devices = [
    {"id": f"{i:08x}-0000-4000-8000-c0ffee{i:06d}", "deviceName": f"CONTOSO-LT-{i:03d}", "operatingSystem": "Windows"}
    for i in range(1, 471)
]
apps = [  # displayName, version, publisher, how many devices
    ("Google Chrome", "157.0.8103.50", "Google LLC", 150),
    ("Google Chrome (x64)", "157.0.8103.50", "Google LLC", 12),
    ("Google Chrome", "158.0.8127.36", "Google LLC", 290),
    ("Mozilla Firefox (x64 en-US)", "156.0", "Mozilla", 18),
    ("Notepad++ (64-bit x64)", "8.8.1", "Notepad++ Team", 37),
    ("WinRAR 7.01 (64-bit)", "7.01.0", "win.rar GmbH", 12),
    ("7-Zip 25.01 (x64)", "25.01", "Igor Pavlov", 64),
    ("PuTTY release 0.83 (64-bit)", "0.83.0.0", "Simon Tatham", 9),
    ("Zoom Workplace (64-bit)", "6.6.10", "Zoom Communications, Inc.", 410),
    ("Python 3.9.13 (64-bit)", "3.9.13", "Python Software Foundation", 6),
    ("Microsoft Teams", "26290.1202.4015.2236", "Microsoft Corporation", 465),
    ("Contoso Expense Helper", "2.3.1", "Contoso Ltd", 140),
]
value = []
for n, (name, version, publisher, count) in enumerate(apps, 1):
    value.append(
        {
            "id": f"{n:04d}a3f1c2b7e9d0{n:08x}{n:04d}"[:44],
            "displayName": name,
            "version": version,
            "publisher": publisher,
            "platform": "windows",
            "sizeInByte": random.randint(5_000_000, 400_000_000),
            "deviceCount": count,
            "managedDevices": random.sample(devices, count),
        }
    )
write(
    OUT / "intune" / "detectedApps.json",
    {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/detectedApps",
        "value": value,
    },
)


# ---------------------------------------------------------------- CycloneDX SBOMs
def sbom(component: dict, packages: list[tuple[str, str, str]]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "syft", "version": "1.33.0"}]},
            "component": component,
        },
        "components": [{"type": "library", "name": n, "version": v, "purl": p} for n, v, p in packages],
    }


def deb(name, version, distro, upstream=None):
    q = f"?arch=amd64&distro={distro}" + (f"&upstream={upstream}" if upstream else "")
    return (name, version, f"pkg:deb/{distro.split('-')[0]}/{name}@{version}{q}")


def apk(name, version, distro, upstream=None):
    q = f"?arch=x86_64&distro={distro}" + (f"&upstream={upstream}" if upstream else "")
    return (name, version, f"pkg:apk/alpine/{name}@{version}{q}")


def lib(ptype, name, version):
    return (name.split("/")[-1], version, f"pkg:{ptype}/{name}@{version}")


write(
    OUT / "servers" / "web-01.cdx.json",
    sbom(
        {"type": "operating-system", "name": "web-01"},
        [
            deb("openssh-server", "1:9.6p1-3ubuntu13.5", "ubuntu-24.04", "openssh"),
            deb("sudo", "1.9.15p5-3ubuntu5", "ubuntu-24.04"),
            deb("nginx", "1.24.0-2ubuntu7.1", "ubuntu-24.04"),
            deb("libssl3t64", "3.0.13-0ubuntu3.5", "ubuntu-24.04", "openssl"),
        ],
    ),
)
write(
    OUT / "servers" / "db-01.cdx.json",
    sbom(
        {"type": "operating-system", "name": "db-01"},
        [
            deb("openssh-server", "1:8.9p1-3ubuntu0.13", "ubuntu-22.04", "openssh"),
            deb("sudo", "1.9.9-1ubuntu2.5", "ubuntu-22.04"),
            deb("postgresql-14", "14.18-0ubuntu0.22.04.1", "ubuntu-22.04"),
        ],
    ),
)

images = {
    "storefront": (
        "ghcr.io/contoso/storefront",
        "2.4.0",
        [
            lib("npm", "next", "15.1.3"),
            lib("npm", "react", "19.0.0"),
            lib("npm", "react-server-dom-webpack", "19.0.0"),
            lib("npm", "axios", "1.7.9"),
            apk("libssl3", "3.3.3-r0", "alpine-3.21.3", "openssl"),
        ],
    ),
    "orders-api": (
        "ghcr.io/contoso/orders-api",
        "1.9.2",
        [
            lib("pypi", "django", "5.1.4"),
            lib("pypi", "urllib3", "2.2.1"),
            lib("pypi", "requests", "2.32.3"),
            deb("libssl3", "3.0.15-1~deb12u1", "debian-12", "openssl"),
        ],
    ),
    "ssh-bastion": (
        "ghcr.io/contoso/ssh-bastion",
        "3.1",
        [
            apk("openssh-server", "10.0_p1-r7", "alpine-3.22.1", "openssh"),
            apk("busybox", "1.37.0-r18", "alpine-3.22.1"),
        ],
    ),
}
for name, (repo, tag, pkgs) in images.items():
    write(OUT / "k8s" / "sboms" / f"{name}.cdx.json", sbom({"type": "container", "name": repo, "version": tag}, pkgs))


# ---------------------------------------------------------------- Kubernetes objects


def pods(ns, workload, image, labels, replicas):
    rs = f"{workload}-{random.randbytes(5).hex()[:9]}"
    return [
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": f"{rs}-{random.randbytes(3).hex()[:5]}",
                "namespace": ns,
                "labels": labels,
                "ownerReferences": [{"kind": "ReplicaSet", "name": rs}],
            },
            "spec": {"containers": [{"name": workload, "image": image}]},
        }
        for _ in range(replicas)
    ]


def service(ns, name, selector, kind="ClusterIP"):
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name, "namespace": ns},
        "spec": {"type": kind, "selector": selector, "ports": [{"port": 443 if kind != "ClusterIP" else 80}]},
    }


items = []
items += pods(
    "ingress-nginx",
    "ingress-nginx-controller",
    "registry.k8s.io/ingress-nginx/controller:v1.11.3",
    {"app.kubernetes.io/name": "ingress-nginx"},
    2,
)
items.append(
    service("ingress-nginx", "ingress-nginx-controller", {"app.kubernetes.io/name": "ingress-nginx"}, "LoadBalancer")
)
items += pods("shop", "storefront", "ghcr.io/contoso/storefront:2.4.0", {"app": "storefront"}, 3)
items.append(service("shop", "storefront", {"app": "storefront"}))
items.append(
    {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": "storefront", "namespace": "shop"},
        "spec": {
            "ingressClassName": "nginx",
            "rules": [
                {
                    "host": "shop.contoso.com",
                    "http": {
                        "paths": [
                            {
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {"service": {"name": "storefront", "port": {"number": 80}}},
                            }
                        ]
                    },
                }
            ],
        },
    }
)
items += pods("orders", "orders-api", "ghcr.io/contoso/orders-api:1.9.2", {"app": "orders-api"}, 2)
items.append(service("orders", "orders-api", {"app": "orders-api"}))
items += pods("ops", "ssh-bastion", "ghcr.io/contoso/ssh-bastion:3.1", {"app": "ssh-bastion"}, 1)
items.append(service("ops", "ssh-bastion", {"app": "ssh-bastion"}))
items += pods("kube-system", "coredns", "registry.k8s.io/coredns/coredns:v1.12.1", {"k8s-app": "kube-dns"}, 2)
write(
    OUT / "k8s" / "cluster.json",
    {
        "name": "prod-aks",
        "serverVersion": {"major": "1", "minor": "34", "gitVersion": "v1.34.5", "platform": "linux/amd64"},
        "items": items,
    },
)
print("wrote demo inventory")
