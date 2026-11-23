from datetime import date

import pytest

from exploitwatch.inventory import Catalog, _split_image, add_cluster, exposed_services
from exploitwatch.match import nvd_affects, osv_query_for, parse_purl, vuln_from_osv
from exploitwatch.models import Asset, Finding, Software, Vuln
from exploitwatch.state import State
from exploitwatch.triage import DEFAULTS, attack_class, classify
from exploitwatch.versions import compare, cvss3_score, in_range


# ---------------------------------------------------------------- versions
@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("157.0.8103.50", "157.0.8103.109", -1),
        ("8.8.9", "8.8.1", 1),
        ("10.6", "10.6p1", -1),
        ("10.6p2", "10.6p1", 1),
        ("v1.11.3", "1.11.3", 0),
        ("1:9.6p1", "9.6p1", 0),
        ("7.01.0", "7.13", -1),
    ],
)
def test_compare(a, b, expected):
    assert compare(a, b) == expected


def test_in_range():
    assert in_range("15.1.3", {"versionStartIncluding": "15.1.0", "versionEndExcluding": "15.1.9"})
    assert not in_range("15.1.9", {"versionStartIncluding": "15.1.0", "versionEndExcluding": "15.1.9"})
    assert not in_range("14.2.0", {"versionStartIncluding": "15.1.0", "versionEndExcluding": "15.1.9"})
    assert in_range("2.0", {"versionEndIncluding": "2.0"})


@pytest.mark.parametrize(
    "vector,score",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3(vector, score):
    assert cvss3_score(vector) == score


def test_cvss4_not_scored():
    assert cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None


# ---------------------------------------------------------------- purls and OSV
def test_parse_purl():
    p = parse_purl("pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13.5?arch=amd64&distro=ubuntu-24.04&upstream=openssh")
    assert p["type"] == "deb" and p["name"] == "openssh-server" and p["version"] == "1:9.6p1-3ubuntu13.5"
    assert p["qualifiers"]["upstream"] == "openssh"


@pytest.mark.parametrize(
    "purl,query",
    [
        (
            "pkg:deb/ubuntu/sudo@1.9.15p5-3ubuntu5?arch=amd64&distro=ubuntu-24.04",
            {"package": {"name": "sudo", "ecosystem": "Ubuntu:24.04:LTS"}, "version": "1.9.15p5-3ubuntu5"},
        ),
        (
            "pkg:deb/ubuntu/sudo@1.9.15?distro=ubuntu-24.10",
            {"package": {"name": "sudo", "ecosystem": "Ubuntu:24.10"}, "version": "1.9.15"},
        ),
        (
            "pkg:deb/debian/libssl3@3.0.15-1~deb12u1?distro=debian-12&upstream=openssl",
            {"package": {"name": "openssl", "ecosystem": "Debian:12"}, "version": "3.0.15-1~deb12u1"},
        ),
        (
            "pkg:apk/alpine/openssh-server@10.0_p1-r7?arch=x86_64&distro=alpine-3.22.1&upstream=openssh",
            {"package": {"name": "openssh", "ecosystem": "Alpine:v3.22"}, "version": "10.0_p1-r7"},
        ),
        ("pkg:npm/next@15.1.3", {"package": {"purl": "pkg:npm/next@15.1.3"}}),
    ],
)
def test_osv_query_for(purl, query):
    assert osv_query_for(purl) == query


def test_distro_notice_with_many_cves_is_skipped():
    rec = {"id": "USN-7604-1", "upstream": ["CVE-2025-1", "CVE-2025-2"], "affected": []}
    rec["upstream"] = ["CVE-2025-10001", "CVE-2025-10002"]
    assert vuln_from_osv(rec, "sudo") is None


def test_osv_record_uses_cve_id_and_fixed_versions():
    rec = {
        "id": "GHSA-mgvx-rpfc-9mpv",
        "aliases": ["CVE-2025-1974", "GO-2025-3567"],
        "summary": "x",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"cwe_ids": ["CWE-653"], "severity": "CRITICAL"},
        "affected": [
            {
                "package": {"name": "k8s.io/ingress-nginx", "ecosystem": "Go"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.11.5"}]}],
            }
        ],
    }
    v = vuln_from_osv(rec, "k8s.io/ingress-nginx")
    assert v.id == "CVE-2025-1974" and v.score == 9.8 and v.fixed == {"1.11.5"}


# ---------------------------------------------------------------- NVD matching
NVD_REC = {
    "id": "CVE-X",
    "configurations": [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "criteria": "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*",
                            "vulnerable": True,
                            "versionEndExcluding": "7.13",
                        },
                        {"criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", "vulnerable": False},
                    ]
                }
            ]
        }
    ],
}


def test_nvd_affects_range():
    assert nvd_affects(NVD_REC, "rarlab:winrar", "7.01.0") == (True, {"7.13"})
    assert nvd_affects(NVD_REC, "rarlab:winrar", "7.13")[0] is False
    assert nvd_affects(NVD_REC, "microsoft:windows", "10")[0] is False  # platform node, not vulnerable


def test_nvd_affects_exact_version_with_update():
    rec = {
        "configurations": [
            {
                "nodes": [
                    {"cpeMatch": [{"criteria": "cpe:2.3:a:openbsd:openssh:10.6:p1:*:*:*:*:*:*", "vulnerable": True}]}
                ]
            }
        ]
    }
    assert nvd_affects(rec, "openbsd:openssh", "10.6p1")[0]
    assert not nvd_affects(rec, "openbsd:openssh", "10.6p2")[0]


# ---------------------------------------------------------------- triage
TODAY = date(2026, 11, 21)


def sw(exposed=False):
    return Software("App", "1.0", assets=[Asset("a", "a", "server", exposed=exposed, exposure="test")])


def endpoint_sw():
    return Software("Browser", "1.0", assets=[Asset("l", "laptop", "endpoint")])


def test_recent_kev_is_zero_day():
    v = Vuln("CVE-1", kev={"dateAdded": "2026-11-09", "knownRansomwareCampaignUse": "Unknown"})
    tier, reasons, notes = classify(sw(), v, TODAY, DEFAULTS)
    assert tier == "urgent" and reasons == ["Zero-day (added to CISA KEV in the last 14 days)"]
    assert notes[reasons[0]] == "added 12d ago"


def test_old_kev_with_ransomware():
    v = Vuln("CVE-1", kev={"dateAdded": "2025-08-12", "knownRansomwareCampaignUse": "Known"})
    tier, reasons, notes = classify(sw(), v, TODAY, DEFAULTS)
    assert tier == "urgent" and reasons == ["On CISA KEV", "Used in ransomware campaigns"]
    assert notes["On CISA KEV"] == "added 2025-08-12"


def test_unauth_network_rce_critical_is_urgent():
    v = Vuln("CVE-1", score=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwes={"CWE-502"})
    assert classify(sw(), v, TODAY, DEFAULTS)[:2] == ("urgent", ["Unauthenticated network RCE"])


def test_same_bug_in_a_desktop_app_goes_to_digest():
    v = Vuln("CVE-1", score=9.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwes={"CWE-502"})
    assert classify(endpoint_sw(), v, TODAY, DEFAULTS)[:2] == ("digest", ["Critical RCE in a desktop app"])


def test_unauth_bypass_high_only_urgent_when_exposed():
    v = Vuln("CVE-1", score=8.1, vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", cwes={"CWE-287"})
    assert classify(sw(), v, TODAY, DEFAULTS)[0] == "log"
    assert classify(sw(exposed=True), v, TODAY, DEFAULTS)[:2] == (
        "urgent",
        ["Unauthenticated network auth bypass on an internet-facing asset"],
    )


def test_exposed_but_below_min_score_is_not_urgent():
    v = Vuln("CVE-1", score=7.0, vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L", cwes={"CWE-94"})
    assert classify(sw(exposed=True), v, TODAY, DEFAULTS)[0] == "log"


def test_rce_needing_user_click_is_not_urgent():
    v = Vuln("CVE-1", score=8.8, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", cwes={"CWE-502"})
    assert classify(sw(), v, TODAY, DEFAULTS)[0] == "log"


def test_memory_corruption_alone_is_not_rce():
    v = Vuln(
        "CVE-1",
        score=9.8,
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwes={"CWE-787"},
        summary="A heap buffer overflow may lead to a crash or possibly attacker controlled code execution.",
    )
    assert attack_class(v) == ""
    assert classify(sw(), v, TODAY, DEFAULTS)[0] == "log"  # critical, but not exposed and not likely exploited


def test_critical_needs_epss_or_exposure_for_digest():
    v = Vuln("CVE-1", score=9.1, vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", epss=0.02)
    assert classify(sw(), v, TODAY, DEFAULTS)[0] == "log"
    v.epss = 0.35
    tier, reasons, notes = classify(sw(), v, TODAY, DEFAULTS)
    assert (tier, reasons) == ("digest", ["Critical and likely to be exploited"])
    assert notes[reasons[0]] == "CVSS 9.1, EPSS 35%"


def test_high_epss_alone_goes_to_digest():
    v = Vuln("CVE-1", score=6.5, epss=0.5)
    assert classify(sw(), v, TODAY, DEFAULTS)[0] == "digest"


def test_attack_class_from_description_when_cwe_is_vague():
    v = Vuln("CVE-1", summary="an unauthenticated attacker can achieve arbitrary code execution", cwes={"CWE-653"})
    assert attack_class(v) == "RCE"


# ---------------------------------------------------------------- Kubernetes
CLUSTER = {
    "name": "c1",
    "serverVersion": {"gitVersion": "v1.34.5-eks-1"},
    "items": [
        {
            "kind": "Pod",
            "metadata": {
                "name": "web-abc12345-x1y2z",
                "namespace": "shop",
                "labels": {"app": "web"},
                "ownerReferences": [{"kind": "ReplicaSet", "name": "web-abc12345"}],
            },
            "spec": {"containers": [{"name": "web", "image": "registry.local:5000/web:1.0"}]},
        },
        {
            "kind": "Pod",
            "metadata": {"name": "ing-1", "namespace": "ingress", "labels": {"app": "ing"}},
            "spec": {
                "containers": [{"name": "c", "image": "registry.k8s.io/ingress-nginx/controller:v1.11.3@sha256:abc"}]
            },
        },
        {
            "kind": "Service",
            "metadata": {"name": "web", "namespace": "shop"},
            "spec": {"type": "ClusterIP", "selector": {"app": "web"}},
        },
        {
            "kind": "Service",
            "metadata": {"name": "ing", "namespace": "ingress"},
            "spec": {"type": "LoadBalancer", "selector": {"app": "ing"}},
        },
        {
            "kind": "Ingress",
            "metadata": {"name": "web", "namespace": "shop"},
            "spec": {
                "rules": [{"host": "shop.example", "http": {"paths": [{"backend": {"service": {"name": "web"}}}]}}]
            },
        },
    ],
}


def test_split_image_with_registry_port_and_digest():
    assert _split_image("registry.local:5000/web:1.0") == ("registry.local:5000/web", "1.0")
    assert _split_image("registry.local:5000/web") == ("registry.local:5000/web", "latest")
    assert _split_image("nginx:1.27@sha256:abc") == ("nginx", "1.27")


def test_exposure_from_services_and_ingress():
    assert exposed_services(CLUSTER["items"]) == {
        ("ingress", "ing"): "Service type LoadBalancer",
        ("shop", "web"): "Ingress shop.example",
    }


def test_cluster_inventory(tmp_path):
    cat = Catalog()
    add_cluster(cat, CLUSTER, tmp_path, [])
    by_name = {s.name: s for s in cat.software}
    assert by_name["Kubernetes"].version == "1.34.5"
    nginx = by_name["ingress-nginx"]
    assert nginx.purl == "pkg:golang/k8s.io/ingress-nginx@1.11.3" and nginx.exposed
    assert any("No SBOM for image registry.local:5000/web:1.0" in g for g in cat.gaps)


# ---------------------------------------------------------------- state
def test_notify_only_new_or_escalated(tmp_path):
    st = State(tmp_path / "s.db")
    s = Software("App", "1.0", cpe="v:p")
    f = Finding(s, "digest", ["x"], vuln=Vuln("CVE-1"))
    st.record([f])
    assert st.to_notify([f], {"urgent", "digest"}) == [f]
    st.mark_notified([f])
    assert st.to_notify([f], {"urgent", "digest"}) == []
    up = Finding(s, "urgent", ["now on KEV"], vuln=Vuln("CVE-1"))
    assert st.to_notify([up], {"urgent", "digest"}) == [up]
    st.ack("CVE-1", "App", "not reachable", "me")
    assert st.to_notify([up], {"urgent", "digest"}) == []
