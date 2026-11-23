"""Vendor advisories (CSAF): parsing, exploitation wording, version matching. No network."""

from datetime import date

from exploitwatch.advisories import Advisories, fixed_in, in_range, parse_range, same_line
from exploitwatch.feeds import exploited_sentences, trim_csaf
from exploitwatch.models import Asset, Software, Vuln
from exploitwatch.triage import DEFAULTS, classify

MS_URL = "https://msrc.microsoft.com/csaf/advisories/2026/msrc_cve-2026-96951.json"
CISCO_URL = "https://www.cisco.com/.well-known/csaf/2026/cisco-sa-asaftd-tunnel-dos.json"


def ms_doc(exploit_status="Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"):
    """Shaped like a Microsoft (MSRC) CSAF advisory: one CVE, version ranges, KB links."""

    def win(pid, name, fixed):
        return {
            "category": "product_name",
            "name": name,
            "branches": [
                {
                    "category": "product_version_range",
                    "name": f"<{fixed}",
                    "product": {"name": f"{name} <{fixed}", "product_id": pid},
                },
                {
                    "category": "product_version",
                    "name": fixed,
                    "product": {"name": f"{name} {fixed}", "product_id": pid + "f"},
                },
            ],
        }

    return {
        "document": {
            "title": "Windows Shell Security Feature Bypass Vulnerability",
            "tracking": {
                "id": "msrc_CVE-2026-96951",
                "initial_release_date": "2026-10-13T07:00:00Z",
                "current_release_date": "2026-10-26T07:00:00Z",
            },
            "references": [
                {"category": "self", "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96951"},
                {"category": "self", "url": MS_URL},
            ],
            "notes": [{"category": "legal_disclaimer", "text": "Exploited in the wild disclaimers don't count."}],
        },
        "product_tree": {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Microsoft",
                    "branches": [
                        win("1", "Windows 11 Version 24H2 for x64-based Systems", "10.0.26100.9711"),
                        win("2", "Windows 11 Version 25H2 for x64-based Systems", "10.0.26200.9711"),
                        win("3", "Windows 10 Version 22H2 for x64-based Systems", "10.0.19045.7807"),
                        win("4", "Windows Server 2025", "10.0.26100.9711"),
                    ],
                }
            ]
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2026-96951",
                "title": "Windows Shell Security Feature Bypass Vulnerability",
                "cwe": {"id": "CWE-693", "name": "Protection Mechanism Failure"},
                "notes": [
                    {
                        "category": "faq",
                        "text": "An attacker who exploited it in the wild could... (FAQ text is hypothetical)",
                    }
                ],
                "product_status": {"known_affected": ["1", "2", "3", "4"], "fixed": ["1f", "2f", "3f", "4f"]},
                "threats": [{"category": "exploit_status", "details": exploit_status}],
                "remediations": [
                    {
                        "category": "vendor_fix",
                        "details": "10.0.26100.9711:Security Update",
                        "product_ids": ["1", "4"],
                        "url": "https://support.microsoft.com/help/5126900",
                    }
                ],
                "scores": [
                    {"cvss_v3": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "baseScore": 8.8}}
                ],
            }
        ],
    }


def cisco_doc(note, cves=("CVE-2026-76418",)):
    """Shaped like a Cisco CSAF advisory: exact affected releases, exploitation in a note."""
    releases = ["9.20.4", "9.20.4.10", "9.22.3"]
    return {
        "document": {
            "title": "Cisco Secure Firewall ASA VPN Denial of Service Vulnerability",
            "tracking": {
                "id": "cisco-sa-asaftd-tunnel-dos",
                "initial_release_date": "2026-10-22T16:00:00+00:00",
                "current_release_date": "2026-11-14T05:00:00+00:00",
            },
            "references": [{"category": "self", "url": "https://sec.cloudapps.cisco.com/security/center/x"}],
            "notes": [{"category": "general", "title": "Exploitation and Public Announcements", "text": note}],
        },
        "product_tree": {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Cisco",
                    "branches": [
                        {
                            "category": "product_family",
                            "name": "Cisco Secure Firewall Adaptive Security Appliance (ASA) Software",
                            "branches": [
                                {
                                    "category": "product_version",
                                    "name": r,
                                    "product": {"name": r, "product_id": f"CSAFPID-{i}"},
                                }
                                for i, r in enumerate(releases)
                            ],
                        }
                    ],
                }
            ]
        },
        "vulnerabilities": [
            {
                "cve": c,
                "title": "VPN DoS",
                "product_status": {"known_affected": [f"CSAFPID-{i}" for i in range(len(releases))]},
                "scores": [
                    {"cvss_v3": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H", "baseScore": 8.6}}
                ],
            }
            for c in cves
        ],
    }


class FakeFeeds:
    """Just enough of Feeds for Advisories: hands back pre-trimmed docs."""

    today = date(2026, 11, 21)

    def __init__(self, docs: dict[str, list[tuple[str, dict]]]):
        self.docs = docs
        self.csaf_used: set = set()
        self.csaf_problems: dict = {}

    def csaf_index(self, provider, url, since):
        return [[u, "x"] for u, _ in self.docs.get(provider, [])]

    def csaf_docs(self, provider, entries):
        return [{**trim_csaf(raw, u), "_url": u} for u, raw in self.docs.get(provider, [])]


def advisories(**docs):
    return Advisories(FakeFeeds(docs), {"providers": list(docs)})


def windows(version):
    return Software(
        name="Windows",
        version=version,
        advisories="microsoft",
        advisory_product=r"^Windows 1[01] Version .* for x64-based Systems$",
        same_line=3,
        assets=[Asset("intune:1", "LT-1", "endpoint")],
    )


def asa(version, exposed=True):
    return Software(
        name="Cisco Secure Firewall ASA",
        version=version,
        advisories="cisco",
        advisory_product=r"Adaptive Security Appliance \(ASA\) Software",
        assets=[Asset("appliance:fw", "fw-edge-01", "appliance", exposed=exposed, exposure="VPN")],
    )


# ---- version ranges ----
def test_parse_range_forms():
    assert in_range("10.0.26100.9580", "<10.0.26100.9711")
    assert not in_range("10.0.26100.9711", "<10.0.26100.9711")
    assert in_range("1.5", "vers:generic/>=1.0|<2.0")
    assert not in_range("2.0", "vers:generic/>=1.0|<2.0")
    assert in_range("3.1", "vers:generic/>=1.0|<2.0|>=3.0|<3.2")
    assert not in_range("2.5", "vers:generic/>=1.0|<2.0|>=3.0|<3.2")
    assert in_range("4.2", ">= 4.0, <= 4.2")
    assert in_range("anything", "vers:generic/*")
    assert parse_range("=1.2.3") == [{"eq": "1.2.3"}]
    assert fixed_in("vers:generic/>=1.0|<2.0|>=3.0|<3.2") == {"2.0", "3.2"}


def test_same_line():
    assert same_line("10.0.26100.9580", "10.0.26100.9711", 3)
    assert not same_line("10.0.19045.7725", "10.0.26100.9711", 3)
    assert same_line("anything", "else", 0)


# ---- exploitation wording ----
def test_exploited_sentences():
    yes = [
        "In October 2026, the Cisco PSIRT became aware of active exploitation of this vulnerability.",
        "The Cisco PSIRT is aware of limited, targeted exploitation of this vulnerability.",
        "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected",
        "This vulnerability is being actively exploited.",
    ]
    no = [
        "These vulnerabilities were found during internal testing and are not known to be actively exploited.",
        "The Cisco PSIRT is not aware of any public announcements or malicious use of the vulnerability.",
        "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely",
        "An attacker could exploit this vulnerability by sending crafted packets.",
    ]
    assert all(exploited_sentences(t) for t in yes)
    assert not any(exploited_sentences(t) for t in no)


def test_trim_microsoft():
    doc = trim_csaf(ms_doc(), MS_URL)
    assert doc["url"].startswith("https://msrc.microsoft.com/update-guide/")
    v = doc["vulns"][0]
    assert v["exploited"] and not v["disclosed"]
    assert v["cwes"] == ["CWE-693"] and v["score"] == 8.8
    assert doc["products"]["1"] == ["Windows 11 Version 24H2 for x64-based Systems", "", "<10.0.26100.9711"]
    assert doc["products"]["1f"][1] == "10.0.26100.9711"
    assert v["fix_urls"]["1"] == "https://support.microsoft.com/help/5126900"


def test_faq_and_disclaimer_text_dont_count_as_exploited():
    doc = trim_csaf(ms_doc("Publicly Disclosed:Yes;Exploited:No;Latest Software Release:Exploitation More Likely"), "")
    v = doc["vulns"][0]
    assert not v["exploited"] and v["disclosed"]


def test_cisco_note_applies_to_named_cves_or_the_only_one():
    one = trim_csaf(cisco_doc("The Cisco PSIRT is aware of attempted exploitation of this vulnerability."), "")
    assert one["vulns"][0]["exploited"]
    named = trim_csaf(
        cisco_doc(
            "In March 2026, the Cisco PSIRT became aware of active exploitation of CVE-2026-20128 only.",
            cves=("CVE-2026-20128", "CVE-2026-20122"),
        ),
        "",
    )
    assert [v["exploited"] for v in named["vulns"]] == [True, False]
    vague = trim_csaf(
        cisco_doc(
            "Two of them are known to be actively exploited.",
            cves=("CVE-2026-20128", "CVE-2026-20122", "CVE-2026-20133"),
        ),
        "",
    )
    assert not any(v["exploited"] for v in vague["vulns"])
    assert all(v["some_exploited"] for v in vague["vulns"])


# ---- matching ----
def test_windows_build_behind_the_fix_matches_its_own_release_only():
    adv = advisories(microsoft=[(MS_URL, ms_doc())])
    vulns = adv.for_software(windows("10.0.26100.9580"))
    assert [v.id for v in vulns] == ["CVE-2026-96951"]
    v = vulns[0]
    assert v.fixed == {"10.0.26100.9711"}  # 24H2's fix, not 25H2's or Windows 10's
    assert v.vendor_exploited and v.vendor[0]["fix_url"].endswith("5126900")
    assert adv.feeds.csaf_used == {("microsoft", MS_URL)}


def test_patched_and_other_release_builds_dont_match():
    adv = advisories(microsoft=[(MS_URL, ms_doc())])
    assert adv.for_software(windows("10.0.26100.9974")) == []  # November build: patched
    assert adv.for_software(windows("10.0.26200.9711")) == []  # 25H2 at the fixed build
    win10 = adv.for_software(windows("10.0.19045.7725"))
    assert win10 and win10[0].fixed == {"10.0.19045.7807"}


def test_cisco_exact_release_list():
    adv = advisories(cisco=[(CISCO_URL, cisco_doc("The Cisco PSIRT is aware of active exploitation."))])
    assert [v.id for v in adv.for_software(asa("9.20.4.10"))] == ["CVE-2026-76418"]
    assert adv.for_software(asa("9.20.4.11")) == []  # not in Cisco's affected list


def test_vague_exploitation_becomes_a_gap_not_an_alert():
    doc = cisco_doc("Two of them are known to be actively exploited.", cves=("CVE-2026-20128", "CVE-2026-20122"))
    adv = advisories(cisco=[(CISCO_URL, doc)])
    vulns = adv.for_software(asa("9.22.3"))
    assert len(vulns) == 2 and not any(v.vendor_exploited for v in vulns)
    assert len(adv.gaps) == 1 and "without naming which CVEs" in adv.gaps[0]


def test_unversioned_exploited_advisory_is_a_gap():
    doc = ms_doc()
    doc["product_tree"]["branches"][0]["branches"].append(
        {
            "category": "product_name",
            "name": "Windows 11 Version 26H1 for x64-based Systems",
            "product": {"name": "Windows 11 Version 26H1 for x64-based Systems", "product_id": "9"},
        }
    )
    doc["vulnerabilities"][0]["product_status"]["known_affected"] = ["9"]
    adv = advisories(microsoft=[(MS_URL, doc)])
    assert adv.for_software(windows("10.0.28000.3000")) == []
    assert any("doesn't give versions" in g for g in adv.gaps)


def test_enrichment_adds_vendor_flags_to_cves_found_elsewhere():
    adv = advisories(cisco=[(CISCO_URL, cisco_doc("The Cisco PSIRT is aware of active exploitation."))])
    v = Vuln(id="CVE-2026-76418")
    adv.enrich(v)
    adv.enrich(v)  # idempotent
    assert len(v.vendor) == 1 and v.vendor_exploited
    assert v.vector.startswith("CVSS:3.1/AV:N")


def test_provider_failure_is_a_gap():
    class Broken(FakeFeeds):
        def csaf_index(self, provider, url, since):
            raise RuntimeError("403 Forbidden")

    adv = Advisories(Broken({}), {"providers": ["cisco"]})
    assert adv.for_software(asa("9.20.4.10")) == []
    assert adv.gaps == ["Couldn't read Cisco advisories: 403 Forbidden"]


# ---- triage ----
def test_vendor_exploited_is_urgent_even_without_kev():
    adv = advisories(cisco=[(CISCO_URL, cisco_doc("The Cisco PSIRT is aware of active exploitation."))])
    sw = asa("9.20.4.10", exposed=False)
    v = adv.for_software(sw)[0]
    tier, reasons, notes = classify(sw, v, date(2026, 11, 21), DEFAULTS)
    assert tier == "urgent" and "Vendor says it is exploited" in reasons
    assert notes["Vendor says it is exploited"] == "Cisco"


def test_publicly_disclosed_goes_to_digest():
    doc = ms_doc("Publicly Disclosed:Yes;Exploited:No;Latest Software Release:Exploitation More Likely")
    adv = advisories(microsoft=[(MS_URL, doc)])
    sw = windows("10.0.26100.9580")
    v = adv.for_software(sw)[0]
    tier, reasons, _ = classify(sw, v, date(2026, 11, 21), DEFAULTS)
    assert tier == "digest" and reasons == ["Publicly disclosed before the fix"]


def test_link_instead_of_version_is_unknown_not_unaffected():
    doc = ms_doc()
    rng = doc["product_tree"]["branches"][0]["branches"][0]["branches"][0]
    rng["name"] = "<https://aka.ms/OfficeSecurityReleases"
    adv = advisories(microsoft=[(MS_URL, doc)])
    assert adv.for_software(windows("10.0.26100.9580")) == []
    assert any("doesn't give versions" in g for g in adv.gaps)
