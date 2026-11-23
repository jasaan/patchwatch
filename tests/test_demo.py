"""End-to-end run on the demo inventory against the recorded feeds (no network)."""

import json
from pathlib import Path

import pytest

from exploitwatch import inventory, notify
from exploitwatch.advisories import Advisories
from exploitwatch.cli import load_config, main
from exploitwatch.feeds import Feeds
from exploitwatch.match import add_epss, match_software
from exploitwatch.report import group
from exploitwatch.triage import triage

DEMO = Path(__file__).resolve().parent.parent / "demo" / "config.yaml"


@pytest.fixture(scope="module")
def run():
    config, base = load_config(str(DEMO))
    feeds = Feeds("replay", base / config["feeds_dir"])
    catalog = inventory.build(config, base)
    adv = Advisories(feeds, config["advisories"])
    results = {sw.key: match_software(sw, feeds, config["nvd_lookback_days"], adv) for sw in catalog.software}
    catalog.gaps += adv.gaps
    add_epss(results, feeds)
    findings = [f for sw in catalog.software for f in triage(sw, results[sw.key], feeds, feeds.today, config["triage"])]
    return catalog, findings, feeds


def alerts_by_tier(findings):
    out = {}
    for a in group(findings):
        out.setdefault(a.tier, set()).add(a.title)
    return out


def test_snapshot_is_complete(run):
    _, _, feeds = run
    assert feeds.missing == []
    assert feeds.today.isoformat() == "2026-11-21"


def test_urgent_alerts(run):
    assert alerts_by_tier(run[1])["urgent"] == {
        "Notepad++ 8.8.1",  # KEV CVE-2025-15556
        "WinRAR 7.01.0",  # KEV CVE-2025-8088 and CVE-2025-6218
        "sudo 1.9.15p5-3ubuntu5",  # KEV CVE-2025-32463 on web-01
        "react-server-dom-webpack 19.0.0",  # KEV CVE-2025-55182 (React2Shell) on the public storefront
        "openssh-server 10.0_p1-r7",  # KEV added 12 days ago: zero-day rule
        "ingress-nginx 1.11.3",  # CVE-2025-1974, unauthenticated RCE behind a LoadBalancer
        "next 15.1.3",  # CVE-2025-29927 middleware auth bypass on the public storefront
        # from vendor advisories
        "Windows 11 24H2 10.0.26100.9580",  # missed October: Microsoft says CVE-2026-96951 is exploited
        "Windows 10 22H2 10.0.19045.7725",  # same, on Windows 10
        "Microsoft Edge 154.0.4258.37",  # CVE-2026-96951 also lists Edge
        "Cisco Secure Firewall ASA 9.20.4.10",  # Cisco PSIRT: CVE-2026-76418 actively exploited
    }


def _finding(findings, product, cve):
    return next(
        f for f in findings if f.vuln and f.vuln.id == cve and f.software.name + " " + f.software.version == product
    )


def test_vendor_exploited_reason_and_fix(run):
    _, findings, _ = run
    f = _finding(findings, "Windows 11 24H2 10.0.26100.9580", "CVE-2026-96951")
    assert "Vendor says it is exploited" in f.reasons and f.notes["Vendor says it is exploited"] == "Microsoft"
    alert = next(a for a in group(findings) if a.title == "Windows 11 24H2 10.0.26100.9580" and a.tier == "urgent")
    assert alert.fix == "10.0.26100.9974"  # November's build fixes everything in the window
    assert alert.links()[0][1] == "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96951"
    asa = _finding(findings, "Cisco Secure Firewall ASA 9.20.4.10", "CVE-2026-76418")
    assert asa.vuln.kev and asa.vuln.vendor_exploited and asa.software.exposed


def test_patched_windows_is_quiet(run):
    _, findings, _ = run
    noisy = {f.software.name + " " + f.software.version for f in findings if f.tier != "log"}
    assert not any(n.endswith("10.0.26100.9974") or n.endswith("10.0.26200.9974") for n in noisy)


def test_vendor_gaps(run):
    catalog, _, _ = run
    assert any("CVE-2026-124194" in g and "doesn't give versions" in g for g in catalog.gaps)  # Office
    assert any("without naming which CVEs" in g for g in catalog.gaps)  # Cisco hardening bundle


def test_browser_criticals_go_to_digest_not_urgent(run):
    tiers = alerts_by_tier(run[1])
    assert "Google Chrome 157.0.8103.50" in tiers["digest"]
    assert "Google Chrome 157.0.8103.50" not in tiers["urgent"]


def test_up_to_date_and_unaffected_versions_are_quiet(run):
    _, findings, _ = run
    noisy = {f.software.name + " " + f.software.version for f in findings if f.tier != "log"}
    assert "Google Chrome 158.0.8127.36" not in noisy  # current Chrome
    assert "sudo 1.9.9-1ubuntu2.5" not in noisy  # CVE-2025-32463 only affects sudo 1.9.14 to 1.9.17


def test_zero_day_reason(run):
    _, findings, _ = run
    f = next(f for f in findings if f.vuln and f.vuln.id == "CVE-2026-123158")
    assert f.tier == "urgent" and f.notes[f.reasons[0]] == "added 12d ago"


def test_weekly_lifecycle(run):
    weekly = alerts_by_tier(run[1])["weekly"]
    assert {"Kubernetes 1.34.5", "Python 3.9.13", "django 5.1.4", "next 15.1.3"} <= weekly


def test_intune_names_merge_and_gaps(run):
    catalog, _, _ = run
    chrome = next(s for s in catalog.software if s.key == "cpe:google:chrome@157.0.8103.50")
    apps = json.loads((DEMO.parent / "inventory/intune/detectedApps.json").read_text())["value"]
    devices = {d["id"] for a in apps if a["version"] == "157.0.8103.50" for d in a["managedDevices"]}
    assert len(chrome.assets) == len(devices)  # "Google Chrome" and "Google Chrome (x64)", each device once
    assert not any(s.name == "Microsoft Teams" for s in catalog.software)  # ignore rule
    assert any("Contoso Expense Helper" in g for g in catalog.gaps)
    assert any("coredns" in g for g in catalog.gaps)


def test_payloads(run):
    alerts = [a for a in group(run[1]) if a.tier in ("urgent", "digest")]
    slack = notify.slack_payload(alerts)
    assert slack["blocks"][0]["type"] == "header" and len(slack["blocks"]) <= 50
    card = notify.teams_payload(alerts)["attachments"][0]
    assert card["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert card["content"]["type"] == "AdaptiveCard"


def test_cli_run_and_ack(tmp_path):
    state = str(tmp_path / "state.db")
    args = [
        "run",
        "--config",
        str(DEMO),
        "--state",
        state,
        "--json",
        str(tmp_path / "f.json"),
        "--report",
        str(tmp_path / "r.md"),
        "--fail-on-urgent",
    ]
    with pytest.raises(SystemExit) as e:
        main(args)
    assert e.value.code == 1  # urgent findings present
    with pytest.raises(SystemExit):
        main(
            ["ack", "CVE-2025-15556", "--product", "Notepad++", "--reason", "updater disabled by GPO", "--state", state]
        )
    with pytest.raises(SystemExit):
        main(args)
    ids = {f["vuln"]["id"] for f in json.loads((tmp_path / "f.json").read_text()) if f["vuln"]}
    assert "CVE-2025-15556" not in ids
    assert "1 acknowledged" in (tmp_path / "r.md").read_text()
