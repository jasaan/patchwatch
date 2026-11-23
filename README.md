# ExploitWatch

**Matches what your company runs (Intune laptops and their Windows builds, Linux servers, Kubernetes, firewalls) against free vulnerability feeds and the vendors' own security advisories, and tells the team only about what needs action: vulnerabilities being exploited right now, zero-days, and network-reachable RCEs and auth bypasses. Everything else is logged, not sent.**

> Built with Claude; designed, reviewed and tested by me. The demo inventory is fictional (Contoso laptops, two servers, one AKS cluster). The feed data is real: CISA KEV, NVD, OSV, EPSS and endoflife.date, recorded with `--live --record` on 2026-11-21, plus Microsoft and Cisco security advisories (CSAF) recorded on 2026-11-23 for the same date. Live Intune (`--live-intune`) and live cluster (`--live-cluster`) collection use Microsoft Graph and kubectl's documented read-only calls, but **haven't been run against a real tenant or cluster yet**. Please report anything that doesn't work.

## What it found in the demo

36 products across 470 laptops, 2 servers, 1 cluster and 1 firewall. That's **2,427 matching vulnerabilities** (1,614 distinct CVEs and advisories), but only **11 urgent alerts**:

| Alert | Why it's urgent |
|---|---|
| Windows 11 24H2 build 26100.9580 (45 laptops) | Missed October's update. **Microsoft says** CVE-2026-96951 (Windows Shell, Mark of the Web bypass) **is exploited**; also on KEV. Fix: build 26100.9974, with the KB link. |
| Windows 10 22H2 (15 laptops) | Same CVE, same reason. Fix: build 19045.7846. |
| Microsoft Edge 154 (28 laptops) | Microsoft lists Edge as affected by the same exploited CVE. |
| Cisco ASA 9.20.4.10 on the internet-facing `fw-edge-01` | **Cisco PSIRT says** CVE-2026-76418 and CVE-2026-20349 are **actively exploited** (both on KEV). Cisco lists 9.20.4.10 as affected by name. |
| Notepad++ 8.8.1 (37 laptops) | On CISA KEV: CVE-2025-15556 (update hijack) |
| WinRAR 7.01 (12 laptops) | On KEV and used by ransomware: CVE-2025-8088, CVE-2025-6218 |
| sudo on `web-01` | On KEV: CVE-2025-32463 (chroot privilege escalation) |
| react-server-dom-webpack 19.0.0 in the public storefront | On KEV, used by ransomware: CVE-2025-55182 (React2Shell) |
| openssh-server on the Alpine bastion pod | **Zero-day:** CVE-2026-123158 was added to KEV 12 days ago |
| ingress-nginx 1.11.3 behind a LoadBalancer | Unauthenticated RCE on an internet-facing workload: CVE-2025-1974 (IngressNightmare) |
| Next.js 15.1.3 in the public storefront | Unauthenticated auth bypass on an internet-facing workload: CVE-2025-29927 |

The [full report](examples/report.md) also has:
- a daily digest of 7 items, for example critical Chrome bugs and EPSS 75% OpenSSL bugs;
- weekly planning, such as Kubernetes 1.34 being out of support and Python 3.9 on 6 laptops;
- gaps, meaning things it couldn't check: an Intune app with no mapping, an image with no SBOM, an **exploited Outlook bug** whose Microsoft advisory gives no version for Microsoft 365 Apps, and a **Cisco hardening advisory** that says "two of these are exploited" without naming which.

The 410 laptops on November's builds don't appear at all.

The [Slack](examples/slack.json) and [Teams](examples/teams.json) messages are in `examples/`.

## How it decides

| Tier | Sent | Rule |
|---|---|---|
| 🔴 **Urgent** | right away | On **CISA KEV**. Counts as a **zero-day** if added in the last 14 days. |
| | | The **vendor's advisory says it's exploited**: Microsoft's "Exploited: Yes", or a Cisco PSIRT exploitation notice. Vendors often say so the day they ship the fix, before KEV lists it. |
| | | The advisory says the vulnerability is **exploited in the wild**. |
| | | **Unauthenticated network RCE or auth bypass** on a server, container or cluster: critical (CVSS ≥ 9.0), or high (≥ 8.0) on an internet-facing asset. |
| 🟠 **Digest** | daily | Critical, and EPSS ≥ 10% or internet-facing. |
| | | EPSS ≥ 10% on its own (likely to be exploited within 30 days). |
| | | A critical RCE in a desktop app or in the laptops' operating system. |
| | | The vendor says it was **publicly disclosed** before the fix. |
| ⚪ **Weekly** | weekly | End of support has passed or is within 90 days. |
| | | A new release of a product you opted in to (`watch_releases`). |
| · Logged | never | Everything else. It's in the report and the JSON, but nobody gets pinged. |

Some choices that keep the noise down:

- **Desktop apps aren't treated like servers.** A browser bug rated "network, no login needed" still requires someone to open a malicious page. Those go to the digest. KEV still makes them urgent.
- **"RCE" means the advisory actually says so.** Injection and deserialization bug types (CWE-77/78/94/502…) count. Memory-corruption types count only when the description claims code execution without hedging. Sentences like "may lead to a crash or possibly code execution" don't count. This moved OpenSSL's "possibly code execution" heap bugs, rated 9.8 in NVD, from urgent to the digest.
- **Internet-facing comes from the source.**
  - Kubernetes: Services of type LoadBalancer or NodePort, and Services behind an Ingress.
  - Servers: a list in the config.
  - Every alert names the asset and why it counts, for example `prod-aks/shop/storefront (Ingress shop.contoso.com)`.
- **One alert per product version.** It lists each reason with the CVEs behind it, the devices or workloads affected, and the lowest version that fixes them all.
- **Vendor wording is read strictly.** "Not known to be actively exploited" doesn't count. When a bundled advisory says "two of these are exploited" without naming them, it goes under **Gaps** with a link to check by hand, instead of marking every CVE in the bundle as exploited.
- **Alerts link to the fix.** Vendor-matched alerts carry the advisory and the update to install (a KB article, Cisco's software page), and the fixed build: "upgrade to 10.0.26100.9974 or later".
- **Repeat alerts are suppressed.** A finding is sent once. It's sent again only if it moves up a tier, for example when a digest CVE lands on KEV.
- **Acknowledgements are recorded.** `exploitwatch ack` silences a CVE for one product and records who decided and why.

## Where the data comes from

| Inventory | How |
|---|---|
| **Intune** | Graph `deviceManagement/detectedApps` and each app's `managedDevices` (permission: `DeviceManagementManagedDevices.Read.All`) |
| **Servers** | CycloneDX SBOMs, one per host, for example `syft / -o cyclonedx-json` |
| **Kubernetes** | Pods, Services and Ingresses from `kubectl` (read-only), plus one SBOM per image. Known add-ons (ingress-nginx, cert-manager, Argo CD) are recognized by controller image. The cluster version is checked for end of support. |
| **Windows builds** | Graph `deviceManagement/managedDevices` (same permission): each laptop's OS build, such as `10.0.26100.9580`, compared with the fixed builds in Microsoft's advisories for that Windows release only. |
| **Appliances** | A short YAML list of firewalls and VPN gateways: host, product, version, internet-facing. Matched against the vendor's advisories (Cisco) or NVD and KEV (Fortinet, Palo Alto, Ivanti). |

| Feed | Used for |
|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited now, date added, ransomware use |
| [OSV](https://osv.dev) | Package vulnerabilities (npm, PyPI, Go, Debian, Ubuntu, Alpine). OSV does the version matching, including distro version rules. |
| [NVD](https://nvd.nist.gov/developers) | Desktop apps by NVD product ID (vendor:product), checked locally against each CVE's version ranges. Also CVSS vectors and CWE types when OSV lacks them. |
| [EPSS](https://www.first.org/epss/) | Probability of exploitation in the next 30 days |
| [endoflife.date](https://endoflife.date) | End-of-support dates and latest releases |
| **Vendor advisories ([CSAF](https://www.csaf.io))** | The vendor's own list of affected versions and fixes, whether it's exploited, and the advisory link. Built in: Microsoft, Cisco, Red Hat, SUSE, Siemens, CISA ICS; any other vendor's `provider-metadata.json` works. Downloaded advisories are cached, so daily runs only fetch what changed. |

Intune names apps loosely ("Google Chrome", "Google Chrome (x64)"), so [`mappings.yaml`](demo/mappings.yaml) maps them to NVD product IDs. `exploitwatch suggest --live` proposes IDs for unmapped apps from the NVD product dictionary. Apps with no mapping appear under **Gaps** in every report; they're never dropped silently. For vendor advisories, `exploitwatch products cisco --live --search 'ASA|Firepower'` lists the vendor's own product names to put in a rule.

## Try it (no accounts needed)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

exploitwatch run                                   # demo inventory + recorded feeds → report
exploitwatch run --notify --dry-run                # also write the Slack/Teams messages to out/
exploitwatch ack CVE-2025-15556 --product "Notepad++" --reason "updater disabled by GPO"
pytest -q                                        # 71 tests, no network
```

Replay mode uses the snapshot's recording date as "today", so results don't drift. To fetch current data instead, run `exploitwatch run --live`. Set `NVD_API_KEY` ([free key](https://nvd.nist.gov/developers/request-an-api-key)) to make it about 10× faster.

## Try it at work

[`starter/`](starter) is a ready-made setup for a Microsoft shop: live Intune, Windows builds, Microsoft and Cisco advisories, and mapping rules for common apps and edge devices. A first run takes about an hour of setup and changes nothing in your tenant: every call is a read.

1. **Install** on a machine that can reach the internet:
   ```bash
   git clone https://github.com/jasaan/exploitwatch && cd exploitwatch
   python3 -m venv .venv && source .venv/bin/activate
   pip install -e ".[intune]"
   cp -r starter ~/exploitwatch-work   # keep your inventory and state outside the repo
   ```
2. **Get read access to Intune.** An Entra admin creates an app registration with the **`DeviceManagementManagedDevices.Read.All`** *application* permission and grants admin consent. Then set:
   ```bash
   export AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=…
   ```
3. **List your appliances** in `~/exploitwatch-work/appliances.yaml` (or delete the example). Firewalls and VPN gateways are where vendors most often announce exploitation.
4. **First run, nothing sent:**
   ```bash
   cd ~/exploitwatch-work
   exploitwatch run --config config.yaml --live --live-intune --save-inventory inventory/ \
     --report report.md --notify --dry-run
   ```
   The first run downloads about 90 days of Microsoft and Cisco advisories (several thousand files, 10 to 20 minutes) into `~/.cache/exploitwatch`. Later runs only fetch what changed. Set `NVD_API_KEY` ([free](https://nvd.nist.gov/developers/request-an-api-key)) to speed up the desktop app checks.
5. **Read `report.md`, starting with Gaps.** It lists the apps no rule covers, ranked by device count. Add rules for the ones that matter:
   - `exploitwatch suggest --config config.yaml --live --live-intune` proposes NVD product IDs for unmapped apps.
   - `exploitwatch products microsoft --live --search 'Visual Studio|SQL'` lists a vendor's product names for an `advisory_product` rule.
   - Mark anything you don't want tracked with `ignore: true`.
   - To re-run without calling Graph, uncomment `file:` and `devices_file:` in `config.yaml`, pointing at what `--save-inventory` wrote.
6. **Turn on notifications** when the report looks right:
   - Slack: `SLACK_WEBHOOK_URL` (incoming webhook).
   - Teams: `TEAMS_WEBHOOK_URL`, from a **Workflows** webhook ("Send webhook alerts to a channel"). The old Office 365 connector webhooks are retired.
   - The `out/*.json` files from `--dry-run` show exactly what would be posted.
7. **Schedule it** daily with `exploitwatch run --config config.yaml --live --live-intune --notify` (urgent and digest), and weekly with `--tiers weekly`. Keep `state.db` between runs so nobody gets the same alert twice.

Servers and Kubernetes are optional: add `server_sboms` (CycloneDX from `syft`) and `kubernetes` to `config.yaml` and run with `--live-cluster`. Internet-facing servers go under `exposure.internet_facing`. `--fail-on-urgent` exits with code 1 when anything is urgent, so a pipeline can gate on it. [`demo.yml`](.github/workflows/demo.yml) shows a daily GitHub Actions run that puts the report on the run's summary page.

## Limits

- **Desktop app version matching is approximate.** It compares dotted versions loosely (157.0.8103.50, 8.8.1, 10.6p1). Package versions are compared by OSV, which knows each ecosystem's rules.
- **NVD only allows 120-day search windows.** So desktop apps are checked against CVEs from the last 120 days **plus every KEV entry for the product**, whatever its age. An old CVE that isn't on KEV and was never patched on a laptop would be missed.
- **CVE platform conditions are ignored.** Some NVD records say "affected only on platform X" (WinRAR **on Windows**). ExploitWatch assumes the platform matches.
- **It can't tell whether vulnerable code is reachable.** "Internet-facing" is per workload: an OpenSSL CVE in a public container counts as internet-facing even if the app never uses that OpenSSL feature. Use `ack` for those.
- **Only vendors that publish CSAF are read directly.** Microsoft, Cisco, Red Hat, SUSE and Siemens do. Adobe, Apple, Google, Fortinet, Palo Alto and Ivanti don't, so their products rely on NVD and KEV.
- **Some advisories give no versions.** Most Microsoft 365 Apps advisories point to a release-notes page instead of a build. When one of those says "exploited", it's listed under **Gaps** to check by hand rather than alerted on or dropped.
- **Windows builds are checked against the x64 advisories.** The fixed build is the same on ARM64. Windows Server, macOS and mobile devices are listed as gaps unless you add rules.
- **How it compares to OWASP Dependency-Track:** Dependency-Track is the better tool for SBOM portfolios alone. ExploitWatch adds Intune desktop apps, Kubernetes exposure, end-of-support tracking, and a deliberately small alert surface for a small security team.

## Layout

```
exploitwatch/
  inventory.py   Intune apps and devices, SBOM, Kubernetes and appliance readers; mapping rules; exposure
  feeds.py       KEV, NVD, OSV, EPSS, endoflife.date and CSAF clients; live / record / replay; cache
  advisories.py  vendor advisories: version ranges, exploitation notices, matching and enrichment
  match.py       OSV and NVD matching, merged by CVE; CVSS and CWE enrichment
  triage.py      the tier rules above
  report.py      grouping into alerts, Markdown report
  notify.py      Slack Block Kit and Teams Adaptive Card messages
  state.py       SQLite: notification history and acknowledgements
  versions.py    version comparison, CVSS v3.1 base score
demo/            fictional inventory, mappings, and the recorded feed snapshot
starter/         config, mappings and appliance list to copy for a real environment
examples/        report, JSON findings and Slack/Teams messages from the demo
tools/make_demo.py  regenerates the demo inventory
```

MIT licensed.
