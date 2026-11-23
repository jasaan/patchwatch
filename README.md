# ExploitWatch

**Matches what your company runs (Intune laptops, Linux servers, Kubernetes) against free vulnerability feeds, and tells the team only about what needs action: vulnerabilities being exploited right now, zero-days, and network-reachable RCEs and auth bypasses. Everything else is logged, not sent.**

> Built with Claude; designed, reviewed and tested by me. The demo inventory is fictional (Contoso laptops, two servers, one AKS cluster). The feed data is real: CISA KEV, NVD, OSV, EPSS and endoflife.date, recorded with `--live --record` on 2026-11-21. Live Intune (`--live-intune`) and live cluster (`--live-cluster`) collection use Microsoft Graph and kubectl's documented read-only calls, but **haven't been run against a real tenant or cluster yet**. Please report anything that doesn't work.

## What it found in the demo

29 products across 470 laptops, 2 servers and 1 cluster. That's **908 matching vulnerabilities** (798 distinct CVEs and advisories), but only **7 urgent alerts**:

| Alert | Why it's urgent |
|---|---|
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
- gaps, meaning things it couldn't check: an Intune app with no mapping, and an image with no SBOM.

The [Slack](examples/slack.json) and [Teams](examples/teams.json) messages are in `examples/`.

## How it decides

| Tier | Sent | Rule |
|---|---|---|
| 🔴 **Urgent** | right away | On **CISA KEV**. Counts as a **zero-day** if added in the last 14 days. |
| | | The advisory says the vulnerability is **exploited in the wild**. |
| | | **Unauthenticated network RCE or auth bypass** on a server, container or cluster: critical (CVSS ≥ 9.0), or high (≥ 8.0) on an internet-facing asset. |
| 🟠 **Digest** | daily | Critical, and EPSS ≥ 10% or internet-facing. |
| | | EPSS ≥ 10% on its own (likely to be exploited within 30 days). |
| | | A critical RCE in a desktop app. |
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
- **Repeat alerts are suppressed.** A finding is sent once. It's sent again only if it moves up a tier, for example when a digest CVE lands on KEV.
- **Acknowledgements are recorded.** `exploitwatch ack` silences a CVE for one product and records who decided and why.

## Where the data comes from

| Inventory | How |
|---|---|
| **Intune** | Graph `deviceManagement/detectedApps` and each app's `managedDevices` (permission: `DeviceManagementManagedDevices.Read.All`) |
| **Servers** | CycloneDX SBOMs, one per host, for example `syft / -o cyclonedx-json` |
| **Kubernetes** | Pods, Services and Ingresses from `kubectl` (read-only), plus one SBOM per image. Known add-ons (ingress-nginx, cert-manager, Argo CD) are recognized by controller image. The cluster version is checked for end of support. |

| Feed | Used for |
|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited now, date added, ransomware use |
| [OSV](https://osv.dev) | Package vulnerabilities (npm, PyPI, Go, Debian, Ubuntu, Alpine). OSV does the version matching, including distro version rules. |
| [NVD](https://nvd.nist.gov/developers) | Desktop apps by NVD product ID (vendor:product), checked locally against each CVE's version ranges. Also CVSS vectors and CWE types when OSV lacks them. |
| [EPSS](https://www.first.org/epss/) | Probability of exploitation in the next 30 days |
| [endoflife.date](https://endoflife.date) | End-of-support dates and latest releases |

Intune names apps loosely ("Google Chrome", "Google Chrome (x64)"), so [`mappings.yaml`](demo/mappings.yaml) maps them to NVD product IDs. `exploitwatch suggest --live` proposes IDs for unmapped apps from the NVD product dictionary. Apps with no mapping appear under **Gaps** in every report; they're never dropped silently.

## Try it (no accounts needed)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

exploitwatch run                                   # demo inventory + recorded feeds → report
exploitwatch run --notify --dry-run                # also write the Slack/Teams messages to out/
exploitwatch ack CVE-2025-15556 --product "Notepad++" --reason "updater disabled by GPO"
pytest -q                                        # 49 tests, no network
```

Replay mode uses the snapshot's recording date as "today", so results don't drift. To fetch current data instead, run `exploitwatch run --live`. Set `NVD_API_KEY` ([free key](https://nvd.nist.gov/developers/request-an-api-key)) to make it about 10× faster.

## Run it on your own environment

1. Copy `demo/config.yaml` and `demo/mappings.yaml`, then point the inventory paths at your data.
2. **Intune:** create an app registration with the `DeviceManagementManagedDevices.Read.All` application permission and admin consent. Set `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`. Install with `pip install -e ".[intune]"`, then run with `--live-intune`.
3. **Kubernetes:** a read-only kubeconfig context, plus `--live-cluster`. Generate image SBOMs with `syft <image> -o cyclonedx-json` into `sbom_dir`; images without one show up as gaps.
4. **Servers:** run syft on each host (or in your build pipeline) and drop the SBOMs in a folder. List internet-facing hosts under `exposure.internet_facing`.
5. **Notifications:**
   - Slack: set `SLACK_WEBHOOK_URL` (incoming webhook).
   - Teams: set `TEAMS_WEBHOOK_URL`, using a **Workflows** webhook ("Send webhook alerts to a channel"). The old Office 365 connector webhooks are retired.
6. **Schedule it:**
   - Daily: `exploitwatch run --live --notify` (urgent and digest).
   - Weekly: `--tiers weekly`.
   - Keep `state.db` between runs so nobody gets the same alert twice. [`demo.yml`](.github/workflows/demo.yml) runs the demo daily in GitHub Actions and puts the report on the run's summary page.

`--fail-on-urgent` exits with code 1 when anything is urgent, so a pipeline can gate on it.

## Limits

- **Desktop app version matching is approximate.** It compares dotted versions loosely (157.0.8103.50, 8.8.1, 10.6p1). Package versions are compared by OSV, which knows each ecosystem's rules.
- **NVD only allows 120-day search windows.** So desktop apps are checked against CVEs from the last 120 days **plus every KEV entry for the product**, whatever its age. An old CVE that isn't on KEV and was never patched on a laptop would be missed.
- **CVE platform conditions are ignored.** Some NVD records say "affected only on platform X" (WinRAR **on Windows**). ExploitWatch assumes the platform matches.
- **It can't tell whether vulnerable code is reachable.** "Internet-facing" is per workload: an OpenSSL CVE in a public container counts as internet-facing even if the app never uses that OpenSSL feature. Use `ack` for those.
- **Vendor feeds aren't read yet.** Exploitation signals come from KEV and NVD descriptions. Reading MSRC's "Exploited: Yes" flag and vendor security advisory feeds (CSAF) is the next step.
- **How it compares to OWASP Dependency-Track:** Dependency-Track is the better tool for SBOM portfolios alone. ExploitWatch adds Intune desktop apps, Kubernetes exposure, end-of-support tracking, and a deliberately small alert surface for a small security team.

## Layout

```
exploitwatch/
  inventory.py   Intune, SBOM and Kubernetes readers; mapping rules; exposure
  feeds.py       KEV, NVD, OSV, EPSS, endoflife.date clients; live / record / replay
  match.py       OSV and NVD matching, merged by CVE; CVSS and CWE enrichment
  triage.py      the tier rules above
  report.py      grouping into alerts, Markdown report
  notify.py      Slack Block Kit and Teams Adaptive Card messages
  state.py       SQLite: notification history and acknowledgements
  versions.py    version comparison, CVSS v3.1 base score
demo/            fictional inventory, mappings, and the recorded feed snapshot
examples/        report, JSON findings and Slack/Teams messages from the demo
tools/make_demo.py  regenerates the demo inventory
```

MIT licensed.
