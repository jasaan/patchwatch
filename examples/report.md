# ExploitWatch report: 2026-11-21

36 products checked. **11 urgent**, 7 for the daily digest, 5 for weekly planning, and 2333 lower-risk findings logged without a notification.

## 🔴 Urgent

### Windows 11 24H2 10.0.26100.9580
*45 endpoints*

- On CISA KEV: CVE-2026-96951 (added 2026-10-13)
- Vendor says it is exploited: CVE-2026-96951 (Microsoft)
- Critical RCE in the endpoint operating system: CVE-2026-112967 (CVSS 9.8), CVE-2026-116928 (CVSS 9.8), CVE-2026-119958 (CVSS 9.8), CVE-2026-69886 (CVSS 9.8) and 12 more
- Critical auth bypass in the endpoint operating system: CVE-2026-85844 (CVSS 9.8)
- 18 vulnerabilities · fix: upgrade to 10.0.26100.9974 or later
- Vendor: [Microsoft CVE-2026-96951](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96951) · [Microsoft CVE-2026-112967](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-112967) · [Update](https://support.microsoft.com/help/5127648)

### Notepad++ 8.8.1
*37 endpoints*

- On CISA KEV: CVE-2025-15556 (added 2026-02-12)
- 1 vulnerability · fix: upgrade to 8.8.9 or later

### Microsoft Edge 154.0.4258.37
*28 endpoints*

- On CISA KEV: CVE-2026-96951 (added 2026-10-13)
- Vendor says it is exploited: CVE-2026-96951 (Microsoft)
- 1 vulnerability · fix: upgrade to 154.0.4258.62 or later
- Vendor: [Microsoft CVE-2026-96951](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96951) · [Update](https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security)

### Windows 10 22H2 10.0.19045.7725
*15 endpoints*

- On CISA KEV: CVE-2026-96951 (added 2026-10-13)
- Vendor says it is exploited: CVE-2026-96951 (Microsoft)
- Critical RCE in the endpoint operating system: CVE-2026-112967 (CVSS 9.8), CVE-2026-116928 (CVSS 9.8), CVE-2026-119958 (CVSS 9.8), CVE-2026-69886 (CVSS 9.8) and 12 more
- Critical auth bypass in the endpoint operating system: CVE-2026-85844 (CVSS 9.8)
- 18 vulnerabilities · fix: upgrade to 10.0.19045.7846 or later
- Vendor: [Microsoft CVE-2026-96951](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96951) · [Microsoft CVE-2026-112967](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-112967) · [Update](https://support.microsoft.com/help/5126657)

### WinRAR 7.01.0
*12 endpoints*

- On CISA KEV: CVE-2025-8088 (added 2025-08-12), CVE-2025-6218 (added 2025-12-09)
- Used in ransomware campaigns: CVE-2025-8088
- Advisory says it is exploited in the wild: CVE-2025-8088
- 2 vulnerabilities · fix: upgrade to 7.13 or later

### Cisco Secure Firewall ASA 9.20.4.10
*1 appliance · internet-facing: fw-edge-01 (AnyConnect VPN on the outside interface)*

- On CISA KEV: CVE-2026-20349 (added 2026-08-11), CVE-2026-76418 (added 2026-10-29)
- Vendor says it is exploited: CVE-2026-20349 (Cisco), CVE-2026-76418 (Cisco)
- Critical and internet-facing: CVE-2026-20329 (CVSS 9.9), CVE-2026-20330 (CVSS 9.9), CVE-2026-20332 (CVSS 9.9), CVE-2026-20331 (CVSS 9.6)
- 6 vulnerabilities
- Vendor: [Cisco CVE-2026-20349](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-vpn-dos-dzv4mQFF) · [Cisco CVE-2026-76418](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-tunnel-dos-s6mgkb75) · [Update](https://software.cisco.com)

### ingress-nginx 1.11.3
*1 workload · internet-facing: prod-aks/ingress-nginx/ingress-nginx-controller (Service type LoadBalancer)*

- Unauthenticated network RCE on an internet-facing asset: CVE-2025-1974 (CVSS 9.8)
- Likely to be exploited soon (EPSS >= 10%): CVE-2025-1098 (EPSS 86%), CVE-2023-5044 (EPSS 54%), CVE-2025-24514 (EPSS 37%), CVE-2025-1097 (EPSS 37%)
- 5 vulnerabilities · fix: upgrade to 1.11.5 or later

### next 15.1.3
*1 workload · internet-facing: prod-aks/shop/storefront (Ingress shop.contoso.com)*

- Unauthenticated network auth bypass on an internet-facing asset: CVE-2025-29927 (CVSS 9.1)
- Unauthenticated network RCE on an internet-facing asset: GHSA-9qr9-h5gf-34mp (CVSS 10.0), CVE-2026-75604 (CVSS 9.0), GHSA-2464-fhr4-w9xw (CVSS 9.0), GHSA-2xp9-vwfh-vxw4 (CVSS 9.0)
- Likely to be exploited soon (EPSS >= 10%): CVE-2026-44578 (EPSS 36%)
- 6 vulnerabilities · fix: upgrade to 15.5.28 or later

### openssh-server 10.0_p1-r7
*1 workload*

- Zero-day (added to CISA KEV in the last 14 days): CVE-2026-123158 (added 12d ago)
- 1 vulnerability · fix: upgrade to 10.0_p1-r11 or later

### react-server-dom-webpack 19.0.0
*1 workload · internet-facing: prod-aks/shop/storefront (Ingress shop.contoso.com)*

- On CISA KEV: CVE-2025-55182 (added 2025-12-05)
- Used in ransomware campaigns: CVE-2025-55182
- Unauthenticated network RCE on an internet-facing asset: CVE-2025-55182 (CVSS 10.0), CVE-2026-126187 (CVSS 9.0)
- Likely to be exploited soon (EPSS >= 10%): CVE-2025-55184 (EPSS 64%), CVE-2025-55183 (EPSS 64%)
- 4 vulnerabilities · fix: upgrade to 19.0.9 or later

### sudo 1.9.15p5-3ubuntu5
*1 server · internet-facing: web-01 (listed as internet-facing in config)*

- On CISA KEV: CVE-2025-32463 (added 2025-09-29)
- 1 vulnerability · fix: upgrade to 1.9.15p5-3ubuntu5.24.04.1 or later


## 🟠 Daily digest

### Google Chrome 157.0.8103.50
*157 endpoints*

- Critical RCE in a desktop app: CVE-2026-130929 (CVSS 9.0), CVE-2026-131020 (CVSS 9.0)
- 2 vulnerabilities · fix: upgrade to 158.0.8127.36 or later

### django 5.1.4
*1 workload*

- Critical and likely to be exploited: CVE-2025-64459 (CVSS 9.1, EPSS 19%)
- Likely to be exploited soon (EPSS >= 10%): CVE-2025-57833 (EPSS 27%), CVE-2025-32873 (EPSS 14%)
- 3 vulnerabilities · fix: upgrade to 5.1.14 or later

### libssl3 3.0.15-1~deb12u1
*1 workload*

- Likely to be exploited soon (EPSS >= 10%): CVE-2025-15467 (EPSS 75%)
- 1 vulnerability · fix: upgrade to 3.0.18-1~deb12u2 or later

### libssl3 3.3.3-r0
*1 workload · internet-facing: prod-aks/shop/storefront (Ingress shop.contoso.com)*

- Critical and internet-facing: CVE-2025-9230 (CVSS 9.8), CVE-2026-31789 (CVSS 9.8), CVE-2026-63073 (CVSS 9.8), CVE-2026-34182 (CVSS 9.1) and 1 more
- Likely to be exploited soon (EPSS >= 10%): CVE-2025-15467 (EPSS 75%)
- 6 vulnerabilities · fix: upgrade to 3.3.7-r1 or later

### libssl3t64 3.0.13-0ubuntu3.5
*1 server · internet-facing: web-01 (listed as internet-facing in config)*

- Critical and internet-facing: CVE-2025-9230 (CVSS 9.8), CVE-2026-31789 (CVSS 9.8), CVE-2026-34182 (CVSS 9.1), CVE-2026-75803 (CVSS 9.1)
- Likely to be exploited soon (EPSS >= 10%): CVE-2025-15467 (EPSS 75%)
- 5 vulnerabilities · fix: upgrade to 3.0.13-0ubuntu3.15 or later

### nginx 1.24.0-2ubuntu7.1
*1 server · internet-facing: web-01 (listed as internet-facing in config)*

- Likely to be exploited soon (EPSS >= 10%): CVE-2026-42945 (EPSS 69%), CVE-2026-49975 (EPSS 32%), CVE-2026-123007 (EPSS 30%), CVE-2026-27654 (EPSS 28%) and 3 more
- 7 vulnerabilities · fix: upgrade to 1.24.0-2ubuntu7.20 or later
- Vendor: [Cisco CVE-2026-113425](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nginx-nov-2026-e8jska2s)

### openssh-server 1:9.6p1-3ubuntu13.5
*1 server · internet-facing: web-01 (listed as internet-facing in config)*

- Likely to be exploited soon (EPSS >= 10%): CVE-2025-26466 (EPSS 39%)
- 1 vulnerability · fix: upgrade to 1:9.6p1-3ubuntu13.8 or later


## ⚪ Weekly planning

### Notepad++ 8.8.1
*37 endpoints*

- End of support was 2025-12-27 (329 days ago)

### Python 3.9.13
*6 endpoints*

- End of support was 2025-10-31 (386 days ago)

### django 5.1.4
*1 workload*

- End of support was 2025-12-03 (353 days ago)

### Kubernetes 1.34.5
*1 cluster*

- End of support was 2026-10-27 (25 days ago)

### next 15.1.3
*1 workload · internet-facing: prod-aks/shop/storefront (Ingress shop.contoso.com)*

- End of support on 2027-01-31 (in 71 days)
- New release 15.5.29 available (installed 15.1.3)

## Logged only

| Product | Findings |
|---|---|
| Google Chrome 157.0.8103.50 | 271 |
| Microsoft 365 Apps 16.0.20131.20140 | 12 |
| 7-Zip 25.01 | 1 |
| Windows 11 24H2 10.0.26100.9580 | 746 |
| Microsoft Edge 154.0.4258.37 | 14 |
| Mozilla Firefox 156.0 | 148 |
| Windows 10 22H2 10.0.19045.7725 | 684 |
| axios 1.7.9 | 33 |
| busybox 1.37.0-r18 | 2 |
| Cisco Secure Firewall ASA 9.20.4.10 | 14 |
| django 5.1.4 | 17 |
| ingress-nginx 1.11.3 | 5 |
| libssl3 3.0.15-1~deb12u1 | 44 |
| libssl3 3.3.3-r0 | 36 |
| libssl3t64 3.0.13-0ubuntu3.5 | 47 |
| next 15.1.3 | 35 |
| nginx 1.24.0-2ubuntu7.1 | 36 |
| openssh-server 10.0_p1-r7 | 2 |
| openssh-server 1:8.9p1-3ubuntu0.13 | 32 |
| openssh-server 1:9.6p1-3ubuntu13.5 | 33 |
| postgresql-14 14.18-0ubuntu0.22.04.1 | 98 |
| react-server-dom-webpack 19.0.0 | 4 |
| requests 2.32.3 | 2 |
| sudo 1.9.15p5-3ubuntu5 | 5 |
| sudo 1.9.9-1ubuntu2.5 | 3 |
| urllib3 2.2.1 | 9 |

## Gaps (not assessed)

- Intune app not mapped to a product: Contoso Expense Helper 2.3.1 (140 devices). Add a rule to mappings.yaml.
- No SBOM for image registry.k8s.io/coredns/coredns:v1.12.1. Generate one with: syft registry.k8s.io/coredns/coredns:v1.12.1 -o cyclonedx-json
- Microsoft says CVE-2026-124194 is exploited in Microsoft 365 Apps for Enterprise for 64-bit Systems, but the advisory doesn't give versions. Check Microsoft 365 Apps 16.0.20131.20140 by hand: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-124194
- Cisco advisory cisco-sa-hardening-asaftdfmc-uvpPROhN affects Cisco Secure Firewall ASA 9.20.4.10 and says "Two vulnerabilities that belong to this vulnerability class are known to be actively exploited." without naming which CVEs. Check: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-hardening-asaftdfmc-uvpPROhN
