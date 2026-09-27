# Week 2 — Data Collection Process

**State:** complete — public-source investigation, VirusTotal/Shodan lookups, and Maltego relationship graph all finished 2026-09-28. This is an example within the broad Infostealer Threat Intelligence theme, not a rename of the project.

## Intelligence question

For one documented infostealer campaign or sample chosen from a reputable public report, which indicators can be validated, which relationships are supported, and what infrastructure context is accessible?

First write the selected public report title, URL, publication date and why it fits. A single example is an evidence set within our general theme, not a change of project topic.

| Selected report | URL | Date | Sample or campaign scope |
|---|---|---|---|
| Kaspersky Securelist, "Lumma/Amadey: fake CAPTCHAs want to know if you're human" | https://securelist.com/fake-captcha-delivers-lumma-amadey/114312/ | 2024-10-29 | One published campaign involving an infostealer and another trojan. The four MD5s are listed together; the article does not label the role of every hash individually. |

Kaspersky describes the fake CAPTCHA delivery, browser-cookie and credential collection, and exfiltration behavior. Its IOC list includes MD5 `e3274bc41f121b918ebb66e2f0cbfe29`. This case is only a sample data set used to study the infostealer class.

## Data source mapping

| Source | Collect | Purpose | Limitation |
|---|---|---|---|
| Public research report | Verifiable hash, domain/IP if published, behavior and date | Provenance and initial question | Some indicators may be old or re-used |
| VirusTotal | Lookup of sourced hash/domain, metadata, timestamp and permalink | Enrich a known observable | Do not upload private files or interpret vendor count as proof |
| Shodan | Search for a sourced infrastructure IP/service only when relevant | Infrastructure context | Open service alone does not imply malware infection; if not relevant, document why |
| Maltego | Visual map of report → sample → indicator → technique | Explain sourced relations | Label manual vs automated edges and cite every edge |
| MITRE ATT&CK | Relevant technique pages | Describe behavior | Technique is not an IOC |

## Procedure and evidence

1. Choose an authoritative report containing at least one public indicator and technical analysis; record the exact URL and date.
2. Search the published hash in VirusTotal; capture query, timestamp, permalink, result and screenshot in `evidence/`.
3. Use Shodan only for a justified infrastructure question about a sourced IP or domain. If none exists, explain the mismatch and demonstrate a generic infrastructure search separately, without associating unrelated hosts with an infostealer.
4. Create a Maltego graph. Each edge must be linked to the selected report, the tool observation or a MITRE page. Save an image and describe uncertainty.
5. Compare sources, remove unsupported assertions and write a short analytic conclusion.

| UTC time | Tool/query | Screenshot/link | Observation | What this does not prove |
|---|---|---|---|---|
| 2026-09-26 (UTC date; exact minute not retained) | VirusTotal search: MD5 `e3274bc41f121b918ebb66e2f0cbfe29` | File report, screenshot | File `0Setup.exe`, SHA-256 `210a9e063211abc76ee5d4b082a207ae20627021d0ec3131963a4a1822aaf9db`; 55/72 engines flagged the existing report; last analysis shown as 2026-03-04. | Detection count is not a fresh scan by our group and changes over time. Vendor labels are not independent proof of a specific campaign. |
| 2026-09-26 (UTC date; exact minute not retained) | VirusTotal Relations for that SHA-256, then domain Relations | File report, domain report | VT showed contacted URL `hxxps://onionoowzwqm[.]shop/api` dated 2024-10-19; passive DNS lists `104.21.28.189` on 2024-08-20. | VT relations can include later reanalyses; only the dated relationship is reported. The resolved IP is shared CDN infrastructure, not a dedicated malware server. Do not block this IP. |
| 2026-09-26 (UTC date; exact minute not retained) | Shodan host lookup `104.21.28.189` | Host record, screenshot | Shodan identified Cloudflare, Inc., CDN tag and web ports 80/443 among other CDN ports; last seen 2026-09-26. | This IP is shared by unrelated sites. Current Shodan services do not prove that the 2024 infostealer campaign is active. Exclude this IP from a malicious IOC list. |
| 2026-09-28 | Maltego graph (7 entities, 6 links) | `evidence/maltego_evid_jb.png` | Built full chain: Kaspersky report → MD5 → SHA-256 → contacted URL → domain → historical IP → Cloudflare. Each edge labeled inline with its exact source and date (Kaspersky Securelist 2024-10-29; VT file relations 2024-10-19; VT passive DNS 2024-08-20; Shodan 2026-09-26). Domain and URL kept defanged throughout — not resolved or visited directly. | A graph shows documented relationships between sourced observables, not that the campaign is currently active or that the historical IP/domain are still malicious today. |

## Maltego graph — uncertainty notes

- All edges are manually verified and sourced; no automated Maltego transforms were run against live infrastructure, in line with the instruction not to resolve or visit the suspicious domain directly.
- The MD5→SHA-256 edge represents the same file (confirmed via VirusTotal), not two distinct samples.
- The historical IP (`104.21.28.189`) is explicitly labeled as shared Cloudflare CDN infrastructure and is excluded from any malicious IOC list — its appearance in passive DNS from 2024-08-20 does not indicate a dedicated malware server, and Cloudflare-fronted IPs are commonly reused across many unrelated sites.
- The contacted URL and domain are shown defanged (`hxxps://`, `[.]shop`) throughout, and were not visited or resolved as part of this exercise.

## Analytic conclusion

The Kaspersky Securelist report (2024-10-29) provided a verifiable MD5 hash that VirusTotal confirmed as file `0Setup.exe` (SHA-256 `210a9e...`), independently corroborating the sample's existence and detection by 55/72 engines as of the last VT scan. VirusTotal Relations further traced a contacted URL (`hxxps://onionoowzwqm[.]shop/api`, observed 2024-10-19) and a historical DNS resolution to `104.21.28.189` (2024-08-20). Shodan confirmed this IP belongs to Cloudflare's shared CDN infrastructure as of 2026-09-26 — this is explicitly **not** treated as a dedicated malicious host and is excluded from any IOC feed, since Cloudflare IPs are shared across many unrelated, legitimate sites.

Overall, the sample hash and its immediate delivery chain (URL → domain) are well-supported by dated, independent sources. The infrastructure context beyond the domain (i.e., the resolved IP) reflects shared hosting rather than dedicated attacker infrastructure, and no claim is made about current campaign activity — all VT/Shodan observations reflect either 2024 historical data or a same-day 2026 lookup against infrastructure that may since have changed hands or purpose.
