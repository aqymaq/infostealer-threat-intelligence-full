# Week 2 — Data Collection Process

**State:** public-source investigation and live VirusTotal/Shodan lookups completed 2026-09-26; actual Maltego graph **pending group work**. This is an example within the broad *Infostealer Threat Intelligence* theme, not a rename of the project.

## Intelligence question

For one **documented infostealer campaign or sample** chosen from a reputable public report, which indicators can be validated, which relationships are supported, and what infrastructure context is accessible?

First write the selected public report title, URL, publication date and why it fits. A single example is an evidence set within our general theme, not a change of project topic.

| Selected report | URL | Date | Sample or campaign scope |
|---|---|---|---|
| Kaspersky Securelist, “Lumma/Amadey: fake CAPTCHAs want to know if you’re human” | https://securelist.com/fake-captcha-delivers-lumma-amadey/114312/ | 2024-10-29 | One published campaign involving an infostealer and another trojan. The four MD5s are listed together; the article does not label the role of every hash individually. |

Kaspersky describes the fake CAPTCHA delivery, browser-cookie and credential collection, and exfiltration behavior. Its IOC list includes MD5 `e3274bc41f121b918ebb66e2f0cbfe29` [1]. This **case is only a sample data set** used to study the infostealer class.

## Data source mapping

| Source | Collect | Purpose | Limitation |
|---|---|---|---|
| Public research report | Verifiable hash, domain/IP if published, behavior and date | Provenance and initial question | Some indicators may be old or re-used |
| VirusTotal | **Lookup** of sourced hash/domain, metadata, timestamp and permalink | Enrich a known observable | Do not upload private files or interpret vendor count as proof |
| Shodan | Search for a **sourced** infrastructure IP/service only when relevant | Infrastructure context | Open service alone does not imply malware infection; if not relevant, document why |
| Maltego | Visual map of report → sample → indicator → technique | Explain sourced relations | Label manual vs automated edges and cite every edge |
| MITRE ATT&CK | Relevant technique pages | Describe behavior | Technique is not an IOC |

## Procedure and evidence

1. Choose an authoritative report containing at least one public indicator and technical analysis; record the exact URL and date.
2. Search the published **hash** in VirusTotal; capture query, timestamp, permalink, result and screenshot in `evidence/`.
3. Use Shodan only for a justified infrastructure question about a **sourced** IP or domain. If none exists, explain the mismatch and demonstrate a generic infrastructure search separately, without associating unrelated hosts with an infostealer.
4. Create a Maltego graph. Each edge must be linked to the selected report, the tool observation or a MITRE page. Save an image and describe uncertainty.
5. Compare sources, remove unsupported assertions and write a short analytic conclusion.

| UTC time | Tool/query | Screenshot/link | Observation | What this does **not** prove |
|---|---|---|---|---|
| 2026-09-26 (UTC date; exact minute not retained) | VirusTotal search: MD5 `e3274bc41f121b918ebb66e2f0cbfe29` | [File report](https://www.virustotal.com/gui/file/210a9e063211abc76ee5d4b082a207ae20627021d0ec3131963a4a1822aaf9db), [screenshot](evidence/virustotal-file.jpg) | File `0Setup.exe`, SHA-256 `210a9e063211abc76ee5d4b082a207ae20627021d0ec3131963a4a1822aaf9db`; **55/72** engines flagged the existing report; last analysis shown as 2026-03-04. | Detection count is not a fresh scan by our group and changes over time. Vendor labels are not independent proof of a specific campaign. |
| 2026-09-26 (UTC date; exact minute not retained) | VirusTotal Relations for that SHA-256, then domain Relations | [File report](https://www.virustotal.com/gui/file/210a9e063211abc76ee5d4b082a207ae20627021d0ec3131963a4a1822aaf9db), [domain report](https://www.virustotal.com/gui/domain/onionoowzwqm.shop) | VT showed contacted URL `https://onionoowzwqm.shop/api` dated 2024-10-19; passive DNS lists `104.21.28.189` on 2024-08-20. | VT relations can include later reanalyses; only the dated relationship is reported. The resolved IP is **shared CDN infrastructure**, not a dedicated malware server. Do not block this IP. |
| 2026-09-26 (UTC date; exact minute not retained) | Shodan host lookup `104.21.28.189` | [Host record](https://www.shodan.io/host/104.21.28.189), [screenshot](evidence/shodan-cdn.jpg) | Shodan identified **Cloudflare, Inc.**, CDN tag and web ports 80/443 among other CDN ports; last seen 2026-09-26. | This IP is shared by unrelated sites. Current Shodan services do not prove that the 2024 infostealer campaign is active. Exclude this IP from a malicious IOC list. |
| Pending | Maltego graph | Pending | Pending | Group must build/export and screenshot a graph in Maltego. |

### Maltego graph to build

Create nodes `Kaspersky report`, `MD5 e3274...`, `SHA-256 210a9...`, `VT contacted URL (defanged: hxxps://onionoowzwqm[.]shop/api)`, `domain onionoowzwqm[.]shop`, `historical IP 104.21.28.189`, `Cloudflare`. Connect only evidenced edges, mark the 2024 dates, and label the IP **shared CDN / excluded from malicious IP feed**. Use the exact source URLs above as link notes. Save the graph screenshot in `evidence/maltego-graph.jpg`. Do not resolve or visit the suspicious domain directly.

### Interim analytical conclusion

A published sample hash has an existing VT report with a high detection count. A related historical domain resolved to a shared Cloudflare IP; Shodan confirms the shared-CDN context today. Therefore the hash is a candidate for a **historical** Week 3 record, while the IP is unsuitable as a malicious indicator. Maltego visualization remains to be performed.

**[1]** Kaspersky Securelist, [the source article](https://securelist.com/fake-captcha-delivers-lumma-amadey/114312/), 2024-10-29. **[2]** VirusTotal file and domain reports above. **[3]** Shodan host record above. Observations were read from public interfaces on 2026-09-26; no malware was downloaded or run.

Only promote verified, attributed observables into the Week 3 working set. Do not include stolen passwords or live session tokens.
