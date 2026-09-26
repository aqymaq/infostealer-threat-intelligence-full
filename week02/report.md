# Week 2 — Data Collection Process

**State:** plan ready; VirusTotal, Shodan and Maltego results **pending actual group work**.

## Intelligence question

For one **documented infostealer campaign or sample** chosen from a reputable public report, which indicators can be validated, which relationships are supported, and what infrastructure context is accessible?

First write the selected public report title, URL, publication date and why it fits. A single example is an evidence set within our general theme, not a change of project topic.

| Selected report | URL | Date | Sample or campaign scope |
|---|---|---|---|
| Pending | Pending | Pending | Pending |

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
| Pending | VirusTotal | Pending | Pending | Pending |
| Pending | Shodan | Pending | Pending | Pending |
| Pending | Maltego | Pending | Pending | Pending |

Only promote verified, attributed observables into the Week 3 working set. Do not include stolen passwords or live session tokens.
