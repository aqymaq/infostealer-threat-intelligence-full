# Week 1 — CTI Fundamentals: Infostealer Threat Intelligence

**Research question:** How can defenders distinguish the infostealer threat from a single malware family and turn public behavioral evidence into defensive decisions?  
**Method:** public-source desk research; no malware execution, local detections or attribution of a particular incident.

## Summary

An **infostealer** is malware whose purpose is to collect sensitive information from a compromised device. Depending on the implementation, targeted data may include saved browser credentials, session cookies, files, account information or wallet data. These are **possible behaviors of the class**, not a claim that every infostealer does everything. MITRE ATT&CK documents browser credential theft as T1555.003, cookie theft as T1539, and exfiltration over an existing command-and-control channel as T1041 [1–3].

## CTI glossary applied to the topic

| Term | Meaning | Application |
|---|---|---|
| CTI | Analyzed threat information used for a decision | Connect observed behavior to a monitoring or response question. |
| Threat actor | Person/group conducting malicious activity | An infostealer operator or affiliate; attribution requires separate evidence. |
| Malware family | Related malicious programs | Individual family names belong in specific evidence records, not in the project title. |
| Asset | Resource to protect | User endpoints, accounts, browser sessions and business data. |
| IOC | Observable associated with potentially malicious activity | A sourced file hash or domain from a documented campaign; verify date and role. |
| TTP | Goals and methods used by an adversary | Access browser credential stores, steal cookies, transfer collected data. |
| OSINT | Publicly available information collected for analysis | ATT&CK, vendor reports and publicly indexed indicator records. |
| C2 | Channel used to communicate with a compromised device | An exfiltration route in some documented infections; not every network connection is C2. |
| Exfiltration | Unauthorized transfer of collected data | Sending stolen data outside the victim environment. |
| Confidence | Degree of support for a conclusion | High for the existence of an ATT&CK technique; none for a claim of infection in our environment without logs. |

## Threat classification and sources

| Dimension | Classification | Qualification |
|---|---|---|
| Type | Information-stealing malware / credential-access threat | A broad class, not one sample or actor. |
| Objectives | Obtain credentials, sessions or other sensitive data | The specific target varies by family and campaign. |
| Potential entry | Malicious download, social engineering or another delivery method | Verify for each case; do not assume a single entry vector. |
| Technical source | Malware on an affected endpoint and infrastructure used in a documented campaign | Observed infrastructure must be tied to a dated source. |
| Human source | Operators, distributors or other actors | Do not infer identity from the malware category alone. |
| Possible impact | Account takeover, unauthorized access or data exposure | Follow-on impact is contingent; do not claim it occurred in this group project. |

The **source of a public report**, **source of a network connection**, and **human actor** are different meanings of “source.” Our Week 2 collection will label them separately.

## ATT&CK behavior map (category-level hypotheses)

| Technique | Why relevant | Defensive question |
|---|---|---|
| [T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/) | Browser credential stores can be targeted [1]. | Did an unusual process access browser credential storage? |
| [T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) | A stolen cookie may allow misuse of an authenticated session [2]. | Did a non-browser process access session material? |
| [T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) | Collected data may be transferred through an established channel [3]. | Is outbound communication consistent with an evidenced campaign? |

These are **research hypotheses for the threat class**. The Week 2 report must tie a specific technique and IOC to a specific published case before saying that they were observed together.

## Decision and next step

Prioritize collection of dated, attributable evidence. Prefer a published report containing a sample hash, a description of behavior and explicit indicator roles. Week 2 will search a verified hash in VirusTotal, use Shodan only when an infrastructure question can be justified, and graph **sourced** relationships in Maltego. Week 3 will filter and normalize the resulting records before any MISP import. No executable malware or real credentials are required for this course report.

## Sources (accessed 2026-09-26)

1. MITRE ATT&CK, [T1555.003: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/).
2. MITRE ATT&CK, [T1539: Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/).
3. MITRE ATT&CK, [T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/).
4. MITRE ATT&CK, [T1204.002: User Execution — Malicious File](https://attack.mitre.org/techniques/T1204/002/).
