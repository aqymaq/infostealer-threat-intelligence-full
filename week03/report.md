# Week 3 — Data Processing and Exploitation

**State:** complete — IOC data filtered/normalized and imported into MISP for the Week 2 selected report (Kaspersky Securelist, Lumma/Amadey Fake CAPTCHA Campaign, 2024-10-29).

## Filtering and normalization

1. For every candidate, keep `type`, `value`, `source_url`, `published_at`, `observed_at`, `role`, `confidence` and a short note.
2. Normalize hashes to lowercase; verify length/hex encoding. Normalize domain case; keep domains and IPs separate. Deduplicate by `(type, value)` **without erasing their source history**.
3. Reject malformed, unsupported or private indicators; never import passwords, cookies or sample binaries.
4. Distinguish a malware sample hash, delivery site, C2 address and merely related host. If an indicator's role is uncertain, mark it for review instead of `to_ids` blocking.
5. Document how many records were accepted, rejected or merged and why.

| type | value | source_url | published_at | observed_at | role | confidence | note |
|---|---|---|---|---|---|---|---|
| md5 | e3274bc41f121b918ebb66e2f0cbfe29 | https://securelist.com/fake-captcha-delivers-lumma-amadey/114312/ | 2024-10-29 | 2026-09-26 | malware sample hash | High | Same file as SHA256 below (0Setup.exe) |
| sha256 | 210a9e063211abc76ee5d4b082a207ae20627021d0ec3131963a4a1822aaf9db | VirusTotal file report | 2024-10-29 | 2026-09-26 | malware sample hash | High | Confirmed same file as MD5 via VirusTotal |
| domain | onionoowzwqm.shop | VirusTotal Relations | 2024-10-19 | 2026-09-26 | delivery/C2 domain | Medium | Contacted URL derived from this domain |
| ip-dst | 104.21.28.189 | VirusTotal passive DNS + Shodan | 2024-08-20 | 2026-09-26 | related host (not malware-specific) | Low | Cloudflare shared CDN — correlation disabled, excluded from malicious IOC treatment |

**Normalization applied:** all hashes lowercased and verified against expected hex length (MD5 = 32 chars, SHA256 = 64 chars). Domain normalized to lowercase and kept as a separate `domain`-type attribute rather than merged with the `ip-dst` type. Deduplicated by `(type, value)` — no duplicate values were entered. No passwords, cookies, or sample binaries were imported at any stage.

**Records accepted/rejected:** 4 accepted, 0 rejected, 0 merged. The IP was accepted but explicitly role-marked as a "related host" rather than a "C2 address," and had MISP correlation disabled, since it represents shared Cloudflare CDN infrastructure rather than a dedicated malicious host — following the instruction to mark uncertain-role indicators for review rather than `to_ids` blocking.

## MISP lab checklist

1. Deploy MISP in the permitted lab and screenshot the running version.
2. Create an event for the specific Week 2 public report, with a descriptive title and restricted distribution suitable for the class.
3. Add only reviewed indicator attributes with source, date and role; do not present old infrastructure as currently active without verification.
4. Screenshot event metadata and imported attributes. Record event ID, UTC time, count, and filtering decisions below.

| Evidence | Actual result |
|---|---|
| MISP version and screenshot | MISP 2.5.47, deployed locally via Docker Compose (misp-docker). |
| Event ID and date | Event ID **2**, created 2026-09-28. Title: "Lumma/Amadey Fake CAPTCHA Campaign — Kaspersky Securelist (2024-10-29)". Distribution: Your organisation only. Threat Level: High. Analysis: Completed. |
| Attributes imported | **4 total**, all dated 2026-09-27/28, role-separated: <br>• `md5` (Payload delivery) — malware sample hash <br>• `sha256` (Payload delivery) — same sample, confirmed via VirusTotal <br>• `domain` (Network activity) — delivery/C2 domain <br>• `ip-dst` (Network activity) — Cloudflare CDN, correlation disabled, explicitly flagged as not a dedicated malicious host. See `evidence/misp_evid_kaspersky.jpg`. |
| Duplicates / rejected items | 0 rejected, 0 duplicates. The malware sample hashes (MD5/SHA256), the C2/delivery domain, and the related-but-shared IP were each kept as distinct attributes with correct categories rather than merged, per the requirement to distinguish a malware sample hash from a delivery site, C2 address, and merely related host. |

**Completion criterion:** real MISP event plus evidence, and a written explanation of data cleaning. ✅ Met — see Event ID 2 above and evidence screenshot. A plan or an empty event does not complete the practical task.

## Analytic conclusion

Four verified indicators from the Kaspersky Securelist report (2024-10-29, Lumma/Amadey fake-CAPTCHA campaign) were imported into a local MISP instance (Event ID 2) with distribution restricted to the organisation. Attributes were deliberately role-separated: the MD5/SHA256 pair represents a single malware sample (`0Setup.exe`, independently confirmed via VirusTotal), the domain represents the delivery/C2 infrastructure contacted by that sample, and the IP address represents merely *related* — not dedicated malicious — infrastructure, since VirusTotal and Shodan both confirm it belongs to Cloudflare's shared CDN. Correlation was explicitly disabled on the IP attribute to prevent MISP from treating shared hosting as a malicious indicator.

No indicator was promoted without a source, publication date, and assigned role, and no stolen credentials, session tokens, or private sample binaries were imported at any stage. The one indicator with genuine uncertainty — the historical IP resolution from 2024-08-20 — was marked with reduced confidence and an explicit note rather than blocked or treated as equivalent to the malware hash and domain, in line with the instruction to mark uncertain-role indicators for review instead of `to_ids` blocking.
