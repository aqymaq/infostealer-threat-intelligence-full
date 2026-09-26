# Week 3 — Data Processing and Exploitation

**State:** method prepared; actual IOC data and MISP work pending Week 2.

## Filtering and normalization

1. For every candidate, keep `type`, `value`, `source_url`, `published_at`, `observed_at`, `role`, `confidence` and a short note.
2. Normalize hashes to lowercase; verify length/hex encoding. Normalize domain case; keep domains and IPs separate. Deduplicate by `(type, value)` **without erasing their source history**.
3. Reject malformed, unsupported or private indicators; never import passwords, cookies or sample binaries.
4. Distinguish a malware sample hash, delivery site, C2 address and merely related host. If an indicator's role is uncertain, mark it for review instead of `to_ids` blocking.
5. Document how many records were accepted, rejected or merged and why.

## MISP lab checklist

1. Deploy MISP in the permitted lab and screenshot the running version.
2. Create an event for the **specific Week 2 public report**, with a descriptive title and restricted distribution suitable for the class.
3. Add only reviewed indicator attributes with source, date and role; do not present old infrastructure as currently active without verification.
4. Screenshot event metadata and imported attributes. Record event ID, UTC time, count, and filtering decisions below.

| Evidence | Actual result |
|---|---|
| MISP version and screenshot | Pending |
| Event ID and date | Pending |
| Attributes imported | Pending |
| Duplicates / rejected items | Pending |

**Completion criterion:** real MISP event plus evidence, and a written explanation of data cleaning. A plan or an empty event does not complete the practical task.
