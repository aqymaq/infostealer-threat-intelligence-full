# Infostealer Threat Hunting Project

Course project on information-stealing malware (LummaC2 as a documented example): threat intel (MISP), detection (Sigma) and threat hunting (Splunk/Sysmon).

Authors: Asilbek Turgunov (group CS-2426) and team, Astana IT University.

## Repository structure

- `report.md` — Week 5 report: threat hunting concept, hypotheses, queries, lab results
- `img/` — screenshots of the lab and query results

## AI-use statement

| Item | Value |
|---|---|
| AI tool | Claude (Anthropic) |
| Share of AI use | ~30% |

**What AI was used for:**
- Step-by-step guidance for the lab setup (Sysmon, audit policy, Splunk) and help with troubleshooting errors
- Drafting and editing the text of `report.md` and the defense speech
- Suggesting query fixes (for example, `rex` parsing on a Russian-locale Windows)

**What was done by the team:**
- Choosing the topic, hypotheses and the overall approach
- Setting up the lab, running all simulations and queries on our own host
- Taking the screenshots and checking that the results in the report match what we actually observed
- Verifying ATT&CK technique IDs and sources

All results and screenshots in the report come from our own lab runs. AI-generated text was reviewed and edited by the team before submission.
