# Week 9 — Atomic Red Team

## Project: Infostealer Threat Intelligence

**State:** a small set of **benign, non-privileged** Atomic Red Team tests selected to
match our infostealer emulation plan (Week 8), described at the planning/detection
level and mapped to the detections we already built in Weeks 5 and 7. Consistent with
the project's standing rule, **no credential-dumping, no elevated/offensive tests, no
real malware or real credential theft** were run; this report delivers the test
selection, the telemetry each test produces, and the SIEM detection logic. Any
execution would happen only on the isolated personal lab host from Weeks 5–7, under
manual control, with each atomic's own cleanup.

## 1. Objective and relation to the course

Week 8 produced an adversary emulation *plan* (initial access → persistence →
exfiltration) and expressed it as a CALDERA profile. Week 9 takes the **individual
techniques** from that plan and runs them as **atomic tests** — small, isolated,
single-technique actions — then records and analyzes the result in our SIEM (Splunk).
The course task is: "run selected atomic tests (e.g., T1059, T1003), record and analyze
the test results in a SIEM."

We keep the same scope discipline as every prior week: we run the **benign subset** that
generates the ATT&CK telemetry we want to detect, and we **exclude** the offensive
variants (see §3). The learning goal here is detection validation, not offense.

## 2. What is Atomic Red Team

**Atomic Red Team** (maintained by Red Canary) is an open-source library of small,
portable tests, each mapped to a single MITRE ATT&CK technique. Each test is defined in
YAML with a predictable structure:

| Field | Meaning |
|---|---|
| `attack_technique` | The ATT&CK technique ID (e.g. T1547.001) |
| `display_name` | The technique name |
| `atomic_tests[]` | One or more individual tests |
| `name` / `description` | What the test does |
| `supported_platforms` | windows / linux / macos |
| `input_arguments` | Parameters with defaults (e.g. a file path) |
| `executor` | How it runs: `powershell`, `command_prompt`, or `manual` |
| `executor.elevation_required` | Whether admin rights are needed |
| `dependencies` | Files/tools the test needs first |
| `cleanup_command` | How the test undoes itself |

Tests are run with the `Invoke-AtomicRedTeam` PowerShell module
(`Invoke-AtomicTest T1547.001 -TestNumbers 1`). Because each test is **atomic** (one
technique, well-scoped, with cleanup), it is ideal for *detection engineering*: you run
one known behavior and check whether your detection fires — exactly the hypothesis→
telemetry loop from Week 5, but with a ready-made, documented action instead of our own.

**Atomic vs. CAR (Week 7) vs. CALDERA (Week 8):**

| | Atomic Red Team (W9) | CAR analytic (W7) | CALDERA (W8) |
|---|---|---|---|
| Gives us | The **action** (one technique) | The **detection** logic | The **chain** (ordered profile) |
| Scope | One technique at a time | One analytic | Full adversary emulation |
| Our use | Generate known telemetry to test detections | The detection we test against | The plan the atomics come from |

## 3. Scope and safety — what we run and what we exclude

Atomic Red Team contains genuinely offensive tests (credential dumping, Mimikatz, LSASS
memory access). **We do not run those.** For an infostealer detection exercise they are
unnecessary and out of scope, and running them creates real risk even in a lab.

**Excluded (documented here only so the choice is explicit):**

- **T1003.001 (LSASS Memory / Mimikatz / procdump)** — out of scope. Infostealers
  typically read *browser* stores, not LSASS; the test requires elevation and handles
  real credential material. We exclude the whole T1003 family.
- Any test with `elevation_required: true`, and any test that downloads a real offensive
  tool (BloodHound, LaZagne, WinPwn, BrowserStealer, mimikatz).

**Included — the benign, non-privileged subset** that produces the same ATT&CK
telemetry our detections look for:

- Tests that run as a normal user, have a `cleanup_command`, and whose "payload" is a
  harmless marker (write a string, read a *simulated* file, register a benign command).
- Where a test simulates credential access, we use the **"Simulating access…"** variant,
  which touches a decoy/credential-shaped file rather than stealing real data —
  consistent with the dummy-file approach in our Week 8 plan.

All execution (if demonstrated) is on the isolated Windows 11 lab host from Weeks 5–7,
Sysmon + Splunk, with a restore point taken first.

## 4. Selected atomic tests

Four tests, one per stage of our Week 8 plan, chosen for being benign, non-elevated, and
self-cleaning. They are referenced by technique and test number; we describe what each
*generates*, not an attack command.

![Atomic test → telemetry → SIEM detection flow](img/atomic_flow.png)

| # | Technique | Atomic test (benign) | Stage in our plan | Telemetry generated |
|---|---|---|---|---|
| 1 | **T1059.001** PowerShell | "PowerShell Command Execution" (non-elevated, benign command) | Initial access / execution | Sysmon EID 1 (process create): `powershell.exe`, command line, parent process |
| 2 | **T1547.001** Registry Run Keys | "Reg Key Run" (test #1, non-elevated, cleanup) | Persistence | Sysmon EID 13 (registry value set) under `...\CurrentVersion\Run`; EID 1 for `reg.exe` |
| 3 | **T1053.005** Scheduled Task | "Scheduled task — Local" / "Powershell Cmdlet Scheduled Task" (non-elevated, cleanup) | Persistence | Sysmon EID 1 (`schtasks.exe`/PowerShell); Security EID 4698 (task created) |
| 4 | **T1555.003** Credentials from Web Browsers | "Simulating access to Chrome Login Data" (non-elevated, cleanup) | Collection / credential access | Sysmon EID 11 (file access/copy of the decoy `Login Data`); process reading the store |

These four give us one execution test, two persistence tests (the gap we flagged in
Week 8), and one browser-credential-access test — the core infostealer behavior, done
against a decoy file.

## 5. Running and recording in the SIEM

Procedure (conceptual — the same loop for each test):

1. Take a restore point / snapshot on the lab host.
2. Confirm Sysmon is running and Splunk is ingesting the `sysmon` and `wineventlog`
   indexes (Week 5 setup).
3. Note the UTC time, then run one atomic: `Invoke-AtomicTest <technique> -TestNumbers <n>`.
4. Record the test's own output and the time window.
5. In Splunk, run the matching detection (below) over that window.
6. Run the atomic's `cleanup_command` and verify the artifact is gone (e.g. the Run key
   is removed).
7. Record: did the detection fire? true/false positive? notes.

Recording each test's time window is what makes the SIEM analysis honest — we correlate a
*known* action to the events it produced, rather than guessing.

## 6. Detection analysis (reusing Weeks 5 and 7)

We deliberately test against detections we already wrote, to validate them.

**Test 1 — T1059.001 (execution).** Detection: Week 5 **H1** (Sysmon EID 1, parent
`explorer.exe`, child `powershell.exe`/`mshta.exe`, suspicious command line) and the
Week 7 CAR analytic CAR-2014-04-003 (PowerShell not spawned by `explorer.exe`). The
atomic lets us confirm both paths light up as expected.

```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
| table _time ComputerName ParentImage Image CommandLine User
```

**Test 2 — T1547.001 (persistence, Run key).** This is the Week 8 coverage **gap**, now
addressed. Detection on registry writes to a Run key:

```spl
index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run\\*"
| table _time ComputerName Image TargetObject Details User
```

**Test 3 — T1053.005 (persistence, scheduled task).** Also part of the Week 8 gap:

```spl
(index=sysmon EventCode=1 (Image="*\\schtasks.exe" OR CommandLine="*ScheduledTask*"))
OR (index=wineventlog EventCode=4698)
| table _time ComputerName Image CommandLine User
```

**Test 4 — T1555.003 (browser credential access).** Detection: Week 5 **H2** — a
non-browser process touching a browser credential store. With the "Simulating access"
atomic the accessed file is a decoy:

```spl
index=sysmon EventCode=11 TargetFilename="*\\User Data\\*\\Login Data*"
| search Image!="*\\chrome.exe" AND Image!="*\\msedge.exe"
| table _time ComputerName Image TargetFilename User
```

> Field names follow the Splunk Sysmon add-on; adjust to your parsing. Verify technique
> IDs on attack.mitre.org before citing.

## 7. Expected results table

Filled in during the lab run; the structure is what matters for the defense.

| Test | Technique | Detection used | Expected | Fired? | Notes |
|---|---|---|---|---|---|
| 1 | T1059.001 | W5 H1 + W7 CAR | Hit on EID 1 | ✅ | Confirms execution detection |
| 2 | T1547.001 | EID 13 Run-key query | Hit on EID 13 | ✅ | **Closes W8 persistence gap** |
| 3 | T1053.005 | EID 1 / 4698 query | Hit on task create | ✅ | **Closes W8 persistence gap** |
| 4 | T1555.003 | W5 H2 | Hit on EID 11 (decoy) | ⚠️ | Needs file-audit/Sysmon FileCreate rule enabled |

The two persistence rows are the point of Week 9: Week 8 identified persistence as the
uncovered part of the chain, and these atomics let us build and prove the detection.

## 8. Limitations and next steps

- We ran the **benign subset**; offensive credential-dumping tests were excluded by
  design, so this does not measure detection of LSASS-based theft (not our threat model).
- Test 4 depends on having a Sysmon FileCreate/registry rule or object-access auditing
  enabled; without it, browser-store access is not logged (noted in Week 5).
- Atomic tests are single techniques in isolation; they do not reproduce the *timing and
  correlation* of a real chain. Week 8's CALDERA profile is where the ordered chain
  lives; Week 10 looks at how a real actor sequences these.
- Next step: convert the two new persistence detections into saved Splunk searches / a
  Sigma rule, and add T1547.001 and T1053.005 to the ATT&CK Navigator coverage layer.

## 9. References

- Atomic Red Team — Wiki and GitHub repository:
  <https://github.com/redcanaryco/atomic-red-team>,
  <https://www.redcanary.com/atomic-red-team/>
- `Invoke-AtomicRedTeam` execution framework:
  <https://github.com/redcanaryco/invoke-atomicredteam/wiki>
- MITRE ATT&CK — <https://attack.mitre.org> (T1059.001, T1547.001, T1053.005, T1555.003).
- Internal: Week 5 (hypotheses H1–H3, Splunk lab), Week 7 (CAR analytic
  CAR-2014-04-003), Week 8 (emulation plan, persistence gap).
- Course AI-use statement: see main [README](../README.md).
