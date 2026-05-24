# CORRELATION-MultiStage-Intrusion

| Field | Value |
|---|---|
| Rule ID | DET-008 |
| Severity | CRITICAL |
| MITRE Technique | Cross-tactic correlation (multiple) |
| Data Source | Multi-source — Sysmon EID 1, 10, 13 + Security EID 4698, 1102, 5156 + System EID 104 |
| Index | wineventlog |
| Validation Status | PASS — 6 distinct techniques observed on one host |

---

## Why this rule exists

Individual technique alerts are noise. Every SOC has hundreds of PowerShell alerts per day, dozens of registry write alerts per hour, and a steady drip of LSASS access events from legitimate agents. Triaging each in isolation is what burns analysts out and produces alert fatigue.

A host that fires *multiple distinct ATT&CK technique alerts in a short time window* is not noise. It's a host being attacked.

This rule fires CRITICAL when a single ComputerName generates events matching 3 or more distinct techniques within a 60-minute window. Severity escalates from per-technique HIGH to per-incident CRITICAL because the correlation itself is the signal.

## SPL

```spl
index=wineventlog earliest=-1h
| eval technique=case(
    EventCode==10 AND match(TargetImage,"lsass"), "T1003-CredAccess",
    EventCode==13 AND match(TargetObject,"Run\\\\"), "T1547-Persistence",
    EventCode==1 AND match(CommandLine,"-enc|IEX|DownloadString|FromBase64"), "T1059-Execution",
    EventCode==4698, "T1053-SchedTask",
    EventCode==1 AND match(lower(ParentImage),"winword|excel|powerpnt"), "T1566-OfficeSpawn",
    EventCode==5156 AND Source_Address!="192.168.100.10" AND Direction="*Inbound*", "T1595-PortScan",
    EventCode==1102 OR EventCode==104, "T1070-DefenseEvasion",
    true(), null()
)
| where isnotnull(technique)
| stats dc(technique) as technique_count,
        values(technique) as techniques_seen,
        min(_time) as first_seen,
        max(_time) as last_seen by ComputerName
| where technique_count >= 3
| eval severity="CRITICAL", alert="MULTI-STAGE INTRUSION DETECTED"
| convert ctime(first_seen) ctime(last_seen)
```

## Validation Evidence

Final result after Phase D execution:

```
ComputerName    : NEXCORE-WIN
technique_count : 6
techniques_seen : T1003-CredAccess
                  T1053-SchedTask
                  T1059-Execution
                  T1547-Persistence
                  T1566-OfficeSpawn
                  T1070-DefenseEvasion
first_seen      : 2026-05-23 12:54:29
last_seen       : 2026-05-23 13:48:32
severity        : CRITICAL
alert           : MULTI-STAGE INTRUSION DETECTED
```

One row. Six distinct techniques. One host. 54-minute window.

The port scan technique didn't make it into the final correlation result because the WFP audit events fell outside the 1-hour `earliest` window when this query ran — extending `earliest=-2h` includes it as a 7th technique.

## Tuning notes

- The `technique_count >= 3` threshold is the key knob. Lower values produce more alerts; higher values catch only obviously coordinated attacks. 3 is appropriate for high-value endpoints (DCs, jump hosts, finance workstations). 4 may be appropriate for general user endpoints.
- The time window (`earliest=-1h`) determines what "concurrent" means. Slow-and-low attacks may need a 24-hour window with a higher threshold.
- The list of techniques can be expanded as new per-technique rules are added. Each new rule adds another `case()` clause.

## Why this is the most important rule in the lab

Every other detection in this lab catches *one thing*. This one catches *intent*. An attacker doing recon is doing recon. An attacker doing recon, then PowerShell execution, then registry persistence, then LSASS access — that's an intrusion in progress. The rule above is what turns seven separate alerts into one incident, and one incident is what an analyst can actually act on.
