# Incident Response Report

**Incident ID:** IR-2026-001
**Classification:** Confidential — Internal SOC Use
**Report Status:** Closed
**Author:** Sidharth Chauhan, SOC Analyst
**Date:** 23 May 2026

---

## 1. Document Header

| Field | Value |
|---|---|
| Incident Title | Multi-stage simulated intrusion against NEXCORE-WIN endpoint |
| Incident ID | IR-2026-001 |
| Classification | Confidential |
| Author | Sidharth Chauhan |
| Reviewed By | — (lab project, single analyst) |
| Date Opened | 23 May 2026, 12:30 IST |
| Date Closed | 23 May 2026, 14:30 IST |
| SIEM | Splunk Enterprise 10.2.3 |
| Telemetry Sources | Sysmon 15.20, Windows Security/System/Application logs, WFP audit (EID 5156) |

---

## 2. Executive Summary

On 23 May 2026, between 12:30 and 14:30 IST, the NEXCORE-WIN endpoint (192.168.100.10) was subjected to a multi-stage attack simulating a financially motivated threat actor profile. The attack chain executed seven MITRE ATT&CK techniques across reconnaissance, execution, persistence, credential access, and defense evasion — culminating in a log-clearing event intended to remove forensic evidence.

All seven techniques were detected. The custom correlation rule fired CRITICAL, identifying NEXCORE-WIN as a host exhibiting six distinct ATT&CK techniques within a 60-minute window. The log-clearing attempt was detected via Security EID 1102 and System EID 104 — events that survive the clearing operation by design.

The exercise validates the endpoint detection pipeline but documents four detection gaps requiring remediation.

---

## 3. Incident Metadata

| Field | Value |
|---|---|
| Severity | CRITICAL |
| Status | Resolved |
| Detection Method | Splunk SIEM — 8 custom SPL rules |
| Affected Asset | NEXCORE-WIN (192.168.100.10) |
| Affected Account | `NEXCORE-WIN\WIN` (local admin) |
| Attacker Origin | 192.168.100.30 (Kali Linux) |
| Initial Detection | T+0:00 — DET-006 fired on inbound TCP scan from attacker IP |
| Final Detection | T+2:00 — DET-005 fired on Security log clearing |
| Total Dwell Time (simulated) | 2 hours |

---

## 4. Attack Narrative

Reconnaissance began at 12:30 IST with an inbound TCP scan from 192.168.100.30 targeting ports 135, 139, 445, 3389, 80, and 443 on NEXCORE-WIN. Windows Filtering Platform audit policy logged each connection attempt as Security EID 5156. The scan completed in under one second.

Following reconnaissance, the attacker pivoted to execution on the endpoint itself (simulated via local execution of Atomic Red Team tests under the `NEXCORE-WIN\WIN` account). Obfuscated PowerShell content was executed via T1027 and T1059.001 — generating Sysmon EID 1 events with command lines containing encoded payloads, `IEX`, and `DownloadString` artifacts.

Persistence was established through two mechanisms: a registry Run key (`HKU\...\Run\Atomic Red Team`) created via `reg.exe` and captured as Sysmon EID 13, and a scheduled task (`T1053_005_OnStartup`) registered via `schtasks.exe` and captured as Windows Security EID 4698. The task content explicitly contained `<Command>cmd.exe</Command><Arguments>/c calc.exe</Arguments>`.

Credential access was attempted via T1003.001 (LSASS memory access). Windows Defender partially blocked the read operation, but Sysmon EID 10 still recorded the access attempt against `C:\Windows\system32\lsass.exe`.

Defense evasion concluded the chain: indicator files were deleted (T1070.004), hidden files were created (T1564.001), and the Security, System, and Application event logs were cleared via `wevtutil cl`. The clearing act itself generated Security EID 1102 and System EID 104 — both of which were detected and correlated.

A simulated initial-access vector was triggered manually: a renamed copy of `cmd.exe` placed at `%TEMP%\winword.exe` was executed and instructed to spawn `powershell.exe`, mimicking a malicious Office macro payload. The parent-child anomaly rule (DET-007) detected this pattern based on process lineage alone.

The multi-technique correlation rule (DET-008) fired CRITICAL with six distinct techniques observed on a single host within the attack window.

---

## 5. Technical Analysis

### 5.1 — T1595 Reconnaissance (DET-006)

**Evidence:** Windows Security EID 5156 (Filtering Platform Connection — permitted inbound).

**Splunk Query:**
```spl
index=wineventlog EventCode=5156 earliest=-2h
Direction="*Inbound*"
Source_Address="192.168.100.30"
| bucket _time span=5m
| stats dc(Destination_Port) as unique_ports,
        values(Destination_Port) as ports_hit,
        count as total_conns by _time, Source_Address
| eval severity=case(
    unique_ports >= 5, "HIGH",
    unique_ports >= 3, "MEDIUM",
    true(), "LOW"
)
| eval alert="Port Scan Detected from Attacker IP"
```

**Result:** Source 192.168.100.30, multiple destination ports hit within a 5-minute bucket, severity HIGH.

### 5.2 — T1059.001 PowerShell Execution (DET-001)

**Evidence:** Sysmon EID 1 process creation events with command-line patterns matching obfuscated or remote-payload execution.

**Splunk Query:**
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(CommandLine="*-enc*"
  OR CommandLine="*-EncodedCommand*"
  OR CommandLine="*IEX*"
  OR CommandLine="*Invoke-Expression*"
  OR CommandLine="*-nop -w hidden*"
  OR CommandLine="*DownloadString*"
  OR CommandLine="*FromBase64String*")
| eval severity="HIGH"
| table _time, ComputerName, User, ParentImage, CommandLine, severity
| sort - _time
```

**Result:** Multiple events; representative command line included `-EncodedCommand` and `IEX` artifacts.

### 5.3 — T1547.001 Registry Run Key Persistence (DET-002)

**Evidence:** Sysmon EID 13 registry-set event modifying `\CurrentVersion\Run\`.

**Splunk Query:**
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
(TargetObject="*\\CurrentVersion\\Run\\*"
  OR TargetObject="*\\CurrentVersion\\RunOnce\\*")
| eval severity="HIGH"
| table _time, ComputerName, User, Image, TargetObject, Details
```

**Result:** 1 event. TargetObject = `HKU\S-1-5-21-3355898466-3594867308-4199659375-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team`, Image = `C:\Windows\system32\reg.exe`, Details = `C:\Path\AtomicRedTeam.exe`.

### 5.4 — T1053.005 Scheduled Task (DET-004)

**Evidence:** Windows Security EID 4698 with full task XML.

**Splunk Query:**
```spl
index=wineventlog source="WinEventLog:Security" EventCode=4698
| eval severity="HIGH"
| table _time, ComputerName, SubjectUserName, TaskName, TaskContent
```

**Result:** Task `T1053_005_OnStartup` registered by `NEXCORE-WIN\WIN`. Embedded XML contained `<Command>cmd.exe</Command><Arguments>/c calc.exe</Arguments>` and BootTrigger configuration for execution on system startup.

### 5.5 — T1003.001 LSASS Memory Access (DET-003)

**Evidence:** Sysmon EID 10 — ProcessAccess events targeting `lsass.exe`.

**Splunk Query (tuned):**
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
TargetImage="*\\lsass.exe"
GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
NOT (SourceImage="*\\MsMpEng.exe"
     OR SourceImage="*\\VBoxService.exe"
     OR SourceImage="*\\csrss.exe"
     OR SourceImage="*\\wininit.exe"
     OR SourceImage="*\\services.exe"
     OR SourceImage="*\\svchost.exe")
| eval severity="CRITICAL"
```

**Result:** Access attempts logged with `GrantedAccess 0x1400` from atomic test execution. Credential-read masks (`0x1010`/`0x1410`) were not observed — Defender's behavior monitoring blocked the read mid-execution. The access attempt itself remains forensic evidence of the technique.

### 5.6 — T1059 / T1566 Office Macro Spawn Anomaly (DET-007)

**Evidence:** Sysmon EID 1 — parent-child process lineage where an Office image name spawns a shell or LOLBin.

**Splunk Query:**
```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval parent_lower=lower(ParentImage), child_lower=lower(Image)
| where (
    match(parent_lower,"winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|acrord32\.exe")
    AND
    match(child_lower,"cmd\.exe|powershell\.exe|powershell_ise\.exe|rundll32\.exe|regsvr32\.exe|wscript\.exe|cscript\.exe|mshta\.exe")
)
| eval severity="HIGH"
```

**Result:** Two events. Renamed `cmd.exe` copies at `%TEMP%\winword.exe` and `%TEMP%\excel.exe` spawning `powershell.exe`. Sysmon logs the image name as written on disk — the rule fires on lineage, not file integrity, which is the point.

### 5.7 — T1070.001 Log Clearing (DET-005)

**Evidence:** Security EID 1102 and System EID 104 — generated by the clearing operation itself.

**Splunk Query:**
```spl
index=wineventlog (EventCode=1102 OR EventCode=104) earliest=-30m
| eval severity="CRITICAL",
       action="Log Cleared — Possible Attacker Covering Tracks"
| table _time, ComputerName, source, EventCode, action, severity
```

**Result:** Three events: 1102 (Security), 104 (System), 104 (Application). All forwarded to Splunk before being cleared from local storage. Off-host log retention is the control that made this detection possible.

### 5.8 — Multi-Technique Correlation (DET-008)

**Splunk Query:**
```spl
index=wineventlog earliest=-2h
| eval technique=case(
    EventCode==10 AND match(TargetImage,"lsass"), "T1003-CredAccess",
    EventCode==13 AND match(TargetObject,"Run\\\\"), "T1547-Persistence",
    EventCode==1 AND match(CommandLine,"-enc|IEX|DownloadString|FromBase64"), "T1059-Execution",
    EventCode==4698, "T1053-SchedTask",
    EventCode==1 AND match(lower(ParentImage),"winword|excel|powerpnt"), "T1566-OfficeSpawn",
    EventCode==5156 AND Source_Address="192.168.100.30" AND Direction="*Inbound*", "T1595-PortScan",
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

**Result:** One row. ComputerName = NEXCORE-WIN, technique_count = 6, techniques_seen = T1003-CredAccess, T1053-SchedTask, T1059-Execution, T1547-Persistence, T1566-OfficeSpawn, T1070-DefenseEvasion.

This is the rule that turns seven individual alerts into one incident.

---

## 6. Attack Timeline

| Timestamp (IST) | T+ | Phase | Technique | Source | Evidence |
|---|---|---|---|---|---|
| 12:30:00 | T+0:00 | Reconnaissance | T1595.001 | Kali → NEXCORE-WIN | Security EID 5156 (multiple) |
| 12:35:00 | T+0:05 | Execution | T1059.001 / T1027 | NEXCORE-WIN\WIN | Sysmon EID 1 (encoded cmdline) |
| 12:45:00 | T+0:15 | Discovery | T1082, T1057, T1135 | NEXCORE-WIN\WIN | Sysmon EID 1 |
| 13:00:00 | T+0:30 | Persistence | T1547.001 | NEXCORE-WIN\WIN | Sysmon EID 13 — Run key write |
| 13:16:47 | T+0:46 | Persistence | T1053.005 | NEXCORE-WIN\WIN | Security EID 4698 — `T1053_005_OnStartup` |
| 13:25:00 | T+0:55 | Credential Access | T1003.001 | NEXCORE-WIN\WIN | Sysmon EID 10 — lsass.exe access |
| 13:40:00 | T+1:10 | Defense Evasion | T1070.004, T1564.001 | NEXCORE-WIN\WIN | Sysmon EID 1, EID 11 |
| 14:00:00 | T+1:30 | Initial Access (sim) | T1566 / T1059 | %TEMP%\winword.exe | Sysmon EID 1 — anomalous parent-child |
| 14:30:00 | T+2:00 | Defense Evasion | T1070.001 | NEXCORE-WIN\WIN | Security EID 1102, System EID 104 |

---

## 7. IOC Table

See `iocs/ioc-list.csv` for the structured CSV. Summary below.

| Type | Value | Confidence | Context | Source |
|---|---|---|---|---|
| IP Address | 192.168.100.30 | HIGH | Attacker — recon + lateral movement attempt | Internal — Security EID 5156 |
| Registry Key | `HKU\S-1-5-21-3355898466-3594867308-4199659375-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team` | HIGH | Persistence — T1547.001 | Sysmon EID 13 |
| File Path | `C:\Path\AtomicRedTeam.exe` | HIGH | Run-key target binary | Sysmon EID 13 (Details field) |
| Scheduled Task | `T1053_005_OnStartup` | HIGH | Persistence via BootTrigger | Security EID 4698 |
| Process Lineage | `winword.exe → powershell.exe` (from `%TEMP%\`) | HIGH | Office macro payload pattern | Sysmon EID 1 |
| Process Lineage | `reg.exe ADD HKCU\...\Run` | MEDIUM | Persistence write via Windows builtin | Sysmon EID 1 + EID 13 |
| Process | `powershell.exe -EncodedCommand` | HIGH | Obfuscated execution | Sysmon EID 1 |
| Process Access | Source `*\unknown*` → `\Device\HarddiskVolume2\Windows\System32\lsass.exe` | HIGH | LSASS read attempt | Sysmon EID 10 |
| Event | Security EID 1102 — Log Cleared | CRITICAL | Anti-forensics | Splunk Alert (DET-005) |
| Event | System EID 104 — Log Cleared | CRITICAL | Anti-forensics | Splunk Alert (DET-005) |

---

## 8. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection | Status |
|---|---|---|---|---|
| Reconnaissance | Active Scanning | T1595.001 | DET-006 | Detected |
| Initial Access | Phishing (Office macro simulated) | T1566 | DET-007 | Detected (lineage proxy) |
| Execution | PowerShell | T1059.001 | DET-001 | Detected |
| Execution | Obfuscated Files | T1027 | DET-001 (overlap) | Detected |
| Persistence | Registry Run Key | T1547.001 | DET-002 | Detected |
| Persistence | Scheduled Task | T1053.005 | DET-004 | Detected |
| Credential Access | LSASS Memory | T1003.001 | DET-003 | Partially detected (access logged, read blocked by Defender) |
| Discovery | System Information | T1082 | — | Logged, no dedicated rule |
| Discovery | Process Discovery | T1057 | — | Logged, no dedicated rule |
| Discovery | Network Share Discovery | T1135 | — | Logged, no dedicated rule |
| Defense Evasion | File Deletion | T1070.004 | — | Logged, no dedicated rule |
| Defense Evasion | Hidden Files | T1564.001 | — | Logged, no dedicated rule |
| Defense Evasion | Clear Event Logs | T1070.001 | DET-005 | Detected |
| Correlation | Multi-technique on single host | (custom) | DET-008 | Detected — 6 techniques |

Full coverage assessment with gaps: `detection-rules/mitre-coverage-map.md`.

---

## 9. Root Cause Analysis

The simulated compromise succeeded because the target host's security posture matched the lab profile rather than an enterprise baseline.

| Contributing Factor | Impact |
|---|---|
| Defender Real-Time Protection disabled for the exercise | Allowed atomic tests to execute. In production this would not be the case. |
| Local admin account used (`NEXCORE-WIN\WIN`) | Persistence mechanisms (Run key, scheduled task) succeeded without privilege escalation. |
| No Credential Guard | T1003.001 access attempts reached LSASS rather than being structurally prevented. |
| No PowerShell Constrained Language Mode | Encoded PowerShell executed without policy restrictions. |
| No AppLocker / WDAC | Renamed `cmd.exe` (`%TEMP%\winword.exe`) executed without binary signing or path enforcement. |
| Default Windows audit policy | WFP connection auditing required manual enablement. Without it, port scan visibility is host-blind. |

The compromise was detected. It was not prevented. That distinction matters.

---

## 10. Containment Actions

For a real incident matching this profile, the following containment steps would be executed in order:

1. Isolate NEXCORE-WIN from the network — disable the network adapter or VLAN-quarantine the host.
2. Disable the affected account (`NEXCORE-WIN\WIN`) at the directory level.
3. Forensically image the endpoint disk and memory before remediation, preserving evidence for IR-2026-001 case file.
4. Remove the registry persistence key: `HKU\S-1-5-21-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team`.
5. Delete the scheduled task: `schtasks /Delete /TN "T1053_005_OnStartup" /F`.
6. Reset credentials for all accounts that have authenticated to the host since first detection (assumed compromised).
7. Block the attacker IP (192.168.100.30) at the perimeter and internal firewalls.
8. Push the IOC list to all other endpoints for retrospective hunting.

---

## 11. Remediation Recommendations

| # | Recommendation | Control Type | Effort |
|---|---|---|---|
| 1 | Enable PowerShell Script Block Logging via GPO (`Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging`) | Detective | Low |
| 2 | Enable Credential Guard on Windows 10/11 endpoints to prevent LSASS memory access from non-privileged processes | Preventive | Medium |
| 3 | Deploy AppLocker or WDAC with a path-and-signer policy that blocks renamed system binaries from `%TEMP%\` | Preventive | Medium |
| 4 | Enable Windows Filtering Platform connection auditing organisation-wide via GPO. The control was applied locally for this exercise; it must be policy-driven in production | Detective | Low |
| 5 | Enable Windows Event ID 4104 (PowerShell script block) in parallel with Sysmon for full command capture | Detective | Low |
| 6 | Move privileged accounts into the Protected Users security group to harden against pass-the-hash and LSASS dumps | Preventive | Low |
| 7 | Implement off-host log retention as the standard — every Windows endpoint forwards logs to Splunk before clearing can erase them locally | Detective | Already in place for this lab; enforce as policy |
| 8 | Deploy network-layer detection (Suricata + Zeek) to close the gap documented in §12.3 | Detective | High — covered in Operation SPECTRE |

---

## 12. Detection Gaps & Lessons Learned

### 12.1 — T1003.001 Read Mask Blindness

Defender blocked the actual LSASS read, which is operationally good but detection-blind: the GrantedAccess masks distinguishing credential dumping from benign access (`0x1010`, `0x1410`) were never observed because the read was killed mid-execution. The access *attempt* was logged (`0x1400`), but a tuned rule looking only at credential-read masks would have missed this entirely.

**Lesson:** Detection rules cannot assume the attack succeeds. Rules should fire on attempted access patterns, with severity scaled by mask specificity.

### 12.2 — SwiftOnSecurity NetworkConnect Exclusion

The Sysmon SwiftOnSecurity config excludes all RFC1918 destinations from NetworkConnect logging (EID 3). This means Sysmon alone is blind to internal port scans. The workaround — enabling WFP connection auditing for Security EID 5156 — works, but requires explicit `auditpol` configuration that is not the Windows default.

**Lesson:** Detection coverage assumptions must be verified against the deployed Sysmon config. The default config is good, but it has opinions about what's worth logging, and those opinions can create blind spots in lab and small-enterprise environments.

### 12.3 — No Network-Layer Visibility

This lab has no IDS, no NSM, no packet capture. Lateral movement attempts are detected via host-side telemetry (Sysmon + WFP), which works for SMB connections initiated *to* the host but is blind to anything that doesn't touch the endpoint OS. Real intrusions rarely confine themselves to one host.

**Lesson:** Endpoint and network detection are complementary, not alternative. This gap is the explicit reason for the follow-up project, [Operation SPECTRE](https://github.com/SidharthX-OPS/operation-spectre-network-threat-detection).

### 12.4 — No Phishing Email Visibility

T1566 was simulated by faking `winword.exe` spawning a shell. In a real environment, detection should happen earlier — at the email gateway, before the user clicks. This lab cannot model that layer.

**Lesson:** Endpoint parent-child detection is a last line of defense. It catches macro execution after the email has already been delivered, opened, and the user has clicked Enable Content. A mature SOC stack catches it three layers earlier.

---

**End of Report — IR-2026-001**
