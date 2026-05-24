# ALERT-CRITICAL-T1003-LSASS-Access

| Field | Value |
|---|---|
| Rule ID | DET-003 |
| Severity | CRITICAL |
| MITRE Technique | [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| Data Source | Sysmon EID 10 (Process Access) |
| Index | wineventlog |
| Validation Status | PARTIAL — access attempt logged, Defender blocked the actual read |

---

## Description

Detects processes attempting to access LSASS memory. LSASS holds cached credentials; reading it is the canonical credential-dumping technique (Mimikatz, procdump, comsvcs.dll MiniDump). This rule fires on non-system processes opening lsass.exe with credential-read access masks.

The version below is **tuned** to reduce noise — the untuned version returns hundreds of benign hits per hour from `VBoxService.exe`, `svchost.exe`, and Defender itself.

## SPL — Tuned

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
| table _time, ComputerName, User, SourceImage, GrantedAccess, TargetImage
| sort - _time
```

## GrantedAccess Mask Reference

| Mask | Meaning |
|---|---|
| `0x1010` | PROCESS_QUERY_INFORMATION + PROCESS_VM_READ — Mimikatz signature |
| `0x1410` | PROCESS_QUERY_INFORMATION + PROCESS_VM_READ + PROCESS_DUP_HANDLE |
| `0x1438` | Process query + read + suspend + write — full credential dump capability |
| `0x143a` | Variant with additional rights |
| `0x1fffff` | PROCESS_ALL_ACCESS — extremely suspicious |
| `0x1400` | PROCESS_QUERY_INFORMATION only — *attempt* without read, often logged when Defender intervenes |

## Validation Evidence

Atomic Red Team T1003.001 was partially blocked by Defender behavior monitoring. Sysmon still logged the access attempts as EID 10 with `GrantedAccess 0x1400` — the read was prevented, but the attempt is forensic evidence.

This is noted in the IR report as a deliberate detection gap. The tuned rule above will not fire on `0x1400` attempts. A complementary lower-severity rule can be added to surface `0x1400` access patterns from non-system sources for retrospective hunting.

## False Positive Notes

Even with tuning, expect occasional benign hits from:
- Endpoint security agents (most EDR tools query lsass.exe legitimately)
- Backup and DR software that snapshots process memory
- VBoxService and VMware Tools

**Tuning approach:** Maintain an allowlist of `SourceImage` paths for known agent binaries. Pair with a hash check in production — agents are signed; mimikatz isn't.
