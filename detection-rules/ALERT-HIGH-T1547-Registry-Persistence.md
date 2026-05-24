# ALERT-HIGH-T1547-Registry-Persistence

| Field | Value |
|---|---|
| Rule ID | DET-002 |
| Severity | HIGH |
| MITRE Technique | [T1547.001 — Boot or Logon Autostart: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) |
| Data Source | Sysmon EID 13 (Registry Value Set) |
| Index | wineventlog |
| Validation Status | PASS |

---

## Description

Detects writes to the standard Windows Run/RunOnce registry keys, the most common persistence mechanism after scheduled tasks. The SwiftOnSecurity Sysmon config includes these registry paths in EID 13 logging by default.

## SPL

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
(TargetObject="*\\CurrentVersion\\Run\\*"
  OR TargetObject="*\\CurrentVersion\\RunOnce\\*"
  OR TargetObject="*\\Run\\*")
| eval severity="HIGH"
| table _time, ComputerName, User, Image, TargetObject, Details
| sort - _time
```

## Validation Evidence

Triggered against Atomic Red Team T1547.001 #1. Captured event:

- `TargetObject`: `HKU\S-1-5-21-3355898466-3594867308-4199659375-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team`
- `Image`: `C:\Windows\system32\reg.exe`
- `Details`: `C:\Path\AtomicRedTeam.exe`

Textbook registry persistence detection.

## False Positive Notes

Legitimate scenarios:
- Software installers writing autorun entries (Adobe Updater, Office Click-to-Run, OEM utilities)
- Group Policy applying authorized startup applications
- IT-deployed agent registrations (EDR, RMM tools)

**Tuning approach:** Whitelist by `Image` (the writing process) for known software updaters, or by `Details` (the path being written) for known authorized binaries under `C:\Program Files\`. Suspect anything writing from `%TEMP%`, `%APPDATA%`, or `C:\Users\Public`.
