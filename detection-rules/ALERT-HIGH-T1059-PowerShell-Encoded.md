# ALERT-HIGH-T1059-PowerShell-Encoded-Cmd

| Field | Value |
|---|---|
| Rule ID | DET-001 |
| Severity | HIGH |
| MITRE Technique | [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| Data Source | Sysmon EID 1 (Process Creation) |
| Index | wineventlog |
| Validation Status | PASS |

---

## Description

Detects PowerShell execution with encoded, obfuscated, or remote-payload command-line patterns. These flags are rare in legitimate administrative scripts and common in malware loaders, post-exploitation toolkits (Empire, Covenant), and Atomic Red Team payloads.

## SPL

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

## Validation Evidence

Triggered against Atomic Red Team tests T1027 and T1059.001 #9. Multiple Sysmon EID 1 events captured with `-EncodedCommand` and `IEX` patterns in the command line.

## False Positive Notes

Legitimate scenarios that may trigger:
- Microsoft Defender ATP / EDR agents using `-EncodedCommand` for inventory scripts
- Configuration management tools (SCCM, Intune) deploying scripts via encoded payloads
- Some PowerShell-based deployment frameworks (PSWindowsUpdate, etc.)

**Tuning approach:** Whitelist by signed parent process, known administrative user accounts, or specific command-line signatures (e.g., known SCCM cmdlet patterns). Do not whitelist by username alone — attackers compromise admin accounts.
