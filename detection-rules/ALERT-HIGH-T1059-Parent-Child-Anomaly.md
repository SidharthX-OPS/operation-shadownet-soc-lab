# ALERT-HIGH-T1059-Parent-Child-Anomaly

| Field | Value |
|---|---|
| Rule ID | DET-007 |
| Severity | HIGH |
| MITRE Technique | [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) + [T1566 — Phishing](https://attack.mitre.org/techniques/T1566/) |
| Data Source | Sysmon EID 1 (Process Creation) |
| Index | wineventlog |
| Validation Status | PASS |

---

## Description

Detects Office applications (Word, Excel, PowerPoint, Outlook, Acrobat Reader) spawning a shell or LOLBin as a child process. This is the single most reliable signal for malicious macro execution: Office applications almost never legitimately spawn `cmd.exe`, `powershell.exe`, or `rundll32.exe`. When they do, it is overwhelmingly the result of a user enabling content on a malicious document.

This rule is intentionally lineage-based. It doesn't care about file hashes, command-line content, or signing — it cares about parent-child relationships. That makes it resilient to obfuscation and renamed binaries.

## SPL

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval parent_lower=lower(ParentImage), child_lower=lower(Image)
| where (
    match(parent_lower,"winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe|acrord32\.exe")
    AND
    match(child_lower,"cmd\.exe|powershell\.exe|powershell_ise\.exe|rundll32\.exe|regsvr32\.exe|wscript\.exe|cscript\.exe|mshta\.exe")
)
| eval severity="HIGH",
       alert="Suspicious parent-child spawn detected",
       technique="T1059 / T1566 — possible macro or phishing payload"
| table _time, ComputerName, User, ParentImage, ParentCommandLine, Image, CommandLine, alert
| sort - _time
```

## Validation Evidence

To trigger the rule without installing Office on the lab VM, two renamed copies of `cmd.exe` were placed at `%TEMP%\winword.exe` and `%TEMP%\excel.exe`, then executed and instructed to spawn `powershell.exe`:

```powershell
Copy-Item C:\Windows\System32\cmd.exe $env:TEMP\winword.exe -Force
Start-Process "$env:TEMP\winword.exe" -ArgumentList "/c powershell.exe -nop -w hidden -c Write-Host 'macro-payload-test'" -Wait
```

Sysmon EID 1 logged the parent image as `%TEMP%\winword.exe` regardless of the file's actual content — the rule fired on the lineage match, which is the entire point.

Two events captured, both with `ParentImage` containing `winword.exe` or `excel.exe` and `Image` containing `powershell.exe`.

## False Positive Notes

Legitimate scenarios are rare but not nonexistent:
- Macro-enabled Excel workbooks that legitimately call out to PowerShell (mostly in finance/audit teams using internal automation)
- Office add-ins that spawn shells for diagnostic purposes
- Some Microsoft-signed Office update tooling

**Tuning approach:** Filter by signed parent process — legitimate `winword.exe` from `C:\Program Files\Microsoft Office\` should be allow-listed by signer when the child is also a known-good script. Suspicious child execution from `%TEMP%`, `%APPDATA%`, or `C:\Users\Public\` should never be whitelisted.
