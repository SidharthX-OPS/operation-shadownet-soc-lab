# Atomic Tests Executed — Operation ShadowNet

Reference timeline of every attack action run during the lab exercise on 23 May 2026, between 12:30 and 14:30 IST.

## Execution environment

- **Target host:** NEXCORE-WIN (192.168.100.10), Windows 10
- **User account:** `NEXCORE-WIN\WIN` (local administrator)
- **Attacker host:** Kali Linux (192.168.100.30)
- **Defender Real-Time Protection:** Disabled for the exercise
- **Atomic Red Team module:** `Invoke-AtomicRedTeam` (PowerShell)

## Timeline

| T+ | Time (IST) | Phase | Technique | Command | Host |
|---|---|---|---|---|---|
| T+0:00 | 12:30:00 | Recon | T1595 | `nmap -Pn -n -T4 -p 135,139,445,3389,80,443 192.168.100.10` | Kali |
| T+0:01 | 12:31:30 | Recon | T1595 | `smbclient -L //192.168.100.10 -N` | Kali |
| T+0:05 | 12:35:00 | Execution | T1027 | `Invoke-AtomicTest T1027` | NEXCORE-WIN |
| T+0:07 | 12:37:00 | Execution | T1059.001 | `Invoke-AtomicTest T1059.001 -TestNumbers 9` | NEXCORE-WIN |
| T+0:10 | 12:40:00 | Discovery | T1082 | `Invoke-AtomicTest T1082` | NEXCORE-WIN |
| T+0:12 | 12:42:00 | Discovery | T1057 | `Invoke-AtomicTest T1057` | NEXCORE-WIN |
| T+0:14 | 12:44:00 | Discovery | T1135 | `Invoke-AtomicTest T1135` | NEXCORE-WIN |
| T+0:30 | 13:00:00 | Persistence | T1547.001 | `Invoke-AtomicTest T1547.001 -TestNumbers 1` | NEXCORE-WIN |
| T+0:46 | 13:16:47 | Persistence | T1053.005 | `Invoke-AtomicTest T1053.005 -TestNumbers 1` | NEXCORE-WIN |
| T+0:55 | 13:25:00 | Credential Access | T1003.001 | `Invoke-AtomicTest T1003.001` | NEXCORE-WIN |
| T+1:10 | 13:40:00 | Defense Evasion | T1070.004 | `Invoke-AtomicTest T1070.004` | NEXCORE-WIN |
| T+1:12 | 13:42:00 | Defense Evasion | T1564.001 | `Invoke-AtomicTest T1564.001` | NEXCORE-WIN |
| T+1:30 | 14:00:00 | Initial Access (sim) | T1566 | `Copy-Item cmd.exe %TEMP%\winword.exe; Start-Process winword.exe -ArgumentList "/c powershell.exe ..."` | NEXCORE-WIN |
| T+1:32 | 14:02:00 | Initial Access (sim) | T1566 | `Copy-Item cmd.exe %TEMP%\excel.exe; Start-Process excel.exe -ArgumentList "/c powershell.exe ..."` | NEXCORE-WIN |
| T+2:00 | 14:30:00 | Defense Evasion | T1070.001 | `wevtutil cl Security; wevtutil cl System; wevtutil cl Application` | NEXCORE-WIN |
| T+2:05 | 14:35:00 | Cleanup | — | `Invoke-AtomicTest T1547.001 -Cleanup`, `T1053.005 -Cleanup`, etc. | NEXCORE-WIN |

## Notes on individual tests

### T1003.001 — Partially blocked
Defender's behavior monitoring intercepted the LSASS memory read mid-execution. Sysmon EID 10 still logged the access attempt with `GrantedAccess 0x1400` (PROCESS_QUERY_INFORMATION only — no read mask). This is real-world realistic and documented as a detection gap in the IR report.

### T1566 simulation rationale
Microsoft Office was not installed on the lab VM. To trigger DET-007 (parent-child anomaly rule), `cmd.exe` was copied to `%TEMP%\winword.exe` and `%TEMP%\excel.exe`, then executed and instructed to spawn `powershell.exe`. Sysmon logs the image name as written on disk — the rule fires on the parent-child lineage match regardless of the file's actual content. This is the correct way to validate a lineage-based detection rule.

### T1070.001 sequencing
Log clearing was intentionally executed last, after all other detections had been validated and screenshotted. The Security log clear via `wevtutil cl Security` generates EID 1102, which is itself logged by the clearing operation — meaning the detection of clearing survives the clearing.

If T1070.001 had been run earlier in the chain, it would have erased the local copies of events for DET-001 through DET-004. Off-host log forwarding to Splunk via Universal Forwarder is what makes early clearing survivable; nonetheless, sequencing the clear as the final action preserved both local and forwarded evidence.

## Cleanup verification

After cleanup commands completed:

- Registry Run key at `HKU\...\Run\Atomic Red Team` — removed
- Scheduled task `T1053_005_OnStartup` — removed
- `%TEMP%\winword.exe` and `%TEMP%\excel.exe` — manually deleted
- Defender Real-Time Protection — re-enabled

The lab returned to a clean baseline state. The Splunk indexes retain all generated telemetry for IR report evidence.
