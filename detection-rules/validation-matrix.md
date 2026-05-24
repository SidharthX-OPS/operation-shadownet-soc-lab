# Detection Rule Validation Matrix

Every rule in this lab was validated against the attack it claims to detect. This is the test result table — what fired, what didn't, and why.

| Rule ID | Technique | Test Executed | Fired? | True / False Positive | Notes |
|---|---|---|---|---|---|
| DET-001 | T1059.001 | `Invoke-AtomicTest T1027` + `T1059.001 -TestNumbers 9` | PASS | True Positive | Multiple Sysmon EID 1 events with `-EncodedCommand`, `IEX`, and `DownloadString` artifacts |
| DET-002 | T1547.001 | `Invoke-AtomicTest T1547.001 -TestNumbers 1` | PASS | True Positive | Sysmon EID 13 captured `HKU\...\Run\Atomic Red Team` → `C:\Path\AtomicRedTeam.exe` written by `reg.exe` |
| DET-003 | T1003.001 | `Invoke-AtomicTest T1003.001` | PARTIAL | True Positive (access attempt) | Defender blocked the actual LSASS read. Sysmon EID 10 logged the access attempt with `GrantedAccess 0x1400`. Credential-read masks (`0x1010`, `0x1410`) not observed — documented as a detection gap |
| DET-004 | T1053.005 | `Invoke-AtomicTest T1053.005 -TestNumbers 1` | PASS | True Positive | Security EID 4698 with full task XML — `T1053_005_OnStartup` running `cmd.exe /c calc.exe` on BootTrigger |
| DET-005 | T1070.001 | `wevtutil cl Security`, `wevtutil cl System`, `wevtutil cl Application` | PASS | True Positive | EID 1102 (Security) + 2× EID 104 (System, Application). All forwarded to Splunk before local clear took effect |
| DET-006 | T1595 | `nmap -Pn -n -T4 -p 135,139,445,3389,80,443 192.168.100.10` from Kali | PASS | True Positive | WFP EID 5156 captured each port probe. Required `auditpol` configuration to enable Filtering Platform Connection auditing |
| DET-007 | T1059 / T1566 | Manual: `%TEMP%\winword.exe` (renamed cmd.exe) → `powershell.exe` | PASS | True Positive | Sysmon EID 1 captured the parent-child lineage. Two distinct events (winword.exe and excel.exe spawn) |
| DET-008 | Correlation | All of the above on a single host | PASS | True Positive | Final result: NEXCORE-WIN with 6 distinct techniques observed within a 60-minute window |

## Validation methodology

For each rule:

1. The corresponding atomic test (or manual trigger) was executed on NEXCORE-WIN with timestamp logged to `attack-simulation/atomic-tests-run.md`.
2. The SPL was run in Splunk within 5 minutes of execution to confirm event capture.
3. The expected fields (User, ComputerName, ParentImage, CommandLine, etc.) were verified to be present and correctly extracted.
4. False positive surface was assessed by reviewing other events that matched the same SPL — for DET-003, this required tuning the rule to filter out 491 benign hits before the credential-access signal was distinguishable.
5. The rule was saved as a Splunk Alert with the naming convention `ALERT-[SEVERITY]-[TECHNIQUE]-[DESC]`.

## Limitations

- All validation was performed in a single lab pass on 23 May 2026. Long-term false positive rates were not measured.
- DET-003 cannot be definitively validated as "catches credential dumping" — only as "catches access attempts." A real dump would have generated additional masks; Defender prevented this in the lab. Production deployment with Credential Guard and without Defender RTP disabled would behave differently.
- DET-006 thresholds (`unique_ports >= 5`) are appropriate for a quiet lab. They require baseline-driven tuning in production.
