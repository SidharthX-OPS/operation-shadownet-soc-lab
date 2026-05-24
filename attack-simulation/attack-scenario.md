# Attack Scenario — Operation ShadowNet

## The setup

You are a SOC analyst at **NexCore Systems**, a mid-sized financial services company. Threat intelligence reports a financially motivated actor group targeting your sector with a known TTP profile: spearphishing for initial access, PowerShell-based loaders for execution, registry and scheduled task persistence, LSASS credential dumping for credential access, and event log clearing to cover tracks before exfiltration.

Management asks one question: *"If they hit us tomorrow, would we see it?"*

This lab is the answer.

## The exercise

A controlled adversary emulation against a Windows 10 endpoint (NEXCORE-WIN), simulating the full kill chain end to end. The goal is not to prove that the attacks work — Atomic Red Team handles that. The goal is to prove that the detection pipeline catches them, at every stage, with confidence high enough to escalate to an incident.

## The actor profile

The simulated adversary follows a documented FIN/financial-crime TTP pattern:

| Stage | Approach | Why |
|---|---|---|
| Recon | External port scan to map exposed services | Identify entry vectors |
| Initial Access | Spearphishing email with macro-enabled document | Bypass perimeter |
| Execution | PowerShell loader, often obfuscated/encoded | Defender evasion |
| Persistence | Registry Run key + scheduled task | Survive reboot, redundancy |
| Credential Access | LSASS memory dump | Lateral movement preparation |
| Defense Evasion | Clear event logs before exit | Anti-forensics |

## The mapping to this lab

| Real-world step | Lab implementation |
|---|---|
| Spearphishing email | Out of scope (no email gateway) |
| Macro-enabled document | Simulated via renamed `%TEMP%\winword.exe` spawning `powershell.exe` |
| Encoded PowerShell loader | `Invoke-AtomicTest T1027` and `T1059.001 -TestNumbers 9` |
| Registry Run key persistence | `Invoke-AtomicTest T1547.001 -TestNumbers 1` |
| Scheduled task persistence | `Invoke-AtomicTest T1053.005 -TestNumbers 1` |
| LSASS dump | `Invoke-AtomicTest T1003.001` (partially blocked by Defender — telemetry retained) |
| File deletion / hidden files | `Invoke-AtomicTest T1070.004`, `T1564.001` |
| Log clearing | `wevtutil cl Security`, `wevtutil cl System`, `wevtutil cl Application` |

## The expected outcome

Every stage of the attack must generate telemetry that the Splunk SIEM ingests. Every detection rule must fire against the technique it claims to detect. The multi-technique correlation rule must consolidate the individual alerts into a single CRITICAL incident.

If any of these fail, the lab fails — and the answer to management's question becomes *"not yet."*

## The actual outcome

All seven detection rules fired. The correlation rule produced a single row identifying NEXCORE-WIN as compromised with six distinct ATT&CK techniques observed in a 54-minute window.

The answer to management's question is *"yes, with these gaps documented in §12 of the IR report."*
