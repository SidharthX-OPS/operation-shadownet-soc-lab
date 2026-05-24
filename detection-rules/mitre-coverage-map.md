# MITRE ATT&CK Coverage Map

Honest assessment of what this lab detects, what it doesn't, and why. Mature detection engineering means knowing the gaps as well as the wins.

## Coverage Summary

**Current coverage: 8 of 14 ATT&CK tactics, 10 named techniques, 8 production-ready detection rules with validation.**

| Tactic | Coverage | Techniques Detected | Gaps |
|---|---|---|---|
| Reconnaissance | Full | T1595.001 — Active Scanning | None at this layer |
| Resource Development | None | — | Out of scope — attacker-side, not visible to defender telemetry |
| Initial Access | Partial | T1566 (via parent-child lineage rule) | No email gateway integration; phishing visibility requires upstream control |
| Execution | Full | T1059.001 — PowerShell, T1027 — Obfuscation (overlap) | Limited LOLBin coverage (certutil, mshta, regsvr32 not yet covered by dedicated rules) |
| Persistence | Full | T1547.001 — Registry Run Keys, T1053.005 — Scheduled Tasks | Service-based persistence (T1543) not covered |
| Privilege Escalation | None | — | Not tested in this lab; requires UAC bypass / token impersonation scenarios |
| Defense Evasion | Full | T1070.001 — Clear Event Logs | T1070.004 (file deletion) and T1564.001 (hidden files) logged but no dedicated rule |
| Credential Access | Partial | T1003.001 — LSASS Memory (attempt logged) | Defender blocked the actual read; credential-read mask validation incomplete |
| Discovery | Logged | T1082, T1057, T1135 telemetry captured | No dedicated detection rules — appears in Sysmon EID 1 but not surfaced as alerts |
| Lateral Movement | Partial | T1021.002 — SMB connection indicators | No PsExec, WMI, or scheduled-task-remote detection |
| Collection | None | — | Out of scope for v1 |
| Command and Control | None | — | No network IDS in this lab — covered in [Operation SPECTRE](https://github.com/SidharthX-OPS/operation-spectre-network-threat-detection) |
| Exfiltration | None | — | No DLP, no network egress monitoring |
| Impact | None | — | Out of scope; requires ransomware/wiper telemetry |

## Detailed Gap Assessment

### Gap 1 — No phishing detection at the email layer

T1566 (Phishing) is the most common initial access vector for real-world intrusions, and this lab has zero visibility into it. The parent-child anomaly rule (DET-007) catches the *aftermath* — a malicious macro spawning a shell — but by that point, the attacker is already executing code on the endpoint.

**Mitigation:** Integration with Microsoft Defender for Office 365, Proofpoint, or Mimecast logs. Detection of attachment hashes against threat intel feeds. URL detonation logs from email gateways. None of these exist in this lab.

### Gap 2 — Living-off-the-Land binary coverage is incomplete

The detection ruleset covers PowerShell heavily (DET-001) but does not have dedicated rules for other common LOLBins:

- `certutil.exe` — used for download/decode operations
- `mshta.exe` — HTA payload execution
- `regsvr32.exe` — SCT/COM-based execution (Squiblydoo)
- `bitsadmin.exe` — download abuse
- `rundll32.exe` — arbitrary DLL execution

Several of these are caught by DET-007 if spawned from Office, but a sophisticated attacker not relying on macros would evade.

**Mitigation:** Per-binary detection rules using Sysmon EID 1 with command-line heuristics specific to each LOLBin's abuse patterns.

### Gap 3 — No network-layer detection

This lab is endpoint-only. SMB lateral movement is detected via Sysmon (host-side) and WFP (inbound connection auditing) — but east-west traffic, internal scanning, C2 beaconing, and DNS exfiltration are entirely invisible.

**Mitigation:** Suricata for signature-based network detection. Zeek for behavioral analysis (conn.log, dns.log, ssl.log). Both implemented in the companion project, [**Operation SPECTRE**](https://github.com/SidharthX-OPS/operation-spectre-network-threat-detection), which exists specifically because this gap was identified in this lab's IR report.

### Gap 4 — No EDR / behavioral analysis layer

This lab uses Sysmon + Splunk, which provides telemetry and detection but not active prevention or runtime behavioral analysis. A commercial EDR (CrowdStrike, SentinelOne, Defender for Endpoint) would provide additional signal — process tree visualization, in-memory detection, and automatic containment — that Sysmon alone cannot.

**Acknowledgement:** This is a structural limitation, not a tunable gap. Production deployments combine SIEM (this) with EDR (separate). The lab demonstrates the SIEM half of that stack.

### Gap 5 — Alert noise not measured

False positive rates were not formally measured across long timeframes. DET-003 was tuned during the lab pass (491 benign hits filtered down to a credential-access signal). The other rules were validated to fire correctly but their long-term FP rate is unknown.

**Mitigation:** Production deployment requires baseline measurement — at minimum, 7 days of unsuppressed alert volume per rule before tuning, then iterative threshold adjustment.

## Why this matters

Recruiters and interviewers see coverage maps in two ways:

1. **Bragging about what you have** — common, weak, transparent
2. **Owning what you don't have** — uncommon, strong, defensible

This map is the second kind. The follow-up question is "what would you build next?" — and the answer is in the SPECTRE project, which closes Gap 3 directly.
