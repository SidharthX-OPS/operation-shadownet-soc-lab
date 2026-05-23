# Operation ShadowNet — Endpoint Detection Lab

![Splunk](https://img.shields.io/badge/SIEM-Splunk-black?style=flat-square&logo=splunk&logoColor=white)
![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon_15.20-0078D4?style=flat-square)
![MITRE](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red?style=flat-square)
![ART](https://img.shields.io/badge/Emulation-Atomic_Red_Team-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=flat-square)

---
<img width="2550" height="1423" alt="splunk-dashboard" src="https://github.com/user-attachments/assets/9995e557-bd8f-46a0-9bb0-8d6badf42a65" />

## What this is

A controlled adversary emulation against a Windows endpoint, with eight custom Splunk detection rules I wrote to catch it. The point wasn't to install Splunk and call it a lab. The point was to write detection logic against attacks I ran myself, validate every rule against the telemetry it claims to catch, and document the gaps honestly.

Three VMs. seven hours. Eight detections. One log-clearing finale.

---

## The setup

| Host | OS | Role | IP |
|---|---|---|---|
| NEXCORE-WIN | Windows 10 | Victim endpoint | 192.168.100.10 |
| NEXCORE-SOC | Ubuntu 22.04 | Splunk SIEM | 192.168.100.20 |
| KALI-ATTACK | Kali Linux | Attacker | 192.168.100.30 |

Telemetry stack: **Sysmon 15.20** with the SwiftOnSecurity config, **Splunk Universal Forwarder** shipping to a dedicated `wineventlog` index, and **Windows Filtering Platform** auditing enabled for inbound connection logging (EID 5156). The default Sysmon SwiftOnSecurity config excludes RFC1918 destinations from NetworkConnect, which would have killed port scan detection — WFP fills that gap.

---

## The attack chain

Seven MITRE techniques across the kill chain, simulated using Atomic Red Team plus two manual triggers for the parent-child anomaly rule.

| Phase | Technique | Tool |
|---|---|---|
| Recon | T1595.001 — Active Scanning | nmap (Kali) |
| Execution | T1059.001 — PowerShell | Atomic T1059.001 #9, T1027 |
| Discovery | T1082, T1057, T1135 | Atomic Red Team |
| Persistence | T1547.001 — Registry Run Key | Atomic T1547.001 #1 |
| Persistence | T1053.005 — Scheduled Task | Atomic T1053.005 #1 |
| Credential Access | T1003.001 — LSASS Memory | Atomic T1003.001 |
| Defense Evasion | T1070.004 — File Deletion | Atomic T1070.004 |
| Defense Evasion | T1564.001 — Hidden Files | Atomic T1564.001 |
| Defense Evasion | T1070.001 — Clear Event Logs | `wevtutil cl` |
| Initial Access (simulated) | T1566 — Office macro spawn | Manual fake `winword.exe` → `powershell.exe` |

---

## The detections

All eight live in `/detection-rules/` with full SPL, MITRE mapping, false positive notes, and validation evidence.

| Rule ID | Severity | Technique | What it catches |
|---|---|---|---|
| DET-001 | HIGH | T1059.001 | PowerShell `-enc`, `IEX`, `DownloadString`, `FromBase64String` |
| DET-002 | HIGH | T1547.001 | Sysmon EID 13 on `\CurrentVersion\Run\*` |
| DET-003 | CRITICAL | T1003.001 | Sysmon EID 10 — non-system access to `lsass.exe` with credential-read masks |
| DET-004 | HIGH | T1053.005 | Security EID 4698 — scheduled task creation |
| DET-005 | CRITICAL | T1070.001 | Security EID 1102 + System EID 104 — log clearing |
| DET-006 | MEDIUM | T1595 | WFP EID 5156 — inbound connection burst from a single source |
| DET-007 | HIGH | T1059 / T1566 | Office app spawning a shell or LOLBin |
| DET-008 | CRITICAL | Correlation | 3+ distinct techniques on the same host inside 60 min |

DET-008 is the rule that matters. Individual technique alerts are noise. A host that lights up five MITRE techniques in 60 minutes is an incident, not an alert — and the correlation rule names it as one.

---

## What actually fired

Run the full SPL in `/detection-rules/CORRELATION-MultiStage-Intrusion.md`. After Phase D, the correlation returned:

```
ComputerName    : NEXCORE-WIN
technique_count : 6
techniques_seen : T1003-CredAccess
                  T1053-SchedTask
                  T1059-Execution
                  T1547-Persistence
                  T1566-OfficeSpawn
                  T1070-DefenseEvasion
severity        : CRITICAL
alert           : MULTI-STAGE INTRUSION DETECTED
```

One row. Six techniques. One host. That's the whole point of the project.

---

## Honest gaps

I'm not going to pretend the lab caught everything.

- **T1003.001 partially blocked.** Defender's behavior monitoring killed the actual LSASS read mid-execution. Sysmon still logged the access attempt (EID 10, `GrantedAccess 0x1400`), but the distinguishing credential-read masks (`0x1010`, `0x1410`) weren't observed. Production deployment needs Credential Guard for definitive prevention.
- **No network IDS.** SMB lateral movement is detected via host-side Sysmon and WFP, not a packet sensor. Suricata/Zeek is out of scope for this lab — covered in [Operation SPECTRE](https://github.com/SidharthX-OPS/operation-spectre-network-threat-detection).
- **No email gateway.** T1566 phishing is simulated by faking `winword.exe` spawning `powershell.exe` — the parent-child rule catches it, but real macro detection at the gateway is absent.
- **SwiftOnSecurity NetworkConnect filter.** The config excludes RFC1918 — meaning Sysmon EID 3 doesn't fire for internal scans. Worked around by enabling WFP auditing for EID 5156. Documented in IR report.

The full coverage map is in `/detection-rules/mitre-coverage-map.md`.

---

## Repo structure

```
operation-shadownet-soc-lab/
├── README.md                              ← you are here
├── Incident-Report-IR-2026-001.md         ← the 12-section IR document
├── iocs/
│   └── ioc-list.csv
├── detection-rules/
│   ├── ALERT-HIGH-T1059-PowerShell-Encoded.md
│   ├── ALERT-HIGH-T1547-Registry-Persistence.md
│   ├── ALERT-CRITICAL-T1003-LSASS-Access.md
│   ├── ALERT-HIGH-T1053-Scheduled-Task.md
│   ├── ALERT-CRITICAL-T1070-Log-Cleared.md
│   ├── ALERT-MEDIUM-T1595-Port-Scan.md
│   ├── ALERT-HIGH-T1059-Parent-Child-Anomaly.md
│   ├── CORRELATION-MultiStage-Intrusion.md
│   ├── validation-matrix.md
│   ├── mitre-coverage-map.md
│   └── sigma/
│       └── DET-001-powershell-encoded.yml
├── attack-simulation/
│   ├── attack-scenario.md
│   └── atomic-tests-run.md
└── screenshots/
    ├── 01-splunk-dashboard.png
    ├── 02-alerts-list.png
    ├── 03-correlation-hero.png
    └── (detection-specific screenshots)
```

---

## What I built this with

- **Splunk Enterprise 10.2.3** (free trial)
- **Sysmon 15.20** with SwiftOnSecurity config v4.50
- **Atomic Red Team** v13.x
- **VirtualBox** Host-Only networking
- **nmap, smbclient, enum4linux-ng** on Kali
- A working understanding of `auditpol`, `btool`, and SPL — gained from breaking everything once and fixing it

---

## Companion project

The IR report's "Detection Gaps" section flagged the absence of network-layer detection. That gap is closed in [**Operation SPECTRE**](https://github.com/SidharthX-OPS/operation-spectre-network-threat-detection) — Suricata + Zeek + Splunk for network telemetry.

---

**Author:** Sidharth Chauhan · [GitHub](https://github.com/SidharthX-OPS) · [TryHackMe — Top 2% Global](https://tryhackme.com/p/SidharthX)
