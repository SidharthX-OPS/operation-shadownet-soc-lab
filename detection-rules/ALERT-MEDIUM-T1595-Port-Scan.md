# ALERT-MEDIUM-T1595-Port-Scan

| Field | Value |
|---|---|
| Rule ID | DET-006 |
| Severity | MEDIUM (HIGH if ≥50 ports) |
| MITRE Technique | [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/) |
| Data Source | Windows Security EID 5156 (Filtering Platform Connection — permitted) |
| Index | wineventlog |
| Validation Status | PASS |

---

## Description

Detects inbound connection bursts from a single source IP within a 5-minute window. Port scans typically generate many short-duration connections to many ports — distinguishable from normal application traffic, which connects to a small set of expected ports repeatedly.

**Important architectural note:** This rule uses Windows Filtering Platform audit events (EID 5156), not Sysmon EID 3. The SwiftOnSecurity Sysmon config excludes all RFC1918 destinations from NetworkConnect logging, which means Sysmon alone is blind to internal port scans. WFP auditing closes this gap but must be explicitly enabled via `auditpol`:

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

## SPL

```spl
index=wineventlog EventCode=5156 earliest=-2h
Direction="*Inbound*"
NOT Source_Address IN ("127.0.0.1", "::1", "192.168.100.10")
NOT Source_Address="-"
| bucket _time span=5m
| stats dc(Destination_Port) as unique_ports,
        values(Destination_Port) as ports_hit,
        count as total_conns by _time, Source_Address
| where unique_ports >= 5
| eval severity=case(
    unique_ports >= 50, "HIGH",
    unique_ports >= 20, "MEDIUM",
    true(), "LOW"
)
| eval alert="Port Scan Detected"
| sort - unique_ports
```

## Validation Evidence

Triggered against `nmap -Pn -n -T4 -p 135,139,445,3389,80,443 192.168.100.10` from Kali (192.168.100.30). EID 5156 events were captured for each port probe and bucketed into a single 5-minute alert with the attacker IP as `Source_Address`.

The threshold (`unique_ports >= 5`) is intentionally low for the lab. Production deployment should tune based on baseline noise — busy hosts may legitimately see 5–10 unique inbound ports from infrastructure services.

## False Positive Notes

Legitimate scenarios:
- Vulnerability scanners (Nessus, Greenbone, Qualys, Rapid7 Insight)
- Monitoring tools doing health checks across multiple services
- Internal NMAP runs by IT/security teams

**Tuning approach:** Maintain an explicit allowlist of `Source_Address` values for authorized scanners. Bucket window can be tightened (1 minute) for faster scans or widened (15 minutes) for slow stealth scans. Pair with EID 5157 (blocked connections) for a richer picture — a scanner hitting blocked ports is more suspicious than one hitting open services.
