
# 01 - Active Network Reconnaissance (Nmap Scan)

**Command executed:**
`nmap -sS -sV 192.168.1.9`

**Timestamp of attack:** Oct 21, 2026 @ 19:39

**Alert fired:**
| Field | Value |
|---|---|
| Time | Oct 21, 2026 @ 19:39:48.690 |
| rule.groups | ids, suricata |
| rule.description | ET SCAN RDP Connection Attempt from Nmap |
| rule.id | 86601 |
| data.alert.category | Detection of a Network Scan |
| data.src_ip | 192.168.1.5 |

**Key log fields:**
- Source IP: 192.168.1.5 (Kali attacker)
- Destination IP: 192.168.1.9 (Windows Server target)
- Destination service: RDP (3389)
- 
**Alert fired:**
| Field | Value |
|---|---|
| Time | Oct 21, 2026 @ 19:40:28.776 |
| rule.groups | ids, suricata |
| rule.description | ET SCAN Possible Nmap User-Agent Observed |
| rule.id | 86601 |
| data.alert.category | Web Application Attack |

**Triage verdict:**
True positive. Checked firewall (OPNsense) logs and confirmed this was expected lab traffic from the known attacker host, not an external threat. In a production environment, this would be classified as reconnaissance against an exposed RDP service and investigated as a precursor to a brute-force or exploitation attempt.

**MITRE ATT&CK mapping:**
- T1595.002 — Active Scanning: Vulnerability Scanning (service-version detection via `-sV`)
- T1046 — Network Service Discovery (RDP service identified as open and reachable)

