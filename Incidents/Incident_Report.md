# INCIDENT ANALYSIS REPORT
## Multi-Stage Network Compromise: Reconnaissance, Brute Force, Persistence & Discovery

* **Incident ID:** SOC-LAB-001
* **Classification:** Training / Simulated Incident
* **Severity:** High
* **Status:** Closed
* **Environment:** Home SOC Lab (VirtualBox — Kali Linux, Windows Server 2022, OPNsense, Suricata, Wazuh, Sysmon)
* **Analyst:** Harisankar
* **Date:** October 21, 2026

---

## 1. Executive Summary

A simulated enterprise attack chain was investigated in a home SOC lab environment built with VirtualBox, Wazuh SIEM, Suricata IDS, and Sysmon. The attack began with network reconnaissance (Nmap) against the target endpoint, Windows Server 2022 (WIN-F97ON0862EU), followed by a brute-force attack against RDP using Hydra that resulted in successful compromise of the local administrator account. Using the compromised credentials, the attacker authenticated via RDP (Remmina) and, from an interactive PowerShell session, established persistence by creating a new local administrator account, enumerated local accounts, and dropped a file into the Downloads directory. The investigation reconstructed the full chain using Suricata, Wazuh, Sysmon, and Windows Security logs, identified indicators of compromise, mapped observed behavior to MITRE ATT&CK techniques, and documented detection coverage and gaps across the monitoring pipeline.

---

## 2. Incident Overview

| Field | Details |
|---|---|
| Incident ID | SOC-LAB-001 |
| Incident type | Network intrusion via credential brute force |
| Attack technique | Reconnaissance → Brute Force → Persistence → Discovery |
| Primary execution | Nmap, Hydra, PowerShell, Windows net commands |
| Affected endpoint | WIN-F97ON0862EU (192.168.1.9) |
| Attacker source | Kali Linux (192.168.1.5) |
| Severity | High — unauthorized admin account created |
| Status | Investigated and resolved (simulated) |
| Date | October 21, 2026 |
| Analyst | Hari |

---
```text
## 3. Attack Chain

Attacker (Kali, 192.168.1.5) scans target
↓
Nmap scan (-sS -sV) detected by Suricata (RDP scan + Nmap user-agent signatures)
↓
RDP brute-force attempt via Hydra (passwords.txt wordlist)
↓
Multiple logon failures → Wazuh correlated alert (Rule 60204, Level 10)
↓
Successful RDP logon with compromised administrator credentials (Event 4624)
↓
Attacker connects via Remmina (RDP client) and opens PowerShell
↓
Local user “hacker123” created and added to Administrators group (persistence)
↓
Discovery command (net user) executed to enumerate accounts
↓
File dropped in Downloads folder (Hacked.txt) → detected by Wazuh FIM

```
---

## 4. Initial Detection

**Alert 1 — Network Scan (RDP probe)**
- Rule description: ET SCAN RDP Connection Attempt from Nmap
- Rule ID: 86601
- Timestamp: Oct 21, 2026 @ 19:39:48.690
- Source: 192.168.1.5 → Destination: 192.168.1.9

**Alert 2 — Network Scan (HTTP user-agent)**
- Rule description: ET SCAN Possible Nmap User-Agent Observed
- Rule ID: 86601 (same ID as Alert 1 — see Section 11)
- Category: Web Application Attack
- Timestamp: Oct 21, 2026 @ 19:40:28.776

A single `nmap -sS -sV` scan generated two independent Suricata signatures roughly 40 seconds apart, confirming the scan touched multiple services (RDP and a web service) on the target.

---

## 5. Investigation

### 5.1 Initial Observations

| Attribute | Observation |
|---|---|
| Host | WIN-F97ON0862EU (192.168.1.9) |
| Attacker source | 192.168.1.5 (Kali Linux) |
| Compromised account | Administrator |
| Access method | RDP via Remmina, NTLM authentication |
| Execution | PowerShell / net1.exe, spawned from interactive RDP session |
| Attack type | External scan → credential brute force → post-exploitation |
| Initial vector | Exposed RDP service |

### 5.2 Timeline Reconstruction

| Time | Event |
|---|---|
| 19:39:48 | Nmap scan (`nmap -sS -sV`) detected — ET SCAN RDP Connection Attempt from Nmap |
| 19:40:28 | Second Suricata alert — ET SCAN Possible Nmap User-Agent Observed |
| 19:55:18 – 20:01:30 | Repeated RDP logon failures from Hydra brute force (6 attempts, Event 4625) *(see Section 11 — timestamp ordering note)* |
| 20:02:10 | Wazuh correlated alert: Multiple Windows Logon Failures (Rule 60204, Level 10) |
| 20:02:11 | Successful RDP logon with Administrator credentials (Event 4624, NTLM) |
| 20:24:15 | Attacker connects via Remmina; `net user hacker123 password@123 /add` and `net localgroup administrators hacker123 /add` executed |
| 20:24:15 | Sysmon flags discovery/execution activity (Rule 92033, 92039) |
| 20:25:38 | Administrators Group Changed confirmed (Event 4732, Rule 60154, Level 12) |
| 20:34:20 | `net user` executed — discovery activity (Sysmon Rule, Event ID 1) |
| 20:43:45 | File `hacked.txt` created in Downloads — Wazuh FIM alert (Rule 554, Level 5) |

### 5.3 Attack Technique Mapping

| Technique | Relevance |
|---|---|
| Network Scanning | Attacker enumerated open services (RDP, HTTP) before attempting access |
| Brute Force | Repeated credential guessing against RDP led to successful compromise |
| Valid Accounts | Compromised Administrator credentials used for all subsequent activity |
| Persistence via Local Account | New administrator-level account ("hacker123") created to maintain access |
| Discovery | Local accounts enumerated post-compromise via `net user` |
| Data Manipulation | File dropped in Downloads, detected by FIM |

### 5.4 Investigation Conclusion

The investigation determined that the simulated incident followed a complete attack lifecycle: external reconnaissance, credential compromise via brute force, interactive post-compromise access via RDP, persistence through an unauthorized administrator account, discovery activity, and a file-system modification. Evidence from Suricata, Wazuh, Sysmon, and Windows Security logs was sufficient to reconstruct the full chain and tie each stage back to the same attacker source (192.168.1.5) and compromised account (Administrator).

---

## 6. Indicators of Compromise (IOC)

**6.1 Network Indicators**
- 192.168.1.5 — Attacker source IP (Kali Linux)
- 192.168.1.9 — Target endpoint (WIN-F97ON0862EU)

**6.2 Host & Account Indicators**
- Compromised account: `Administrator` (NTLM authentication over RDP)
- Unauthorized account created: `hacker123`
- File dropped: `C:\Users\Administrator\Downloads\hacked.txt`

**6.3 Behavioral & Execution Chain Indicators**
- 6 consecutive RDP logon failures from a single source, followed by a success
- `net1 user hacker123 password@123 /add` — account creation command
- `net localgroup administrators hacker123 /add` — privilege escalation command
- `net1 users` — discovery command
- `Out-File` write to Downloads folder, captured in real time by FIM

---

## 7. MITRE ATT&CK Mapping

**T1595.002 / T1046 — Active Scanning / Network Service Discovery**
The attacker used `nmap -sS -sV` to probe the target for open services and versions prior to the brute-force attempt, triggering two distinct Suricata signatures.

**T1110.001 — Brute Force: Password Guessing**
A Hydra-driven dictionary attack against RDP produced six failed logon attempts, correlated by Wazuh into a Level 10 alert (Rule 60204) before a successful logon was observed.

**T1078 — Valid Accounts**
Following the brute-force attempt, the attacker authenticated successfully via NTLM over RDP using the Administrator account, which Wazuh additionally flagged as a possible pass-the-hash pattern.

**T1136.001 — Create Account: Local Account**
A new local account, `hacker123`, was created and added to the Administrators group to establish persistence independent of the original compromised credentials.

**T1098 — Account Manipulation**
The addition of `hacker123` to the local Administrators group was independently confirmed via Event 4732 and Wazuh Rule 60154 (Level 12).

**T1087.001 — Account Discovery: Local Account**
The attacker executed `net user` to enumerate local accounts on the compromised host.

**T1565.001 — Stored Data Manipulation**
A text file (`hacked.txt`) was written to the Downloads folder, detected in real time by Wazuh's File Integrity Monitoring.

---

## 8. Impact Assessment

The attacker gained full administrative access to the target endpoint via brute-forced credentials and established an independent, persistent administrator-level account (`hacker123`). This would allow continued access even if the original compromised account's password were changed. Discovery activity and the file drop indicate the attacker was actively operating within the environment post-compromise, consistent with staging for further actions such as lateral movement, data exfiltration, or additional privilege abuse.

---

## 9. Incident Response

**9.1 Recommended Response Actions (Simulated)**

As this was a controlled lab exercise, no live response was required; however, in a production environment the following actions would be taken based on the evidence collected:

- Disable the compromised Administrator account and force a password reset
- Disable and remove the unauthorized `hacker123` local account
- Review the local Administrators group for any other unauthorized additions
- Isolate WIN-F97ON0862EU from the network pending full review
- Review RDP access logs for any additional source IPs beyond the identified attacker (192.168.1.5)
- Investigate and remove the dropped file (`hacked.txt`) and audit for further persistence mechanisms (scheduled tasks, services, startup entries)
- Preserve Sysmon, Windows Security, and FIM logs for the affected time window as evidence

**9.2 Recommended Prevention Measures**

- Enforce an account lockout policy after a low threshold of failed logon attempts
- Restrict RDP access to a jump host or VPN rather than direct exposure
- Enable PowerShell Script Block Logging and Module Logging for full command visibility
- Alert on creation of new local accounts and additions to the Administrators group
- Synchronize time sources (NTP) across all systems for reliable log correlation

---

## 10. Lessons Learned

- OPNsense firewall logs could not be correlated with endpoint/IDS logs due to a timezone mismatch between systems, reinforcing the need for consistent NTP synchronization across all layers
- Traffic between Kali and the Windows Server stayed within the same subnet, so it never passed through the OPNsense firewall, limiting that source's visibility into this attack
- Wazuh's brute-force correlation rule (60204) triggered reliably with only 6 failed attempts, confirming the detection logic works well even at low attempt counts
- A roughly 9-minute gap existed between the discovery command and the file drop, both attributed to the same session but logged independently, showing that Wazuh detects individual actions well but does not automatically chain them into a single attacker session — that correlation remains a manual analyst task
- Sysmon's "account discovery" classification for `net.exe`/`net1.exe` activity did not distinguish between enumeration and account creation/modification, both were tagged similarly despite different intent and risk

---

## 11. Known Data Quality Observations

- **Duplicate rule ID:** Both Suricata scan alerts in Section 4 shared rule.id 86601 despite differing descriptions and alert categories (Network Scan vs. Web Application Attack). This points to a rule-ID mapping inconsistency in this Suricata ruleset version. In production, relying on rule.id alone for filtering or deduplication would conflate unrelated detections; description, category, and SID should be checked together.
- **Timestamp ordering (brute force):** The first logged 4625 (logon failure) events appear timestamped earlier (19:55:18) than the recorded Hydra launch time (20:01:30). This is most likely a clock or logging artifact rather than an actual pre-attack failure burst, and is noted here for transparency; the correlated Wazuh alert (20:02:10) and successful logon (20:02:11) remain the reliable anchor points for this scenario.
