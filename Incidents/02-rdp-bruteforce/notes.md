
# 02 - RDP Brute Force & Account Compromise

**Command executed:**
`hydra -l administrator -P passwords.txt rdp://192.168.1.9`
(passwords.txt: custom wordlist created for this lab)

**Timestamp of attack:** Oct 21, 2026 @ 19:58:30

**Alert 1 — Repeated Logon Failures**
| Field | Value |
|---|---|
| Time | Oct 21, 2026 @ 20:02:55.117 |
| rule.groups | windows, windows_security, authentication_failed |
| rule.description | Logon Failure - Unknown user or bad password |
| data.win.system.eventID | 4625 |
| data.src_ip | 192.168.1.5 |
| Count | 6 failed attempts from same source |

**Alert 2 — Correlated Brute Force Detection**
| Field | Value |
|---|---|
| Time | Oct 21, 2026 @ 20:02:10.107 |
| Agent | WIN-F97ON0862EU |
| rule.description | Multiple Windows Logon Failures |
| rule.id | 60204 |
| rule.level | 10 |

**Alert 3 — Successful Logon (Compromise Confirmed)**
| Field | Value |
|---|---|
| Time | Oct 21, 2026 @ 20:02:11.551 |
| rule.groups | win_evt_channel, windows, authentication_success |
| rule.description | Successful Remote Logon Detected - User: Administrator - NTLM authentication, possible pass-the-hash attack - Possible RDP connection |
| data.win.system.eventID | 4624 |
| User | Administrator |

**Key log fields:**
- Source IP: 192.168.1.5 (Kali attacker)
- Destination: 192.168.1.9 (Windows Server target)
- Target account: Administrator
- Authentication type: NTLM

**Triage verdict:**
True positive. Six consecutive logon failures against the Administrator account from a single internal source, correlated by Wazuh into a Level 10 alert, followed within seconds by a successful logon from the same source using the same account. This confirms credential compromise via brute force. In production, this account would be immediately locked, the password reset, and the source IP blocked pending investigation.

**MITRE ATT&CK mapping:**
- T1110.001 — Brute Force: Password Guessing
- T1078 — Valid Accounts (post-compromise use of legitimate credentials)

**Detection gap / observation:**
Wazuh's built-in rule correctly flagged the successful logon itself as a *"possible pass-the-hash attack"* due to the use of NTLM authentication over RDP. This is a default rule behavior worth noting: the alert correctly surfaces risky authentication methods even when the logon is legitimate-looking, but analysts should verify context (source IP, prior failed attempts) before escalating, since NTLM-over-RDP can also occur in benign configurations. The ~6-attempt threshold was sufficient to trigger Wazuh's correlation rule in this lab, which is lower than many real-world brute-force detection thresholds (often 8-10+), suggesting this ruleset is tuned conservatively for faster detection.
