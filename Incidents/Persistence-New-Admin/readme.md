# 03 - Persistence via Unauthorized Local Administrator

**Commands executed:**
# **New Account Add:**
`net user hacker123 password@123 /add`

**Adding to administrators group:**
`net localgroup administrators hacker123 /add`

**Timestamp of attack:** Oct 21, 2026 @ 20:24:15

**Alert 1 — Discovery/Execution Detected by Sysmon**
| Field | Value |
|---|---|
| Time | Oct 21, 2026 @ 20:24:15.385 |
| rule.groups | sysmon, sysmon_eid1_detections, windows |
| rule.description | Discovery activity spawned via powershell execution |
| rule.id | 92033 |
| data.win.system.eventID | 1 |
| rule.level | 3 |

**Alert 2 — Account Discovery Command Flagged**
| Field | Value |
|---|---|
| Time | Oct 21, 2026 @ 20:24:15.424 |
| rule.groups | sysmon, sysmon_eid1_detections, windows |
| rule.description | A net.exe account discovery command was initiated |
| rule.id | 92039 |
| data.win.system.eventID | 1 |
| rule.level | 3 |
| data.win.eventdata.commandLine | `C:\Windows\system32\net1 user hacker123 password@123 /add` |
| agent.name | WIN-F97ON0862EU (192.168.1.9) |

**Alert 3 — Administrators Group Changed**
| Field | Value |
|---|---|
| Time | Oct 21, 2026 @ 20:25:38.082 |
| rule.groups | windows, windows_security, group_changed, win_group_changed |
| rule.description | Administrators Group Changed |
| data.win.system.eventID | 4732 |
| rule.id | 60154 |
| rule.level | 12 |
| data.win.system.message | "A member was added to a security-enabled local group." |

**Supporting events observed (from timeline):**
- Event 4720 (20:24:15.505) — User account enabled or created
- Event 4722 (20:24:15.544) — User account enabled or created
- Event 4738 (20:24:15.544) — User account changed
- Event 4728 (20:24:15.504) — Domain Users Group Changed

**Key log fields:**
- Host: WIN-F97ON0862EU (192.168.1.9)
- New account: hacker123
- Executing process: `net1.exe` (spawned by `net.exe`), invoked via PowerShell
- Command line captured: `net1 user hacker123 password@123 /add`

**Triage verdict:**
True positive. Manually checked the local Administrators group on the server and confirmed the `hacker123` account had been added, consistent with the Wazuh alert. This represents successful establishment of persistence by the attacker, an independent administrator-level account separate from the originally compromised credentials. Rule 60154 (Level 12) correctly classified the group modification as a high-severity event, appropriately higher than the account-creation events alone (Level 3), since adding a user to Administrators carries greater risk than account creation by itself.

**MITRE ATT&CK mapping:**
- T1136.001 — Create Account: Local Account
- T1098 — Account Manipulation (escalation into Administrators group)


