# 04 - Post-Compromise Discovery & File Drop

**Commands executed:**
* **Discovery Command:**
`net users`
* **File Drop:**
“You Are Hacked!” | Out-File -FilePath “C:\Users\Administrator\Downloads\Hacked.txt”


**Timestamp of attack:** Oct 21, 2026 @ 20:34:20 (discovery), 20:43:45 (file drop)

---

**Alert 1 — Discovery Activity (net user)**
| Field | Value |
|---|---|
| Time | Oct 21, 2026 @ 20:34:20.257 |
| rule.groups | sysmon, sysmon_eid1_detections, windows |
| rule.description | Discovery activity executed |
| data.win.system.eventID | 1 |
| data.win.eventdata.commandLine | `C:\Windows\system32\net1 users` |
| agent.name | WIN-F97ON0862EU (192.168.1.9) |
| data.win.eventdata.image | C:\Windows\System32\net1.exe |
| data.win.eventdata.integrityLevel | High |

A related alert, **"Discovery activity spawned via powershell execution"**, fired one second earlier (20:34:20.247), confirming `net.exe` was spawned from an active PowerShell session rather than run directly.

---

**Alert 2 — File Integrity Monitoring (File Drop)**
| Field | Value |
|---|---|
| Time | Oct 21, 2026 @ 20:43:45.178 |
| rule.groups | ossec, syscheck, syscheck_entry_added, syscheck file |
| rule.description | File added to the system |
| rule.level | 5 |
| rule.id | 554 |
| syscheck.path | c:\users\administrator\downloads\hacked.txt |
| syscheck.event | added |
| full_log | File 'c:\users\administrator\downloads\hacked.txt' added. Mode: realtime |

**Key log fields:**
- Host: WIN-F97ON0862EU (192.168.1.9)
- Process: net1.exe, spawned via PowerShell
- File created: `hacked.txt` in Administrator's Downloads folder
- Detection mechanism: Wazuh FIM (`syscheck`), real-time mode

**Triage verdict:**
True positive for both actions. The `net user` command confirms the attacker enumerated local accounts after establishing persistence, consistent with the earlier discovery activity in the previous scenario. The file drop into Downloads was correctly caught by Wazuh's File Integrity Monitoring in real-time mode, confirming FIM is actively watching that directory. Rule level 5 is appropriately moderate, a single file add isn't inherently malicious, but combined with the prior brute force and persistence activity, this strongly indicates attacker-controlled file placement.

**MITRE ATT&CK mapping:**
- T1087.001 — Account Discovery: Local Account (`net user`)
- T1565.001 — Data Manipulation: Stored Data Manipulation, or alternatively T1491.001 (Defacement: Internal Defacement) if framed as attacker-left evidence/calling-card behavior
