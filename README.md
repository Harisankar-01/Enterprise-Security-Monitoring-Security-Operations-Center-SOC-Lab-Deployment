# Security Operations Centre(SOC) Lab Deployment
A multi-layered virtual SOC sandbox (Wazuh, Sysmon, Suricata, OPNsense) deployed on Kali Linux and Windows Server 2022 to engineer log pipelines and map live threat detections to the MITRE ATT&amp;CK framework.

# SOC-Lab-Pipeline-Engineering

A multi-layered Virtual Security Operations Center (vSOC) sandbox environment engineered to aggregate, decode, and analyze multi-vector threat activity in real time. This project demonstrates end-to-end log pipeline engineering, passive network monitoring, security architecture validation, and custom detection engineering mapped to the **MITRE ATT&CK Framework**.

---

## Architecture Blueprint & Data Flow

The infrastructure is built inside an isolated **VirtualBox NAT Network** (`SOC_Lab`) to guarantee safe execution and containment of simulated threats. A single, resource-efficient **Kali Linux** node serves a dual role as both the offensive testing instance and the centralized hosting core for the defensive security stack.

### 🌐 Logical Network Topology

``mermaid
flowchart TD
    NET[Internet / Home Router] -->|WAN: Bridged Adapter| FW

    FW["OPNsense Firewall<br/>LAN: 192.168.1.1"]

    FW --- LAN{{"SOC-LAB Network<br/>192.168.1.0/24"}}

    LAN --- KALI["Kali Linux<br/>192.168.1.5<br/>• Wazuh Manager / SIEM<br/>• Suricata NIDS<br/>• Attacker tools"]
    LAN --- WIN["Windows Server 2022<br/>192.168.1.9<br/>• Wazuh Agent<br/>• Sysmon<br/>• Security / System / Application logs"]

    WIN -. "Sysmon + Windows event logs" .-> KALI
    ```
    ---
    
##  Technology Stack & Telemetry Mapping

| Component | Technology | Security Visibility Value Provided |
| :--- | :--- | :--- |
| **SIEM / XDR Core** | **Wazuh Engine (on Kali)** | Aggregates, parses, decodes, and alerts on multi-source security events. |
| **Perimeter Security** | **OPNsense Firewall** | Filters boundary network access and logs dropped inbound connection rules. |
| **Network IDS** | **Suricata NIDS** | Performs deep packet inspection on the virtual interface to catch exploits in transit. |
| **Endpoint Target** | **Windows Server 2022** | Acts as the enterprise crown-jewel node holding sensitive simulated directory assets. |
| **Host Telemetry** | **Microsoft Sysmon,other Windows application,authentication and securtity logs** | Records granular execution logs (Parent-Child tracking, terminal arguments). |
| **Data Integrity** | **Wazuh FIM (`syscheck`)** | Real-time tracking of unauthorized changes in the file system (`Downloads`). |

---

## 🔌 Pipeline Configuration & Integration Details

### 1. Endpoint Auditing (Sysmon & FIM)
The Windows Server 2022 endpoint has the lightweight Wazuh Agent running. The agent configuration (`ossec.conf`) was modified to pull telemetry directly from the Windows Event Viewer channel for Sysmon, as well as actively monitor the target directory:
```xml
<!-- Ingestion of Sysmon Process Creation Telemetry -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- File Integrity Monitoring Configuration -->
<syscheck>
  <directories check_all="yes" realtime="yes">c:/Users/Administrator/Downloads</directories>
</syscheck>
```

### 2. Network Sniffing (Suricata)
Suricata is configured on the Kali interface in promiscuous mode to monitor communications heading to the target network. The raw JSON alert outputs generated in `eve.json` are constantly parsed by the central Wazuh Manager configuration:
```xml
<localfile>
  <location>/var/log/suricata/eve.json</location>
  <log_format>json</log_format>
</localfile>
```

### 3. Perimeter Log Streaming (OPNsense)
OPNsense is configured via its Remote Syslog options to stream boundary packet logs to the Wazuh Server's IP address. To catch these, the Wazuh Manager's master syslog listener was opened up over TCP Port 514:
```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>192.168.1.5</allowed-ips>
</remote>
```

---

## 🚀 Custom Detection Engineering (Rules XML)

Because OPNsense uses a unique comma-separated structure (`filterlog`), custom XML detection logic was authored and injected into `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager to extract meaningful security insights and separate permitted traffic from perimeter blocks:

```xml
<group name="opnsense_firewall,">

  <!-- Parent Rule: This flags when any OPNsense log arrives -->
  <rule id="100200" level="1">
    <decoded_as>syslog</decoded_as>
    <match>filterlog</match>
    <description>OPNsense raw firewall event tracker.</description>
  </rule>

  <!-- Child Rule 1: High Priority Alert for Blocks -->
  <rule id="100201" level="5">
    <if_sid>100200</if_sid>
    <match>,block,</match>
    <description>OPNsense Firewall: Inbound connection attempt BLOCKED</description>
    <group>firewall,packet_drop,</group>
  </rule>

  <!-- Child Rule 2: Low Priority Alert for Allowed Outbound Traffic -->
  <rule id="100202" level="3">
    <if_sid>100200</if_sid>
    <match>,pass,</match>
    <description>OPNsense Firewall: Outbound connection PERMITTED</description>
    <group>firewall,packet_allow,</group>
  </rule>

</group>
```

---

##  Cyber Threat simulations
### Use Case 1: Active Network Reconnaissance
* **Tactical Simulation:** Executed a nmap scan using ` sudo nmap -sS 192.168.1.9` against the target endpoint from kali linux machine to determine the active ports of the endpoint and found the open rdp 3389.
* **Telemetry Correlation:**
  * **Suricata IDS** triggered an "ET SCAN Possible Nmap User-Agent" signature match, exposing the attacking machine's source IP and the probed destination.
  * **Opnsense Firewall** Captured the network traffic from attacker machine to endpoint exposing the dataflow,ip and other packet details
  * **Wazuh** ingested the Suricata alert, surfacing it in the threat-hunting dashboard for correlation against subsequent events.

### Use Case 2: Credential Brute Force & Account Compromise
* **Tactical Simulation:** Launched a dictionary-based brute-force attack against the RDP service using `Hydra` with a custom wordlist, driving repeated authentication attempts against the local administrator account and found Credentials.
* **Telemetry Correlation:**
  * **Windows Security Log** recorded a sustained burst of Event ID 4625 (logon failure) entries from the same source IP, followed by a single Event ID 4624 (logon success).
  * **Wazuh Rule 60204** ("Multiple Windows Logon Failures," Level 10) correlated the failed-logon burst into a single high-severity alert, flagging the account under active attack prior to compromise.
    

### Use Case 3: Persistence via Unauthorized Local Administrator
* **Tactical Simulation:** Using the compromised administrator credentials established a rdp connection using remmina(rdp client), created a new local user account and escalated it into the local Administrators group to establish independent, persistent access.
* **Telemetry Correlation:**
  * **Windows Security Log** captured Event ID 4720 (account created) and Event ID 4732 (member added to a security-enabled local group), both attributed back to the compromised administrator account.
  * **Sysmon (Event ID 1)** captured the exact `net user` and `net localgroup` command lines, tracking the process lineage back to the interactive RDP session.

### Use Case 4: Post-Compromise Account Discovery
* **Tactical Simulation:** Executed a local account enumeration command (`net user`) from within the compromised session to simulate attacker reconnaissance of the internal environment. From powershell dropped a file named malware.exe to the downloads folder 
* **Telemetry Correlation:**
  * **Sysmon (Event ID 1)** logged the full command line and parent process of both executions, confirming execution context within the compromised administrator session.
  * **Wazuh** classified the activity as discovery behavior, correlating it against the prior persistence event as part of the same attacker session.
  * **wazuh FIM** tracked the file download and alerts that a file added to the downloads folder.
---

## 🧠 Key Takeaways & Defense-in-Depth Lessons
## Key Takeaways

This project demonstrates a core industry principle: defense in depth, and the real-world consequences of improperly configured systems and security controls. Firewalls are designed to monitor and enforce boundaries, but attackers routinely bypass them entirely through open service ports, exposed services, or compromised credentials, as this lab demonstrated when RDP brute force succeeded without ever touching the perimeter firewall.
No single security layer is sufficient on its own. When systems are deployed with weak authentication policies, unrestricted service exposure, and no correlation across log sources, attackers gain a significant advantage, moving from initial reconnaissance to full compromise and persistence with minimal resistance. This lab reinforces that effective detection depends not just on having security tools in place, but on configuring them correctly, enforcing policies like account lockout and MFA, and ensuring logs from every layer (network, host, and firewall) are synchronized and correlated so an attack can be traced end-to-end rather than observed as isolated, disconnected events.

<div>
<img src="https://img.shields.io/badge/-Wazuh-3A75C4?&style=for-the-badge&logo=wazuh&logoColor=white" />
<img src="https://img.shields.io/badge/-Sysmon-0078D4?&style=for-the-badge&logo=windows&logoColor=white" />
<img src="https://img.shields.io/badge/-Suricata-EF3B2D?&style=for-the-badge&logo=suricata&logoColor=white" />
<img src="https://img.shields.io/badge/-OPNsense-EF3B2D?&style=for-the-badge&logo=opnsense&logoColor=white" />
<img src="https://img.shields.io/badge/-Windows-0078D4?&style=for-the-badge&logo=windows&logoColor=white" />
<img src="https://img.shields.io/badge/-Kali%20Linux-557C94?&style=for-the-badge&logo=kalilinux&logoColor=white" />
</div>
