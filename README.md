# Security Operations Centre(SOC) Lab Deployment
A multi-layered virtual SOC sandbox (Wazuh, Sysmon, Suricata, OPNsense) deployed on Kali Linux and Windows Server 2022 to engineer log pipelines and map live threat detections to the MITRE ATT&amp;CK framework.

# Wazuh-SOC-Lab-Pipeline-Engineering

A multi-layered Virtual Security Operations Center (vSOC) sandbox environment engineered to aggregate, decode, and analyze multi-vector threat activity in real time. This project demonstrates end-to-end log pipeline engineering, passive network monitoring, security architecture validation, and custom detection engineering mapped to the **MITRE ATT&CK Framework**.

---

## 🏗️ Architecture Blueprint & Data Flow

The infrastructure is built inside an isolated **VirtualBox NAT Network** (`SOC_Lab`) to guarantee safe execution and containment of simulated threats. A single, resource-efficient **Kali Linux** node serves a dual role as both the offensive testing instance and the centralized hosting core for the defensive security stack.

### 🌐 Logical Network Topology
```text
         [ Public Internet / Home Router ]
                         │
                 (Bridged Interface)
                         ▼
               ┌───────────────────┐
               │ OPNsense Firewall │
               └───────────────────┘
                         │
                   (NAT Network)
            ┌────────────┴────────────┐
            ▼                         ▼
  ┌───────────────────┐     ┌───────────────────┐
  │ Windows Server    │     │ Kali Linux        │
  │ 2022 (Target)     │     │ (Attacker Box)    │
  └───────────────────┘     └───────────────────┘
            │          ▲              │          ▲
            │          │              │          │
     (Sysmon & FIM) (Syslog Logs) (Launches) (Hosts SIEM Core)
            │          │           (Attacks)     │
            ▼          │              │          ▼
     ┌──────────────┐  │              │    ┌──────────────┐
     │ Wazuh Agent  │──┼──────────────┘    │ Suricata IDS │
     └──────────────┘  │                   └──────────────┘
                       │                          │
                       │                    (eve.json Log)
                       │                          │
                       ▼                          ▼
               ┌──────────────────────────────────┐
               │     Wazuh Server & Dashboard     │
               │        (Hosted on Kali)          │
               └──────────────────────────────────┘
```

---

## 🛠️ Technology Stack & Telemetry Mapping

| Component | Technology | Security Visibility Value Provided |
| :--- | :--- | :--- |
| **SIEM / XDR Core** | **Wazuh Engine (on Kali)** | Aggregates, parses, decodes, and alerts on multi-source security events. |
| **Perimeter Security** | **OPNsense Firewall** | Filters boundary network access and logs dropped inbound connection rules. |
| **Network IDS** | **Suricata NIDS** | Performs deep packet inspection on the virtual interface to catch exploits in transit. |
| **Endpoint Target** | **Windows Server 2022** | Acts as the enterprise crown-jewel node holding sensitive simulated directory assets. |
| **Host Telemetry** | **Microsoft Sysmon** | Records granular execution logs (Parent-Child tracking, terminal arguments). |
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
OPNsense is configured via its Remote Syslog options to stream boundary packet logs to the Wazuh Server's IP address. To catch these, the Wazuh Manager's master syslog listener was opened up over UDP Port 514:
```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>0.0.0.0/0</allowed-ips>
</remote>
```

---

## 🚀 Custom Detection Engineering (Rules XML)

Because OPNsense uses a unique comma-separated structure (`filterlog`), custom XML detection logic was authored and injected into `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager to extract meaningful security insights and separate permitted traffic from perimeter blocks:

```xml
<group name="opnsense_firewall,">

  <!-- Parent Rule: This flags when any OPNsense log arrives -->
  <rule id="100200" level="0">
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

## ⚔️ Cyber Threat Simulations & Incident Reports

To validate the defense-in-depth architecture, a multi-stage simulation was executed from the offensive Kali environment targeting the Windows Server.

### Use Case 1: Active Network Reconnaissance
* **Tactical Simulation:** Executed an aggressive host fingerprinting and port sweep using `nmap -Pn -sV` against the target.
* **Telemetry Correlation:** 
  * **OPNsense Firewall** immediately dropped unauthorized interface access attempts, recording hits under Custom Rule `100201`.
  * **Suricata IDS** simultaneously triggered signature match exceptions for network layer reconnaissance, exposing the attacking machine's IP.

### Use Case 2: Malicious Payload Drop & FIM Execution
* **Tactical Simulation:** A script simulation forced an outbound web connection to drop an executable file directly inside the server's monitored `Downloads` folder, followed by executing the script via an internal command path.
* **Telemetry Correlation:** 
  * **Wazuh FIM (`syscheck`)** instantly blared a high-priority alert flagging a raw hash modification inside the protected repository directory path.
  * **Sysmon (Event ID 1)** captured the exact execution parameters, tracking the complete parent-child process tree mapping back to `powershell.exe`.

---

## 🧠 Key Takeaways & Defense-in-Depth Lessons
This project highlights the core industry principle of **Defense-in-Depth**. Firewalls are designed to monitor boundaries, but attackers routinely bypass them using open service ports or compromised credentials. By layering perimeter filtering (**OPNsense**) with network stream inspection (**Suricata**) and continuous endpoint evaluation (**Sysmon / Wazuh FIM**), the infrastructure maintains complete tactical visibility over an adversary even if the outer perimeter defenses completely fail.

<div>
<img src="https://img.shields.io/badge/-Wazuh-3A75C4?&style=for-the-badge&logo=wazuh&logoColor=white" />
<img src="https://img.shields.io/badge/-Sysmon-0078D4?&style=for-the-badge&logo=windows&logoColor=white" />
<img src="https://img.shields.io/badge/-Suricata-EF3B2D?&style=for-the-badge&logo=suricata&logoColor=white" />
<img src="https://img.shields.io/badge/-OPNsense-EF3B2D?&style=for-the-badge&logo=opnsense&logoColor=white" />
<img src="https://img.shields.io/badge/-Windows-0078D4?&style=for-the-badge&logo=windows&logoColor=white" />
<img src="https://img.shields.io/badge/-Kali%20Linux-557C94?&style=for-the-badge&logo=kalilinux&logoColor=white" />
</div>
