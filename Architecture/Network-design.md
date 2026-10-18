
Internet / Home router
        |
   [WAN: bridged adapter]
     OPNsense Firewall
   [LAN: 192.168.1.1]
        |
   SOC-LAB NAT Network (192.168.1.0/24)
     |                       |
 Kali Linux              Windows Server 2022
 192.168.1.5             192.168.1.9
 - Wazuh Manager/SIEM    - Wazuh agent
 - Suricata NIDS         - Sysmon
 - Attacker tools        - Security/System/Application logs
