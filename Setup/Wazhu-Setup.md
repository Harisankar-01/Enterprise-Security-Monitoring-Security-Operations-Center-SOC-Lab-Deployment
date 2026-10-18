## Wazuh Installation And Set-Up
installed (Wazuh all in one) by executing the following command:
```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```
then opened the webui from the below link and entered credentials and opened dashboard

```
https://192.168.1.5
```
And Check services by executing these commands:

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
```
## Installation And Configuration Of Wazuh Agent On Windows Server 2022

* installed Wazhu-agent through the official installer for windows <a href=https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.9-1.msi>WAZUH-AGENT FOR WINDOWS <a/>
* ran the installer and entered the manager ip (linux machine ip where i installed Wazhu-SIEM)
* Now we can see a active agent from the wazuh dashboard
  
