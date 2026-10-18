## Steps I Did For Installing Sysmon On Windows Server 2022 and Forwarding logs to Wazhu
# Step 1 :Installation
* Install sysinternalssuit from <a href="https://download.sysinternals.com/files/SysinternalsSuite.zip">Microsoft-Official-Site</a>
* unzip it and navigate to the extracted folder 
* download the configuration file for sysmon from github
* Create a folder named sysmon and move the symon64.exe file and the downloaded configuration file to the folder
* Then open PowerShell as administrator and navigate to the Sysmon directory ran the below command
*  ```powershell
   .\Sysmon64.exe -i sysmonconfig.xml -accepteula ```
* sysmon installed successfuly
* To verify installation ran
```powershell
Get-Service Sysmon64 | Select-Object Name, Status, StartType
```
### Step 2: Wire Sysmon to Forward Events into the Wazuh Agent

Now that Sysmon is creating logs locally inside the Windows Event Viewer, we must modify the local **Wazuh Agent** so it knows to watch this channel and ship the raw execution data back to our central Kali Linux SIEM server.

1. Open the local Wazuh configuration file using Notepad (run as Administrator) or your terminal:
   ```text
   C:\Program Files (x86)\ossec-agent\ossec.conf
   ```
2. Scroll to the bottom of the file and paste this specific channel listener block directly inside the main `<ossec_config>` section, right above the final closing tag:

```xml
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
```

3. Save and close the `ossec.conf` configuration file.
4. Restart your Wazuh Agent service to force it to load the newly added Sysmon data stream pipeline:
   ```powershell
   Restart-Service -Name wazuhsvc
   ```

---

### Step 3: Verify the Pipeline via Wazuh Dashboard

To confirm the telemetry pipeline is active, log into your central **Wazuh Dashboard** on your host computer:
1. Navigate to the **Discover** tab.
2. Type the following query into the top search bar using Kibana Query Language (KQL):
   ```text
   rule.groups: "sysmon"
   ```
3. Hit **Refresh**. You will instantly see a timeline of detailed process events. 

Expand any event to view rich forensic data points, including **`data.win.eventdata.parentImage`** (the process that spawned the action) and **`data.win.eventdata.commandLine`** (the exact parameters run by the system), giving you true Tier 1 hunting visibility.
