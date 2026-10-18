## STEPS I DID FOR INSTALLING AND CONFIGURING OPNSESNE FIREWALL
* **STEP1**
* Install the iso file of opnsense and install it in virtualbox and open network settings
* Then SET adapter1(LAN) to NAT_NETWORK:SOC_LAB(isolated network )And enable adapter 2(WAN) and SET to Bridged Adapter for accessing home router
* run the VM and complete the installation SET LAN and WAN
* login as root,enter password:opnsense then enter
* Go to browser on windows server 2022 and enter the url http://192.168.1.1

## Step 2 : OPNsense Remote Syslog & Wazuh Integration

By default, an enterprise-grade perimeter firewall drops thousands of malicious connection attempts silently at the edge. To bring this critical data into our SIEM framework, **OPNsense** is configured to forward structured network boundary logs (`filterlog`) straight to our central **Wazuh Manager** over standard remote syslog over UDP port 514 [wazuh-remoted logs].

---

### Step 1: Configure OPNsense to Send Remote Logs

To prevent our SIEM indexer from getting overwhelmed with useless data in a lab environment, we explicitly configure OPNsense to stream **blocked traffic only** (boundary drop telemetry).

1. Log into your **OPNsense Web GUI** (typically via your target server at `https://192.168.1.5` or your specific LAN management gateway IP).
2. In the left-hand navigation sidebar, go to **System** ➔ **Logging** ➔ **Targets**.
3. Click the **`+` (Plus)** button in the bottom right corner to create a new remote logging destination.
4. Fill out the target configuration properties exactly like this:
   * **Enabled:** ☑ (Check this box to activate the pipeline)
   * **Transport:** `UDP (4)`
   * **Applications:** Select `filter` *(This isolates packet filter firewall rules. You can optionally multi-select `dhcp` or `sshd` to audit network access)*.
   * **Levels:** Select `info` and `notice` *(or leave blank to send all priority values)*.
   * **Hostname / IP:** Type your **Kali Linux Wazuh Server IP Address**.
   * **Port:** `514`
5. Click **Save** and then click the **Apply** button at the top of the interface to fire up the remote logging data pipeline.

---

### Step 2: Open the UDP Syslog Receiver on the Wazuh Server

By default, the central Wazuh Manager blocks outside syslog feeds to remain secure. We must configure the manager on our **Kali Linux box** to listen for the incoming UDP packets streaming from OPNsense.

1. Connect to your **Kali Linux terminal** and open the master manager configuration:
   ```bash
   sudo nano /var/ossec/etc/ossec.conf
   ```
2. Scroll down until you find the main `<ossec_config>` section and paste this remote configuration block to bind the network socket globally across all virtual interfaces:

```xml
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
  </remote>
```

3. Save the file and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).
4. Force the `wazuh-manager` background service to reload its updated interface sockets:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

---

### Step 3: Verify the Interface Socket Binding

To prove that the pipeline isn't blocked on the host system layer, verify that `wazuh-remoted` successfully claimed the socket using the terminal network utility tool:

```bash
sudo ss -ulnp | grep 514
```

**Expected Successful Output:**
```text
UNCONN   0      0         0.0.0.0:514        0.0.0.0:*      users:(("wazuh-remoted",pid=xxxx,fd=x))
```
*(This confirms the Kali Linux network stack is officially catching the raw OPNsense UDP logs [wazuh-remoted logs]).*

---

### Step 4: Triage Firewall Alerts on the Dashboard

Once your custom rules (defined in `local_rules.xml`) parse the comma-separated `filterlog` syntax strings, you can hunt for live perimeter blocks:

1. Open your **Wazuh Dashboard** web interface.
2. Navigate to the **Discover** search view panel.
3. Apply a custom query filter to see your new rules working:
   ```text
   rule.id: 100201 OR rule.id: 100202
   ```
4. Click **Refresh**. The interface will display custom formatted alerts detailing **"OPNsense Firewall: Inbound connection attempt BLOCKED"**, mapping out foreign port scans or unauthorized ingress traffic sweeps instantly!

  
