## Steps I Did For Installing And Configuring Suricata NIDS
## Step1:Install Suricata (NIDS)

```bash
sudo apt install suricata -y
```

Set the monitored interface in `/etc/suricata/suricata.yaml`:

```yaml
af-packet:
  - interface: eth0
```

Update rules and start:

```bash
sudo suricata-update
sudo systemctl enable --now suricata
```
## Step 2: wire suricata logs with wazhu
suricata saves all logs in a eve.json file 

SO Add this inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

Restart the manager:

```bash
sudo systemctl restart wazuh-manager
