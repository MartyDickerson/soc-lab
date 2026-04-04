# 🔗 06 — Wazuh → Splunk Integration

This guide sets up real-time forwarding of Wazuh alerts to Splunk using a Python script that tails the Wazuh alerts file and sends events to Splunk's HTTP Event Collector (HEC).

---

## Architecture

```
Wazuh Manager
     │
     │ writes to
     ▼
/var/ossec/logs/alerts/alerts.json
     │
     │ tailed by
     ▼
wazuh_to_splunk.py (Python forwarder)
     │
     │ HTTP POST to port 8088
     ▼
Splunk HEC (192.168.1.6:8088)
     │
     │ stores in
     ▼
index=main sourcetype=wazuh
```

---

## Step 1 — Copy the Forwarder Script

Copy `wazuh_to_splunk.py` from the `scripts/` folder to your Wazuh server:

```bash
scp scripts/wazuh_to_splunk.py user@your-wazuh-ip:~/soc-automation/
```

Or create it directly:

```bash
nano ~/soc-automation/wazuh_to_splunk.py
```

Paste the contents of `scripts/wazuh_to_splunk.py`.

---

## Step 2 — Update Configuration

Edit the script and update these values at the top:

```python
SPLUNK_HEC_URL = "http://YOUR-SPLUNK-IP:8088/services/collector/event"
SPLUNK_TOKEN   = "YOUR-HEC-TOKEN"
ALERT_LOG      = "/var/ossec/logs/alerts/alerts.json"
```

Replace:
- `YOUR-SPLUNK-IP` with your Windows Server IP (find with `ipconfig`)
- `YOUR-HEC-TOKEN` with the token from Splunk HEC setup

---

## Step 3 — Test the Forwarder

Activate your venv and run the script:

```bash
source ~/soc-automation/venv/bin/activate
sudo ~/soc-automation/venv/bin/python ~/soc-automation/wazuh_to_splunk.py
```

In a **second terminal**, generate a test alert:

```bash
sudo docker run hello-world
```

You should see output like:
```
[*] Starting Wazuh → Splunk forwarder...
[+] Sent alert: Docker: Container hello-world created
[+] Sent alert: Docker: Container hello-world started
[+] Sent alert: Docker: Container hello-world received the action: die
```

> 📷 **Add screenshot:** Terminal showing forwarder sending alerts

---

## Step 4 — Verify in Splunk

Go to Splunk at `http://YOUR-SPLUNK-IP:8000`:
1. Click **Search & Reporting**
2. Search:
```
index=main sourcetype=wazuh
```
3. Set time to **Last 15 minutes**

> 📷 **Add screenshot:** Splunk showing Wazuh alerts in Search & Reporting

---

## Step 5 — Install as a Permanent Service

Create a systemd service so the forwarder runs automatically:

```bash
sudo cat > /etc/systemd/system/wazuh-splunk.service << 'EOF'
[Unit]
Description=Wazuh to Splunk HEC Forwarder
After=network.target wazuh-manager.service

[Service]
Type=simple
User=root
ExecStart=/home/YOUR-USERNAME/soc-automation/venv/bin/python /home/YOUR-USERNAME/soc-automation/wazuh_to_splunk.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

Replace `YOUR-USERNAME` with your Ubuntu username.

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-splunk --now
sudo systemctl status wazuh-splunk
```

> 💡 **What this does:** Creates a system service that automatically starts the forwarder on boot and restarts it if it crashes.

Expected output:
```
● wazuh-splunk.service - Wazuh to Splunk HEC Forwarder
     Active: active (running)
```

> 📷 **Add screenshot:** Terminal showing wazuh-splunk service running

---

## Step 6 — Monitor the Forwarder

Check live logs:
```bash
sudo journalctl -fu wazuh-splunk
```

Check service status:
```bash
sudo systemctl status wazuh-splunk
```

Restart if needed:
```bash
sudo systemctl restart wazuh-splunk
```

---

## Useful Splunk Searches

Once data is flowing, try these searches in Splunk:

```
# All Wazuh alerts
index=main sourcetype=wazuh

# High severity alerts only (level 10+)
index=main sourcetype=wazuh rule.level>=10

# Docker events only
index=main sourcetype=wazuh rule.groups=docker

# Failed login attempts
index=main sourcetype=wazuh rule.groups=authentication_failed

# MITRE ATT&CK alerts
index=main sourcetype=wazuh rule.mitre.tactic=*

# Alerts by agent
index=main sourcetype=wazuh | stats count by agent.name | sort -count

# Top alert types
index=main sourcetype=wazuh | stats count by rule.description | sort -count | head 10
```

---

## ➡️ Next Step

Proceed to [07 — Splunk SOC Dashboard](07-dashboard.md).
