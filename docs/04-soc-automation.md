# 🤖 04 — SOC Automation Script

This guide sets up the Python SOC automation script that automatically triages Wazuh alerts, enriches IOCs, and generates reports — acting as your automated Tier 1 analyst.

---

## What Does the SOC Script Do?

```
Every hour (via cron):
┌─────────────────────────────────────────────────┐
│  1. Connect to Wazuh API & Indexer              │
│  2. Pull all alerts above severity threshold     │
│  3. Extract IOCs (IPs, hashes, URLs, domains)   │
│  4. Enrich IPs via VirusTotal & AbuseIPDB       │
│  5. Map MITRE ATT&CK tactics → recommended fix  │
│  6. Print color-coded triage report             │
│  7. Save JSON report to disk                    │
└─────────────────────────────────────────────────┘
```

---

## Step 1 — Create Working Directory

```bash
mkdir ~/soc-automation && cd ~/soc-automation
```

---

## Step 2 — Set Up Python Virtual Environment

```bash
sudo apt install python3-venv -y
python3 -m venv ~/soc-automation/venv
source ~/soc-automation/venv/bin/activate
```

> 💡 **What this does:** Creates an isolated Python environment so the script's dependencies don't conflict with system Python packages. You'll see `(venv)` in your prompt when it's active.

---

## Step 3 — Install Dependencies

```bash
pip install requests python-dotenv colorama tabulate
```

---

## Step 4 — Create Environment Config

```bash
cat > ~/soc-automation/.env << 'EOF'
WAZUH_HOST=https://localhost:55000
WAZUH_USER=wazuh
WAZUH_PASS=your-wazuh-api-password
WAZUH_VERIFY_SSL=false
WAZUH_INDEXER_HOST=https://localhost:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your-indexer-password
WAZUH_INDEXER_INDEX=wazuh-alerts-*
MIN_SEVERITY=7
VT_API_KEY=
ABUSEIPDB_KEY=
EOF
```

> 💡 **What this does:** Stores credentials in a `.env` file so they're not hardcoded in the script. Never commit this file to GitHub.

Replace passwords using:
```bash
sudo tar -O -xf ~/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

---

## Step 5 — Copy the Script

Copy `soc_automation_wazuh.py` from the `scripts/` folder to `~/soc-automation/` on your server.

Using SCP from your local machine:
```bash
scp scripts/soc_automation_wazuh.py user@your-wazuh-ip:~/soc-automation/
```

Or paste it directly with nano:
```bash
nano ~/soc-automation/soc_automation_wazuh.py
```

---

## Step 6 — Test Run

```bash
cd ~/soc-automation
sudo ~/soc-automation/venv/bin/python soc_automation_wazuh.py --mode full --logfile /var/ossec/logs/alerts/alerts.json
```

> 📷 **Add screenshot:** Terminal showing SOC script output with colored alert table

Expected output:
```
════════════════════════════════════════════════
  SOC AUTOMATION FRAMEWORK  |  Wazuh Edition
════════════════════════════════════════════════
✔ Wazuh API authenticated
✔ Wazuh Indexer connected

── Active Agents (1) ──────────────────────────
╭──────┬───────────────┬───────┬────────╮
│  ID  │ Name          │  IP   │ Status │
├──────┼───────────────┼───────┼────────┤
│  000 │ SOC101-ubuntu │ local │ active │
╰──────┴───────────────┴───────┴────────╯

🚨 WAZUH ALERT TRIAGE
...
```

---

## Step 7 — Set Up Cron Job (Hourly Automation)

```bash
sudo crontab -e
```

Add this line at the bottom:

```bash
0 * * * * cd /home/yourusername/soc-automation && /home/yourusername/soc-automation/venv/bin/python soc_automation_wazuh.py --mode full --logfile /var/ossec/logs/alerts/alerts.json >> /home/yourusername/soc-automation/cron.log 2>&1
```

> 💡 **What this does:** Schedules the script to run automatically at the top of every hour. Output is saved to `cron.log` for review.

Verify the cron job:
```bash
sudo crontab -l
```

---

## Usage Examples

```bash
# Full run — agents + triage + log analysis
sudo ~/soc-automation/venv/bin/python soc_automation_wazuh.py --mode full

# Triage only — last 4 hours, critical alerts only
sudo ~/soc-automation/venv/bin/python soc_automation_wazuh.py --mode triage --min-severity 12 --hours 4

# Log file analysis only
sudo ~/soc-automation/venv/bin/python soc_automation_wazuh.py --mode logs --logfile /var/ossec/logs/alerts/alerts.json

# Show all agents
sudo ~/soc-automation/venv/bin/python soc_automation_wazuh.py --mode agents
```

---

## Understanding the Output

| Field | Description |
|---|---|
| `Lvl` | Wazuh rule level (0-15). 12+ = Critical |
| `Severity` | LOW / MEDIUM / HIGH / CRITICAL |
| `Agent` | Which machine the alert came from |
| `Rule ID` | Wazuh rule number that fired |
| `MITRE` | ATT&CK technique ID (e.g. T1053.003) |
| `IOC IPs` | IP addresses extracted from the alert |
| `Action` | Recommended response action |

---

## ➡️ Next Step

Proceed to [05 — Splunk Setup](05-splunk-setup.md).
