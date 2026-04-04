# 🛡️ SOC Home Lab

![Wazuh](https://img.shields.io/badge/Wazuh-4.x-blue?style=flat-square)
![Splunk](https://img.shields.io/badge/Splunk-10.x-green?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-29.x-2496ED?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10+-yellow?style=flat-square)
![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-E95420?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)

> A fully functional home Security Operations Center built with Wazuh, Splunk, Docker, and a custom SOC Automation Script. Covers threat detection, alert triage, log analysis, and real-time SIEM integration.

---

## 🏗️ Architecture

---

## 🚀 What This Lab Detects

| Threat | Tool |
|---|---|
| Brute force & failed logins | Wazuh |
| File integrity changes | Wazuh Syscheck |
| Privilege escalation | Wazuh + MITRE ATT&CK |
| Docker container events | Wazuh Docker Listener |
| Registry modifications | Wazuh (Windows agent) |
| Malicious IPs | VirusTotal + AbuseIPDB |
| C2 beacons & malware | SOC Automation Script |
| Compliance violations | GDPR, HIPAA, PCI-DSS |

---

## 📋 Setup Guides

1. [Prerequisites](docs/01-prerequisites.md)
2. [Wazuh Server Setup](docs/02-wazuh-setup.md)
3. [Docker Setup & Monitoring](docs/03-docker-setup.md)
4. [SOC Automation Script](docs/04-soc-automation.md)
5. [Splunk Setup](docs/05-splunk-setup.md)
6. [Wazuh to Splunk Integration](docs/06-integration.md)
7. [Splunk SOC Dashboard](docs/07-dashboard.md)
8. [Troubleshooting](docs/08-troubleshooting.md)

---

## ⚡ Quick Start
```bash
git clone https://github.com/MartyDickerson/soc-lab.git
cd soc-lab
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
nano .env
sudo venv/bin/python scripts/soc_automation_wazuh.py --mode full
```

---

## 🔍 Useful Splunk Searches

### 🔴 High Priority — Run These Daily

All critical alerts (level 12+)
index=main sourcetype=wazuh rule.level>=12 | table _time, agent.name, rule.description, rule.mitre.tactic | sort -_time
Failed login attempts
index=main sourcetype=wazuh rule.groups=authentication_failed | stats count by agent.name, data.srcip | sort -count
Privilege escalation
index=main sourcetype=wazuh rule.mitre.tactic="Privilege Escalation" | table _time, agent.name, rule.description | sort -_time

---

## ⚠️ Disclaimer

For educational purposes only. Only deploy on systems you own or have permission to monitor.

---

## 📄 License

MIT License
