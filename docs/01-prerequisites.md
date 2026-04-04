# 📋 01 — Prerequisites

Before setting up your SOC lab, make sure you have the following ready.

---

## 🖥️ Hardware Requirements

| Component | Minimum | Recommended |
|---|---|---|
| Wazuh Server RAM | 4GB | 8GB+ |
| Wazuh Server CPU | 2 cores | 4 cores |
| Wazuh Server Disk | 50GB | 100GB+ |
| Splunk Server RAM | 4GB | 8GB+ |
| Splunk Server Disk | 40GB | 100GB+ |

---

## 💿 Software Requirements

### Wazuh Server (Ubuntu VM)
- Ubuntu 22.04 or 24.04 LTS
- Python 3.10+
- Internet access for installation

### Splunk Server (Windows)
- Windows Server 2019/2022 or Windows 10/11
- Internet access for download

---

## 🌐 Network Requirements

Make sure the following ports are open between your machines:

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 1514 | UDP/TCP | Agents → Manager | Wazuh agent communication |
| 1515 | TCP | Agents → Manager | Wazuh agent enrollment |
| 55000 | TCP | Admin → Manager | Wazuh REST API |
| 9200 | TCP | Admin → Indexer | Wazuh Indexer API |
| 443 | TCP | Admin → Dashboard | Wazuh web UI |
| 8000 | TCP | Admin → Splunk | Splunk web UI |
| 8088 | TCP | Wazuh → Splunk | Splunk HEC |
| 8089 | TCP | Admin → Splunk | Splunk management |

---

## 📦 Accounts Needed

- **Splunk account** — free at https://www.splunk.com (needed to download Splunk)
- **VirusTotal account** — free at https://www.virustotal.com (optional, for IP enrichment)
- **AbuseIPDB account** — free at https://www.abuseipdb.com (optional, for IP enrichment)

---

## ✅ Pre-flight Checklist

Before starting, confirm:

- [ ] Ubuntu VM is running and you can SSH into it
- [ ] Windows Server/VM is running
- [ ] Both machines can ping each other
- [ ] You have admin/sudo access on both machines
- [ ] Ports listed above are open in your firewall/router

---

## 🔑 Credentials to Keep Track Of

As you set up, write these down in a safe place:

| Service | Username | Password |
|---|---|---|
| Wazuh Dashboard | admin | (set during install) |
| Wazuh API | wazuh | (from wazuh-passwords.txt) |
| Wazuh Indexer | admin | (from wazuh-passwords.txt) |
| Splunk | admin | (set during install) |

> 💡 **Tip:** Run `sudo tar -O -xf ~/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt` to retrieve all Wazuh passwords after install.

---

## ➡️ Next Step

Once prerequisites are met, proceed to [02 — Wazuh Setup](02-wazuh-setup.md).
