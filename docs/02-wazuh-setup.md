# 🛡️ 02 — Wazuh Server Setup

This guide installs Wazuh as a single-node deployment on Ubuntu, which includes the Wazuh Manager, Indexer, and Dashboard all on one server.

---

## 📸 Screenshot Placeholder
> 📷 **Add screenshot:** Wazuh Dashboard login page at `https://your-server-ip`

---

## What is Wazuh?

Wazuh is an open-source security platform that provides:
- **Threat detection** — monitors logs and alerts on suspicious activity
- **File integrity monitoring** — detects unauthorized file changes
- **Vulnerability detection** — scans for known CVEs on endpoints
- **Compliance** — maps alerts to GDPR, HIPAA, PCI-DSS, NIST

---

## Step 1 — Update Ubuntu

SSH into your Ubuntu server and update:

```bash
sudo apt update && sudo apt upgrade -y
```

> 💡 **What this does:** Updates the package list and upgrades existing packages to prevent conflicts during Wazuh installation.

---

## Step 2 — Download the Wazuh Install Script

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml
```

> 💡 **What this does:** Downloads the official Wazuh automated installer and its configuration file. This is the easiest way to install all three Wazuh components at once.

---

## Step 3 — Configure the Install

Edit the config file:

```bash
nano config.yml
```

Set your server's IP address:

```yaml
nodes:
  indexer:
    - name: node-1
      ip: "<YOUR-SERVER-IP>"
  server:
    - name: wazuh-1
      ip: "<YOUR-SERVER-IP>"
  dashboard:
    - name: dashboard
      ip: "<YOUR-SERVER-IP>"
```

> 💡 **What this does:** Tells Wazuh which IP address each component will run on. For a single-node setup, all three point to the same IP.

---

## Step 4 — Run the Installer

```bash
sudo bash wazuh-install.sh -a
```

This will take **10-15 minutes**. It installs:
- Wazuh Manager (alert engine)
- Wazuh Indexer (OpenSearch database)
- Wazuh Dashboard (web interface)

> 💡 **What this does:** Installs all three Wazuh components automatically. At the end it will print your admin password — **save this immediately**.

---

## Step 5 — Save Your Passwords

When the install finishes, retrieve all passwords:

```bash
sudo tar -O -xf ~/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

> 📷 **Add screenshot:** Terminal showing wazuh-passwords.txt output

Key passwords to save:

| Field | Description |
|---|---|
| `indexer_username: admin` | Wazuh Dashboard & Indexer login |
| `api_username: wazuh` | Wazuh REST API |
| `api_username: wazuh-wui` | Wazuh Dashboard internal API |

---

## Step 6 — Verify Services Are Running

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

All three should show `active (running)`.

> 💡 **What this does:** Confirms all three Wazuh components started successfully after install.

---

## Step 7 — Access the Dashboard

Open your browser and navigate to:

```
https://your-server-ip
```

Log in with:
- **Username:** `admin`
- **Password:** (from wazuh-passwords.txt)

> 📷 **Add screenshot:** Wazuh Dashboard home page after login

---

## Step 8 — Verify Agent Connection

In the Wazuh Dashboard:
1. Go to **Agents** in the left sidebar
2. You should see your server listed as agent `000`

> 📷 **Add screenshot:** Wazuh Agents page showing active agents

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Dashboard won't load | `sudo systemctl restart wazuh-dashboard` |
| Can't log in | Check password from wazuh-passwords.txt |
| Manager not running | `sudo systemctl start wazuh-manager` |
| Indexer not running | `sudo systemctl start wazuh-indexer` |

---

## ➡️ Next Step

Proceed to [03 — Docker Setup](03-docker-setup.md).
