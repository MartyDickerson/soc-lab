# 📊 05 — Splunk Setup (Windows Server)

This guide installs Splunk Enterprise on Windows Server and configures it to receive Wazuh alerts via HTTP Event Collector (HEC).

---

## What is Splunk?

Splunk is a powerful SIEM platform that lets you:
- **Search** across all your security data with SPL queries
- **Visualize** data with dashboards and charts
- **Correlate** events across multiple sources
- **Alert** on specific conditions in real time
- **Report** for compliance and executive summaries

In this lab, Splunk acts as your **advanced investigation workbench** while Wazuh handles the detection and collection.

---

## Step 1 — Download Splunk Enterprise

1. Go to https://www.splunk.com/en_us/download/splunk-enterprise.html
2. Create a free Splunk account if needed
3. Select **Windows** → **64-bit** → **.msi**
4. Copy the wget command shown on the download page

In **PowerShell as Administrator**:
```powershell
wget -O splunk-installer.msi "YOUR-DOWNLOAD-URL-HERE"
```

> 💡 **What this does:** Downloads the Splunk Enterprise installer directly from Splunk's CDN using the authenticated download URL.

---

## Step 2 — Install Splunk

Run the installer silently:
```powershell
msiexec /i "C:\Windows\System32\splunk-installer.msi" AGREETOLICENSE=Yes SPLUNKUSERNAME=admin SPLUNKPASSWORD=YourPassword123! /quiet
```

Wait 3-5 minutes for installation to complete.

> 💡 **What this does:** Installs Splunk Enterprise silently with your chosen admin credentials. The `/quiet` flag suppresses the GUI installer.

---

## Step 3 — Verify Splunk is Running

Open browser and go to:
```
http://localhost:8000
```

Log in with:
- **Username:** `admin`
- **Password:** `YourPassword123!`

> 📷 **Add screenshot:** Splunk Enterprise login page

> 📷 **Add screenshot:** Splunk home dashboard after login

---

## Step 4 — Open Firewall Ports

In **PowerShell as Administrator**:

```powershell
# Splunk web interface
netsh advfirewall firewall add rule name="Splunk Web" protocol=TCP dir=in localport=8000 action=allow

# Splunk HEC (HTTP Event Collector)
netsh advfirewall firewall add rule name="Splunk HEC" protocol=TCP dir=in localport=8088 action=allow

# Splunk management
netsh advfirewall firewall add rule name="Splunk Mgmt" protocol=TCP dir=in localport=8089 action=allow
```

> 💡 **What this does:** Opens the necessary firewall ports so Wazuh can forward alerts to Splunk and you can access the web interface from other machines on the network.

---

## Step 5 — Configure HTTP Event Collector (HEC)

HEC is the endpoint that receives data from Wazuh.

1. In Splunk go to **Settings** → **Data Inputs**
2. Click **HTTP Event Collector**
3. Click **Global Settings**
4. Set:
   - All Tokens: **Enabled**
   - Enable SSL: **Unchecked**
   - HTTP Port: **8088**
5. Click **Save**

> 📷 **Add screenshot:** HEC Global Settings page

Then create a token:
1. Click **New Token**
2. Name: `wazuh-hec`
3. Click **Next**
4. Source type: `_json`
5. Default Index: `main`
6. Click **Review** → **Submit**
7. **Copy the token** — you'll need it for the integration

> 📷 **Add screenshot:** HEC token creation page showing the token value

---

## Step 6 — Test HEC Connection

From your **Wazuh server**, test that Splunk is reachable:

```bash
curl -v http://YOUR-SPLUNK-IP:8088/services/collector/event \
  -H "Authorization: Splunk YOUR-HEC-TOKEN" \
  -d '{"event": "test"}'
```

Expected response:
```json
{"text":"Success","code":0}
```

> 💡 **What this does:** Sends a test event to Splunk HEC to verify the connection is working before setting up the full forwarder.

---

## Splunk Free vs Enterprise

This lab uses the **free tier** of Splunk Enterprise which includes:
- ✅ 500MB/day data ingestion
- ✅ All search features
- ✅ Dashboards and visualizations
- ✅ Alerts
- ❌ No authentication (single user)
- ❌ No distributed search

For a home lab, 500MB/day is more than enough for Wazuh alerts.

---

## ➡️ Next Step

Proceed to [06 — Wazuh → Splunk Integration](06-integration.md).
