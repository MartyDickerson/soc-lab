# 📈 07 — Building the Splunk SOC Dashboard

This guide walks through building a custom Wazuh SOC dashboard in Splunk with panels for alert severity, top threats, agent activity, MITRE ATT&CK coverage, and more.

---

## 📸 Screenshot Placeholder
> 📷 **Add screenshot:** Completed Splunk SOC Dashboard with all panels

---

## Step 1 — Create a New Dashboard

1. In Splunk go to **Search & Reporting**
2. Click **Dashboards** in the top navigation
3. Click **Create New Dashboard**
4. Fill in:
   - **Title:** `Wazuh SOC Dashboard`
   - **Description:** `Real-time Wazuh security alerts from all agents`
   - Select: **Classic Dashboard**
5. Click **Create**

---

## Step 2 — Add Panel 1: Alert Severity Distribution

1. Click **Add Panel** → **New** → **Pie Chart**
2. Enter this search:
```
index=main sourcetype=wazuh 
| eval severity=case(rule.level>=12,"Critical", rule.level>=8,"High", rule.level>=4,"Medium", true(),"Low") 
| stats count by severity
```
3. Title: `Alert Severity Distribution`
4. Click **Apply**

> 💡 **What this shows:** A pie chart breaking down alerts into Critical, High, Medium, and Low severity so you can see your overall threat landscape at a glance.

> 📷 **Add screenshot:** Severity pie chart panel

---

## Step 3 — Add Panel 2: Alerts Over Time

1. Click **Add Panel** → **New** → **Line Chart**
2. Enter this search:
```
index=main sourcetype=wazuh 
| timechart span=1h count by agent.name
```
3. Title: `Alerts Over Time by Agent`
4. Click **Apply**

> 💡 **What this shows:** A line chart showing alert volume over time, broken down by agent. Spikes indicate potential incidents.

---

## Step 4 — Add Panel 3: Top 10 Alert Types

1. Click **Add Panel** → **New** → **Bar Chart**
2. Enter this search:
```
index=main sourcetype=wazuh 
| stats count by rule.description 
| sort -count 
| head 10
```
3. Title: `Top 10 Alert Types`
4. Click **Apply**

> 💡 **What this shows:** Your most common alert types. If one dominates, it may need tuning or immediate investigation.

---

## Step 5 — Add Panel 4: Agent Activity

1. Click **Add Panel** → **New** → **Bar Chart**
2. Enter this search:
```
index=main sourcetype=wazuh 
| stats count by agent.name 
| sort -count
```
3. Title: `Alerts by Agent`
4. Click **Apply**

> 💡 **What this shows:** Which endpoints are generating the most alerts. A sudden spike from one agent can indicate compromise.

---

## Step 6 — Add Panel 5: MITRE ATT&CK Tactics

1. Click **Add Panel** → **New** → **Bar Chart**
2. Enter this search:
```
index=main sourcetype=wazuh rule.mitre.tactic=* 
| stats count by rule.mitre.tactic 
| sort -count
```
3. Title: `MITRE ATT&CK Tactics Detected`
4. Click **Apply**

> 💡 **What this shows:** Which MITRE ATT&CK tactics are being detected. This helps you understand the attack patterns targeting your environment.

---

## Step 7 — Add Panel 6: High Severity Alert Table

1. Click **Add Panel** → **New** → **Table**
2. Enter this search:
```
index=main sourcetype=wazuh rule.level>=10 
| table _time, agent.name, rule.level, rule.description, rule.mitre.tactic 
| sort -rule.level 
| head 20
```
3. Title: `High Severity Alerts (Level 10+)`
4. Click **Apply**

> 💡 **What this shows:** A live table of your most critical alerts that need immediate attention.

---

## Step 8 — Add Panel 7: Docker Events

1. Click **Add Panel** → **New** → **Table**
2. Enter this search:
```
index=main sourcetype=wazuh rule.groups=docker 
| table _time, agent.name, rule.description, data.docker.Action, data.docker.Actor.Attributes.image 
| sort -_time 
| head 20
```
3. Title: `Docker Container Events`
4. Click **Apply**

---

## Step 9 — Save and Set Time Range

1. Click **Save** in the top right
2. Set the default time range to **Last 24 hours**
3. Click **Save**

---

## Step 10 — Set Dashboard to Auto-Refresh

1. Click **Edit** on the dashboard
2. Look for the refresh option in the top right
3. Set to **Every 5 minutes**
4. Click **Save**

> 💡 **What this does:** Keeps your dashboard current without manually refreshing, giving you a live SOC monitoring view.

---

## Complete Dashboard Layout

```
┌─────────────────────────────────────────────────────────────┐
│              WAZUH SOC DASHBOARD                             │
├──────────────────────┬──────────────────────────────────────┤
│  Alert Severity      │  Alerts Over Time                    │
│  (Pie Chart)         │  (Line Chart)                        │
├──────────────────────┴──────────────────────────────────────┤
│  Top 10 Alert Types          │  Alerts by Agent             │
│  (Bar Chart)                 │  (Bar Chart)                 │
├──────────────────────────────┴──────────────────────────────┤
│  MITRE ATT&CK Tactics                                        │
│  (Bar Chart)                                                 │
├─────────────────────────────────────────────────────────────┤
│  High Severity Alerts Table (Level 10+)                      │
├─────────────────────────────────────────────────────────────┤
│  Docker Container Events Table                               │
└─────────────────────────────────────────────────────────────┘
```

> 📷 **Add screenshot:** Full Splunk SOC Dashboard with all panels populated

---

## ➡️ Next Step

Proceed to [08 — Troubleshooting](08-troubleshooting.md).
