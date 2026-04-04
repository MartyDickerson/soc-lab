# 🐳 03 — Docker Setup & Monitoring

This guide installs Docker on your Ubuntu Wazuh server and enables Wazuh's Docker monitoring module so all container activity is tracked and alerted on.

---

## What is Docker Monitoring in Wazuh?

When enabled, Wazuh monitors all Docker events including:
- Container created / started / stopped
- Image pulled
- Network connected / disconnected
- Container crashes or unexpected exits
- Suspicious container behavior

All events appear in both the Wazuh Dashboard and Splunk.

---

## Step 1 — Install Docker

Update packages and install prerequisites:

```bash
sudo apt update
sudo apt install apt-transport-https ca-certificates curl software-properties-common -y
```

Add Docker's GPG key:

```bash
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
```

Add Docker repository:

```bash
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

Install Docker:

```bash
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io -y
```

Start and enable Docker:

```bash
sudo systemctl enable docker --now
```

> 💡 **What this does:** Installs Docker Community Edition from the official Docker repository and starts it as a system service that runs on boot.

---

## Step 2 — Verify Docker Works

```bash
sudo docker run hello-world
```

You should see `Hello from Docker!` in the output.

> 📷 **Add screenshot:** Terminal showing hello-world Docker output

---

## Step 3 — Add Your User to Docker Group

This lets you run Docker without sudo:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

---

## Step 4 — Install Docker Python Module for Wazuh

```bash
sudo pip3 install docker --break-system-packages
```

> 💡 **What this does:** Installs the Python Docker SDK that Wazuh's Docker listener module uses to communicate with the Docker daemon.

---

## Step 5 — Enable Docker Listener in Wazuh

Edit the Wazuh config:

```bash
sudo python3 -c "
import re
with open('/var/ossec/etc/ossec.conf', 'r') as f:
    content = f.read()
cleaned = re.sub(r'\s*<wodle name=\"docker-listener\">.*?</wodle>', '', content, flags=re.DOTALL)
block = '''
  <wodle name=\"docker-listener\">
    <interval>10m</interval>
    <attempts>5</attempts>
    <run_on_start>yes</run_on_start>
    <disabled>no</disabled>
  </wodle>
'''
cleaned = cleaned.rstrip()
cleaned = cleaned[:-len('</ossec_config>')] + block + '</ossec_config>'
with open('/var/ossec/etc/ossec.conf', 'w') as f:
    f.write(cleaned)
print('Done')
"
```

> 💡 **What this does:** Adds the Docker listener configuration block to Wazuh's main config file. This tells Wazuh to monitor Docker events every 10 minutes and on startup.

---

## Step 6 — Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

Look for `DockerListener` in the process list — it confirms Docker monitoring is active.

---

## Step 7 — Test Docker Monitoring

Generate a Docker event:

```bash
sudo docker run hello-world
```

Wait 1-2 minutes then check Wazuh Dashboard:

1. Go to `https://your-server-ip`
2. Navigate to **Modules → Security Events**
3. Search for `rule.groups: docker`

> 📷 **Add screenshot:** Wazuh Dashboard showing Docker events

You should see events like:
- `Docker: Container hello-world created`
- `Docker: Container hello-world started`
- `Docker: Container hello-world received the action: die`

---

## Docker Event Severity Levels

| Event | Rule Level | Action |
|---|---|---|
| Container created | 3 (Info) | Monitor |
| Container started | 3 (Info) | Monitor |
| Container died (exit 0) | 7 (Medium) | Monitor |
| Container died (exit ≠ 0) | 7 (Medium) | Investigate |
| Privileged container | 10 (High) | Investigate immediately |

---

## ➡️ Next Step

Proceed to [04 — SOC Automation Script](04-soc-automation.md).
