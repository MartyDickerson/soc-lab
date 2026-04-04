# 🔧 08 — Troubleshooting

Common issues and fixes for your SOC lab setup.

---

## Wazuh Issues

| Problem | Cause | Fix |
|---|---|---|
| Dashboard won't load | Service not running | `sudo systemctl restart wazuh-dashboard` |
| Can't log in | Wrong password | Check `wazuh-passwords.txt` |
| Manager not running | Service stopped | `sudo systemctl start wazuh-manager` |
| Indexer not running | Service stopped | `sudo systemctl start wazuh-indexer` |
| No alerts showing | Threshold too high | Lower `MIN_SEVERITY` to `0` |
| Config error on restart | Bad ossec.conf | `sudo /var/ossec/bin/wazuh-control check` |

### Check all Wazuh services at once:
```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
```

### View Wazuh Manager logs:
```bash
sudo tail -f /var/ossec/logs/ossec.log
```

---

## Docker Monitoring Issues

| Problem | Cause | Fix |
|---|---|---|
| No Docker events in Wazuh | Listener not configured | Re-add docker-listener block to ossec.conf |
| Manager fails after Docker config | Duplicate config blocks | Run the Python cleanup script from Doc 03 |
| Docker events not showing in dashboard | Time filter | Change dashboard time to "Last 24 hours" |

### Check Docker listener is running:
```bash
sudo systemctl status wazuh-manager | grep Docker
```

### Test Docker event generation:
```bash
sudo docker run hello-world
sudo grep -i docker /var/ossec/logs/alerts/alerts.json | tail -5
```

---

## SOC Script Issues

| Problem | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError` | Dependencies not installed | `pip install requests python-dotenv colorama tabulate` |
| `401 Unauthorized` | Wrong API password | Check `.env` — use password from `wazuh-passwords.txt` |
| `Connection refused` on 55000 | Manager not running | `sudo systemctl start wazuh-manager` |
| `Connection refused` on 9200 | Indexer not running | `sudo systemctl start wazuh-indexer` |
| `python3.11 not found` | Alias conflict | `unalias python3` then re-run |
| `externally-managed-environment` | Ubuntu pip restriction | Use venv: `python3 -m venv venv` |
| No alerts in triage | Level threshold too high | Add `--min-severity 0` to see all alerts |

### Fix the python3 alias issue:
```bash
unalias python3
type python3  # should show /usr/bin/python3
```

### Test Wazuh API manually:
```bash
curl -k -u wazuh:YOUR-PASSWORD https://localhost:55000
```

### Test Wazuh Indexer manually:
```bash
curl -k -u admin:YOUR-PASSWORD https://localhost:9200/_cluster/health
```

---

## Splunk Issues

| Problem | Cause | Fix |
|---|---|---|
| Can't access `localhost:8000` | Splunk not running | `& "C:\Program Files\Splunk\bin\splunk.exe" start` |
| Login failed | Wrong password | Reset: `splunk.exe edit user admin -password NewPass123!` |
| License expired | Old install | Reinstall fresh with new download |
| No data in Splunk | HEC not enabled | Settings → Data Inputs → HEC → Global Settings → Enable |
| HEC connection timeout | Firewall blocking 8088 | `netsh advfirewall firewall add rule name="Splunk HEC" protocol=TCP dir=in localport=8088 action=allow` |

### Check Splunk service status (PowerShell):
```powershell
Get-Service -Name "Splunk*"
```

### Restart Splunk (PowerShell as Admin):
```powershell
& "C:\Program Files\Splunk\bin\splunk.exe" restart
```

---

## Wazuh → Splunk Forwarder Issues

| Problem | Cause | Fix |
|---|---|---|
| `Connection timed out` | Firewall blocking 8088 | Add firewall rule on Windows Server |
| `output type http undefined` | Old Filebeat version | Use Python forwarder script instead |
| `[Errno 2] No such file` | Wrong script path | Check path with `find / -name wazuh_to_splunk.py` |
| Service not starting | Wrong Python path | Use full venv path in service file |
| No output in Splunk | HEC token wrong | Verify token in Splunk HEC settings |

### Test HEC connection from Wazuh server:
```bash
curl -v http://YOUR-SPLUNK-IP:8088/services/collector/event \
  -H "Authorization: Splunk YOUR-TOKEN" \
  -d '{"event":"test"}'
```

Expected: `{"text":"Success","code":0}`

### Check forwarder service logs:
```bash
sudo journalctl -fu wazuh-splunk
```

---

## Finding Passwords

### All Wazuh passwords (from install):
```bash
sudo tar -O -xf ~/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

### Wazuh API config:
```bash
sudo cat /var/ossec/api/configuration/api.yaml
```

### Reset Wazuh API password:
```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh \
  -A -u wazuh -p NewPassword123! \
  -au admin -ap YOUR-ADMIN-PASSWORD
```

---

## Quick Health Check Script

Run this to check everything at once:

```bash
echo "=== Wazuh Services ===" && \
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard && \
echo "=== Docker ===" && \
sudo systemctl is-active docker && \
echo "=== Splunk Forwarder ===" && \
sudo systemctl is-active wazuh-splunk && \
echo "=== Recent Alerts ===" && \
sudo tail -3 /var/ossec/logs/alerts/alerts.json | python3 -m json.tool | grep description
```

---

## Getting Help

- Wazuh Documentation: https://documentation.wazuh.com
- Wazuh Community: https://wazuh.com/community
- Splunk Documentation: https://docs.splunk.com
- Splunk Community: https://community.splunk.com
