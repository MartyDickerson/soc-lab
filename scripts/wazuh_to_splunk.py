#!/usr/bin/env python3
"""
Wazuh to Splunk HEC Forwarder
Tails Wazuh alerts.json and forwards to Splunk HEC in real time.
Run as a systemd service for continuous forwarding.

Usage:
    python3 wazuh_to_splunk.py

Setup as service:
    See docs/06-integration.md
"""

import json
import time
import requests
import urllib3
import os
from dotenv import load_dotenv

urllib3.disable_warnings()
load_dotenv()

SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "http://192.168.1.6:8088/services/collector/event")
SPLUNK_TOKEN   = os.getenv("SPLUNK_HEC_TOKEN", "your-hec-token-here")
ALERT_LOG      = "/var/ossec/logs/alerts/alerts.json"
HEADERS        = {"Authorization": f"Splunk {SPLUNK_TOKEN}"}


def send_to_splunk(event: dict):
    payload = {"event": event, "sourcetype": "wazuh", "index": "main"}
    try:
        r = requests.post(SPLUNK_HEC_URL, json=payload, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            print(f"[+] Sent: {event.get('rule', {}).get('description', 'unknown')}")
        else:
            print(f"[-] Splunk error {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[-] Connection error: {e}")


def tail_alerts():
    print("[*] Starting Wazuh → Splunk forwarder...")
    print(f"[*] Watching : {ALERT_LOG}")
    print(f"[*] Sending  : {SPLUNK_HEC_URL}")
    with open(ALERT_LOG, "r") as f:
        f.seek(0, 2)  # seek to end of file
        while True:
            line = f.readline()
            if line:
                try:
                    event = json.loads(line.strip())
                    send_to_splunk(event)
                except json.JSONDecodeError:
                    pass
            else:
                time.sleep(1)


if __name__ == "__main__":
    tail_alerts()
