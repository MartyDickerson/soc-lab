#!/usr/bin/env python3
"""
SOC Automation Script — Alert Triage, Enrichment & Log Analysis
Integrates with Splunk REST API for automated alert handling and log parsing.

Usage:
    python soc_automation.py --mode triage
    python soc_automation.py --mode logs --index main --earliest -1h
    python soc_automation.py --mode full

Dependencies:
    pip install requests python-dotenv colorama tabulate
"""

import os
import re
import sys
import json
import logging
import argparse
import ipaddress
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field, asdict

import requests
import urllib3
from dotenv import load_dotenv
from colorama import init, Fore, Style
from tabulate import tabulate

# ── Init ──────────────────────────────────────────────────────────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("soc_automation.log"),
    ],
)
log = logging.getLogger(__name__)


# ── Config ────────────────────────────────────────────────────────────────────
class Config:
    # Splunk
    SPLUNK_HOST: str        = os.getenv("SPLUNK_HOST", "https://localhost:8089")
    SPLUNK_USER: str        = os.getenv("SPLUNK_USER", "admin")
    SPLUNK_PASS: str        = os.getenv("SPLUNK_PASS", "changeme")
    SPLUNK_TOKEN: str       = os.getenv("SPLUNK_TOKEN", "")          # Bearer token (preferred)
    SPLUNK_VERIFY_SSL: bool = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"

    # VirusTotal (free tier — optional enrichment)
    VT_API_KEY: str         = os.getenv("VT_API_KEY", "")

    # AbuseIPDB (optional enrichment)
    ABUSEIPDB_KEY: str      = os.getenv("ABUSEIPDB_KEY", "")

    # Alert thresholds
    SEVERITY_MAP = {
        "critical": 4,
        "high":     3,
        "medium":   2,
        "low":      1,
        "info":     0,
    }

    # Splunk saved-search names to poll (edit to match your environment)
    ALERT_SEARCHES = [
        "SOC - Failed Logins Threshold",
        "SOC - Suspicious Outbound Traffic",
        "SOC - Privilege Escalation Detected",
        "SOC - Malware C2 Beacon",
    ]

    # Log parsing rules: (regex_pattern, field_name_group_dict)
    LOG_PATTERNS = [
        # Syslog-style: Jan 12 14:32:01 host sshd[1234]: Failed password for root from 1.2.3.4
        (
            r"(?P<timestamp>\w{3}\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.+)",
            "syslog",
        ),
        # Windows EventLog (simplified)
        (
            r"EventID=(?P<event_id>\d+).*?User=(?P<user>\S+).*?Source=(?P<source_ip>[\d.]+)",
            "windows_event",
        ),
        # Generic IP + action
        (
            r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?P<action>ALLOW|DENY|BLOCK|ACCEPT|DROP).*?(?P<dst_port>\d{2,5})",
            "firewall",
        ),
    ]


# ── Data Models ───────────────────────────────────────────────────────────────
@dataclass
class Alert:
    sid: str
    name: str
    severity: str
    trigger_time: str
    result_count: int
    owner: str = "unassigned"
    status: str = "new"
    enrichment: dict = field(default_factory=dict)
    iocs: list = field(default_factory=list)
    recommendation: str = ""

    @property
    def severity_score(self) -> int:
        return Config.SEVERITY_MAP.get(self.severity.lower(), 0)


@dataclass
class LogEvent:
    raw: str
    pattern_type: str
    fields: dict
    timestamp: str = ""
    anomaly_flags: list = field(default_factory=list)


# ── Splunk Client ─────────────────────────────────────────────────────────────
class SplunkClient:
    def __init__(self):
        self.base = Config.SPLUNK_HOST.rstrip("/")
        self.session = requests.Session()
        self.session.verify = Config.SPLUNK_VERIFY_SSL

        if Config.SPLUNK_TOKEN:
            self.session.headers.update({"Authorization": f"Bearer {Config.SPLUNK_TOKEN}"})
        else:
            self.session.auth = (Config.SPLUNK_USER, Config.SPLUNK_PASS)

    def _get(self, path: str, params: dict = None) -> dict:
        url = f"{self.base}{path}"
        params = {**(params or {}), "output_mode": "json"}
        resp = self.session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: dict = None) -> dict:
        url = f"{self.base}{path}"
        resp = self.session.post(
            url, data={**(data or {}), "output_mode": "json"}, timeout=30
        )
        resp.raise_for_status()
        return resp.json()

    def test_connection(self) -> bool:
        try:
            self._get("/services/server/info")
            log.info(f"{Fore.GREEN}✔ Splunk connection OK{Style.RESET_ALL}")
            return True
        except Exception as e:
            log.error(f"{Fore.RED}✘ Splunk connection failed: {e}{Style.RESET_ALL}")
            return False

    def get_fired_alerts(self) -> list[dict]:
        """Return all recently fired alerts from the activity feed."""
        try:
            data = self._get("/services/alerts/fired_alerts", {"count": 50})
            return data.get("entry", [])
        except Exception as e:
            log.warning(f"Could not fetch fired alerts: {e}")
            return []

    def run_search(self, spl: str, earliest: str = "-15m", latest: str = "now") -> list[dict]:
        """Run a one-shot SPL search and return results."""
        try:
            job = self._post(
                "/services/search/jobs",
                {"search": f"search {spl}", "earliest_time": earliest, "latest_time": latest, "exec_mode": "oneshot"},
            )
            return job.get("results", [])
        except Exception as e:
            log.warning(f"Search failed ({spl[:60]}…): {e}")
            return []

    def get_alert_results(self, sid: str) -> list[dict]:
        """Fetch result rows from a fired alert by SID."""
        try:
            data = self._get(f"/services/search/jobs/{sid}/results", {"count": 100})
            return data.get("results", [])
        except Exception as e:
            log.warning(f"Could not fetch results for SID {sid}: {e}")
            return []


# ── Enrichment ────────────────────────────────────────────────────────────────
class Enricher:
    VT_URL    = "https://www.virustotal.com/api/v3"
    ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def virustotal_ip(ip: str) -> dict:
        if not Config.VT_API_KEY or Enricher.is_private_ip(ip):
            return {}
        try:
            r = requests.get(
                f"{Enricher.VT_URL}/ip_addresses/{ip}",
                headers={"x-apikey": Config.VT_API_KEY},
                timeout=10,
            )
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
                return {"vt_malicious": stats.get("malicious", 0), "vt_suspicious": stats.get("suspicious", 0)}
        except Exception as e:
            log.debug(f"VT lookup failed for {ip}: {e}")
        return {}

    @staticmethod
    def abuseipdb(ip: str) -> dict:
        if not Config.ABUSEIPDB_KEY or Enricher.is_private_ip(ip):
            return {}
        try:
            r = requests.get(
                Enricher.ABUSE_URL,
                headers={"Key": Config.ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                return {
                    "abuse_confidence": d.get("abuseConfidenceScore", 0),
                    "abuse_country":    d.get("countryCode", ""),
                    "abuse_reports":    d.get("totalReports", 0),
                }
        except Exception as e:
            log.debug(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {}

    @classmethod
    def enrich_ip(cls, ip: str) -> dict:
        result = {"ip": ip, "is_private": cls.is_private_ip(ip)}
        result.update(cls.virustotal_ip(ip))
        result.update(cls.abuseipdb(ip))
        return result


# ── IOC Extractor ─────────────────────────────────────────────────────────────
class IOCExtractor:
    IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
    URL_RE  = re.compile(r"https?://[^\s\"'>]+")
    DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top)\b")

    @classmethod
    def extract(cls, text: str) -> dict:
        return {
            "ips":     list(set(cls.IP_RE.findall(text))),
            "hashes":  list(set(cls.HASH_RE.findall(text))),
            "urls":    list(set(cls.URL_RE.findall(text))),
            "domains": list(set(cls.DOMAIN_RE.findall(text))),
        }


# ── Log Analyzer ──────────────────────────────────────────────────────────────
class LogAnalyzer:
    # Patterns that flag suspicious activity
    ANOMALY_RULES = [
        (re.compile(r"failed password", re.I),      "brute_force_candidate"),
        (re.compile(r"invalid user",    re.I),      "invalid_user_attempt"),
        (re.compile(r"sudo|su\b",       re.I),      "privilege_use"),
        (re.compile(r"DENY|BLOCK|DROP", re.I),      "blocked_traffic"),
        (re.compile(r"powershell|cmd\.exe|wscript", re.I), "suspicious_process"),
        (re.compile(r"mimikatz|cobalt|metasploit",  re.I), "known_tool_signature"),
        (re.compile(r"base64|fromcharcode",         re.I), "encoding_obfuscation"),
        (re.compile(r"net user|net localgroup",     re.I), "account_enumeration"),
    ]

    @classmethod
    def parse_line(cls, line: str) -> Optional[LogEvent]:
        for pattern, label in Config.LOG_PATTERNS:
            m = re.search(pattern, line)
            if m:
                fields = m.groupdict()
                flags = [flag for rx, flag in cls.ANOMALY_RULES if rx.search(line)]
                return LogEvent(
                    raw=line.strip(),
                    pattern_type=label,
                    fields=fields,
                    timestamp=fields.get("timestamp", ""),
                    anomaly_flags=flags,
                )
        return None

    @classmethod
    def analyze_file(cls, filepath: str) -> list[LogEvent]:
        events = []
        try:
            with open(filepath, "r", errors="replace") as fh:
                for line in fh:
                    ev = cls.parse_line(line)
                    if ev:
                        events.append(ev)
        except FileNotFoundError:
            log.error(f"Log file not found: {filepath}")
        return events

    @classmethod
    def analyze_splunk_results(cls, results: list[dict]) -> list[LogEvent]:
        events = []
        for row in results:
            raw = row.get("_raw", json.dumps(row))
            ev = cls.parse_line(raw) or LogEvent(
                raw=raw, pattern_type="raw", fields=row, anomaly_flags=[]
            )
            # Re-run anomaly rules on the full raw line
            for rx, flag in cls.ANOMALY_RULES:
                if rx.search(raw) and flag not in ev.anomaly_flags:
                    ev.anomaly_flags.append(flag)
            events.append(ev)
        return events


# ── Triage Engine ─────────────────────────────────────────────────────────────
class TriageEngine:
    def __init__(self, splunk: SplunkClient):
        self.splunk = splunk

    def _severity_from_name(self, name: str) -> str:
        name_l = name.lower()
        for sev in ("critical", "high", "medium", "low"):
            if sev in name_l:
                return sev
        return "medium"

    def _recommend(self, alert: Alert) -> str:
        flags = [f for ioc in alert.iocs for f in []]  # placeholder
        name_l = alert.name.lower()
        if "malware" in name_l or "c2" in name_l:
            return "🔴 Isolate endpoint immediately. Capture memory. Open P1 incident."
        if "privilege" in name_l or "escalation" in name_l:
            return "🟠 Verify user activity with manager. Disable account if unauthorized."
        if "brute" in name_l or "failed login" in name_l:
            return "🟡 Check geo-location of source IP. Consider temp block + password reset."
        if "outbound" in name_l or "exfil" in name_l:
            return "🟠 Capture full packet data. Verify destination reputation. Block if malicious."
        if alert.severity_score >= 3:
            return "🟠 Escalate to Tier 2. Collect logs from affected host."
        return "🟢 Monitor. Correlate with other alerts before escalating."

    def triage_fired_alerts(self) -> list[Alert]:
        raw_alerts = self.splunk.get_fired_alerts()
        alerts: list[Alert] = []

        for entry in raw_alerts:
            content = entry.get("content", {})
            sid     = content.get("sid", entry.get("name", "unknown"))
            name    = entry.get("name", "Unknown Alert")
            sev     = content.get("alert.severity", self._severity_from_name(name))
            ts      = content.get("trigger_time", datetime.now(timezone.utc).isoformat())
            count   = int(content.get("triggered_alert_count", 1))

            alert = Alert(
                sid=sid,
                name=name,
                severity=sev,
                trigger_time=ts,
                result_count=count,
            )

            # Pull results & enrich IOCs
            results = self.splunk.get_alert_results(sid)
            all_text = " ".join(json.dumps(r) for r in results)
            iocs = IOCExtractor.extract(all_text)
            alert.iocs = iocs

            for ip in iocs["ips"][:3]:  # limit API calls
                enrich = Enricher.enrich_ip(ip)
                alert.enrichment[ip] = enrich

            alert.recommendation = self._recommend(alert)
            alerts.append(alert)

        return sorted(alerts, key=lambda a: a.severity_score, reverse=True)


# ── Reporter ──────────────────────────────────────────────────────────────────
class Reporter:
    @staticmethod
    def print_alerts(alerts: list[Alert]):
        if not alerts:
            print(f"\n{Fore.YELLOW}No fired alerts found.{Style.RESET_ALL}\n")
            return

        sev_color = {
            "critical": Fore.RED + Style.BRIGHT,
            "high":     Fore.RED,
            "medium":   Fore.YELLOW,
            "low":      Fore.CYAN,
            "info":     Fore.WHITE,
        }

        print(f"\n{Fore.CYAN}{'─'*70}")
        print(f"  🚨  ALERT TRIAGE REPORT  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'─'*70}{Style.RESET_ALL}\n")

        table_rows = []
        for a in alerts:
            col = sev_color.get(a.severity.lower(), "")
            table_rows.append([
                col + a.severity.upper() + Style.RESET_ALL,
                a.name[:45],
                a.result_count,
                a.trigger_time[:19],
                a.status,
            ])

        print(tabulate(
            table_rows,
            headers=["Severity", "Alert Name", "Events", "Triggered", "Status"],
            tablefmt="rounded_outline",
        ))

        for a in alerts:
            col = sev_color.get(a.severity.lower(), "")
            print(f"\n{col}[{a.severity.upper()}] {a.name}{Style.RESET_ALL}")
            print(f"  SID        : {a.sid}")
            print(f"  Events     : {a.result_count}")
            print(f"  Triggered  : {a.trigger_time[:19]}")
            if a.iocs["ips"]:
                print(f"  IPs found  : {', '.join(a.iocs['ips'][:5])}")
            if a.enrichment:
                for ip, data in a.enrichment.items():
                    parts = [f"{k}={v}" for k, v in data.items() if k != "ip"]
                    if parts:
                        print(f"  Enrichment ({ip}): {', '.join(parts)}")
            print(f"  Action     : {a.recommendation}")

        # Save JSON report
        report_path = f"alert_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, "w") as fh:
            json.dump([asdict(a) for a in alerts], fh, indent=2)
        print(f"\n{Fore.GREEN}✔ JSON report saved → {report_path}{Style.RESET_ALL}")

    @staticmethod
    def print_log_events(events: list[LogEvent], show_all: bool = False):
        flagged = [e for e in events if e.anomaly_flags]
        print(f"\n{Fore.CYAN}{'─'*70}")
        print(f"  📋  LOG ANALYSIS REPORT  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'─'*70}{Style.RESET_ALL}")
        print(f"  Total parsed : {len(events)}")
        print(f"  Flagged      : {Fore.YELLOW}{len(flagged)}{Style.RESET_ALL}\n")

        display = events if show_all else flagged
        for ev in display[:50]:  # cap display
            flag_str = ", ".join(ev.anomaly_flags) if ev.anomaly_flags else "—"
            col = Fore.RED if ev.anomaly_flags else Fore.WHITE
            print(f"{col}[{ev.pattern_type}]{Style.RESET_ALL} {ev.raw[:100]}")
            if ev.anomaly_flags:
                print(f"  ⚠  Flags: {Fore.YELLOW}{flag_str}{Style.RESET_ALL}")


# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="SOC Automation — Splunk Triage & Log Analysis")
    p.add_argument("--mode",     choices=["triage", "logs", "full"], default="full",
                   help="triage=alerts only | logs=log analysis | full=both")
    p.add_argument("--logfile",  help="Path to a local log file to analyze")
    p.add_argument("--spl",      help="Custom SPL query for log analysis")
    p.add_argument("--index",    default="main", help="Splunk index (default: main)")
    p.add_argument("--earliest", default="-1h",  help="Earliest time (default: -1h)")
    p.add_argument("--show-all", action="store_true", help="Show all log events, not just flagged")
    return p.parse_args()


def main():
    args = parse_args()
    splunk = SplunkClient()

    print(f"\n{Fore.CYAN}{'═'*70}")
    print("  SOC AUTOMATION FRAMEWORK  |  Splunk Edition")
    print(f"{'═'*70}{Style.RESET_ALL}")

    connected = splunk.test_connection()

    # ── Triage Mode ──────────────────────────────────────────────────────────
    if args.mode in ("triage", "full"):
        print(f"\n{Fore.CYAN}[*] Running alert triage...{Style.RESET_ALL}")
        if connected:
            engine = TriageEngine(splunk)
            alerts = engine.triage_fired_alerts()
            Reporter.print_alerts(alerts)
        else:
            log.warning("Skipping triage — Splunk not reachable.")

    # ── Log Analysis Mode ─────────────────────────────────────────────────────
    if args.mode in ("logs", "full"):
        print(f"\n{Fore.CYAN}[*] Running log analysis...{Style.RESET_ALL}")
        events: list[LogEvent] = []

        if args.logfile:
            log.info(f"Parsing local file: {args.logfile}")
            events = LogAnalyzer.analyze_file(args.logfile)

        elif connected:
            spl = args.spl or f"index={args.index} | head 500"
            log.info(f"Querying Splunk: {spl}")
            results = splunk.run_search(spl, earliest=args.earliest)
            events = LogAnalyzer.analyze_splunk_results(results)

        Reporter.print_log_events(events, show_all=args.show_all)

    print(f"\n{Fore.GREEN}[✔] SOC automation run complete.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
