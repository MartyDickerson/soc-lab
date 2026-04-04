#!/usr/bin/env python3
"""
SOC Automation Script — Wazuh Edition
Alert Triage, Enrichment & Log Analysis via Wazuh REST API + local log parsing.

Usage:
    python soc_automation_wazuh.py --mode triage
    python soc_automation_wazuh.py --mode logs --logfile /var/ossec/logs/alerts/alerts.json
    python soc_automation_wazuh.py --mode full
    python soc_automation_wazuh.py --mode full --min-severity 10

Dependencies:
    pip install requests python-dotenv colorama tabulate

Wazuh API docs: https://documentation.wazuh.com/current/user-manual/api/reference.html
"""

import os
import re
import sys
import json
import logging
import argparse
import ipaddress
from datetime import datetime, timezone, timedelta
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
        logging.FileHandler("soc_wazuh.log"),
    ],
)
log = logging.getLogger(__name__)


# ── Config ────────────────────────────────────────────────────────────────────
class Config:
    # Wazuh Manager API
    WAZUH_HOST: str        = os.getenv("WAZUH_HOST", "https://localhost:55000")
    WAZUH_USER: str        = os.getenv("WAZUH_USER", "wazuh")
    WAZUH_PASS: str        = os.getenv("WAZUH_PASS", "wazuh")
    WAZUH_VERIFY_SSL: bool = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

    # Wazuh Indexer (OpenSearch/Elasticsearch) — for alert queries
    INDEXER_HOST: str      = os.getenv("WAZUH_INDEXER_HOST", "https://localhost:9200")
    INDEXER_USER: str      = os.getenv("WAZUH_INDEXER_USER", "admin")
    INDEXER_PASS: str      = os.getenv("WAZUH_INDEXER_PASS", "admin")
    INDEXER_INDEX: str     = os.getenv("WAZUH_INDEXER_INDEX", "wazuh-alerts-*")

    # VirusTotal (optional enrichment — free tier 4 req/min)
    VT_API_KEY: str        = os.getenv("VT_API_KEY", "")

    # AbuseIPDB (optional enrichment — free tier 1000 req/day)
    ABUSEIPDB_KEY: str     = os.getenv("ABUSEIPDB_KEY", "")

    # Wazuh alert severity is 0–15 (rule.level)
    # 0-3: low, 4-7: medium, 8-11: high, 12-15: critical
    LEVEL_LABELS = {
        range(0,  4):  ("low",      Fore.CYAN),
        range(4,  8):  ("medium",   Fore.YELLOW),
        range(8,  12): ("high",     Fore.RED),
        range(12, 16): ("critical", Fore.RED + Style.BRIGHT),
    }

    # Minimum rule.level to include in triage (0 = all)
    MIN_SEVERITY: int      = int(os.getenv("MIN_SEVERITY", "7"))

    # Wazuh alert log paths (common defaults)
    ALERT_LOG_PATHS = [
        "/var/ossec/logs/alerts/alerts.json",
        "/var/ossec/logs/alerts/alerts.log",
        "alerts.json",   # local fallback for testing
    ]

    # MITRE ATT&CK tactic → recommended action
    TACTIC_ACTIONS = {
        "initial-access":       "🔴 Block source IP. Review perimeter firewall rules.",
        "execution":            "🔴 Kill process. Isolate endpoint. Capture memory dump.",
        "persistence":          "🟠 Audit startup items / cron jobs / registry run keys.",
        "privilege-escalation": "🟠 Verify user activity. Disable account if unauthorized.",
        "defense-evasion":      "🟠 Review log gaps. Check AV/EDR exclusions.",
        "credential-access":    "🔴 Force password reset. Enable MFA. Check for lateral movement.",
        "discovery":            "🟡 Correlate with other alerts. May be recon — watch for follow-on activity.",
        "lateral-movement":     "🔴 Segment affected hosts. Review SMB/RDP/SSH logs.",
        "collection":           "🟠 Identify target data. Check DLP alerts.",
        "exfiltration":         "🔴 Block egress destination. Preserve forensic artifacts.",
        "command-and-control":  "🔴 Block C2 IP/domain. Isolate endpoint. Open P1 incident.",
        "impact":               "🔴 Declare incident. Initiate BCP. Preserve evidence.",
    }


# ── Helpers ───────────────────────────────────────────────────────────────────
def level_to_severity(level: int) -> tuple[str, str]:
    """Return (label, color) for a Wazuh rule level (0-15)."""
    for rng, (label, color) in Config.LEVEL_LABELS.items():
        if level in rng:
            return label, color
    return "unknown", Fore.WHITE


# ── Data Models ───────────────────────────────────────────────────────────────
@dataclass
class WazuhAlert:
    alert_id:     str
    timestamp:    str
    agent_id:     str
    agent_name:   str
    rule_id:      str
    rule_level:   int
    rule_desc:    str
    groups:       list
    mitre_ids:    list
    mitre_tactics: list
    src_ip:       str = ""
    dst_ip:       str = ""
    user:         str = ""
    full_log:     str = ""
    enrichment:   dict = field(default_factory=dict)
    iocs:         dict = field(default_factory=dict)
    recommendation: str = ""

    @property
    def severity(self) -> str:
        return level_to_severity(self.rule_level)[0]

    @property
    def color(self) -> str:
        return level_to_severity(self.rule_level)[1]


@dataclass
class LogEvent:
    raw:          str
    source:       str   # "json_alert" | "plain_alert" | "ossec_log"
    fields:       dict
    rule_level:   int   = 0
    rule_desc:    str   = ""
    agent_name:   str   = ""
    anomaly_flags: list = field(default_factory=list)


# ── Wazuh API Client ──────────────────────────────────────────────────────────
class WazuhClient:
    def __init__(self):
        self.base    = Config.WAZUH_HOST.rstrip("/")
        self.session = requests.Session()
        self.session.verify = Config.WAZUH_VERIFY_SSL
        self._token: str = ""

    def authenticate(self) -> bool:
        try:
            r = self.session.post(
                f"{self.base}/security/user/authenticate",
                auth=(Config.WAZUH_USER, Config.WAZUH_PASS),
                timeout=15,
            )
            r.raise_for_status()
            self._token = r.json()["data"]["token"]
            self.session.headers.update({"Authorization": f"Bearer {self._token}"})
            log.info(f"{Fore.GREEN}✔ Wazuh API authenticated{Style.RESET_ALL}")
            return True
        except Exception as e:
            log.error(f"{Fore.RED}✘ Wazuh auth failed: {e}{Style.RESET_ALL}")
            return False

    def _get(self, path: str, params: dict = None) -> dict:
        r = self.session.get(f"{self.base}{path}", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    # ── Agents ────────────────────────────────────────────────────────────────
    def get_agents(self, status: str = "active") -> list[dict]:
        try:
            data = self._get("/agents", {"status": status, "limit": 500})
            return data.get("data", {}).get("affected_items", [])
        except Exception as e:
            log.warning(f"Could not fetch agents: {e}")
            return []

    # ── Vulnerability Summary ─────────────────────────────────────────────────
    def get_agent_vulns(self, agent_id: str) -> list[dict]:
        try:
            data = self._get(
                f"/vulnerability/{agent_id}",
                {"severity": "critical,high", "limit": 10},
            )
            return data.get("data", {}).get("affected_items", [])
        except Exception:
            return []

    # ── SCA (Security Config Assessment) ──────────────────────────────────────
    def get_sca_summary(self, agent_id: str) -> dict:
        try:
            data = self._get(f"/sca/{agent_id}")
            items = data.get("data", {}).get("affected_items", [])
            return items[0] if items else {}
        except Exception:
            return {}


# ── Wazuh Indexer Client (OpenSearch) ─────────────────────────────────────────
class IndexerClient:
    """Query the Wazuh Indexer (OpenSearch/Elasticsearch) for alerts."""

    def __init__(self):
        self.base    = Config.INDEXER_HOST.rstrip("/")
        self.session = requests.Session()
        self.session.verify = Config.WAZUH_VERIFY_SSL
        self.session.auth   = (Config.INDEXER_USER, Config.INDEXER_PASS)

    def test_connection(self) -> bool:
        try:
            r = self.session.get(f"{self.base}/_cluster/health", timeout=10)
            r.raise_for_status()
            log.info(f"{Fore.GREEN}✔ Wazuh Indexer connected{Style.RESET_ALL}")
            return True
        except Exception as e:
            log.warning(f"{Fore.YELLOW}⚠ Wazuh Indexer not reachable: {e}{Style.RESET_ALL}")
            return False

    def get_recent_alerts(
        self,
        min_level: int = 7,
        hours: int = 1,
        size: int = 100,
    ) -> list[dict]:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        query = {
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": min_level}}},
                        {"range": {"timestamp": {"gte": since}}},
                    ]
                }
            },
        }
        try:
            r = self.session.post(
                f"{self.base}/{Config.INDEXER_INDEX}/_search",
                json=query,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])
            return [h["_source"] for h in hits]
        except Exception as e:
            log.warning(f"Indexer query failed: {e}")
            return []


# ── Enrichment ────────────────────────────────────────────────────────────────
class Enricher:
    VT_URL    = "https://www.virustotal.com/api/v3"
    ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

    @staticmethod
    def is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def virustotal_ip(ip: str) -> dict:
        if not Config.VT_API_KEY or Enricher.is_private(ip):
            return {}
        try:
            r = requests.get(
                f"{Enricher.VT_URL}/ip_addresses/{ip}",
                headers={"x-apikey": Config.VT_API_KEY},
                timeout=10,
            )
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
                return {
                    "vt_malicious":  stats.get("malicious", 0),
                    "vt_suspicious": stats.get("suspicious", 0),
                }
        except Exception as e:
            log.debug(f"VT lookup failed for {ip}: {e}")
        return {}

    @staticmethod
    def abuseipdb(ip: str) -> dict:
        if not Config.ABUSEIPDB_KEY or Enricher.is_private(ip):
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
                    "abuse_score":   d.get("abuseConfidenceScore", 0),
                    "abuse_country": d.get("countryCode", ""),
                    "abuse_reports": d.get("totalReports", 0),
                }
        except Exception as e:
            log.debug(f"AbuseIPDB failed for {ip}: {e}")
        return {}

    @classmethod
    def enrich_ip(cls, ip: str) -> dict:
        result = {"ip": ip, "private": cls.is_private(ip)}
        result.update(cls.virustotal_ip(ip))
        result.update(cls.abuseipdb(ip))
        return result


# ── IOC Extractor ─────────────────────────────────────────────────────────────
class IOCExtractor:
    IP_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    HASH_RE   = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
    URL_RE    = re.compile(r"https?://[^\s\"'>]+")
    DOMAIN_RE = re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|gov|edu)\b"
    )

    @classmethod
    def extract(cls, text: str) -> dict:
        return {
            "ips":     list(set(cls.IP_RE.findall(text))),
            "hashes":  list(set(cls.HASH_RE.findall(text))),
            "urls":    list(set(cls.URL_RE.findall(text))),
            "domains": list(set(cls.DOMAIN_RE.findall(text))),
        }


# ── Alert Parser (from Wazuh API / Indexer hits) ──────────────────────────────
class AlertParser:
    @staticmethod
    def from_indexer_hit(hit: dict) -> WazuhAlert:
        rule    = hit.get("rule", {})
        agent   = hit.get("agent", {})
        data    = hit.get("data", {})
        mitre   = rule.get("mitre", {})
        network = hit.get("network", {})

        # Try several field paths for src IP
        src_ip = (
            data.get("srcip")
            or data.get("src_ip")
            or network.get("srcip")
            or hit.get("srcip", "")
        )
        dst_ip = (
            data.get("dstip")
            or data.get("dst_ip")
            or network.get("dstip", "")
        )
        user = (
            data.get("dstuser")
            or data.get("srcuser")
            or hit.get("predecoder", {}).get("user", "")
            or ""
        )

        return WazuhAlert(
            alert_id      = hit.get("id", hit.get("_id", "unknown")),
            timestamp     = hit.get("timestamp", ""),
            agent_id      = agent.get("id", "000"),
            agent_name    = agent.get("name", "unknown"),
            rule_id       = str(rule.get("id", "")),
            rule_level    = int(rule.get("level", 0)),
            rule_desc     = rule.get("description", ""),
            groups        = rule.get("groups", []),
            mitre_ids     = mitre.get("id", []),
            mitre_tactics = mitre.get("tactic", []),
            src_ip        = src_ip,
            dst_ip        = dst_ip,
            user          = user,
            full_log      = hit.get("full_log", ""),
        )


# ── Log File Analyzer ─────────────────────────────────────────────────────────
class LogAnalyzer:
    """Parse Wazuh alert JSON/plain log files and flag suspicious events."""

    ANOMALY_RULES = [
        (re.compile(r"authentication fail|failed password|invalid user",    re.I), "auth_failure"),
        (re.compile(r"sudo|su\b",                                           re.I), "privilege_use"),
        (re.compile(r"useradd|usermod|passwd|groupadd",                     re.I), "account_modification"),
        (re.compile(r"mimikatz|cobalt|metasploit|empire|bloodhound",        re.I), "known_attack_tool"),
        (re.compile(r"powershell|cmd\.exe|wscript|cscript|mshta",          re.I), "suspicious_process"),
        (re.compile(r"base64|fromcharcode|invoke-expression",               re.I), "obfuscation"),
        (re.compile(r"net user|net localgroup|whoami|id\b",                 re.I), "enumeration"),
        (re.compile(r"wget|curl.*http|certutil.*http",                      re.I), "download_attempt"),
        (re.compile(r"chmod \+x|chmod 777",                                 re.I), "permission_change"),
        (re.compile(r"/etc/passwd|/etc/shadow|sam hive|ntds\.dit",         re.I), "credential_file_access"),
        (re.compile(r"\.onion|tor2web",                                     re.I), "darknet_indicator"),
        (re.compile(r"rootkit|hide.*process|ld_preload",                    re.I), "rootkit_indicator"),
    ]

    @classmethod
    def parse_json_alert(cls, line: str) -> Optional[LogEvent]:
        """Parse a single JSON alert line from alerts.json."""
        try:
            obj   = json.loads(line.strip())
            rule  = obj.get("rule", {})
            agent = obj.get("agent", {})
            flags = [f for rx, f in cls.ANOMALY_RULES if rx.search(line)]
            return LogEvent(
                raw        = line.strip(),
                source     = "json_alert",
                fields     = obj,
                rule_level = int(rule.get("level", 0)),
                rule_desc  = rule.get("description", ""),
                agent_name = agent.get("name", "unknown"),
                anomaly_flags = flags,
            )
        except (json.JSONDecodeError, ValueError):
            return None

    @classmethod
    def parse_plain_alert(cls, line: str) -> Optional[LogEvent]:
        """Parse a plain-text ossec alert line."""
        level_m = re.search(r"Rule:\s*(\d+)\s*\(level\s*(\d+)\)", line)
        desc_m  = re.search(r"\)\s*->\s*(.+)", line)
        flags   = [f for rx, f in cls.ANOMALY_RULES if rx.search(line)]
        if level_m or flags:
            return LogEvent(
                raw        = line.strip(),
                source     = "plain_alert",
                fields     = {
                    "rule_id":    level_m.group(1) if level_m else "",
                    "rule_level": int(level_m.group(2)) if level_m else 0,
                    "description": desc_m.group(1).strip() if desc_m else "",
                },
                rule_level = int(level_m.group(2)) if level_m else 0,
                rule_desc  = desc_m.group(1).strip() if desc_m else "",
                anomaly_flags = flags,
            )
        return None

    @classmethod
    def analyze_file(cls, filepath: str, min_level: int = 0) -> list[LogEvent]:
        events: list[LogEvent] = []
        try:
            with open(filepath, "r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    ev = cls.parse_json_alert(line) or cls.parse_plain_alert(line)
                    if ev and ev.rule_level >= min_level:
                        events.append(ev)
        except FileNotFoundError:
            log.error(f"Log file not found: {filepath}")
        return events

    @staticmethod
    def auto_detect_logfile() -> Optional[str]:
        for path in Config.ALERT_LOG_PATHS:
            if os.path.isfile(path):
                log.info(f"Auto-detected alert log: {path}")
                return path
        return None


# ── Triage Engine ─────────────────────────────────────────────────────────────
class TriageEngine:
    def __init__(self, wazuh: WazuhClient, indexer: IndexerClient):
        self.wazuh   = wazuh
        self.indexer = indexer

    def _recommend(self, alert: WazuhAlert) -> str:
        # MITRE tactic → action mapping
        for tactic in alert.mitre_tactics:
            key = tactic.lower().replace(" ", "-")
            if key in Config.TACTIC_ACTIONS:
                return Config.TACTIC_ACTIONS[key]

        # Enrichment-based escalation
        for ip, data in alert.enrichment.items():
            if data.get("vt_malicious", 0) > 5:
                return f"🔴 IP {ip} confirmed malicious on VirusTotal. Isolate & block."
            if data.get("abuse_score", 0) > 75:
                return f"🟠 IP {ip} has high abuse score ({data['abuse_score']}). Consider blocking."

        # Keyword-based fallback
        desc = alert.rule_desc.lower()
        if any(k in desc for k in ("malware", "ransomware", "trojan", "c2", "beacon")):
            return "🔴 Isolate endpoint immediately. Capture memory. Open P1 incident."
        if any(k in desc for k in ("brute force", "multiple failed", "login attempt")):
            return "🟡 Geo-check source IP. Temp-block after threshold. Force password reset."
        if any(k in desc for k in ("privilege", "escalation", "sudo", "root")):
            return "🟠 Verify with user's manager. Disable account if unauthorized."
        if any(k in desc for k in ("sql injection", "xss", "web attack", "scanner")):
            return "🟠 Review WAF rules. Block attacking IP. Check for successful exploitation."
        if alert.rule_level >= 12:
            return "🔴 Critical alert — escalate to Tier 2 immediately."
        if alert.rule_level >= 8:
            return "🟠 Escalate to Tier 2. Collect logs from affected agent."
        return "🟢 Monitor. Correlate with peer alerts before escalating."

    def triage(self, min_level: int, hours: int = 1) -> list[WazuhAlert]:
        raw_hits = self.indexer.get_recent_alerts(min_level=min_level, hours=hours)
        alerts: list[WazuhAlert] = []

        for hit in raw_hits:
            alert = AlertParser.from_indexer_hit(hit)

            # IOC extraction
            alert.iocs = IOCExtractor.extract(json.dumps(hit))

            # Enrich top IPs
            for ip in ([alert.src_ip] if alert.src_ip else []) + alert.iocs["ips"][:2]:
                if ip and ip not in alert.enrichment:
                    alert.enrichment[ip] = Enricher.enrich_ip(ip)

            alert.recommendation = self._recommend(alert)
            alerts.append(alert)

        return sorted(alerts, key=lambda a: a.rule_level, reverse=True)


# ── Reporter ──────────────────────────────────────────────────────────────────
class Reporter:
    @staticmethod
    def print_agent_summary(agents: list[dict]):
        if not agents:
            print(f"\n{Fore.YELLOW}No active agents found.{Style.RESET_ALL}")
            return
        print(f"\n{Fore.CYAN}── Active Agents ({len(agents)}) ──────────────────────────{Style.RESET_ALL}")
        rows = [
            [a.get("id"), a.get("name"), a.get("ip", "N/A"), a.get("os", {}).get("name", "N/A"), a.get("status")]
            for a in agents[:20]
        ]
        print(tabulate(rows, headers=["ID", "Name", "IP", "OS", "Status"], tablefmt="rounded_outline"))

    @staticmethod
    def print_alerts(alerts: list[WazuhAlert]):
        if not alerts:
            print(f"\n{Fore.YELLOW}No alerts above threshold.{Style.RESET_ALL}\n")
            return

        print(f"\n{Fore.CYAN}{'─'*72}")
        print(f"  🚨  WAZUH ALERT TRIAGE  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'─'*72}{Style.RESET_ALL}\n")

        # Summary table
        rows = []
        for a in alerts:
            col = a.color
            rows.append([
                col + str(a.rule_level) + Style.RESET_ALL,
                col + a.severity.upper() + Style.RESET_ALL,
                a.agent_name[:20],
                a.rule_id,
                a.rule_desc[:42],
                a.timestamp[:19],
            ])
        print(tabulate(
            rows,
            headers=["Lvl", "Severity", "Agent", "Rule ID", "Description", "Time"],
            tablefmt="rounded_outline",
        ))

        # Detailed cards
        for a in alerts:
            print(f"\n{a.color}[Lvl {a.rule_level} / {a.severity.upper()}] {a.rule_desc}{Style.RESET_ALL}")
            print(f"  Agent     : {a.agent_name} (ID: {a.agent_id})")
            print(f"  Rule      : {a.rule_id}  |  Groups: {', '.join(a.groups) or '—'}")
            print(f"  Timestamp : {a.timestamp[:19]}")
            if a.src_ip:
                print(f"  Src IP    : {a.src_ip}")
            if a.user:
                print(f"  User      : {a.user}")
            if a.mitre_ids:
                print(f"  MITRE     : {', '.join(a.mitre_ids)}  ({', '.join(a.mitre_tactics)})")
            if a.iocs["ips"]:
                print(f"  IOC IPs   : {', '.join(a.iocs['ips'][:5])}")
            if a.iocs["hashes"]:
                print(f"  IOC Hash  : {', '.join(a.iocs['hashes'][:3])}")
            if a.enrichment:
                for ip, data in a.enrichment.items():
                    parts = [f"{k}={v}" for k, v in data.items() if k not in ("ip", "private") and v]
                    if parts:
                        print(f"  Enrich({ip}): {', '.join(parts)}")
            print(f"  Action    : {a.recommendation}")

        # JSON export
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"wazuh_alert_report_{ts}.json"
        with open(report_path, "w") as fh:
            json.dump([asdict(a) for a in alerts], fh, indent=2, default=str)
        print(f"\n{Fore.GREEN}✔ Report saved → {report_path}{Style.RESET_ALL}")

    @staticmethod
    def print_log_events(events: list[LogEvent], show_all: bool = False):
        flagged = [e for e in events if e.anomaly_flags]
        print(f"\n{Fore.CYAN}{'─'*72}")
        print(f"  📋  LOG ANALYSIS  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'─'*72}{Style.RESET_ALL}")
        print(f"  Parsed  : {len(events)}")
        print(f"  Flagged : {Fore.YELLOW}{len(flagged)}{Style.RESET_ALL}\n")

        display = events if show_all else flagged
        for ev in display[:60]:
            flag_str = ", ".join(ev.anomaly_flags) if ev.anomaly_flags else "—"
            col = Fore.RED if ev.anomaly_flags else Fore.WHITE
            lvl = f"[Lvl {ev.rule_level}]" if ev.rule_level else ""
            src = f"[{ev.source}]"
            print(f"{col}{src}{lvl}{Style.RESET_ALL} {ev.rule_desc or ev.raw[:90]}")
            if ev.anomaly_flags:
                print(f"  ⚠  {Fore.YELLOW}{flag_str}{Style.RESET_ALL}")

        if flagged:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = f"wazuh_log_flagged_{ts}.json"
            with open(path, "w") as fh:
                json.dump([asdict(e) for e in flagged], fh, indent=2, default=str)
            print(f"\n{Fore.GREEN}✔ Flagged events saved → {path}{Style.RESET_ALL}")


# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SOC Automation — Wazuh Alert Triage & Log Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python soc_automation_wazuh.py --mode full
  python soc_automation_wazuh.py --mode triage --min-severity 10 --hours 4
  python soc_automation_wazuh.py --mode logs --logfile /var/ossec/logs/alerts/alerts.json
  python soc_automation_wazuh.py --mode logs --show-all
        """,
    )
    p.add_argument("--mode",         choices=["triage", "logs", "agents", "full"], default="full")
    p.add_argument("--min-severity", type=int, default=Config.MIN_SEVERITY,
                   help="Minimum Wazuh rule level (0-15, default 7)")
    p.add_argument("--hours",        type=int, default=1,
                   help="Look-back window in hours (default: 1)")
    p.add_argument("--logfile",      help="Path to alerts.json or alerts.log (auto-detected if omitted)")
    p.add_argument("--show-all",     action="store_true",
                   help="Show all log events, not just flagged ones")
    return p.parse_args()


def main():
    args = parse_args()

    print(f"\n{Fore.CYAN}{'═'*72}")
    print("  SOC AUTOMATION FRAMEWORK  |  Wazuh Edition")
    print(f"{'═'*72}{Style.RESET_ALL}")

    wazuh   = WazuhClient()
    indexer = IndexerClient()

    api_ok     = wazuh.authenticate()
    indexer_ok = indexer.test_connection()

    # ── Agents Overview ────────────────────────────────────────────────────────
    if args.mode in ("agents", "full") and api_ok:
        agents = wazuh.get_agents()
        Reporter.print_agent_summary(agents)

    # ── Alert Triage ───────────────────────────────────────────────────────────
    if args.mode in ("triage", "full"):
        print(f"\n{Fore.CYAN}[*] Running alert triage (last {args.hours}h, level ≥ {args.min_severity})...{Style.RESET_ALL}")
        if indexer_ok:
            engine = TriageEngine(wazuh, indexer)
            alerts = engine.triage(min_level=args.min_severity, hours=args.hours)
            Reporter.print_alerts(alerts)
        else:
            log.warning("Wazuh Indexer unreachable — skipping triage. Try --mode logs instead.")

    # ── Log File Analysis ──────────────────────────────────────────────────────
    if args.mode in ("logs", "full"):
        print(f"\n{Fore.CYAN}[*] Running log analysis...{Style.RESET_ALL}")
        logfile = args.logfile or LogAnalyzer.auto_detect_logfile()
        if logfile:
            events = LogAnalyzer.analyze_file(logfile, min_level=args.min_severity)
            Reporter.print_log_events(events, show_all=args.show_all)
        else:
            log.warning(
                "No log file found. Provide --logfile or place alerts.json in the current directory."
            )

    print(f"\n{Fore.GREEN}[✔] Wazuh SOC automation run complete.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
