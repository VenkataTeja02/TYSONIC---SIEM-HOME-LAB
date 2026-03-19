"""
SIEM Alert Engine - Handles alert generation, storage, routing and audit logging
"""

import json
import sqlite3
import csv
import uuid
import socket
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum

from siem_logger import get_logger
logger = get_logger(__name__)

from siem_logger import get_logger
logger = get_logger(__name__)

# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────

class Severity(str, Enum):
    LOW      = "Low"
    MEDIUM   = "Medium"
    HIGH     = "High"
    CRITICAL = "Critical"

SEVERITY_SCORE = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

MITIGATION_MAP = {
    "web_attack":       [
        "Block the source IP at the firewall immediately.",
        "Review and patch the targeted web application.",
        "Enable WAF rules to filter malicious payloads.",
        "Rotate web application credentials and API keys.",
        "Audit recent access logs for further compromise.",
    ],
    "reverse_shell":    [
        "Isolate the affected host from the network immediately.",
        "Kill the reverse shell process and collect memory dump.",
        "Perform full forensic investigation of the endpoint.",
        "Scan all hosts for similar backdoors or IOCs.",
        "Re-image the compromised system after investigation.",
    ],
    "abnormal_login":   [
        "Force password reset for the affected account.",
        "Enable MFA on all privileged accounts.",
        "Review and revoke active sessions for the user.",
        "Notify the user and check for credential leaks.",
        "Audit all recent actions taken by the account.",
    ],
    "malicious_ip":     [
        "Block the IP at perimeter firewall and proxy.",
        "Add IP to threat intelligence blocklist.",
        "Review all recent connections from this IP.",
        "Scan internal hosts for signs of compromise.",
        "Report IP to threat intelligence sharing platforms.",
    ],
    "port_scan":        [
        "Block the scanning IP at the firewall.",
        "Review exposed services and close unnecessary ports.",
        "Enable IDS/IPS signature for port scan detection.",
        "Check if any subsequent exploitation attempts occurred.",
    ],
    "brute_force":      [
        "Lock the targeted account temporarily.",
        "Implement account lockout policy.",
        "Enable CAPTCHA on login endpoints.",
        "Block source IP after threshold of failed attempts.",
        "Enable alerting for future brute force activity.",
    ],
    "data_exfiltration":[
        "Block the destination IP/domain immediately.",
        "Identify and classify data that may have been exfiltrated.",
        "Notify data protection officer and legal team.",
        "Review DLP policies and tighten egress filtering.",
        "Preserve logs for forensic and regulatory purposes.",
    ],
    "ids_alert":        [
        "Review the IDS signature that triggered this alert.",
        "Correlate with other alerts from the same source IP.",
        "Check if this is a false positive and tune the rule if needed.",
        "Escalate to tier-2 analyst if recurrence is high.",
    ],
    "malware":          [
        "Isolate the affected host from the network immediately.",
        "Run a full endpoint scan with updated signatures.",
        "Collect memory dump and preserve forensic evidence.",
        "Check for lateral movement to other hosts.",
        "Re-image system after complete investigation.",
    ],
    "default":          [
        "Investigate the alert and gather additional context.",
        "Escalate to the security team for manual review.",
        "Document findings in the incident management system.",
        "Apply relevant patches and configuration hardening.",
    ],
    "phishing":         [
        "Block the phishing domain/URL at the DNS and proxy level immediately.",
        "Notify all users who may have visited the phishing URL.",
        "Reset credentials for any accounts that may have been compromised.",
        "Report the phishing URL to Google Safe Browsing and anti-phishing feeds.",
        "Scan email gateway logs for related phishing campaign indicators.",
        "Add phishing domain to threat intelligence blocklist.",
    ],
    "ddos":             [
        "Activate upstream DDoS mitigation / scrubbing centre if available.",
        "Block the attacking IP range at the perimeter firewall immediately.",
        "Rate-limit or null-route traffic from the attacking subnet.",
        "Enable connection rate limiting on the affected service.",
        "Contact your ISP/upstream provider to block traffic at their edge.",
        "Enable CAPTCHA or Cloudflare Under Attack mode on web services.",
        "Document traffic patterns and preserve flow logs for investigation.",
    ],
}

@dataclass
class Alert:
    alert_id:    str          = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:   str          = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    alert_type:  str          = "unknown"
    severity:    Severity     = Severity.MEDIUM
    source_ip:   str          = "0.0.0.0"
    dest_ip:     str          = "0.0.0.0"
    description: str          = ""
    log_evidence:str          = ""
    hostname:    str          = field(default_factory=lambda: socket.gethostname())
    status:      str          = "open"           # open | acknowledged | resolved
    tags:        List[str]    = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["tags"]     = json.dumps(self.tags)
        return d

    def mitigation_steps(self) -> List[str]:
        key = self.alert_type.lower().replace(" ", "_")
        return MITIGATION_MAP.get(key, MITIGATION_MAP["default"])


# ─────────────────────────────────────────────
# Storage Layer
# ─────────────────────────────────────────────

class AlertStorage:
    """Multi-format alert storage: SQLite + JSON + CSV"""

    def __init__(self, base_dir: str = "./siem_data"):
        self.base_dir  = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path   = self.base_dir / "alerts.db"
        self.json_path = self.base_dir / "alerts.json"
        self.csv_path  = self.base_dir / "alerts.csv"
        self._init_db()
        self._init_csv()

    # SQLite
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id     TEXT PRIMARY KEY,
                timestamp    TEXT,
                alert_type   TEXT,
                severity     TEXT,
                source_ip    TEXT,
                dest_ip      TEXT,
                description  TEXT,
                log_evidence TEXT,
                hostname     TEXT,
                status       TEXT,
                tags         TEXT
            )
        """)
        conn.commit()
        conn.close()

    # CSV header
    def _init_csv(self):
        if not self.csv_path.exists():
            with open(self.csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "alert_id","timestamp","alert_type","severity",
                    "source_ip","dest_ip","description","log_evidence",
                    "hostname","status","tags"
                ])
                writer.writeheader()

    def save(self, alert: Alert):
        d = alert.to_dict()

        # SQLite
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT OR REPLACE INTO alerts VALUES
            (:alert_id,:timestamp,:alert_type,:severity,:source_ip,
             :dest_ip,:description,:log_evidence,:hostname,:status,:tags)
        """, d)
        conn.commit()
        conn.close()

        # JSON (append-style list)
        alerts = self._load_json()
        alerts.append(d)
        with open(self.json_path, "w") as f:
            json.dump(alerts, f, indent=2)

        # CSV
        with open(self.csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(d.keys()))
            writer.writerow(d)

    def _load_json(self) -> List[Dict]:
        if self.json_path.exists():
            try:
                with open(self.json_path) as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def get_all(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_by_severity(self, severity: str) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM alerts WHERE severity=? ORDER BY timestamp DESC",
            (severity,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def update_status(self, alert_id: str, status: str):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "UPDATE alerts SET status=? WHERE alert_id=?",
            (status, alert_id)
        )
        conn.commit()
        conn.close()


    def audit_log(self, action: str, user: str, detail: str = ""):
        """Write an immutable audit trail entry."""
        entry = {
            "ts":     datetime.utcnow().isoformat() + "Z",
            "action": action,
            "user":   user,
            "detail": detail,
        }
        audit_path = self.base_dir / "audit.jsonl"
        with open(audit_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def stats(self) -> Dict:
        conn = sqlite3.connect(self.db_path)
        total    = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_sev   = conn.execute(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
        ).fetchall()
        by_type  = conn.execute(
            "SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type"
        ).fetchall()
        open_cnt = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status='open'"
        ).fetchone()[0]
        conn.close()
        return {
            "total":        total,
            "open":         open_cnt,
            "by_severity":  dict(by_sev),
            "by_type":      dict(by_type),
        }


# ─────────────────────────────────────────────
# Telegram Notifier
# ─────────────────────────────────────────────

class TelegramNotifier:
    """Sends SIEM alerts to a Telegram chat via Bot API."""

    def __init__(self, telegram_token: str = "", telegram_chat: str = ""):
        self.telegram_token = telegram_token
        self.telegram_chat  = telegram_chat

    def _format(self, alert: Alert) -> str:
        sev_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(
            alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity), "⚪"
        )
        sev = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        return (
            f"{sev_emoji} *SIEM ALERT — {sev}*\n"
            f"🔍 Type: `{alert.alert_type}`\n"
            f"🕐 Time: `{alert.timestamp}`\n"
            f"📡 Src: `{alert.source_ip}` → Dst: `{alert.dest_ip}`\n"
            f"🖥 Host: `{alert.hostname}`\n"
            f"📝 _{alert.description}_"
        )

    def send(self, alert: Alert) -> bool:
        if not self.telegram_token or not self.telegram_chat:
            logger.debug("Telegram not configured — skipping notification.")
            return False
        try:
            import urllib.request as _ur
            url  = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = json.dumps({
                "chat_id":    self.telegram_chat,
                "text":       self._format(alert),
                "parse_mode": "Markdown",
            }).encode()
            req = _ur.Request(url, data=data, headers={"Content-Type": "application/json"})
            _ur.urlopen(req, timeout=5)
            logger.info("Telegram alert sent: %s", alert.alert_type)
            return True
        except Exception as e:
            logger.warning("Telegram send failed: %s", e)
            return False

    def send_test(self) -> bool:
        """Send a test message to verify bot token and chat ID."""
        if not self.telegram_token or not self.telegram_chat:
            return False
        try:
            import urllib.request as _ur
            url  = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = json.dumps({
                "chat_id":    self.telegram_chat,
                "text":       "✅ *TYSONIC SIEM* — Telegram alerts are working!",
                "parse_mode": "Markdown",
            }).encode()
            req = _ur.Request(url, data=data, headers={"Content-Type": "application/json"})
            _ur.urlopen(req, timeout=5)
            return True
        except Exception as e:
            logger.warning("Telegram test failed: %s", e)
            return False

    def notify_all(self, alert: Alert):
        self.send(alert)


logger.debug("Alert Engine module loaded.")