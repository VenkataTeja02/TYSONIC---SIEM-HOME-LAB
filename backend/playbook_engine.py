"""
Automated Incident Response Playbook Engine —
Runs response actions based on alert type and severity:
  - IP blocking via iptables
  - Telegram notifications
  - Evidence collection
"""

import subprocess
import threading
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import ipaddress
import socket
from siem_logger import get_logger

logger = get_logger(__name__)
# ─────────────────────────────────────────────
# IPs that must NEVER be blocked
# ─────────────────────────────────────────────

def _get_own_ips() -> set:
    """Return all IPs assigned to this machine."""
    ips = {"127.0.0.1", "0.0.0.0", "::1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except Exception:
        pass
    try:
        import subprocess
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=3)
        for ip in r.stdout.split():
            ips.add(ip.strip())
    except Exception:
        pass
    return ips

# Private/reserved ranges that should never be auto-blocked
_SAFE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]

def _is_safe_ip(ip: str) -> bool:
    """Return True if this IP should never be blocked."""
    if not ip:
        return True
    # Check own machine IPs
    if ip in _get_own_ips():
        return True
    # Check private/reserved ranges
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _SAFE_NETWORKS)
    except ValueError:
        return True  # unparseable — don't block it


# ─────────────────────────────────────────────
# Playbook Definitions
# ─────────────────────────────────────────────

PLAYBOOKS = {
    "port_scan": {
        "name":    "Port Scan Response",
        "actions": ["log_event", "rate_limit_ip"],
        "auto":    False,
    },
    "brute_force": {
        "name":    "Brute Force Response",
        "actions": ["log_event", "block_ip", "notify_telegram"],
        "auto":    True,
        "severity_threshold": "High",
    },
    "web_attack": {
        "name":    "Web Attack Response",
        "actions": ["log_event", "block_ip", "notify_telegram", "collect_evidence"],
        "auto":    True,
        "severity_threshold": "High",
    },
    "reverse_shell": {
        "name":    "Reverse Shell Response",
        "actions": ["log_event", "block_ip", "notify_telegram", "collect_evidence"],
        "auto":    True,
        "severity_threshold": "Critical",
    },
    "malware": {
        "name":    "Malware Response",
        "actions": ["log_event", "block_ip", "notify_telegram", "collect_evidence"],
        "auto":    True,
        "severity_threshold": "Critical",
    },
    "data_exfiltration": {
        "name":    "Data Exfiltration Response",
        "actions": ["log_event", "block_ip", "notify_telegram", "collect_evidence"],
        "auto":    True,
        "severity_threshold": "High",
    },
    "malicious_ip": {
        "name":    "Malicious IP Response",
        "actions": ["log_event", "block_ip"],
        "auto":    True,
        "severity_threshold": "Medium",
    },
    "ids_alert": {
        "name":    "IDS Alert Response",
        "actions": ["log_event"],
        "auto":    False,
    },
    "abnormal_login": {
        "name":    "Abnormal Login Response",
        "actions": ["log_event", "notify_telegram"],
        "auto":    True,
        "severity_threshold": "Medium",
    },
    "lateral_movement": {
        "name":    "Lateral Movement Response",
        "actions": ["log_event", "block_ip", "notify_telegram", "collect_evidence"],
        "auto":    True,
        "severity_threshold": "High",
    },
    "ransomware": {
        "name":    "Ransomware Response",
        "actions": ["log_event", "block_ip", "notify_telegram", "collect_evidence"],
        "auto":    True,
        "severity_threshold": "Critical",
    },
    "credential_dump": {
        "name":    "Credential Dump Response",
        "actions": ["log_event", "block_ip", "notify_telegram", "collect_evidence"],
        "auto":    True,
        "severity_threshold": "Critical",
    },
    "c2_beacon": {
        "name":    "C2 Beacon Response",
        "actions": ["log_event", "block_ip", "notify_telegram", "collect_evidence"],
        "auto":    True,
        "severity_threshold": "High",
    },
    "phishing": {
        "name":    "Phishing Response",
        "actions": ["log_event", "block_ip", "notify_telegram", "collect_evidence"],
        "auto":    True,
        "severity_threshold": "High",
    },
    "ddos": {
        "name":    "DDoS Response",
        "actions": ["log_event", "block_ip", "notify_telegram", "rate_limit_ip"],
        "auto":    True,
        "severity_threshold": "High",
    },
    "default": {
        "name":    "Default Response",
        "actions": ["log_event"],
        "auto":    False,
    },
}

SEV_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


# ─────────────────────────────────────────────
# Playbook Engine
# ─────────────────────────────────────────────

class PlaybookEngine:

    def __init__(self, data_dir: str = "./siem_data", telegram_config: dict = None):
        self.data_dir        = Path(data_dir)
        self.telegram_config = telegram_config or {}
        self.blocked_ips  = set()
        self._load_blocked()
        self._lock        = threading.Lock()
        self.execution_log = []     # in-memory log of recent playbook runs

    def _load_blocked(self):
        """Load previously blocked IPs from disk."""
        path = self.data_dir / "blocked_ips.json"
        if path.exists():
            try:
                with open(path) as f:
                    self.blocked_ips = set(json.load(f))
            except Exception:
                pass

    def _save_blocked(self):
        path = self.data_dir / "blocked_ips.json"
        with open(path, "w") as f:
            json.dump(list(self.blocked_ips), f)

    # ─────────────────────────────────────────
    # Main entry point
    # ─────────────────────────────────────────

    def run(self, alert: dict, force: bool = False) -> dict:
        """
        Evaluate and run the appropriate playbook for this alert.
        Returns execution result dict.
        """
        atype    = alert.get("alert_type", "default")
        severity = alert.get("severity", "Low")
        src_ip   = alert.get("source_ip", "")
        pb       = PLAYBOOKS.get(atype, PLAYBOOKS["default"])

        result = {
            "playbook":   pb["name"],
            "alert_id":   alert.get("alert_id",""),
            "alert_type": atype,
            "severity":   severity,
            "source_ip":  src_ip,
            "actions_run": [],
            "actions_skipped": [],
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "auto":       False,
        }

        # Check if auto-run criteria met
        threshold = pb.get("severity_threshold", "Critical")
        auto_ok   = pb.get("auto", False) and (
            SEV_ORDER.get(severity, 0) >= SEV_ORDER.get(threshold, 3)
        )

        if not auto_ok and not force:
            result["status"] = "skipped"
            result["reason"] = f"Auto threshold not met ({severity} < {threshold})"
            return result

        result["auto"] = auto_ok

        # Run each action
        for action in pb.get("actions", []):
            try:
                fn = getattr(self, f"_action_{action}", None)
                if fn:
                    action_result = fn(alert)
                    result["actions_run"].append({"action": action, **action_result})
                else:
                    result["actions_skipped"].append(action)
            except Exception as e:
                result["actions_run"].append({"action": action, "ok": False, "error": str(e)})

        result["status"] = "completed"

        # Store in log
        with self._lock:
            self.execution_log.insert(0, result)
            if len(self.execution_log) > 200:
                self.execution_log = self.execution_log[:200]

        return result

    # ─────────────────────────────────────────
    # Actions
    # ─────────────────────────────────────────

    def _action_log_event(self, alert: dict) -> dict:
        log_path = self.data_dir / "playbook_log.jsonl"
        entry    = {**alert, "logged_at": datetime.now(timezone.utc).isoformat()}
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        return {"ok": True, "message": "Event logged"}

    def _action_block_ip(self, alert: dict) -> dict:
        ip = alert.get("source_ip","")
        if not ip:
            return {"ok": False, "message": "No IP to block"}
        if _is_safe_ip(ip):
            return {"ok": False, "message": f"Refused to block safe/local IP: {ip}"}

        if ip in self.blocked_ips:
            return {"ok": True, "message": f"{ip} already blocked"}

        # Try iptables (requires root — silently skip if not available)
        blocked = False
        try:
            result = subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                blocked = True
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            pass   # iptables not available or no root

        self.blocked_ips.add(ip)
        self._save_blocked()

        msg = f"{ip} blocked via iptables" if blocked else f"{ip} recorded as blocked (iptables unavailable)"
        logger.info("Playbook: %s", msg)
        return {"ok": True, "message": msg, "ip": ip, "iptables": blocked}

    def _action_rate_limit_ip(self, alert: dict) -> dict:
        ip = alert.get("source_ip","")
        if not ip or _is_safe_ip(ip):
            return {"ok": False, "message": f"Skipped rate-limit for safe/local IP: {ip}"}
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-s", ip,
                 "-m", "limit", "--limit", "10/min", "-j", "ACCEPT"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass
        return {"ok": True, "message": f"Rate limit applied to {ip}"}

    def _action_notify_telegram(self, alert: dict) -> dict:
        cfg     = self.telegram_config
        token   = cfg.get("token", "")
        chat_id = cfg.get("chat_id", "")
        if not token or not chat_id:
            return {"ok": False, "message": "Telegram not configured"}
        try:
            import urllib.request
            import json as _json
            sev    = alert.get("severity", "Low")
            atype  = alert.get("alert_type", "")
            src    = alert.get("source_ip", "")
            dst    = alert.get("dest_ip", "")
            ts     = alert.get("timestamp", "")
            desc   = alert.get("description", "")
            emojis = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
            icon   = emojis.get(sev, "⚪")
            lines  = [
                icon + " *SIEM ALERT — " + sev + "*",
                "🔍 Type: `" + atype + "`",
                "⚡ Severity: *" + sev + "*",
                "📡 Src: `" + src + "` → Dst: `" + dst + "`",
                "🕐 Time: `" + ts + "`",
                "📝 _" + desc + "_",
                "🤖 _Automated playbook executed_",
            ]
            sep  = "\n"
            text = sep.join(lines)
            url  = "https://api.telegram.org/bot" + token + "/sendMessage"
            data = _json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}).encode()
            req  = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
            return {"ok": True, "message": "Telegram sent to " + chat_id}
        except Exception as e:
            return {"ok": False, "message": str(e)}


    def _action_collect_evidence(self, alert: dict) -> dict:
        ev_dir  = self.data_dir / "evidence"
        ev_dir.mkdir(exist_ok=True)
        ts      = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        ev_file = ev_dir / f"evidence_{alert.get('alert_id','')[:8]}_{ts}.json"
        evidence = {
            "alert":      alert,
            "collected":  datetime.now(timezone.utc).isoformat(),
            "network_state": _get_netstat(),
        }
        with open(ev_file, "w") as f:
            json.dump(evidence, f, indent=2)
        return {"ok": True, "message": f"Evidence saved: {ev_file.name}"}

    # ─────────────────────────────────────────
    # Query API
    # ─────────────────────────────────────────

    def get_playbooks(self) -> list:
        """Return all playbook definitions (for dashboard display)."""
        return [
            {
                "alert_type": k,
                "name":       v["name"],
                "actions":    v["actions"],
                "auto":       v.get("auto", False),
                "threshold":  v.get("severity_threshold", "—"),
            }
            for k, v in PLAYBOOKS.items()
        ]

    def get_log(self, limit: int = 50) -> list:
        with self._lock:
            return self.execution_log[:limit]

    def get_blocked_ips(self) -> list:
        return sorted(self.blocked_ips)

    def unblock_ip(self, ip: str) -> dict:
        if ip not in self.blocked_ips:
            return {"ok": False, "message": f"{ip} is not blocked"}
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
        except Exception:
            pass
        self.blocked_ips.discard(ip)
        self._save_blocked()
        return {"ok": True, "message": f"{ip} unblocked"}


def _get_netstat() -> str:
    try:
        r = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=3)
        return r.stdout[:2000]
    except Exception:
        return "unavailable"