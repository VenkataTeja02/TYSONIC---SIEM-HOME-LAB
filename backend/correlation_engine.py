"""
SIEM Correlation Engine
Links individual alerts into multi-step attack incidents.

Chains detected (MITRE ATT&CK kill-chain order):
  - Recon → Initial Access → Execution → Persistence → Exfiltration
  - Port Scan → Brute Force → Lateral Movement
  - Credential Dump → Pass-the-Hash → Domain Compromise
  - Web Probe → SQLi/RCE → Reverse Shell → C2 → Exfil

Each correlation rule defines:
  steps      : ordered list of alert_types to chain
  window_sec : time window the chain must complete within
  severity   : incident severity when chain fires
  name       : incident name
  mitre      : primary MITRE technique
"""

import json
import threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Callable


# ─────────────────────────────────────────────
# Correlation Rules
# ─────────────────────────────────────────────

CORRELATION_RULES = [

    {
        "id":         "C001",
        "name":       "Recon → Brute Force → Compromise",
        "steps":      ["port_scan", "brute_force", "abnormal_login"],
        "window_sec": 3600,          # 1 hour
        "severity":   "Critical",
        "mitre":      "T1078",
        "description": "Attacker performed port scan, followed by brute force, then achieved login.",
    },

    {
        "id":         "C002",
        "name":       "Web Probe → Exploitation → Shell",
        "steps":      ["web_attack", "web_attack", "reverse_shell"],
        "window_sec": 1800,          # 30 min
        "severity":   "Critical",
        "mitre":      "T1190",
        "description": "Web application probed, exploited, then reverse shell established.",
    },

    {
        "id":         "C003",
        "name":       "Initial Access → Credential Dump → Lateral Movement",
        "steps":      ["brute_force", "malware", "malicious_ip"],
        "window_sec": 7200,          # 2 hours
        "severity":   "Critical",
        "mitre":      "T1003",
        "description": "Initial access via brute force, credential dumping, then lateral movement detected.",
    },

    {
        "id":         "C004",
        "name":       "Recon → Exploitation → Exfiltration",
        "steps":      ["port_scan", "web_attack", "data_exfiltration"],
        "window_sec": 3600,
        "severity":   "High",
        "mitre":      "T1041",
        "description": "Network recon followed by exploitation and data exfiltration.",
    },

    {
        "id":         "C005",
        "name":       "Malware Install → C2 Beacon → Data Exfil",
        "steps":      ["malware", "malicious_ip", "data_exfiltration"],
        "window_sec": 7200,
        "severity":   "Critical",
        "mitre":      "T1071",
        "description": "Malware installed, C2 channel established, data exfiltration followed.",
    },

    {
        "id":         "C006",
        "name":       "Brute Force → Lateral Movement",
        "steps":      ["brute_force", "malicious_ip"],
        "window_sec": 1800,
        "severity":   "High",
        "mitre":      "T1021",
        "description": "Brute force succeeded and lateral movement to internal hosts detected.",
    },

    {
        "id":         "C007",
        "name":       "Port Scan → Service Exploitation",
        "steps":      ["port_scan", "web_attack"],
        "window_sec": 900,           # 15 min
        "severity":   "High",
        "mitre":      "T1046",
        "description": "Port scan immediately followed by targeted service exploitation.",
    },

    {
        "id":         "C008",
        "name":       "Credential Dump → Pass-the-Hash → Admin Access",
        "steps":      ["malware", "brute_force", "abnormal_login"],
        "window_sec": 3600,
        "severity":   "Critical",
        "mitre":      "T1550.002",
        "description": "Credential dumping followed by pass-the-hash and privileged login.",
    },

    {
        "id":         "C009",
        "name":       "Reverse Shell → Persistence → Exfiltration",
        "steps":      ["reverse_shell", "malware", "data_exfiltration"],
        "window_sec": 7200,
        "severity":   "Critical",
        "mitre":      "T1059",
        "description": "Reverse shell established, persistence set, then data exfiltrated.",
    },

    {
        "id":         "C010",
        "name":       "Multi-Vector Attack (Any 4 different alert types)",
        "steps":      None,          # special: handled by _multi_vector_check
        "window_sec": 3600,
        "severity":   "High",
        "mitre":      "T1200",
        "description": "4 or more distinct attack types from the same source IP within 1 hour.",
        "special":    "multi_vector",
    },
]


SEV_ORD = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


# ─────────────────────────────────────────────
# Incident Model
# ─────────────────────────────────────────────

class Incident:
    def __init__(self, rule: dict, source_ip: str, alerts: list):
        self.incident_id  = _gen_id()
        self.rule_id      = rule["id"]
        self.name         = rule["name"]
        self.severity     = rule["severity"]
        self.mitre        = rule.get("mitre", "")
        self.description  = rule.get("description", "")
        self.source_ip    = source_ip
        self.alert_ids    = [a.get("alert_id", "") for a in alerts]
        self.alert_types  = [a.get("alert_type", "") for a in alerts]
        self.first_seen   = alerts[0].get("timestamp", "") if alerts else ""
        self.last_seen    = alerts[-1].get("timestamp", "") if alerts else ""
        self.created_at   = datetime.now(timezone.utc).isoformat()
        self.status       = "open"

    def to_dict(self) -> dict:
        return {
            "incident_id":  self.incident_id,
            "rule_id":      self.rule_id,
            "name":         self.name,
            "severity":     self.severity,
            "mitre":        self.mitre,
            "description":  self.description,
            "source_ip":    self.source_ip,
            "alert_ids":    self.alert_ids,
            "alert_types":  self.alert_types,
            "first_seen":   self.first_seen,
            "last_seen":    self.last_seen,
            "created_at":   self.created_at,
            "status":       self.status,
            "alert_count":  len(self.alert_ids),
        }


def _gen_id() -> str:
    import uuid
    return str(uuid.uuid4())

def _parse_ts(ts_str: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


# ─────────────────────────────────────────────
# Correlation Engine
# ─────────────────────────────────────────────

class CorrelationEngine:

    def __init__(self, data_dir: str = "./siem_data"):
        self.data_dir       = Path(data_dir)
        self._lock          = threading.Lock()
        self._incidents:    List[Incident] = []
        self._listeners:    List[Callable] = []
        self._incidents_file = self.data_dir / "incidents.json"
        self._load_incidents()

    # ─────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────

    def evaluate(self, all_alerts: List[Dict]) -> List[Incident]:
        """
        Run all correlation rules against the current alert set.
        Returns list of NEW incidents created this run.
        """
        new_incidents = []
        existing_alert_sets = {
            frozenset(inc.alert_ids) for inc in self._incidents
        }

        for rule in CORRELATION_RULES:
            if rule.get("special") == "multi_vector":
                found = self._multi_vector_check(rule, all_alerts)
            elif rule["steps"]:
                found = self._chain_check(rule, all_alerts)
            else:
                found = []

            for source_ip, matched_alerts in found:
                alert_set = frozenset(a.get("alert_id","") for a in matched_alerts)
                if alert_set in existing_alert_sets:
                    continue   # already created
                incident = Incident(rule, source_ip, matched_alerts)
                with self._lock:
                    self._incidents.insert(0, incident)
                    existing_alert_sets.add(alert_set)
                new_incidents.append(incident)
                self._notify(incident)
                print(f"[Correlation] NEW INCIDENT: {incident.name} | {source_ip} | {incident.severity}")

        self._save_incidents()
        return new_incidents

    def get_incidents(self, limit: int = 100) -> List[Dict]:
        with self._lock:
            return [i.to_dict() for i in self._incidents[:limit]]

    def get_incident(self, incident_id: str) -> Optional[Dict]:
        with self._lock:
            for i in self._incidents:
                if i.incident_id == incident_id:
                    return i.to_dict()
        return None

    def update_status(self, incident_id: str, status: str):
        with self._lock:
            for i in self._incidents:
                if i.incident_id == incident_id:
                    i.status = status
        self._save_incidents()

    def get_stats(self) -> dict:
        with self._lock:
            total = len(self._incidents)
            by_sev = defaultdict(int)
            by_rule = defaultdict(int)
            for i in self._incidents:
                by_sev[i.severity] += 1
                by_rule[i.name] += 1
        return {
            "total":    total,
            "by_severity": dict(by_sev),
            "by_rule":  dict(by_rule),
            "open":     sum(1 for i in self._incidents if i.status == "open"),
        }

    def add_listener(self, fn: Callable):
        self._listeners.append(fn)

    # ─────────────────────────────────────────
    # Chain matching
    # ─────────────────────────────────────────

    def _chain_check(self, rule: dict, all_alerts: List[Dict]):
        """
        For each source IP, find ordered sequences matching rule["steps"]
        within rule["window_sec"].
        Returns list of (source_ip, [matched_alert, ...])
        """
        steps       = rule["steps"]
        window_sec  = rule["window_sec"]
        results     = []

        # Group alerts by source IP
        by_ip = defaultdict(list)
        for a in all_alerts:
            ip = a.get("source_ip", "")
            if ip and ip not in ("0.0.0.0",):
                by_ip[ip].append(a)

        for ip, alerts in by_ip.items():
            # Sort by timestamp
            sorted_alerts = sorted(
                alerts, key=lambda a: _parse_ts(a.get("timestamp","")) or datetime.min.replace(tzinfo=timezone.utc)
            )
            # Sliding window search
            match = self._find_chain(sorted_alerts, steps, window_sec)
            if match:
                results.append((ip, match))

        return results

    def _find_chain(self, sorted_alerts: List[Dict], steps: List[str], window_sec: int):
        """Find first ordered occurrence of all steps within window_sec."""
        n = len(steps)
        for i, alert in enumerate(sorted_alerts):
            if alert.get("alert_type") != steps[0]:
                continue
            t0 = _parse_ts(alert.get("timestamp",""))
            if not t0:
                continue
            # Try to complete the chain from this starting alert
            chain   = [alert]
            step_i  = 1
            for j in range(i+1, len(sorted_alerts)):
                if step_i >= n:
                    break
                candidate = sorted_alerts[j]
                t1 = _parse_ts(candidate.get("timestamp",""))
                if not t1:
                    continue
                if (t1 - t0).total_seconds() > window_sec:
                    break
                if candidate.get("alert_type") == steps[step_i]:
                    chain.append(candidate)
                    step_i += 1
            if step_i >= n:
                return chain
        return None

    def _multi_vector_check(self, rule: dict, all_alerts: List[Dict]):
        """Fire when a single IP produces 4+ distinct alert types in the window."""
        window_sec = rule["window_sec"]
        now        = datetime.now(timezone.utc)
        results    = []

        by_ip = defaultdict(list)
        for a in all_alerts:
            ip = a.get("source_ip","")
            if not ip or ip == "0.0.0.0":
                continue
            ts = _parse_ts(a.get("timestamp",""))
            if ts and (now - ts).total_seconds() <= window_sec:
                by_ip[ip].append(a)

        for ip, alerts in by_ip.items():
            types = set(a.get("alert_type","") for a in alerts)
            if len(types) >= 4:
                results.append((ip, sorted(
                    alerts,
                    key=lambda a: _parse_ts(a.get("timestamp","")) or datetime.min.replace(tzinfo=timezone.utc)
                )))

        return results

    # ─────────────────────────────────────────
    # Persistence
    # ─────────────────────────────────────────

    def _save_incidents(self):
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with self._lock:
                data = [i.to_dict() for i in self._incidents[:500]]
            with open(self._incidents_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[Correlation] Save error: {e}")

    def _load_incidents(self):
        if self._incidents_file.exists():
            try:
                with open(self._incidents_file) as f:
                    raw = json.load(f)
                # Reconstruct as dicts (not full Incident objects, for simplicity)
                # We'll wrap them in a lightweight proxy
                for d in raw:
                    inc             = Incident.__new__(Incident)
                    inc.__dict__.update(d)
                    inc.alert_ids   = d.get("alert_ids", [])
                    inc.alert_types = d.get("alert_types", [])
                    self._incidents.append(inc)
                print(f"[Correlation] Loaded {len(self._incidents)} incidents from disk.")
            except Exception as e:
                print(f"[Correlation] Load error: {e}")

    def _notify(self, incident: Incident):
        for fn in self._listeners:
            try:
                fn(incident)
            except Exception as e:
                print(f"[Correlation] Listener error: {e}")


# Singleton
correlation_engine = CorrelationEngine()
