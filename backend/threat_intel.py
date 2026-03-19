"""
Threat Intelligence Module —
- IP reputation via AbuseIPDB / AlienVault OTX / local blocklist
- MITRE ATT&CK framework mapping
- Geolocation via ip-api.com
- ML-based anomaly detection (Isolation Forest)
- UEBA: User & Entity Behavioral Analytics with baselines
- Behavioral profiling per source IP
"""

import json
import math
import time
import threading
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from siem_logger import get_logger

logger = get_logger(__name__)

# ─────────────────────────────────────────────
# MITRE ATT&CK Mappings
# ─────────────────────────────────────────────

MITRE_MAP = {
    "port_scan":        {"id": "T1046",  "name": "Network Service Discovery",        "tactic": "Discovery"},
    "network_scan":     {"id": "T1046",  "name": "Network Service Discovery",        "tactic": "Discovery"},
    "brute_force":      {"id": "T1110",  "name": "Brute Force",                      "tactic": "Credential Access"},
    "web_attack":       {"id": "T1190",  "name": "Exploit Public-Facing Application","tactic": "Initial Access"},
    "sql_injection":    {"id": "T1190",  "name": "Exploit Public-Facing Application","tactic": "Initial Access"},
    "reverse_shell":    {"id": "T1059",  "name": "Command and Scripting Interpreter","tactic": "Execution"},
    "malware":          {"id": "T1204",  "name": "User Execution",                   "tactic": "Execution"},
    "data_exfiltration":{"id": "T1041",  "name": "Exfiltration Over C2 Channel",     "tactic": "Exfiltration"},
    "malicious_ip":     {"id": "T1071",  "name": "Application Layer Protocol",       "tactic": "Command and Control"},
    "abnormal_login":   {"id": "T1078",  "name": "Valid Accounts",                   "tactic": "Defense Evasion"},
    "ids_alert":        {"id": "T1040",  "name": "Network Sniffing",                 "tactic": "Discovery"},
    "phishing":         {"id": "T1566",  "name": "Phishing",                         "tactic": "Initial Access"},
    "ddos":             {"id": "T1498",  "name": "Network Denial of Service",        "tactic": "Impact"},
    "unknown":          {"id": "T0000",  "name": "Unknown Technique",                "tactic": "Unknown"},
}

def get_mitre(alert_type: str) -> dict:
    key = alert_type.lower().replace(" ", "_").replace("-", "_")
    return MITRE_MAP.get(key, MITRE_MAP["unknown"])


# ─────────────────────────────────────────────
# Geolocation
# ─────────────────────────────────────────────

_geo_cache = {}
_geo_lock  = threading.Lock()

def geolocate(ip: str) -> dict:
    if not ip or ip in ("0.0.0.0", "127.0.0.1") or ip.startswith(("10.", "192.168.", "172.")):
        return {"country": "Private", "country_code": "XX", "city": "—", "lat": 0, "lon": 0, "isp": "—"}
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org,as"
        req = urllib.request.Request(url, headers={"User-Agent": "TysonicSIEM/3.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            result = {
                "country":      data.get("country", "—"),
                "country_code": data.get("countryCode", "XX"),
                "city":         data.get("city", "—"),
                "lat":          data.get("lat", 0),
                "lon":          data.get("lon", 0),
                "isp":          data.get("isp") or data.get("org", "—"),
            }
            with _geo_lock:
                _geo_cache[ip] = result
            return result
    except Exception:
        pass
    fallback = {"country": "Unknown", "country_code": "??", "city": "—", "lat": 0, "lon": 0, "isp": "—"}
    with _geo_lock:
        _geo_cache[ip] = fallback
    return fallback


# ─────────────────────────────────────────────
# IP Reputation
# ─────────────────────────────────────────────

_rep_cache     = {}
_rep_lock      = threading.Lock()
_ABUSEIPDB_KEY = ""
_OTX_KEY       = ""

LOCAL_BLOCKLIST = {
    "198.20.69.74", "198.20.69.98", "198.20.70.114", "185.220.101.45",
    "185.220.102.8","185.107.47.171","5.2.69.50","89.234.157.254",
    "171.25.193.25","204.85.191.30","107.189.1.208",
}

def configure_threat_intel(abuseipdb_key: str = "", otx_key: str = ""):
    global _ABUSEIPDB_KEY, _OTX_KEY
    _ABUSEIPDB_KEY = abuseipdb_key
    _OTX_KEY       = otx_key

def _check_abuseipdb(ip):
    if not _ABUSEIPDB_KEY:
        return {}
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode()).get("data", {})
        return {"score": data.get("abuseConfidenceScore",0), "reports": data.get("totalReports",0),
                "source": "AbuseIPDB", "malicious": data.get("abuseConfidenceScore",0) > 25}
    except Exception:
        return {}

def _check_otx(ip):
    if not _OTX_KEY:
        return {}
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation"
        req = urllib.request.Request(url, headers={"X-OTX-API-KEY": _OTX_KEY})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
        rep   = data.get("reputation", {})
        score = rep.get("threat_score", 0)
        return {"score": score, "source": "AlienVault OTX", "malicious": score > 2,
                "activities": [a.get("name","") for a in rep.get("activities",[])]}
    except Exception:
        return {}

def check_ip_reputation(ip: str) -> dict:
    if not ip or ip in ("0.0.0.0", "127.0.0.1"):
        return {"malicious": False, "score": 0, "source": "none"}
    with _rep_lock:
        if ip in _rep_cache:
            return _rep_cache[ip]
    result = {"malicious": False, "score": 0, "source": "none", "details": {}}
    if ip in LOCAL_BLOCKLIST:
        result = {"malicious": True, "score": 100, "source": "local_blocklist", "details": {}}
    else:
        abuse = _check_abuseipdb(ip)
        if abuse:
            result = {**result, **abuse, "details": {"abuseipdb": abuse}}
        otx = _check_otx(ip)
        if otx and otx.get("malicious"):
            result["malicious"] = True
            result["score"]     = max(result.get("score",0), otx.get("score",0) * 10)
            result["source"]    = result.get("source","") + "+OTX"
            result["details"]["otx"] = otx
    with _rep_lock:
        _rep_cache[ip] = result
    return result


# ─────────────────────────────────────────────
# Risk Scoring
# ─────────────────────────────────────────────

SEV_SCORE = {"Critical": 40, "High": 20, "Medium": 8, "Low": 2}

def calculate_risk_score(alerts: list) -> dict:
    if not alerts:
        return {"score": 0, "label": "Low", "color": "#34d399"}
    now   = datetime.now(timezone.utc)
    total = 0
    count = 0
    for a in alerts:
        try:
            ts     = datetime.fromisoformat(a.get("timestamp","").replace("Z","+00:00"))
            age    = (now - ts).total_seconds() / 3600
            if age > 24:
                continue
            weight = max(0.1, 1 - age / 24)
            total += SEV_SCORE.get(a.get("severity","Low"), 2) * weight
            count += 1
        except Exception:
            pass
    score = min(100, int(total))
    if score >= 75:
        label, color = "Critical", "#c084fc"
    elif score >= 50:
        label, color = "High",     "#f87171"
    elif score >= 25:
        label, color = "Medium",   "#fbbf24"
    else:
        label, color = "Low",      "#34d399"
    return {"score": score, "label": label, "color": color, "alert_count_24h": count}


# ─────────────────────────────────────────────
# Statistical Anomaly Detection (original, kept)
# ─────────────────────────────────────────────

def _age_minutes(ts_str, now):
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z","+00:00"))
        return (now - ts).total_seconds() / 60
    except Exception:
        return 9999

def detect_anomalies(alerts: list) -> list:
    anomalies = []
    now       = datetime.now(timezone.utc)
    ip_counts = {}
    recent_times = []
    for a in alerts:
        try:
            ts  = datetime.fromisoformat(a.get("timestamp","").replace("Z","+00:00"))
            age = (now - ts).total_seconds() / 60
            if age > 10:
                continue
            src = a.get("source_ip","")
            ip_counts[src] = ip_counts.get(src,0) + 1
            recent_times.append(ts)
        except Exception:
            pass
    for ip, cnt in ip_counts.items():
        if cnt >= 10:
            anomalies.append({"type": "high_frequency",
                               "description": f"IP {ip} generated {cnt} alerts in last 10 minutes",
                               "source_ip": ip, "severity": "High" if cnt >= 20 else "Medium"})
    for a in alerts:
        if a.get("alert_type") not in ("abnormal_login","brute_force"):
            continue
        try:
            ts   = datetime.fromisoformat(a.get("timestamp","").replace("Z","+00:00"))
            if 0 <= ts.hour < 5:
                anomalies.append({"type": "off_hours_login",
                                   "description": f"Login at {ts.strftime('%H:%M')} UTC from {a.get('source_ip')}",
                                   "source_ip": a.get("source_ip",""), "severity": "Medium"})
        except Exception:
            pass
    last5m  = sum(1 for a in alerts if _age_minutes(a.get("timestamp",""), now) <= 5)
    last1h  = sum(1 for a in alerts if _age_minutes(a.get("timestamp",""), now) <= 60)
    avg_5m  = last1h / 12
    if avg_5m > 0 and last5m > avg_5m * 5:
        anomalies.append({"type": "traffic_spike",
                           "description": f"Alert rate spike: {last5m} in 5 min (avg {avg_5m:.1f})",
                           "source_ip": "multiple", "severity": "High"})
    return anomalies[:20]


# ═════════════════════════════════════════════════════════════════
#  ML-BASED ANOMALY DETECTION
#  Pure-Python Isolation Forest (no scikit-learn dependency)
# ═════════════════════════════════════════════════════════════════

import random

class _IsolationTree:
    """Single isolation tree (pure Python)."""
    def __init__(self, max_depth=10):
        self.max_depth = max_depth
        self.tree      = None

    def fit(self, X: list, depth=0):
        if len(X) <= 1 or depth >= self.max_depth:
            return {"type": "leaf", "size": len(X)}
        n_features = len(X[0])
        feat  = random.randint(0, n_features - 1)
        vals  = [row[feat] for row in X]
        mn, mx = min(vals), max(vals)
        if mn == mx:
            return {"type": "leaf", "size": len(X)}
        split = random.uniform(mn, mx)
        left  = [row for row in X if row[feat] < split]
        right = [row for row in X if row[feat] >= split]
        return {
            "type":  "node",
            "feat":  feat,
            "split": split,
            "left":  self.fit(left,  depth+1),
            "right": self.fit(right, depth+1),
        }

    def path_length(self, x, node, depth=0) -> int:
        if node["type"] == "leaf":
            return depth + _c(node["size"])
        if x[node["feat"]] < node["split"]:
            return self.path_length(x, node["left"],  depth+1)
        return     self.path_length(x, node["right"], depth+1)


def _c(n: int) -> float:
    """Average path length for BST of size n."""
    if n <= 1: return 0
    return 2 * (math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n)


class IsolationForest:
    """Isolation Forest anomaly detector — pure Python, zero dependencies."""

    def __init__(self, n_trees=50, sample_size=64, threshold=0.62):
        self.n_trees     = n_trees
        self.sample_size = sample_size
        self.threshold   = threshold
        self.trees       = []
        self._trained    = False
        self._lock       = threading.Lock()

    def fit(self, X: list):
        if len(X) < 10:
            return
        trees = []
        for _ in range(self.n_trees):
            sample = random.sample(X, min(self.sample_size, len(X)))
            t      = _IsolationTree(max_depth=int(math.ceil(math.log2(self.sample_size))))
            node   = t.fit(sample)
            trees.append((t, node))
        with self._lock:
            self.trees    = trees
            self._trained = True

    def score(self, x: list) -> float:
        """Anomaly score: >0.5 = anomalous, closer to 1.0 = more anomalous."""
        if not self._trained or not self.trees:
            return 0.5
        lengths = []
        for t, node in self.trees:
            lengths.append(t.path_length(x, node))
        avg = sum(lengths) / len(lengths)
        return 2 ** (-avg / _c(self.sample_size))

    def is_anomaly(self, x: list) -> bool:
        return self.score(x) >= self.threshold


# ─────────────────────────────────────────────
# UEBA — User & Entity Behavioral Analytics
# ─────────────────────────────────────────────

class UEBAEngine:
    """
    Builds behavioral profiles per source IP.
    Baseline: rolling 7-day window of alert patterns.
    Features per IP per hour:
      - alert_count, unique_alert_types, unique_dest_ips,
        avg_severity_score, off_hours_ratio, port_scan_ratio
    """

    SEV_NUM = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    def __init__(self, data_dir: str = "./siem_data"):
        self.data_dir     = Path(data_dir)
        self._profiles    = {}      # ip → {hourly_features}
        self._models      = {}      # ip → IsolationForest
        self._global_model= IsolationForest(n_trees=100, sample_size=128)
        self._lock        = threading.Lock()
        self._baseline_file = self.data_dir / "ueba_baselines.json"
        self._load_baselines()

    # ── Feature extraction ────────────────────

    def _extract_features(self, alerts: list, source_ip: str = None) -> list:
        """
        Extract hourly feature vector for given IP.
        Returns list of feature vectors (one per alert hour bucket).
        """
        if source_ip:
            alerts = [a for a in alerts if a.get("source_ip") == source_ip]
        if not alerts:
            return []

        by_hour = defaultdict(list)
        for a in alerts:
            try:
                ts = datetime.fromisoformat(a.get("timestamp","").replace("Z","+00:00"))
                bucket = ts.strftime("%Y-%m-%dT%H")
                by_hour[bucket].append(a)
            except Exception:
                pass

        vectors = []
        for bucket, bucket_alerts in by_hour.items():
            hour = int(bucket.split("T")[1]) if "T" in bucket else 0
            types = set(a.get("alert_type","") for a in bucket_alerts)
            dests = set(a.get("dest_ip","")   for a in bucket_alerts)
            sevs  = [self.SEV_NUM.get(a.get("severity","Low"), 1) for a in bucket_alerts]
            off_hours = 1 if 0 <= hour < 6 or hour >= 22 else 0
            scan_cnt  = sum(1 for a in bucket_alerts if a.get("alert_type") == "port_scan")

            vectors.append([
                float(len(bucket_alerts)),                              # alert count
                float(len(types)),                                      # unique types
                float(len(dests)),                                      # unique dest IPs
                float(sum(sevs) / len(sevs)) if sevs else 1.0,         # avg severity
                float(off_hours),                                       # off-hours flag
                float(scan_cnt / len(bucket_alerts)) if bucket_alerts else 0.0,  # scan ratio
                float(hour),                                            # hour of day
            ])
        return vectors

    # ── Training ──────────────────────────────

    def train(self, all_alerts: list):
        """
        Re-train global model and per-IP models.
        Called periodically (e.g., every 30 min or when new alerts arrive).
        """
        # Global model (all IPs)
        all_vecs = self._extract_features(all_alerts)
        if len(all_vecs) >= 10:
            self._global_model.fit(all_vecs)

        # Per-IP models
        by_ip = defaultdict(list)
        for a in all_alerts:
            ip = a.get("source_ip","")
            if ip and ip not in ("0.0.0.0",):
                by_ip[ip].append(a)

        for ip, ip_alerts in by_ip.items():
            vecs = self._extract_features(ip_alerts, ip)
            if len(vecs) >= 8:
                model = IsolationForest(n_trees=30, sample_size=32)
                model.fit(vecs)
                with self._lock:
                    self._models[ip] = model

        self._save_baselines()
        logger.info("UEBA models trained. Global samples: %d, IP models: %d", len(all_vecs), len(self._models))

    # ── Scoring ───────────────────────────────

    def score_ip(self, source_ip: str, recent_alerts: list) -> dict:
        """
        Score a source IP's recent behaviour.
        Returns anomaly_score, is_anomaly, contributing_factors.
        """
        vecs = self._extract_features(recent_alerts, source_ip)
        if not vecs:
            return {"anomaly_score": 0.0, "is_anomaly": False, "factors": []}

        vec = vecs[-1]   # most recent hour

        # Use per-IP model if available, else global
        with self._lock:
            model = self._models.get(source_ip, self._global_model)

        score   = model.score(vec)
        is_anom = model.is_anomaly(vec)

        factors = []
        alert_count, n_types, n_dests, avg_sev, off_hours, scan_ratio, hour = vec
        if alert_count > 20:
            factors.append(f"High alert volume ({int(alert_count)} alerts this hour)")
        if n_types >= 4:
            factors.append(f"Wide attack variety ({int(n_types)} different attack types)")
        if avg_sev >= 3:
            factors.append("High average alert severity")
        if off_hours:
            factors.append(f"Activity during off-hours ({int(hour):02d}:00 UTC)")
        if scan_ratio > 0.5:
            factors.append("Majority of activity is port scanning")
        if n_dests > 10:
            factors.append(f"Wide targeting ({int(n_dests)} different destinations)")

        return {
            "anomaly_score":  round(score, 3),
            "is_anomaly":     is_anom,
            "factors":        factors,
            "feature_vector": {
                "alert_count":   int(alert_count),
                "unique_types":  int(n_types),
                "unique_dests":  int(n_dests),
                "avg_severity":  round(avg_sev, 2),
                "off_hours":     bool(off_hours),
                "scan_ratio":    round(scan_ratio, 2),
            }
        }

    def detect_ueba_anomalies(self, all_alerts: list) -> list:
        """
        Run UEBA scoring across all recent active IPs.
        Returns list of anomaly dicts for IPs scoring above threshold.
        """
        now      = datetime.now(timezone.utc)
        recent   = [
            a for a in all_alerts
            if _age_minutes(a.get("timestamp",""), now) <= 60
        ]
        by_ip    = defaultdict(list)
        for a in recent:
            ip = a.get("source_ip","")
            if ip and ip != "0.0.0.0":
                by_ip[ip].append(a)

        results = []
        for ip, alerts in by_ip.items():
            scored = self.score_ip(ip, alerts)
            if scored["is_anomaly"] or scored["anomaly_score"] >= 0.55:
                results.append({
                    "type":          "ueba_anomaly",
                    "source_ip":     ip,
                    "anomaly_score": scored["anomaly_score"],
                    "severity":      "High" if scored["anomaly_score"] >= 0.70 else "Medium",
                    "description":   f"UEBA: Anomalous behaviour from {ip} (score {scored['anomaly_score']:.2f})",
                    "factors":       scored["factors"],
                    "features":      scored.get("feature_vector", {}),
                })
        return sorted(results, key=lambda x: -x["anomaly_score"])

    # ── Persistence ───────────────────────────

    def _save_baselines(self):
        """Save per-IP profile summaries (not full model weights — those retrain)."""
        try:
            summary = {
                ip: {"trained": True, "n_trees": m.n_trees}
                for ip, m in self._models.items()
            }
            with open(self._baseline_file, "w") as f:
                json.dump(summary, f)
        except Exception as e:
            logger.error("UEBA baseline save error: %s", e)

    def _load_baselines(self):
        pass   # Models retrain from alert data on startup


# ─────────────────────────────────────────────
# Singletons
# ─────────────────────────────────────────────

ueba_engine = UEBAEngine()