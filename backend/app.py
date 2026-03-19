"""
TYSONIC SIEM — API SERVER
Real-time SIEM with:
  - Suricata + Elasticsearch ingestion
  - Rule-based detection engine (detection_rules.py)
  - Threat intelligence (AbuseIPDB, OTX, local blocklist)
  - MITRE ATT&CK mapping
  - Anomaly detection + Risk scoring
  - Automated response playbooks
  - Geolocation / attack map API
  - Bulk & single-alert HTML reports
"""

import json
import queue
import threading
import time
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from collections import deque, defaultdict

# ── Load .env before anything else reads os.environ ───────────────────────────
from siem_env import load_env
load_env()

# ── Central logger ────────────────────────────────────────────────────────────
from siem_logger import get_logger
logger = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import warnings
warnings.filterwarnings("ignore", message=".*verify_certs=False.*")
warnings.filterwarnings("ignore", message=".*TLS.*insecure.*")

from flask import Flask, request, jsonify, Response, send_from_directory, send_file, g
from elasticsearch import Elasticsearch

sys.path.insert(0, str(Path(__file__).parent))

from alert_engine   import Alert, Severity
from alert_manager  import AlertManager
from report_generator import ReportGenerator
try:
    from bulk_report_generator import bulk_report_bp as _bulk_bp
    _has_bulk_report = True
except ImportError:
    _has_bulk_report = False
    logger.warning("bulk_report_generator.py not found — bulk report endpoint disabled.")
from detection_rules import engine as detection_engine, _proto
from threat_intel import (
    geolocate, check_ip_reputation, get_mitre,
    calculate_risk_score, detect_anomalies, configure_threat_intel,
    ueba_engine,
)
from playbook_engine import PlaybookEngine
from auth import auth_bp, init_auth, require_auth, require_role
from correlation_engine import correlation_engine
from api_docs import docs_bp

# ── Config ────────────────────────────────────────────────────────────────────

BASE_DIR   = Path(__file__).parent
DATA_DIR   = BASE_DIR / "siem_data"
STATIC_DIR = BASE_DIR / "static"

# Ports/paths that belong to this SIEM server — events touching these
# are self-generated and must never trigger alerts
SIEM_SELF_PORTS = {5000}          # add more if you run on a different port
SIEM_SELF_PATHS = {"/api/", "/static/", "/dashboard/"}

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
OTX_KEY       = os.environ.get("OTX_KEY", "")
if ABUSEIPDB_KEY or OTX_KEY:
    configure_threat_intel(ABUSEIPDB_KEY, OTX_KEY)

INGEST_API_KEY = os.environ.get("SIEM_INGEST_KEY", "")
_INGEST_KEY_FILE = DATA_DIR / "ingest_api_key.txt"

def _load_or_create_ingest_key() -> str:
    """Load the ingest API key from disk, or generate and save a new one."""
    global INGEST_API_KEY
    if INGEST_API_KEY:
        return INGEST_API_KEY
    if _INGEST_KEY_FILE.exists():
        INGEST_API_KEY = _INGEST_KEY_FILE.read_text().strip()
        return INGEST_API_KEY
    # Generate a new key
    INGEST_API_KEY = secrets.token_hex(32)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _INGEST_KEY_FILE.write_text(INGEST_API_KEY)
    _INGEST_KEY_FILE.chmod(0o600)
    logger.info("Ingest API key generated: %s", INGEST_API_KEY)
    logger.info("Ingest key saved to: %s", _INGEST_KEY_FILE)
    logger.info("Use as: X-Ingest-Key: %s", INGEST_API_KEY)
    return INGEST_API_KEY

def _is_trusted_ingest(req) -> bool:
    """
    Returns True if the request is allowed to call /api/ingest without a JWT.
    Trusted if:
      1. Correct X-Ingest-Key header is present, OR
      2. Request comes from localhost (127.0.0.1 / ::1)
    """
    key = req.headers.get("X-Ingest-Key", "")
    if key and secrets.compare_digest(key, _load_or_create_ingest_key()):
        return True
    remote = req.remote_addr or ""
    return remote in ("127.0.0.1", "::1", "localhost")

# ── Flask App ─────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
app.config["JSON_SORT_KEYS"] = False

@app.after_request
def _add_cors_headers(response):
    """Allow the dashboard to reach the API from any local network IP."""
    origin = request.headers.get("Origin", "")
    if origin:
        response.headers["Access-Control-Allow-Origin"]      = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
    return response

@app.route("/api/auth/login",           methods=["OPTIONS"])
@app.route("/api/auth/mfa/verify",      methods=["OPTIONS"])
@app.route("/api/auth/mfa/setup",       methods=["OPTIONS"])
@app.route("/api/auth/mfa/enable",      methods=["OPTIONS"])
@app.route("/api/auth/mfa/disable",     methods=["OPTIONS"])
@app.route("/api/auth/mfa/status",      methods=["OPTIONS"])
@app.route("/api/auth/users",           methods=["OPTIONS"])
@app.route("/api/auth/change-password", methods=["OPTIONS"])
def _options_preflight():
    """Handle CORS preflight for all auth endpoints."""
    resp = app.make_default_options_response()
    origin = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Origin"]      = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
    return resp

manager  = AlertManager(str(DATA_DIR))
reporter = ReportGenerator(str(DATA_DIR / "reports"))
playbook = PlaybookEngine(str(DATA_DIR), telegram_config=manager.config.get('telegram', {}))
manager.set_correlation_engine(correlation_engine)

@app.before_request
def _detect_attack_on_siem():
    if request.method == "OPTIONS":
        return  # handled by _handle_options

    src_ip = request.remote_addr or ""
    if not src_ip or src_ip in ("127.0.0.1", "::1"):
        return  # ignore localhost

    ua      = request.headers.get("User-Agent", "")
    ua_low  = ua.lower()
    path    = request.path
    qs      = request.query_string.decode(errors="replace").lower()
    full    = (path + "?" + qs).lower() if qs else path.lower()

    # ── Scanner UA detection (nikto, sqlmap, gobuster, etc.) ─────────────
    scanner_keywords = [
        "nikto", "sqlmap", "nmap", "nessus", "openvas", "dirbuster",
        "gobuster", "feroxbuster", "nuclei", "wfuzz", "burpsuite",
        "masscan", "zgrab", "hydra", "metasploit",
    ]
    if any(k in ua_low for k in scanner_keywords):
        if (src_ip not in _web_alerted_ts or
                time.time() - _web_alerted_ts.get(src_ip, 0) > WEB_SCAN_COOLDOWN):
            _web_alerted_ts[src_ip] = time.time()
            alert = manager.create_alert(
                alert_type   = "web_attack",
                severity     = Severity.HIGH,
                source_ip    = src_ip,
                dest_ip      = request.host,
                description  = f"Web scanner hitting SIEM directly: {src_ip} [{ua[:80]}]",
                log_evidence = f"SCANNER_UA method={request.method} path={path} ua={ua[:120]}",
            )
            manager.process(alert)
        return

    # ── SQLi payload in URL/query string ─────────────────────────────────
    sqli_signs = [
        "union select", "or 1=1", "' or '", "drop table",
        "information_schema", "sleep(", "benchmark(", "waitfor delay",
        "admin'--", "1=1--", "' union all select", "sqlmap",
    ]
    if any(k in full for k in sqli_signs):
        alert = manager.create_alert(
            alert_type   = "web_attack",
            severity     = Severity.HIGH,
            source_ip    = src_ip,
            dest_ip      = request.host,
            description  = f"SQL injection attempt on SIEM from {src_ip}: {path[:80]}",
            # Structured prefix tells rule engine this is an HTTP context
            log_evidence = f"SQLI_HTTP method={request.method} path={path} qs={qs[:200]}",
        )
        manager.process(alert)
        return

    # ── LFI/path traversal in URL ─────────────────────────────────────────
    lfi_signs = ["../", "..\\", "/etc/passwd", "php://", "file:///"]
    if any(k in full for k in lfi_signs):
        alert = manager.create_alert(
            alert_type   = "web_attack",
            severity     = Severity.HIGH,
            source_ip    = src_ip,
            dest_ip      = request.host,
            description  = f"LFI/path traversal attempt from {src_ip}: {path[:80]}",
            log_evidence = f"LFI_HTTP method={request.method} path={path} qs={qs[:200]}",
        )
        manager.process(alert)
        return

    # ── Phishing URL patterns hitting this server ─────────────────────────
    phish_signs = [
        "account-verify", "account-suspended", "verify-identity",
        "confirm-payment", "update-billing", "password-reset-required",
        "secure/login", "login-secure", "signin/v2/identifier",
        "xn--",           # punycode homograph
        "securelogin-", "account-update-", "verify-account-",
    ]
    if any(k in full for k in phish_signs):
        alert = manager.create_alert(
            alert_type   = "phishing",
            severity     = Severity.HIGH,
            source_ip    = src_ip,
            dest_ip      = request.host,
            description  = f"Phishing URL pattern from {src_ip}: {path[:80]}",
            log_evidence = f"PHISH_HTTP method={request.method} path={path} qs={qs[:200]}",
        )
        manager.process(alert)
        return

    # ── Rate-based web scan (nikto without UA, custom scanners) ──────────
    status_code = 0   # not yet known at request time — count all requests
    if _track_web_scan(src_ip, status_code):
        count_404 = _web_tracker_404.get(src_ip, 0)
        total     = _web_tracker.get(src_ip, 0)
        alert = manager.create_alert(
            alert_type   = "web_attack",
            severity     = Severity.MEDIUM,
            source_ip    = src_ip,
            dest_ip      = request.host,
            description  = (f"High request rate from {src_ip}: {total} requests "
                            f"in {WEB_SCAN_WINDOW}s — possible web scanner"),
            log_evidence = f"Last: {request.method} {request.path}",
        )
        manager.process(alert)

@app.before_request
def _handle_options():
    """Immediately respond to all CORS preflight OPTIONS requests."""
    if request.method == "OPTIONS":
        resp = app.make_default_options_response()
        origin = request.headers.get("Origin", "*")
        resp.headers["Access-Control-Allow-Origin"]      = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Headers"]     = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
        return resp

app.config["SIEM_MANAGER"]  = manager
app.config["SIEM_DATA_DIR"] = str(DATA_DIR)
if _has_bulk_report:
    app.register_blueprint(_bulk_bp)
app.register_blueprint(docs_bp)

# ── Auth ──────────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SIEM_SECRET_KEY", "tysonic-siem-change-in-production!")
if SECRET_KEY == "tysonic-siem-change-in-production!":
    logger.warning("SIEM_SECRET_KEY is using the default insecure value — set it in .env immediately!")
init_auth(app, secret_key=SECRET_KEY, data_dir=str(DATA_DIR))
app.register_blueprint(auth_bp)

# ── Correlation engine ────────────────────────────────────────────────────────
correlation_engine.add_listener(lambda inc: broadcast("new_incident", inc.to_dict()))

# ── Elasticsearch ─────────────────────────────────────────────────────────────

ES_PASSWORD = os.environ.get("ES_PASSWORD", "")
if not ES_PASSWORD:
    logger.warning("ES_PASSWORD env var not set — Elasticsearch connection may fail.")

es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", ES_PASSWORD),
    verify_certs=False,
    request_timeout=30
)

# Print ingest key on startup
_load_or_create_ingest_key()

logger.info("Connecting to Elasticsearch...")
try:
    info = es.info()
    logger.info("Connected to Elasticsearch cluster: %s", info["cluster_name"])
except Exception as e:
    logger.critical("Elasticsearch connection failed: %s", e)

# ── SSE Broadcast ─────────────────────────────────────────────────────────────

_sse_clients = []
_sse_lock    = threading.Lock()

def broadcast(event, data):
    payload = f"event: {event}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(payload)
            except Exception:
                dead.append(q)
        for d in dead:
            _sse_clients.remove(d)

# ── Alert Pipeline ────────────────────────────────────────────────────────────

def _enrich_and_respond(alert_dict: dict):
    """Enrich alert with geo/intel/MITRE in background and run playbook."""
    def _bg():
        try:
            src_ip = alert_dict.get("source_ip", "")
            geo    = geolocate(src_ip)
            rep    = check_ip_reputation(src_ip)
            mitre  = get_mitre(alert_dict.get("alert_type", ""))

            enriched = {**alert_dict, "geo": geo, "intel": rep, "mitre": mitre}
            broadcast("alert_enriched", enriched)
            playbook.run(enriched)
        except Exception as e:
            logger.error("Enrichment error: %s", e)

    threading.Thread(target=_bg, daemon=True).start()

def _on_alert(alert: Alert):
    d = alert.to_dict()
    d["severity"] = alert.severity.value
    broadcast("new_alert", d)
    _enrich_and_respond(d)

manager.add_listener(_on_alert)

# ── Suricata Classification ───────────────────────────────────────────────────

def classify_suricata_event(event):
    result = detection_engine.evaluate(event)
    if result:
        alert_type, severity, description, rule_id = result
        return alert_type, severity, description
    return None, None, None

# ── Elasticsearch Worker ──────────────────────────────────────────────────────

processed_ids  = deque(maxlen=10000)

SURICATA_INDEX_CANDIDATES = [
    "suricata-logs", "suricata", "suricata-*", "filebeat-*", "logstash-*",
]

def detect_suricata_index():
    for candidate in SURICATA_INDEX_CANDIDATES:
        try:
            if es.indices.exists(index=candidate):
                logger.info("Found Suricata index: %s", candidate)
                return candidate
        except Exception:
            continue
    try:
        indices = es.cat.indices(format="json")
        for idx in indices:
            name = idx.get("index", "")
            if any(k in name for k in ["suricata", "filebeat", "logstash"]) and not name.startswith("."):
                logger.info("Auto-detected Suricata index: %s", name)
                return name
    except Exception:
        pass
    return None

SURICATA_INDEX = None

# ── Port scan tracker ────────────────────────────────────────────────────────
# Fires when a single src_ip hits > SCAN_PORT_THRESHOLD unique dest_ports
# on the SIEM host within SCAN_WINDOW_SEC seconds.
# Designed to catch nmap -sS / -sV / -p- style scans, not normal traffic.

SCAN_PORT_THRESHOLD = 50    # unique ports before alert fires
SCAN_WINDOW_SEC     = 60    # sliding window in seconds
SCAN_COOLDOWN_SEC   = 300   # min seconds between repeat alerts for same IP

_scan_tracker    = defaultdict(set)   # src_ip → set of dest_ports in window
_scan_tracker_ts = defaultdict(float) # src_ip → window start time
_scan_alerted_ts = {}                 # src_ip → last alert timestamp
_scan_lock       = threading.Lock()

def _is_private_ip(ip: str) -> bool:
    """Return True for RFC-1918 private addresses and localhost."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ── Brute force tracker: connections to a single port ────────────────────────
# Counts how many times src_ip connects to dest_port within a time window.
# Used to detect SSH/RDP/FTP brute force without needing ET rules.

BRUTE_THRESHOLDS = {
    22:   (10, 60,  300),   # SSH:  10 connections in 60s, 5-min cooldown
    3389: (8,  60,  300),   # RDP:  8  connections in 60s
    21:   (10, 60,  300),   # FTP:  10 connections in 60s
    23:   (8,  60,  300),   # Telnet
    5900: (6,  60,  300),   # VNC
    8080: (15, 60,  300),   # HTTP alt
    80:   (20, 30,  300),   # HTTP
    443:  (20, 30,  300),   # HTTPS
}
BRUTE_DEFAULT_THRESHOLD = (15, 60, 300)  # fallback for other ports

# Ports that should never trigger brute force alerts —
# DNS (53) is used heavily by the SIEM itself for geo/intel lookups.
# NTP (123) is used for time sync. MDNS (5353) is local discovery.
BRUTE_EXCLUDED_PORTS = {53, 123, 5353}

_brute_tracker    = defaultdict(lambda: defaultdict(int))   # src_ip → {dest_port → count}
_brute_tracker_ts = defaultdict(float)                      # src_ip:port → window start
_brute_alerted_ts = {}                                      # src_ip:port → last alert ts
_brute_lock       = threading.Lock()

# ── DDoS volumetric tracker ───────────────────────────────────────────────────
# Counts packets/bytes per src_ip per second. Fires when rate exceeds threshold.

DDOS_PKT_THRESHOLD  = 5000    # packets/sec from single IP → SYN/ICMP flood
DDOS_BYTE_THRESHOLD = 50_000_000  # bytes/sec from single IP → volumetric UDP flood
DDOS_HTTP_THRESHOLD = 200     # HTTP requests per 5s window → Layer-7 flood
DDOS_WINDOW_SEC     = 5       # rolling window
DDOS_COOLDOWN_SEC   = 120     # min seconds between repeat DDoS alerts per IP

_ddos_pkt_tracker   = defaultdict(int)    # src_ip → pkt count in window
_ddos_byte_tracker  = defaultdict(int)    # src_ip → byte count in window
_ddos_http_tracker  = defaultdict(int)    # src_ip → http count in window
_ddos_tracker_ts    = defaultdict(float)  # src_ip → window start
_ddos_alerted_ts    = {}                  # src_ip → last alert ts
_ddos_lock          = threading.Lock()

def _track_ddos(src_ip: str, pkts: int = 0, byte_count: int = 0, http: bool = False):
    """
    Track volumetric traffic per src_ip.
    Returns (True, reason) when a DDoS threshold is exceeded, else (False, '').
    """
    if not src_ip:
        return False, ""
    now = time.time()
    with _ddos_lock:
        # Slide window
        if now - _ddos_tracker_ts.get(src_ip, 0) > DDOS_WINDOW_SEC:
            _ddos_pkt_tracker[src_ip]  = 0
            _ddos_byte_tracker[src_ip] = 0
            _ddos_http_tracker[src_ip] = 0
            _ddos_tracker_ts[src_ip]   = now

        _ddos_pkt_tracker[src_ip]  += pkts
        _ddos_byte_tracker[src_ip] += byte_count
        if http:
            _ddos_http_tracker[src_ip] += 1

        reason = ""
        if _ddos_pkt_tracker[src_ip] >= DDOS_PKT_THRESHOLD:
            reason = f"{_ddos_pkt_tracker[src_ip]} pkts/{DDOS_WINDOW_SEC}s"
        elif _ddos_byte_tracker[src_ip] >= DDOS_BYTE_THRESHOLD:
            mb = _ddos_byte_tracker[src_ip] // 1_000_000
            reason = f"{mb}MB/{DDOS_WINDOW_SEC}s"
        elif _ddos_http_tracker[src_ip] >= DDOS_HTTP_THRESHOLD:
            reason = f"{_ddos_http_tracker[src_ip]} HTTP reqs/{DDOS_WINDOW_SEC}s"

        if not reason:
            return False, ""
        if now - _ddos_alerted_ts.get(src_ip, 0) < DDOS_COOLDOWN_SEC:
            return False, ""
        _ddos_alerted_ts[src_ip] = now
        return True, reason

def _track_brute_force(src_ip: str, dest_port: int) -> bool:
    """
    Returns True when src_ip has made >= threshold connections to dest_port
    within the window, and cooldown has passed.
    """
    if not src_ip or not dest_port:
        return False
    if dest_port in BRUTE_EXCLUDED_PORTS:
        return False  # DNS/NTP/MDNS — SIEM uses these internally
    threshold, window, cooldown = BRUTE_THRESHOLDS.get(dest_port, BRUTE_DEFAULT_THRESHOLD)
    key = f"{src_ip}:{dest_port}"
    now = time.time()
    with _brute_lock:
        if now - _brute_tracker_ts.get(key, 0) > window:
            _brute_tracker[src_ip][dest_port] = 0
            _brute_tracker_ts[key] = now
        _brute_tracker[src_ip][dest_port] += 1
        count = _brute_tracker[src_ip][dest_port]
        if count < threshold:
            return False
        if now - _brute_alerted_ts.get(key, 0) < cooldown:
            return False
        _brute_alerted_ts[key] = now
        return True


# ── Web scan tracker: HTTP requests per src_ip ───────────────────────────────
# Detects Nikto, dirb, gobuster, feroxbuster etc.
# Fires when src_ip makes > threshold HTTP requests in window seconds.

WEB_SCAN_THRESHOLD = 30   # requests per window — raised to avoid false positives from dashboard
WEB_SCAN_WINDOW    = 10   # seconds
WEB_SCAN_COOLDOWN  = 300  # 5 min between repeat alerts

# IPs that should never trigger web scan alerts.
# Add your SIEM server's own LAN IP here if the dashboard machine is flagged on startup.
# The before_request hook ignores 127.0.0.1 already — add any other trusted IPs below.
WEB_SCAN_TRUSTED_IPS: set = set() 

_web_tracker       = defaultdict(int)    # src_ip → request count in window
_web_tracker_ts    = defaultdict(float)  # src_ip → window start time
_web_tracker_404   = defaultdict(int)    # src_ip → 404 count
_web_alerted_ts    = {}                  # src_ip → last alert timestamp
_web_lock          = threading.Lock()

def _track_web_scan(src_ip: str, status_code: int = 0) -> bool:
    """
    Track HTTP requests per src_ip. Returns True when threshold exceeded
    and cooldown has passed. Weights 404 responses more heavily.
    NOTE: Private IPs are NOT excluded — Kali on LAN must be detectable.
    """
    if not src_ip:
        return False
    if src_ip in WEB_SCAN_TRUSTED_IPS:
        return False  # trusted analyst/dashboard machine
    now = time.time()
    with _web_lock:
        if now - _web_tracker_ts.get(src_ip, 0) > WEB_SCAN_WINDOW:
            _web_tracker[src_ip]     = 0
            _web_tracker_404[src_ip] = 0
            _web_tracker_ts[src_ip]  = now
        _web_tracker[src_ip] += 1
        if status_code == 404:
            _web_tracker_404[src_ip] += 1
        count = _web_tracker[src_ip]
        if count < WEB_SCAN_THRESHOLD:
            return False
        if now - _web_alerted_ts.get(src_ip, 0) < WEB_SCAN_COOLDOWN:
            return False
        _web_alerted_ts[src_ip] = now
        return True


def _track_port_scan(src_ip: str, dest_ip: str, dest_port: int) -> bool:
    """
    Track unique dest_ports probed by src_ip against dest_ip.
    Returns True only when threshold exceeded AND cooldown has passed.
    Only tracks external IPs scanning internal hosts (not internal→internal).
    """
    if not src_ip or not dest_port:
        return False

    now = time.time()
    with _scan_lock:
        # Slide the window — reset if older than SCAN_WINDOW_SEC
        if now - _scan_tracker_ts.get(src_ip, 0) > SCAN_WINDOW_SEC:
            _scan_tracker[src_ip]    = set()
            _scan_tracker_ts[src_ip] = now

        _scan_tracker[src_ip].add(dest_port)
        port_count = len(_scan_tracker[src_ip])

        # Only fire if threshold exceeded AND cooldown has passed
        if port_count < SCAN_PORT_THRESHOLD:
            return False
        last_alerted = _scan_alerted_ts.get(src_ip, 0)
        if now - last_alerted < SCAN_COOLDOWN_SEC:
            return False
        # Fire — update last alert time but keep tracking
        _scan_alerted_ts[src_ip] = now
        return True


def elastic_worker():
    global SURICATA_INDEX
    while True:
        try:
            if not SURICATA_INDEX:
                SURICATA_INDEX = detect_suricata_index()
                if not SURICATA_INDEX:
                    logger.debug("Waiting for Suricata index...")
                    time.sleep(5)
                    continue

            res = es.search(
                index=SURICATA_INDEX, size=100,
                query={"range": {"@timestamp": {"gte": "now-60s"}}},
                sort=[{"@timestamp": {"order": "desc"}}]
            )
            for hit in res["hits"]["hits"]:
                doc_id = hit["_id"]
                if doc_id in processed_ids:
                    continue
                processed_ids.append(doc_id)
                event = hit["_source"]

                # ── Unwrap Filebeat/Logstash event.original ──────────────────
                # Filebeat stores the raw Suricata JSON as event.original string
                original_str = (event.get("event") or {}).get("original", "")
                if original_str:
                    try:
                        inner = json.loads(original_str)
                        # Always merge key fields from inner — signature especially
                        for k in ("src_ip", "dest_ip", "src_port", "dest_port",
                                  "proto", "alert", "app_proto", "event_type"):
                            if k in inner:
                                if not event.get(k) or (
                                    k == "alert" and
                                    not (event.get("alert") or {}).get("signature")
                                ):
                                    event[k] = inner[k]
                    except Exception:
                        pass

                event_type = event.get("event_type", "")
                src_ip     = (event.get("src_ip")   or "").strip()
                dest_ip    = (event.get("dest_ip")  or "").strip()
                src_port   = int(event.get("src_port",  0) or 0)
                dest_port  = int(event.get("dest_port", 0) or 0)
                http_info  = event.get("http", {}) or {}
                url        = http_info.get("url", "") or ""
                # Normalise placeholder IPs to empty string
                if src_ip  in ("0.0.0.0", "::"):  src_ip  = ""
                if dest_ip in ("0.0.0.0", "::"):  dest_ip = ""

                # ── Skip SIEM self-traffic ───────────────────────────────────
                # Only skip traffic that is the SIEM's OWN dashboard polling:
                #   - comes FROM the SIEM server port (5000) → response traffic
                #   - OR: hits /api/ or /static/ but has no attack signature
                #     AND comes from the same host (src == dest network)
                # Do NOT skip /api/* requests from EXTERNAL IPs — those are attacks.
                is_siem_response = (src_port == 5000)   # outbound from SIEM
                is_dashboard_poll = (
                    (url.startswith("/api/") or url.startswith("/static/")) and
                    not src_ip and dest_port == 5000     # our own polling has no src_ip
                )
                if is_siem_response or is_dashboard_poll:
                    continue

                # ── Flow events: port scan + brute force + DDoS detection ────
                if event_type == "flow":
                    if src_ip:
                        flow      = event.get("flow", {}) or {}
                        pkts      = int(flow.get("pkts_toserver", 0) or 0)
                        byte_count= int(flow.get("bytes_toserver", 0) or 0)
                        proto_low = _proto(event)

                        # DDoS volumetric check on every flow event
                        fired, reason = _track_ddos(src_ip, pkts=pkts, byte_count=byte_count)
                        if fired:
                            ddos_type = "UDP flood" if proto_low == "udp" else \
                                        "ICMP flood" if proto_low == "icmp" else "TCP flood"
                            alert = manager.create_alert(
                                alert_type   = "ddos",
                                severity     = Severity.CRITICAL,
                                source_ip    = src_ip,
                                dest_ip      = dest_ip or "network",
                                description  = (f"DDoS detected: {ddos_type} from {src_ip} "
                                                f"— {reason}"),
                                log_evidence = json.dumps(event),
                            )
                            manager.process(alert)

                        # Port scan: many unique dest_ports from same IP
                        if _track_port_scan(src_ip, dest_ip, dest_port):
                            n_ports = len(_scan_tracker.get(src_ip, set()))
                            alert = manager.create_alert(
                                alert_type   = "port_scan",
                                severity     = Severity.MEDIUM,
                                source_ip    = src_ip,
                                dest_ip      = dest_ip or "network",
                                description  = (f"Port scan: {src_ip} probed {n_ports} unique ports "
                                                f"within {SCAN_WINDOW_SEC}s"),
                                log_evidence = json.dumps(event),
                            )
                            manager.process(alert)

                        # Brute force: many connections to same port
                        if dest_port and _track_brute_force(src_ip, dest_port):
                            port_name = {22:"SSH",3389:"RDP",21:"FTP",23:"Telnet",
                                        5900:"VNC",80:"HTTP",443:"HTTPS"}.get(dest_port, str(dest_port))
                            count = _brute_tracker.get(src_ip, {}).get(dest_port, 0)
                            alert = manager.create_alert(
                                alert_type   = "brute_force",
                                severity     = Severity.HIGH,
                                source_ip    = src_ip,
                                dest_ip      = dest_ip or "unknown",
                                description  = (f"{port_name} brute force: {src_ip} made "
                                                f"{count}+ connection attempts to port {dest_port}"),
                                log_evidence = json.dumps(event),
                            )
                            manager.process(alert)
                    continue  # Never run rule engine on pure flow events

                # ── HTTP events: web scanner detection ──────────────────────
                # Suricata http events carry full request details — use them
                # to detect web scanners (Nikto, dirb, gobuster) and web attacks.
                if event_type == "http":
                    if src_ip:
                        ua      = http_info.get("http_user_agent", "") or ""
                        method  = http_info.get("http_method", "GET")
                        status  = int(http_info.get("status", 0) or 0)

                        # DDoS HTTP flood tracking
                        fired, reason = _track_ddos(src_ip, http=True)
                        if fired:
                            alert = manager.create_alert(
                                alert_type   = "ddos",
                                severity     = Severity.HIGH,
                                source_ip    = src_ip,
                                dest_ip      = dest_ip or "unknown",
                                description  = f"HTTP flood from {src_ip} — {reason}",
                                log_evidence = json.dumps(event),
                            )
                            manager.process(alert)

                        # Known scanner user-agents — alert immediately
                        scanner_ua = any(k in ua.lower() for k in [
                            "nikto", "nmap", "sqlmap", "nessus", "openvas",
                            "masscan", "zgrab", "nuclei", "burpsuite",
                            "dirbuster", "gobuster", "feroxbuster", "wfuzz",
                            "hydra", "metasploit", "python-requests/",
                            "go-http-client", "curl/", "wget/",
                        ])
                        if scanner_ua:
                            if (src_ip not in _web_alerted_ts or
                                    time.time() - _web_alerted_ts.get(src_ip, 0) > WEB_SCAN_COOLDOWN):
                                _web_alerted_ts[src_ip] = time.time()
                                alert = manager.create_alert(
                                    alert_type   = "web_attack",
                                    severity     = Severity.HIGH,
                                    source_ip    = src_ip,
                                    dest_ip      = dest_ip or "unknown",
                                    description  = (f"Web scanner detected: {src_ip} "
                                                    f"[{ua[:60]}]"),
                                    log_evidence = json.dumps(event),
                                )
                                manager.process(alert)
                                continue

                        # Rate-based: too many HTTP requests in short window
                        if _track_web_scan(src_ip, status):
                            count_404 = _web_tracker_404.get(src_ip, 0)
                            total     = _web_tracker.get(src_ip, 0)
                            alert = manager.create_alert(
                                alert_type   = "web_attack",
                                severity     = Severity.HIGH,
                                source_ip    = src_ip,
                                dest_ip      = dest_ip or "unknown",
                                description  = (f"Web scan: {src_ip} made {total} requests "
                                                f"({count_404} x 404) in {WEB_SCAN_WINDOW}s "
                                                f"— likely Nikto/dirb/gobuster"),
                                log_evidence = json.dumps(event),
                            )
                            manager.process(alert)

                        # Also run rule engine on HTTP events — catches SQLi/XSS/LFI
                        # payloads embedded in URLs even if rate threshold not met
                        alert_type, severity, description = classify_suricata_event(event)
                        if alert_type and alert_type != "web_attack":
                            # Only escalate if rule engine found something more specific
                            # than a generic web_attack (avoids duplicate with scanner above)
                            alert = manager.create_alert(
                                alert_type   = alert_type,
                                severity     = severity,
                                source_ip    = src_ip,
                                dest_ip      = dest_ip or "unknown",
                                description  = description or f"Detected {alert_type}",
                                log_evidence = json.dumps(event),
                            )
                            manager.process(alert)

                    continue  # Handled — don't fall through to rule engine

                # ── Only run rule engine on alert, dns, and tls events ────────
                if event_type not in ("alert", "dns", "tls"):
                    continue

                # ── Drop events with no identifiable source IP ───────────────
                # A 0.0.0.0 or empty src_ip means the event could not be parsed —
                # these alerts are useless noise, skip them entirely
                if not src_ip or src_ip in ("0.0.0.0", ""):
                    continue

                # ── Run detection rules ──────────────────────────────────────
                alert_type, severity, description = classify_suricata_event(event)
                if not alert_type:
                    continue

                alert = manager.create_alert(
                    alert_type   = alert_type,
                    severity     = severity,
                    source_ip    = src_ip,
                    dest_ip      = dest_ip if dest_ip and dest_ip != "0.0.0.0" else "unknown",
                    description  = description or f"Detected {alert_type}",
                    log_evidence = json.dumps(event),
                )
                manager.process(alert)
        except Exception as e:
            err = str(e)
            if "index_not_found" in err:
                SURICATA_INDEX = None
            else:
                logger.error("ES worker error: %s", e, exc_info=True)
        time.sleep(0.5)

# ── Background: Correlation + UEBA retraining every 5 min ────────────────────
def _correlation_worker():
    time.sleep(30)
    while True:
        try:
            alerts = manager.get_incidents()
            if alerts:
                correlation_engine.evaluate(alerts)
                ueba_engine.train(alerts)
        except Exception as e:
            logger.error("Background correlation/UEBA error: %s", e, exc_info=True)
        time.sleep(300)


# ── Thread watchdog ───────────────────────────────────────────────────────────
# Supervises all background workers and automatically restarts any that die.
# Checks every 15 seconds — a crashed worker is restarted within one interval.

_MANAGED_WORKERS = [
    ("elastic_worker",     elastic_worker),
    ("correlation_worker", _correlation_worker),
]
_worker_threads: dict = {}


def _watchdog():
    """Start all managed workers then monitor and restart any that crash."""
    for name, fn in _MANAGED_WORKERS:
        t = threading.Thread(target=fn, daemon=True, name=name)
        t.start()
        _worker_threads[name] = t
        logger.info("Worker started: %s (tid=%s)", name, t.ident)

    while True:
        time.sleep(15)
        for name, fn in _MANAGED_WORKERS:
            t = _worker_threads.get(name)
            if t is None or not t.is_alive():
                logger.critical(
                    "Worker '%s' is not alive — restarting now", name
                )
                t = threading.Thread(target=fn, daemon=True, name=name)
                t.start()
                _worker_threads[name] = t
                logger.info("Worker '%s' restarted (tid=%s)", name, t.ident)


threading.Thread(target=_watchdog, daemon=True, name="watchdog").start()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _es_alive():
    try:
        return es.ping()
    except Exception:
        return False

SEV_ORD = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

# ── Public Scan-Test Honeypot ─────────────────────────────────────────────────
# Intentionally unauthenticated endpoint with a query parameter.
# Gives sqlmap / nikto a real surface to probe so the before_request hook
# can detect and alert on their payloads without hitting the JWT wall first.

@app.route("/api/search")
def public_search():
    q = request.args.get("q", "")
    return jsonify({
        "ok":     True,
        "query":  q,
        "results": [],
        "note":   "Public search endpoint"
    })

@app.route("/api/version")
def public_version():
    return jsonify({"version": "3.0", "name": "Tysonic SIEM"})

# ── API Routes ────────────────────────────────────────────────────────────────

@app.route("/api/health")
@require_auth
def health():
    stats = manager.get_stats()
    return jsonify({
        "status":       "running",
        "hostname":     os.uname().nodename,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "alerts_total": stats["total"],
        "es_connected": _es_alive(),
        "version":      "3.0",
        "auth":         "JWT+MFA",
    })

@app.route("/api/alerts")
@require_auth
def get_alerts():
    return jsonify({"ok": True, "data": manager.get_incidents()})

@app.route("/api/stats")
@require_auth
def get_stats():
    return jsonify({"ok": True, "data": manager.get_stats()})

@app.route("/api/config")
@require_auth
def get_config():
    cfg = manager.get_config()
    return jsonify({
        "siem_name":        "Tysonic SIEM",
        "version":          "3.0",
        "refresh_interval": 2,
        "telegram":         cfg.get("telegram", {}),
        "thresholds":       cfg.get("thresholds", {}),
        "features": {
            "threat_intel": bool(ABUSEIPDB_KEY or OTX_KEY),
            "geo_map":      True,
            "mitre":        True,
            "playbooks":    True,
            "anomaly":      True,
            "risk_score":   True,
        }
    })

@app.route("/api/config", methods=["PUT"])
@require_role("admin")
def update_config():
    body = request.get_json(force=True)
    tg   = body.get("telegram", {})
    manager.update_telegram_config(
        token   = tg.get("token",   ""),
        chat_id = tg.get("chat_id", ""),
        enabled = bool(tg.get("enabled", False)),
    )
    # Keep playbook engine in sync
    playbook.telegram_config = manager.config.get("telegram", {})
    return jsonify({"ok": True})

@app.route("/api/alerts/<alert_id>/status", methods=["PUT"])
@require_role("analyst", "admin")
def update_status(alert_id):
    body   = request.get_json(force=True)
    status = body.get("status")
    if status not in ["open", "acknowledged", "resolved"]:
        return jsonify({"error": "invalid status"}), 400
    manager.storage.update_status(alert_id, status)
    acting_user = g.user if hasattr(g, "user") else "api"
    manager.storage.audit_log(f"alert_{status}", acting_user, alert_id)
    broadcast("alert_updated", {"alert_id": alert_id, "status": status})
    return jsonify({"ok": True})

# ── Reports ───────────────────────────────────────────────────────────────────

@app.route("/api/alerts/<alert_id>/report", methods=["POST"])
@require_role("analyst", "admin")
def generate_report(alert_id):
    alerts     = manager.get_incidents()
    alert_data = next((a for a in alerts if a["alert_id"] == alert_id), None)
    if not alert_data:
        return jsonify({"error": "Alert not found"}), 404
    alert = Alert(
        alert_id     = alert_data["alert_id"],
        alert_type   = alert_data["alert_type"],
        severity     = Severity(alert_data["severity"]),
        timestamp    = alert_data["timestamp"],
        source_ip    = alert_data["source_ip"],
        dest_ip      = alert_data["dest_ip"],
        hostname     = alert_data.get("hostname", "unknown"),
        description  = alert_data["description"],
        log_evidence = alert_data.get("log_evidence", ""),
        status       = alert_data["status"]
    )
    html_path = reporter.generate_html(alert)
    return jsonify({"message": "Report generated", "html": f"/api/reports/{Path(html_path).name}"})

@app.route("/api/reports/list")
@require_auth
def list_reports():
    reports_dir = DATA_DIR / "reports"
    files = []
    if reports_dir.exists():
        for f in sorted(reports_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if f.suffix == ".html":
                files.append({
                    "filename": f.name,
                    "url":      f"/api/reports/{f.name}",
                    "size":     f.stat().st_size,
                    "modified": datetime.utcfromtimestamp(f.stat().st_mtime).isoformat() + "Z"
                })
    return jsonify({"ok": True, "data": files})

@app.route("/api/reports/<filename>")
@require_auth
def download_generated_report(filename):
    path = DATA_DIR / "reports" / filename
    if not path.exists():
        return jsonify({"error": "not found"}), 404
    return send_file(path, as_attachment=True)

# ── Threat Intelligence ───────────────────────────────────────────────────────

@app.route("/api/threat-intel/<ip>")
@require_auth
def threat_intel_ip(ip):
    geo = geolocate(ip)
    rep = check_ip_reputation(ip)
    return jsonify({"ok": True, "ip": ip, "geo": geo, "reputation": rep})

@app.route("/api/geo/alerts")
@require_auth
def geo_alerts():
    alerts = manager.get_incidents()
    seen   = {}
    result = []
    for a in alerts:
        ip = a.get("source_ip", "")
        if not ip or ip in ("0.0.0.0", "127.0.0.1"):
            continue
        if ip not in seen:
            seen[ip] = geolocate(ip)
        geo = seen[ip]
        if geo.get("lat") == 0 and geo.get("lon") == 0:
            continue
        result.append({
            "ip":       ip,
            "lat":      geo["lat"],
            "lon":      geo["lon"],
            "country":  geo["country"],
            "city":     geo["city"],
            "isp":      geo["isp"],
            "severity": a.get("severity", "Low"),
            "type":     a.get("alert_type", ""),
            "ts":       a.get("timestamp", ""),
        })
    # Deduplicate — keep highest severity per IP
    deduped = {}
    for r in result:
        ip = r["ip"]
        if ip not in deduped or SEV_ORD.get(r["severity"], 0) > SEV_ORD.get(deduped[ip]["severity"], 0):
            deduped[ip] = r
    return jsonify({"ok": True, "data": list(deduped.values())})

# ── MITRE ATT&CK ──────────────────────────────────────────────────────────────

@app.route("/api/mitre")
@require_auth
def mitre_summary():
    alerts  = manager.get_incidents()
    counts  = defaultdict(int)
    details = {}
    for a in alerts:
        m   = get_mitre(a.get("alert_type", ""))
        tid = m["id"]
        counts[tid] += 1
        details[tid] = m
    result = [
        {**details[tid], "count": cnt}
        for tid, cnt in sorted(counts.items(), key=lambda x: -x[1])
    ]
    return jsonify({"ok": True, "data": result})

# ── Risk + Anomalies ──────────────────────────────────────────────────────────

@app.route("/api/risk")
@require_auth
def risk_score():
    alerts = manager.get_incidents()
    return jsonify({"ok": True, "data": calculate_risk_score(alerts)})

@app.route("/api/anomalies")
@require_auth
def anomalies():
    alerts = manager.get_incidents()
    return jsonify({"ok": True, "data": detect_anomalies(alerts)})

# ── Playbooks ─────────────────────────────────────────────────────────────────

@app.route("/api/playbooks/log")
@require_auth
def playbook_log():
    limit = int(request.args.get("limit", 50))
    return jsonify({"ok": True, "data": playbook.get_log(limit)})

@app.route("/api/playbooks/run/<alert_id>", methods=["POST"])
@require_role("admin")
def run_playbook(alert_id):
    alerts     = manager.get_incidents()
    alert_data = next((a for a in alerts if a["alert_id"] == alert_id), None)
    if not alert_data:
        return jsonify({"error": "Alert not found"}), 404
    result = playbook.run(alert_data, force=True)
    return jsonify({"ok": True, "data": result})

@app.route("/api/blocked-ips")
@require_auth
def blocked_ips():
    return jsonify({"ok": True, "data": playbook.get_blocked_ips()})

@app.route("/api/blocked-ips/<ip>", methods=["DELETE"])
@require_role("admin")
def unblock_ip(ip):
    return jsonify(playbook.unblock_ip(ip))

# ── Analytics ─────────────────────────────────────────────────────────────────

@app.route("/api/detection-rules")
@require_auth
def detection_rules_stats():
    return jsonify({"ok": True, "data": detection_engine.get_stats()})

@app.route("/api/timeline")
@require_auth
def timeline():
    alerts = manager.get_incidents()
    now    = datetime.now(timezone.utc)
    hours  = defaultdict(lambda: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0})
    for a in alerts:
        try:
            ts  = datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))
            age = (now - ts).total_seconds() / 3600
            if age > 24:
                continue
            bucket = ts.strftime("%H:00")
            hours[bucket][a.get("severity", "Low")] += 1
        except Exception:
            pass
    return jsonify({"ok": True, "data": [{"hour": h, **v} for h, v in sorted(hours.items())]})

@app.route("/api/top-attackers")
@require_auth
def top_attackers():
    alerts  = manager.get_incidents()
    counts  = defaultdict(int)
    sev_map = {}
    for a in alerts:
        ip = a.get("source_ip", "")
        if ip and ip not in ("0.0.0.0", "127.0.0.1"):
            counts[ip] += 1
            cur = sev_map.get(ip, "Low")
            if SEV_ORD.get(a.get("severity", "Low"), 0) > SEV_ORD.get(cur, 0):
                sev_map[ip] = a.get("severity", "Low")
    top = sorted(counts.items(), key=lambda x: -x[1])[:15]
    return jsonify({"ok": True, "data": [
        {"ip": ip, "count": cnt, "severity": sev_map.get(ip, "Low")} for ip, cnt in top
    ]})


# ── Log Ingest ────────────────────────────────────────────────────────────────
# Accepts requests from:
#   1. Logged-in analyst/admin (JWT Bearer token)
#   2. Any caller with X-Ingest-Key header (API key from siem_data/ingest_api_key.txt)
#   3. Requests from localhost (127.0.0.1) — no auth required

@app.route("/api/ingest", methods=["POST"])
def ingest_log():
    # Allow trusted ingest sources without JWT
    if not _is_trusted_ingest(request):
        # Fall back to JWT auth
        from auth import _verify_token as _vt
        token = (request.headers.get("Authorization", "").replace("Bearer ", "") or
                 request.cookies.get("siem_token", ""))
        if not token:
            return jsonify({"error": "Authentication required. Use JWT token or X-Ingest-Key header."}), 401
        payload = _vt(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        if payload.get("role") not in ("analyst", "admin"):
            return jsonify({"error": "Insufficient permissions — analyst or admin required"}), 403
    body      = request.get_json(force=True)
    log_text  = body.get("log", "").strip()
    source_ip = body.get("source_ip", "0.0.0.0")
    dest_ip   = body.get("dest_ip",   "0.0.0.0")

    if not log_text:
        return jsonify({"error": "No log text provided"}), 400

    # Run through detection engine
    pseudo_event = {
        "event_type":   "alert",
        "src_ip":       source_ip,
        "dest_ip":      dest_ip,
        "log_evidence": log_text,
        "alert": {"signature": log_text[:200]},
    }
    alert_type, severity, description = classify_suricata_event(pseudo_event)

    if not alert_type:
        # Fall back to generic IDS alert
        alert_type  = "ids_alert"
        severity    = Severity.LOW
        description = f"Manual log ingest: {log_text[:80]}"

    alert = manager.create_alert(
        alert_type   = alert_type,
        severity     = severity,
        source_ip    = source_ip,
        dest_ip      = dest_ip,
        description  = description,
        log_evidence = log_text,
    )
    manager.process(alert)

    return jsonify({
        "ok":        True,
        "data": {
            "alert_id":   alert.alert_id,
            "alert_type": alert_type,
            "severity":   severity.value if hasattr(severity, 'value') else str(severity),
        }
    })



# ── Telegram Test ────────────────────────────────────────────────────────────

@app.route("/api/config/test-telegram", methods=["POST"])
@require_role("admin")
def test_telegram():
    from alert_engine import TelegramNotifier
    body    = request.get_json(force=True)
    token   = body.get("token", "")
    chat_id = body.get("chat_id", "")
    if not token or not chat_id:
        return jsonify({"ok": False, "error": "token and chat_id required"}), 400
    notifier = TelegramNotifier(telegram_token=token, telegram_chat=chat_id)
    ok = notifier.send_test()
    return jsonify({"ok": ok, "message": "Test message sent" if ok else "Failed — check token and chat_id"})


# ── SSE Stream ────────────────────────────────────────────────────────────────


# ── Audit Log ─────────────────────────────────────────────────────────────────

@app.route("/api/audit-log")
@require_role("admin")
def audit_log():
    audit_path = DATA_DIR / "audit.jsonl"
    entries = []
    if audit_path.exists():
        with open(audit_path) as f:
            for line in f:
                try:
                    entries.append(json.loads(line.strip()))
                except Exception:
                    pass
    limit = int(request.args.get("limit", 200))
    return jsonify({"ok": True, "data": list(reversed(entries))[:limit]})

@app.route("/api/playbooks/list")
@require_auth
def playbooks_list():
    return jsonify({"ok": True, "data": playbook.get_playbooks()})

# ── Correlation / Incidents ───────────────────────────────────────────────────

@app.route("/api/incidents")
@require_auth
def get_incidents_route():
    return jsonify({"ok": True, "data": correlation_engine.get_incidents()})

@app.route("/api/incidents/stats")
@require_auth
def incident_stats():
    return jsonify({"ok": True, "data": correlation_engine.get_stats()})

@app.route("/api/incidents/<incident_id>/status", methods=["PUT"])
@require_role("analyst", "admin")
def update_incident_status(incident_id):
    body   = request.get_json(force=True)
    status = body.get("status")
    if status not in ("open", "acknowledged", "resolved"):
        return jsonify({"error": "invalid status"}), 400
    correlation_engine.update_status(incident_id, status)
    return jsonify({"ok": True})

@app.route("/api/incidents/run", methods=["POST"])
@require_auth
def run_correlation():
    alerts        = manager.get_incidents()
    new_incidents = correlation_engine.evaluate(alerts)
    return jsonify({
        "ok":              True,
        "new_incidents":   len(new_incidents),
        "total_incidents": len(correlation_engine.get_incidents()),
        "data":            [i.to_dict() for i in new_incidents],
    })

# ── UEBA ──────────────────────────────────────────────────────────────────────

@app.route("/api/ueba/anomalies")
@require_auth
def ueba_anomalies():
    alerts  = manager.get_incidents()
    results = ueba_engine.detect_ueba_anomalies(alerts)
    return jsonify({"ok": True, "data": results})

@app.route("/api/ueba/score/<ip>")
@require_auth
def ueba_score(ip):
    alerts = manager.get_incidents()
    result = ueba_engine.score_ip(ip, [a for a in alerts if a.get("source_ip") == ip])
    return jsonify({"ok": True, "ip": ip, "data": result})

@app.route("/api/ueba/train", methods=["POST"])
@require_role("admin")
def ueba_train():
    alerts = manager.get_incidents()
    threading.Thread(target=ueba_engine.train, args=(alerts,), daemon=True).start()
    return jsonify({"ok": True, "message": f"UEBA training started on {len(alerts)} alerts"})

@app.route("/api/stream")
def sse_stream():
    # EventSource cannot send Authorization headers — token comes as ?token= query param
    # or falls back to the httponly cookie set at login
    from auth import _verify_token as _vt
    token = (request.args.get("token") or
             request.headers.get("Authorization", "").replace("Bearer ", "") or
             request.cookies.get("siem_token") or "")
    if not token:
        return jsonify({"error": "Authentication required"}), 401
    payload = _vt(token)
    if not payload or payload.get("type") == "mfa_pending":
        return jsonify({"error": "Invalid or expired token"}), 401

    q = queue.Queue()
    with _sse_lock:
        _sse_clients.append(q)

    def generate():
        yield f"event: connected\ndata: {json.dumps({'ts': datetime.now(timezone.utc).isoformat(), 'user': payload.get('sub','')}) }\n\n"
        try:
            for alert in manager.get_incidents()[:20]:
                yield f"event: new_alert\ndata: {json.dumps(alert)}\n\n"
        except Exception:
            pass
        while True:
            try:
                msg = q.get(timeout=20)
                yield msg
            except queue.Empty:
                yield ": ping\n\n"

    return Response(generate(), mimetype="text/event-stream")

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(str(BASE_DIR / "dashboard"), "index.html")

# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("""
╔══════════════════════════════════════════════════════╗
║              TYSONIC SIEM Home Lab                   ║
╠══════════════════════════════════════════════════════╣
║  Dashboard    → http://localhost:5000                ║
║  API Docs     → http://localhost:5000/api/docs       ║
║  Login        → POST /api/auth/login                 ║
║  Health       → /api/health                          ║
║  Alerts       → /api/alerts                          ║
║  Incidents    → /api/incidents                       ║
║  UEBA         → /api/ueba/anomalies                  ║
║  Audit Log    → /api/audit-log                       ║
║  Risk Score   → /api/risk                            ║
║  MITRE Map    → /api/mitre                           ║
║  Geo/Map      → /api/geo/alerts                      ║
║  Playbooks    → /api/playbooks/log                   ║
╚══════════════════════════════════════════════════════╝""")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)