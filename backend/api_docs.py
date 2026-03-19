"""
SIEM API Documentation
Serves:
  GET /api/docs              -> Custom two-panel API docs UI
  GET /api/docs/openapi.json -> OpenAPI 3.0 JSON spec

Register in app.py:
    from api_docs import docs_bp
    app.register_blueprint(docs_bp)
"""

from flask import Blueprint, jsonify, Response

docs_bp = Blueprint("docs", __name__)

# ── OpenAPI 3.0 Specification ─────────────────────────────────────────────────

OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "Tysonic SIEM API",
        "version": "3.0.0",
        "description": "SIEM REST API. Authenticate via POST /api/auth/login to get a JWT token.",
        "contact": {"name": "Tysonic SIEM"},
    },
    "servers": [{"url": "/", "description": "This server"}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
        },
    },
    "security": [{"bearerAuth": []}],
    "paths": {
        "/api/auth/login":            {"post": {"tags": ["Authentication"], "summary": "Login", "security": [], "responses": {"200": {"description": "JWT token"}}}},
        "/api/auth/mfa/verify":       {"post": {"tags": ["Authentication"], "summary": "Verify MFA code", "responses": {"200": {"description": "Full JWT"}}}},
        "/api/auth/mfa/setup":        {"get":  {"tags": ["Authentication"], "summary": "Get MFA QR code", "responses": {"200": {"description": "QR data"}}}},
        "/api/auth/mfa/enable":       {"post": {"tags": ["Authentication"], "summary": "Activate MFA", "responses": {"200": {"description": "Enabled"}}}},
        "/api/auth/change-password":  {"post": {"tags": ["Authentication"], "summary": "Change password", "responses": {"200": {"description": "Changed"}}}},
        "/api/alerts":                {"get":  {"tags": ["Alerts"], "summary": "List all alerts", "responses": {"200": {"description": "Alert array"}}}},
        "/api/stats":                 {"get":  {"tags": ["Alerts"], "summary": "Alert counts by severity", "responses": {"200": {"description": "Stats"}}}},
        "/api/timeline":              {"get":  {"tags": ["Alerts"], "summary": "Hourly alert volume", "responses": {"200": {"description": "Timeline"}}}},
        "/api/top-attackers":         {"get":  {"tags": ["Alerts"], "summary": "Top 15 source IPs", "responses": {"200": {"description": "Attackers"}}}},
        "/api/detection-rules":       {"get":  {"tags": ["Alerts"], "summary": "Rule hit counts", "responses": {"200": {"description": "Rules"}}}},
        "/api/ingest":                {"post": {"tags": ["Ingest"], "summary": "Submit raw log line", "responses": {"200": {"description": "Alert created"}}}},
        "/api/threat-intel/{ip}":     {"get":  {"tags": ["Threat Intel"], "summary": "Geo + reputation for IP", "responses": {"200": {"description": "Intel"}}}},
        "/api/geo/alerts":            {"get":  {"tags": ["Threat Intel"], "summary": "Alert IPs with geo coords", "responses": {"200": {"description": "Geo data"}}}},
        "/api/mitre":                 {"get":  {"tags": ["Threat Intel"], "summary": "MITRE ATT&CK counts", "responses": {"200": {"description": "Techniques"}}}},
        "/api/risk":                  {"get":  {"tags": ["Threat Intel"], "summary": "Current risk score", "responses": {"200": {"description": "Score"}}}},
        "/api/anomalies":             {"get":  {"tags": ["Threat Intel"], "summary": "Statistical anomalies", "responses": {"200": {"description": "Anomalies"}}}},
        "/api/ueba/anomalies":        {"get":  {"tags": ["Threat Intel"], "summary": "UEBA ML anomaly scores", "responses": {"200": {"description": "Results"}}}},
        "/api/ueba/score/{ip}":       {"get":  {"tags": ["Threat Intel"], "summary": "UEBA score for one IP", "responses": {"200": {"description": "Score"}}}},
        "/api/ueba/train":            {"post": {"tags": ["Threat Intel"], "summary": "Retrain UEBA model", "responses": {"200": {"description": "Started"}}}},
        "/api/incidents":             {"get":  {"tags": ["Incidents"], "summary": "List incidents", "responses": {"200": {"description": "Incidents"}}}},
        "/api/incidents/run":         {"post": {"tags": ["Incidents"], "summary": "Run correlation engine", "responses": {"200": {"description": "Result"}}}},
        "/api/incidents/stats":       {"get":  {"tags": ["Incidents"], "summary": "Incident statistics", "responses": {"200": {"description": "Stats"}}}},
        "/api/playbooks/list":        {"get":  {"tags": ["Playbooks"], "summary": "List playbooks", "responses": {"200": {"description": "Playbooks"}}}},
        "/api/playbooks/log":         {"get":  {"tags": ["Playbooks"], "summary": "Execution log", "responses": {"200": {"description": "Log"}}}},
        "/api/blocked-ips":           {"get":  {"tags": ["Playbooks"], "summary": "List blocked IPs", "responses": {"200": {"description": "IPs"}}}},
        "/api/alerts/{alert_id}/report": {"post": {"tags": ["Reports"], "summary": "Generate report", "responses": {"200": {"description": "Created"}}}},
        "/api/reports/list":          {"get":  {"tags": ["Reports"], "summary": "List report files", "responses": {"200": {"description": "Files"}}}},
        "/api/health":                {"get":  {"tags": ["System"], "summary": "Server health", "responses": {"200": {"description": "Health"}}}},
        "/api/config":                {"get":  {"tags": ["System"], "summary": "Get config", "responses": {"200": {"description": "Config"}}},
                                       "put":  {"tags": ["System"], "summary": "Update config", "responses": {"200": {"description": "Updated"}}}},
        "/api/audit-log":             {"get":  {"tags": ["System"], "summary": "Audit trail", "responses": {"200": {"description": "Entries"}}}},
        "/api/stream":                {"get":  {"tags": ["System"], "summary": "SSE stream", "responses": {"200": {"description": "Stream"}}}},
        "/api/search":                {"get":  {"tags": ["Public"], "summary": "Public search (honeypot)", "security": [], "responses": {"200": {"description": "Results"}}}},
        "/api/version":               {"get":  {"tags": ["Public"], "summary": "Version info", "security": [], "responses": {"200": {"description": "Version"}}}},
    },
}


@docs_bp.route("/api/docs/openapi.json")
def openapi_json():
    return jsonify(OPENAPI_SPEC)


# ── Docs HTML ─────────────────────────────────────────────────────────────────

_DOCS_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TYSONIC SIEM  — API Reference</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#f0f4f8;--bg2:#ffffff;--bg3:#f8fafc;--border:#dde3ec;--border2:#c8d3e0;--cyan:#0284c7;--cyan2:#0369a1;--green:#16a34a;--orange:#ea580c;--red:#dc2626;--yellow:#b45309;--purple:#7c3aed;--text:#1e293b;--muted:#64748b;--dim:#94a3b8;--mono:'Space Mono',monospace;--sans:'Syne',sans-serif;}
*{margin:0;padding:0;box-sizing:border-box;}html{scroll-behavior:smooth;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);overflow-x:hidden;}
::-webkit-scrollbar{width:6px;}::-webkit-scrollbar-track{background:var(--bg);}::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px;}
#sidebar{position:fixed;left:0;top:0;bottom:0;width:240px;background:var(--bg2);border-right:1px solid var(--border);z-index:100;display:flex;flex-direction:column;overflow-y:auto;}
.sb-logo{padding:22px 20px 14px;border-bottom:1px solid var(--border);}
.sb-logo .name{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--cyan);letter-spacing:2px;}
.sb-logo .ver{font-family:var(--mono);font-size:10px;color:var(--muted);margin-top:3px;letter-spacing:1px;}
.sb-status{display:flex;align-items:center;gap:6px;padding:9px 20px;background:rgba(22,163,74,.06);border-bottom:1px solid var(--border);font-family:var(--mono);font-size:10px;color:var(--green);letter-spacing:1px;}
.sb-dot{width:7px;height:7px;background:var(--green);border-radius:50%;animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.sb-sw{padding:10px 14px;border-bottom:1px solid var(--border);}
.sb-si{width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:6px 10px;font-family:var(--mono);font-size:11px;color:var(--text);outline:none;}
.sb-si:focus{border-color:var(--cyan);}
.sb-si::placeholder{color:var(--dim);}
.nav-sec{padding:12px 20px 4px;font-family:var(--mono);font-size:9px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;}
.nav-item{display:flex;align-items:center;gap:8px;padding:8px 20px;cursor:pointer;font-family:var(--mono);font-size:11px;color:var(--muted);letter-spacing:.5px;border-left:2px solid transparent;transition:all .12s;text-decoration:none;}
.nav-item:hover{color:var(--text);background:rgba(0,0,0,.04);}
.nav-item.active{color:var(--cyan);border-left-color:var(--cyan);background:rgba(2,132,199,.08);}
.nav-item .ico{font-size:12px;width:16px;text-align:center;flex-shrink:0;}
.nav-cnt{margin-left:auto;font-size:9px;padding:1px 6px;border-radius:8px;background:var(--bg3);color:var(--dim);}
#main{margin-left:240px;min-height:100vh;}
#hero{padding:56px 56px 44px;border-bottom:1px solid var(--border);background:linear-gradient(135deg,var(--bg2) 0%,var(--bg) 100%);position:relative;overflow:hidden;}
#hero::before{content:'';position:absolute;inset:0;pointer-events:none;background:radial-gradient(ellipse at top right,rgba(2,132,199,.06) 0%,transparent 60%);}
.hero-badge{display:inline-flex;align-items:center;gap:8px;background:rgba(2,132,199,.08);border:1px solid rgba(2,132,199,.25);border-radius:4px;padding:4px 12px;font-family:var(--mono);font-size:10px;color:var(--cyan);letter-spacing:2px;margin-bottom:18px;}
.hero-title{font-size:52px;font-weight:800;line-height:1.05;background:linear-gradient(135deg,#1e293b 30%,var(--cyan) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:10px;}
.hero-sub{font-size:15px;color:var(--muted);margin-bottom:28px;max-width:540px;line-height:1.6;}
.hero-stats{display:flex;gap:32px;flex-wrap:wrap;}
.hero-stat .num{font-family:var(--mono);font-size:26px;font-weight:700;color:var(--cyan);}
.hero-stat .lbl{font-family:var(--mono);font-size:10px;color:var(--muted);letter-spacing:1px;}
.section{padding:44px 56px;border-bottom:1px solid var(--border);opacity:0;transform:translateY(18px);transition:opacity .5s,transform .5s;}
.section.visible{opacity:1;transform:translateY(0);}
.sec-hdr{display:flex;align-items:center;gap:14px;margin-bottom:22px;}
.sec-num{font-family:var(--mono);font-size:11px;color:var(--cyan);background:rgba(2,132,199,.08);border:1px solid rgba(2,132,199,.25);padding:3px 8px;border-radius:3px;letter-spacing:1px;}
.sec-title{font-size:22px;font-weight:700;color:var(--text);}
.sec-desc{font-family:var(--mono);font-size:12px;color:var(--muted);line-height:1.6;margin-bottom:18px;}
.info-box{background:rgba(2,132,199,.05);border:1px solid rgba(2,132,199,.2);border-radius:5px;padding:12px 16px;margin-bottom:14px;font-family:var(--mono);font-size:12px;color:var(--text);line-height:1.7;}
.info-box code{background:rgba(2,132,199,.1);color:var(--cyan);padding:1px 5px;border-radius:3px;font-size:11px;}
.warn-box{background:rgba(180,83,9,.04);border:1px solid rgba(180,83,9,.2);border-radius:5px;padding:12px 16px;margin-bottom:14px;font-family:var(--mono);font-size:12px;color:var(--text);line-height:1.7;}
.warn-box code{background:rgba(180,83,9,.08);color:var(--yellow);padding:1px 5px;border-radius:3px;font-size:11px;}
.GET{background:rgba(22,163,74,.1);color:var(--green);border:1px solid rgba(22,163,74,.25);}
.POST{background:rgba(2,132,199,.1);color:var(--cyan);border:1px solid rgba(2,132,199,.25);}
.PUT{background:rgba(180,83,9,.1);color:var(--yellow);border:1px solid rgba(180,83,9,.25);}
.DELETE{background:rgba(220,38,38,.1);color:var(--red);border:1px solid rgba(220,38,38,.25);}
.mbadge{font-family:var(--mono);font-size:10px;font-weight:700;padding:3px 9px;border-radius:4px;flex-shrink:0;}
.auth-pub{background:rgba(100,116,139,.08);color:var(--muted);border:1px solid var(--border);}
.auth-jwt{background:rgba(124,58,237,.08);color:var(--purple);border:1px solid rgba(124,58,237,.2);}
.auth-an{background:rgba(234,88,12,.08);color:var(--orange);border:1px solid rgba(234,88,12,.2);}
.auth-adm{background:rgba(220,38,38,.08);color:var(--red);border:1px solid rgba(220,38,38,.2);}
.auth-key{background:rgba(22,163,74,.08);color:var(--green);border:1px solid rgba(22,163,74,.2);}
.achip{font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 8px;border-radius:10px;letter-spacing:.5px;flex-shrink:0;}
.ep-card{background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:10px;overflow:hidden;}
.ep-card:hover{box-shadow:0 2px 10px rgba(0,0,0,.06);}
.ep-hdr{display:flex;align-items:center;gap:10px;padding:11px 16px;cursor:pointer;border-bottom:1px solid var(--border);transition:background .12s;user-select:none;}
.ep-hdr:hover{background:var(--bg3);}
.ep-hdr.closed{border-bottom:none;}
.ep-path{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--text);}
.ep-sum{font-size:11px;color:var(--muted);margin-top:2px;}
.chev{color:var(--dim);font-size:11px;transition:transform .2s;flex-shrink:0;margin-left:auto;}
.chev.closed{transform:rotate(-90deg);}
.ep-body{display:block;}
.ep-body.closed{display:none;}
.ep-desc{font-family:var(--mono);font-size:12px;color:var(--text);line-height:1.7;padding:12px 16px 10px;border-bottom:1px solid var(--border);background:rgba(2,132,199,.02);}
.tabs{display:flex;border-bottom:1px solid var(--border);padding:0 16px;background:var(--bg3);}
.tab{font-family:var(--mono);font-size:10px;padding:8px 12px;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:color .12s;letter-spacing:.5px;text-transform:uppercase;}
.tab:hover{color:var(--text);}
.tab.active{color:var(--cyan);border-bottom-color:var(--cyan);}
.panel{padding:16px;display:none;}
.panel.active{display:block;}
.dt{width:100%;border-collapse:collapse;}
.dt th{background:var(--bg3);color:var(--muted);font-family:var(--mono);font-size:9px;letter-spacing:2px;text-transform:uppercase;padding:7px 12px;text-align:left;border-bottom:1px solid var(--border);}
.dt td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top;font-family:var(--mono);font-size:11px;}
.dt tr:last-child td{border-bottom:none;}
.pn{color:var(--cyan);font-weight:700;}.pt{color:var(--purple);}.pd{color:var(--muted);}
.rtag{background:rgba(220,38,38,.07);color:var(--red);border:1px solid rgba(220,38,38,.2);font-size:8px;padding:1px 4px;border-radius:2px;}
.otag{background:rgba(148,163,184,.07);color:var(--dim);border:1px solid var(--border);font-size:8px;padding:1px 4px;border-radius:2px;}
.ptag{background:rgba(180,83,9,.07);color:var(--yellow);border:1px solid rgba(180,83,9,.2);font-size:8px;padding:1px 4px;border-radius:2px;}
.cb{background:var(--bg3);border:1px solid var(--border2);border-left:3px solid var(--cyan);border-radius:4px;padding:12px 14px;font-family:var(--mono);font-size:11px;line-height:1.8;overflow-x:auto;position:relative;margin-bottom:8px;white-space:pre;}
.cpcopy{position:absolute;top:7px;right:8px;font-family:var(--mono);font-size:8px;padding:2px 6px;border:1px solid var(--border2);border-radius:2px;background:var(--bg2);color:var(--muted);cursor:pointer;}
.cpcopy:hover{color:var(--cyan);border-color:var(--cyan);}
.rrow{display:flex;align-items:flex-start;gap:8px;margin-bottom:8px;}
.rcode{font-family:var(--mono);font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px;flex-shrink:0;margin-top:2px;}
.s200,.s201{background:rgba(22,163,74,.1);color:var(--green);border:1px solid rgba(22,163,74,.2);}
.s400{background:rgba(180,83,9,.1);color:var(--yellow);border:1px solid rgba(180,83,9,.2);}
.s401,.s403{background:rgba(220,38,38,.1);color:var(--red);border:1px solid rgba(220,38,38,.2);}
.s404{background:rgba(100,116,139,.1);color:var(--muted);border:1px solid var(--border);}
.rdesc{font-family:var(--mono);font-size:11px;color:var(--muted);margin-bottom:4px;}
.try-wrap{background:var(--bg3);border-radius:5px;padding:14px;}
.trlbl{font-family:var(--mono);font-size:9px;color:var(--muted);letter-spacing:2px;text-transform:uppercase;margin-bottom:4px;}
.trin{width:100%;background:var(--bg2);border:1px solid var(--border2);border-radius:4px;padding:7px 10px;font-family:var(--mono);font-size:11px;color:var(--text);outline:none;margin-bottom:8px;}
.trin:focus{border-color:var(--cyan);}
.trta{min-height:64px;resize:vertical;}
.trrow{display:flex;gap:7px;margin-bottom:6px;}
.trsend{font-family:var(--mono);font-size:11px;font-weight:700;padding:7px 14px;border-radius:4px;background:var(--cyan);color:#fff;border:none;cursor:pointer;}
.trsend:hover{background:var(--cyan2);}
.trclear{font-family:var(--mono);font-size:11px;padding:7px 12px;border-radius:4px;background:var(--bg2);color:var(--muted);border:1px solid var(--border2);cursor:pointer;}
.trres{display:none;margin-top:8px;background:var(--bg2);border:1px solid var(--border2);border-left:3px solid var(--border2);border-radius:4px;padding:10px;font-family:var(--mono);font-size:11px;color:var(--muted);line-height:1.6;max-height:220px;overflow-y:auto;}
.trres.show{display:block;}
.rok{color:var(--green);font-weight:700;}.rerr{color:var(--red);font-weight:700;}
</style>
</head>
<body>

<nav id="sidebar">
  <div class="sb-logo">
    <div class="name">TYSONIC SIEM</div>
    <div class="ver">&middot; API REFERENCE</div>
  </div>
  <div class="sb-status"><div class="sb-dot"></div>35+ ENDPOINTS</div>
  <div class="sb-sw">
    <input class="sb-si" id="sb-search" placeholder="&#128269; Search..." oninput="filterNav(this.value)">
  </div>
  <div class="nav-sec">GETTING STARTED</div>
  <a class="nav-item active" href="#hero"><span class="ico">&#127968;</span>Overview</a>
  <a class="nav-item" href="#s-start"><span class="ico">&#128274;</span>Authentication</a>
  <a class="nav-item" href="#s-errors"><span class="ico">&#9888;&#65039;</span>Error Handling</a>
  <div class="nav-sec">ENDPOINTS</div>
  <a class="nav-item" href="#g-auth"><span class="ico">&#128273;</span>Authentication <span class="nav-cnt">5</span></a>
  <a class="nav-item" href="#g-alerts"><span class="ico">&#128680;</span>Alerts <span class="nav-cnt">6</span></a>
  <a class="nav-item" href="#g-ingest"><span class="ico">&#128229;</span>Log Ingest <span class="nav-cnt">1</span></a>
  <a class="nav-item" href="#g-intel"><span class="ico">&#127758;</span>Threat Intel <span class="nav-cnt">8</span></a>
  <a class="nav-item" href="#g-incidents"><span class="ico">&#128279;</span>Incidents <span class="nav-cnt">4</span></a>
  <a class="nav-item" href="#g-playbooks"><span class="ico">&#129302;</span>Playbooks <span class="nav-cnt">5</span></a>
  <a class="nav-item" href="#g-reports"><span class="ico">&#128196;</span>Reports <span class="nav-cnt">3</span></a>
  <a class="nav-item" href="#g-system"><span class="ico">&#9881;&#65039;</span>System <span class="nav-cnt">8</span></a>
  <div class="nav-sec">LINKS</div>
  <a class="nav-item" href="/api/docs/openapi.json" target="_blank"><span class="ico">&#128196;</span>OpenAPI JSON</a>
  <a class="nav-item" href="/"><span class="ico">&#8592;</span>Dashboard</a>
</nav>

<div id="main">
  <div id="hero" class="section" style="opacity:1;transform:none;">
    <div class="hero-badge">&#9889; REST API &middot; JSON &middot; JWT AUTH</div>
    <div class="hero-title">API Reference</div>
    <div class="hero-sub">Complete REST API for TYSONIC SIEM &mdash; all endpoints, request/response schemas, and a live try-it console.</div>
    <div class="hero-stats">
      <div class="hero-stat"><div class="num">35+</div><div class="lbl">ENDPOINTS</div></div>
      <div class="hero-stat"><div class="num">8</div><div class="lbl">GROUPS</div></div>
      <div class="hero-stat"><div class="num">JWT</div><div class="lbl">AUTH METHOD</div></div>
      <div class="hero-stat"><div class="num">SSE</div><div class="lbl">REALTIME</div></div>
    </div>
  </div>

  <div id="s-start" class="section">
    <div class="sec-hdr"><span class="sec-num">START</span><span class="sec-title">Getting Started</span></div>
    <div class="info-box">
      <strong>Step 1</strong> &mdash; Login via <code>POST /api/auth/login</code> to get a JWT token.<br>
      <strong>Step 2</strong> &mdash; Click any endpoint in the left sidebar.<br>
      <strong>Step 3</strong> &mdash; Paste your token in the Try It console and hit Send.
    </div>
    <div class="warn-box"><strong>SSE exception</strong> &mdash; <code>GET /api/stream</code> requires <code>?token=JWT</code> as a query param since EventSource cannot send Authorization headers.</div>
    <div style="font-family:var(--mono);font-size:9px;color:var(--muted);letter-spacing:2px;margin-bottom:10px;">ROLE PERMISSIONS</div>
    <table class="dt">
      <tr><th>ROLE</th><th>ACCESS LEVEL</th><th>PERMISSIONS</th></tr>
      <tr><td class="pn">viewer</td><td class="pd">Read-only</td><td class="pd">Alerts, stats, timeline, geo map, MITRE, risk score</td></tr>
      <tr><td class="pn">analyst</td><td class="pd">Read + Write</td><td class="pd">All viewer + acknowledge/resolve alerts, generate reports, run playbooks</td></tr>
      <tr><td class="pn">admin</td><td class="pd">Full access</td><td class="pd">All analyst + manage users, config, audit log, unblock IPs, train UEBA</td></tr>
    </table>
  </div>

  <div id="s-errors" class="section">
    <div class="sec-hdr"><span class="sec-num">ERR</span><span class="sec-title">Error Handling</span></div>
    <div class="sec-desc">All errors return JSON with an <code style="background:rgba(220,38,38,.08);color:var(--red);padding:1px 5px;border-radius:3px;">error</code> field. Success always includes <code style="background:rgba(22,163,74,.08);color:var(--green);padding:1px 5px;border-radius:3px;">ok: true</code>.</div>
    <table class="dt">
      <tr><th>STATUS</th><th>MEANING</th><th>EXAMPLE RESPONSE</th></tr>
      <tr><td style="color:var(--green)">200 OK</td><td class="pd">Success</td><td class="pd">{"ok": true, "data": [...]}</td></tr>
      <tr><td style="color:var(--yellow)">400 Bad Request</td><td class="pd">Missing or invalid field</td><td class="pd">{"error": "No log text provided"}</td></tr>
      <tr><td style="color:var(--red)">401 Unauthorized</td><td class="pd">Token missing or expired</td><td class="pd">{"error": "Authentication required"}</td></tr>
      <tr><td style="color:var(--red)">403 Forbidden</td><td class="pd">Role insufficient</td><td class="pd">{"error": "Admin role required"}</td></tr>
      <tr><td style="color:var(--muted)">404 Not Found</td><td class="pd">Resource not found</td><td class="pd">{"error": "Alert not found"}</td></tr>
    </table>
  </div>

  <div id="ep-sections"></div>
</div>

<script>
const GROUPS = [{"id":"g-auth","num":"01","icon":"🔑","label":"Authentication","desc":"Login, MFA setup, token management and password change.","eps":[{"m":"POST","p":"/api/auth/login","a":"pub","s":"Login — get JWT token","desc":"Returns full JWT (8h TTL) if MFA disabled. Returns short-lived mfa_token (5 min) if MFA enabled.","body":[{"n":"username","t":"string","r":1,"d":"Account username"},{"n":"password","t":"string","r":1,"d":"Account password"}],"res":[{"c":200,"l":"Token returned","b":"{ \"ok\": true, \"token\": \"eyJhbGciOiJIUzI1NiJ9...\", \"role\": \"admin\" }"},{"c":200,"l":"MFA required","b":"{ \"mfa_required\": true, \"mfa_token\": \"eyJ...\" }"},{"c":401,"l":"Invalid credentials","b":"{ \"error\": \"Invalid credentials\" }"}],"ex":"curl -s -X POST http://localhost:5000/api/auth/login \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"username\":\"admin\",\"password\":\"Admin@SIEM2025!\"}'","tryable":true,"tbody":"{\"username\":\"admin\",\"password\":\"Admin@SIEM2025!\"}"},{"m":"POST","p":"/api/auth/mfa/verify","a":"jwt","s":"Verify MFA code — get full JWT","desc":"Submit the 6-digit TOTP code from Google Authenticator along with the mfa_token from login.","body":[{"n":"mfa_token","t":"string","r":1,"d":"Short-lived token from login response"},{"n":"totp_code","t":"string","r":1,"d":"6-digit Google Authenticator code"}],"res":[{"c":200,"l":"Verified","b":"{ \"token\": \"eyJ...\" }"},{"c":401,"l":"Invalid code","b":"{ \"error\": \"Invalid TOTP code\" }"}],"ex":"curl -s -X POST http://localhost:5000/api/auth/mfa/verify \\\n  -d '{\"mfa_token\":\"eyJ...\",\"totp_code\":\"123456\"}'"},{"m":"GET","p":"/api/auth/mfa/setup","a":"jwt","s":"Get QR code for Google Authenticator","desc":"Returns TOTP secret, QR URI, SVG and base64 PNG. Scan with Google Authenticator before calling mfa/enable.","res":[{"c":200,"l":"QR data","b":"{ \"secret\": \"BASE32SECRET\", \"qr_uri\": \"otpauth://totp/...\", \"qr_png_b64\": \"iVBOR...\" }"}],"ex":"curl -s http://localhost:5000/api/auth/mfa/setup \\\n  -H \"Authorization: Bearer $TOKEN\""},{"m":"POST","p":"/api/auth/mfa/enable","a":"jwt","s":"Activate MFA after scanning QR","desc":"Enable MFA for the current user. Must provide the current TOTP code to confirm the device is correctly configured.","body":[{"n":"totp_code","t":"string","r":1,"d":"6-digit code to confirm setup"}],"res":[{"c":200,"l":"MFA enabled","b":"{ \"ok\": true }"},{"c":400,"l":"Invalid code","b":"{ \"error\": \"Invalid TOTP code\" }"}],"ex":"curl -s -X POST http://localhost:5000/api/auth/mfa/enable \\\n  -H \"Authorization: Bearer $TOKEN\" \\\n  -d '{\"totp_code\":\"123456\"}'"},{"m":"POST","p":"/api/auth/change-password","a":"jwt","s":"Change current user password","desc":"Change password for the authenticated user. Requires current password for verification. Dashboard auto-logs out on success.","body":[{"n":"current_password","t":"string","r":1,"d":"Current password for verification"},{"n":"new_password","t":"string","r":1,"d":"New password (minimum 10 characters)"}],"res":[{"c":200,"l":"Changed","b":"{ \"ok\": true }"},{"c":401,"l":"Wrong password","b":"{ \"error\": \"Current password incorrect\" }"}],"ex":"curl -s -X POST http://localhost:5000/api/auth/change-password \\\n  -H \"Authorization: Bearer $TOKEN\" \\\n  -d '{\"current_password\":\"old\",\"new_password\":\"NewPass123!\"}'"}]},{"id":"g-alerts","num":"02","icon":"🚨","label":"Alerts","desc":"List, filter, update status, and manage security alerts.","eps":[{"m":"GET","p":"/api/alerts","a":"jwt","s":"List all alerts newest first","desc":"Returns all stored alerts ordered by timestamp descending. Use ?limit=N to control result size (default 500).","qp":[{"n":"limit","t":"integer","r":0,"d":"Max results to return. Default: 500"}],"res":[{"c":200,"l":"Alert array","b":"{ \"ok\": true, \"data\": [{ \"alert_id\": \"3fa85...\", \"severity\": \"High\", \"alert_type\": \"web_attack\", \"status\": \"open\" }] }"}],"ex":"curl -s \"http://localhost:5000/api/alerts?limit=50\" \\\n  -H \"Authorization: Bearer $TOKEN\"","tryable":true,"tpath":"/api/alerts?limit=10"},{"m":"GET","p":"/api/stats","a":"jwt","s":"Alert counts by severity and type","desc":"Returns total alert count, open count, breakdown by severity level (Low/Medium/High/Critical), and breakdown by alert type.","res":[{"c":200,"l":"Stats","b":"{ \"total\": 142, \"open\": 38, \"by_severity\": { \"High\": 52 }, \"by_type\": { \"web_attack\": 64 } }"}],"ex":"curl -s http://localhost:5000/api/stats -H \"Authorization: Bearer $TOKEN\"","tryable":true,"tpath":"/api/stats"},{"m":"PUT","p":"/api/alerts/{alert_id}/status","a":"analyst","s":"Update alert status","desc":"Change alert status. Valid values: open, acknowledged, resolved. Change is broadcast via SSE to all connected dashboard clients immediately.","pp":[{"n":"alert_id","t":"string","r":1,"d":"UUID of the alert to update"}],"body":[{"n":"status","t":"string","r":1,"d":"New status: open | acknowledged | resolved"}],"res":[{"c":200,"l":"Updated","b":"{ \"ok\": true }"},{"c":400,"l":"Invalid status","b":"{ \"error\": \"invalid status\" }"},{"c":404,"l":"Not found","b":"{ \"error\": \"Alert not found\" }"}],"ex":"curl -s -X PUT http://localhost:5000/api/alerts/ALERT_ID/status \\\n  -H \"Authorization: Bearer $TOKEN\" \\\n  -d '{\"status\":\"acknowledged\"}'"},{"m":"GET","p":"/api/timeline","a":"jwt","s":"Hourly alert volume — last 24h","desc":"Returns alert counts per hour for the last 24 hours, broken down by severity. Used for the timeline chart on the dashboard.","res":[{"c":200,"l":"Timeline","b":"{ \"data\": [{ \"hour\": \"14:00\", \"Critical\": 2, \"High\": 8, \"Medium\": 14, \"Low\": 5 }] }"}],"ex":"curl -s http://localhost:5000/api/timeline -H \"Authorization: Bearer $TOKEN\"","tryable":true,"tpath":"/api/timeline"},{"m":"GET","p":"/api/top-attackers","a":"jwt","s":"Top 15 source IPs by alert count","desc":"Returns the 15 most active attacker IPs ranked by total alert count, including their peak severity.","res":[{"c":200,"l":"Attackers","b":"{ \"data\": [{ \"ip\": \"1.2.3.4\", \"count\": 42, \"severity\": \"Critical\" }] }"}],"ex":"curl -s http://localhost:5000/api/top-attackers -H \"Authorization: Bearer $TOKEN\"","tryable":true,"tpath":"/api/top-attackers"},{"m":"GET","p":"/api/detection-rules","a":"jwt","s":"Detection rule hit counts","desc":"Returns hit statistics for every detection rule showing which rules are firing most frequently. Useful for understanding your threat landscape.","res":[{"c":200,"l":"Rules","b":"{ \"data\": [{ \"rule_id\": \"R010\", \"rule_name\": \"SQL Injection\", \"hits\": 24, \"category\": \"web_attack\" }] }"}],"ex":"curl -s http://localhost:5000/api/detection-rules -H \"Authorization: Bearer $TOKEN\""}]},{"id":"g-ingest","num":"03","icon":"📥","label":"Log Ingest","desc":"Submit raw log lines directly to the 40+ rule detection engine.","eps":[{"m":"POST","p":"/api/ingest","a":"key","s":"Submit raw log line for detection","desc":"Accepts a raw log string, runs it through the detection engine, and creates an alert if any rule matches. Auth options: JWT Bearer token, X-Ingest-Key header (from siem_data/ingest_api_key.txt), or localhost requests (no auth needed).","body":[{"n":"log","t":"string","r":1,"d":"Raw log text to analyse"},{"n":"source_ip","t":"string","r":0,"d":"Source IP address. Default: 0.0.0.0"},{"n":"dest_ip","t":"string","r":0,"d":"Destination IP address. Default: 0.0.0.0"}],"res":[{"c":200,"l":"Alert created","b":"{ \"ok\": true, \"data\": { \"alert_type\": \"web_attack\", \"severity\": \"High\", \"alert_id\": \"3fa85...\" } }"},{"c":400,"l":"No log text","b":"{ \"error\": \"No log text provided\" }"},{"c":401,"l":"Not authenticated","b":"{ \"error\": \"Authentication required. Use JWT token or X-Ingest-Key header.\" }"}],"ex":"curl -s -X POST http://localhost:5000/api/ingest \\\n  -H \"X-Ingest-Key: $(cat siem_data/ingest_api_key.txt)\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"log\":\"union select * from users\",\"source_ip\":\"1.2.3.4\"}'","tryable":true,"tbody":"{\"log\":\"union select * from users\",\"source_ip\":\"1.2.3.4\",\"dest_ip\":\"10.0.0.1\"}"}]},{"id":"g-intel","num":"04","icon":"🌐","label":"Threat Intel","desc":"IP reputation, geo, MITRE mapping, risk scoring, anomaly detection and UEBA.","eps":[{"m":"GET","p":"/api/threat-intel/{ip}","a":"jwt","s":"Geo + reputation for an IP","desc":"Checks AbuseIPDB, AlienVault OTX, and a local blocklist. Returns geo coordinates, country, ISP, and malicious/safe determination. Results are cached in memory.","pp":[{"n":"ip","t":"string","r":1,"d":"IPv4 address to look up"}],"res":[{"c":200,"l":"Intel data","b":"{ \"geo\": { \"country\": \"Russia\", \"city\": \"Moscow\", \"lat\": 55.7, \"lon\": 37.6 }, \"reputation\": { \"malicious\": true, \"score\": 92, \"source\": \"AbuseIPDB\" } }"}],"ex":"curl -s http://localhost:5000/api/threat-intel/1.2.3.4 \\\n  -H \"Authorization: Bearer $TOKEN\""},{"m":"GET","p":"/api/geo/alerts","a":"jwt","s":"Alert IPs with geo coordinates (attack map)","desc":"Returns all unique attacker IPs from the alert database with geo coordinates for plotting on the attack map. Deduplicates per IP keeping highest severity.","res":[{"c":200,"l":"Geo data","b":"{ \"data\": [{ \"ip\": \"1.2.3.4\", \"lat\": 55.7, \"lon\": 37.6, \"country\": \"Russia\", \"severity\": \"High\", \"type\": \"brute_force\" }] }"}],"ex":"curl -s http://localhost:5000/api/geo/alerts -H \"Authorization: Bearer $TOKEN\""},{"m":"GET","p":"/api/mitre","a":"jwt","s":"MITRE ATT&CK technique counts","desc":"Counts how many alerts map to each MITRE ATT&CK technique ID. Shows which attack tactics are most prevalent in your environment.","res":[{"c":200,"l":"Techniques","b":"{ \"data\": [{ \"id\": \"T1190\", \"name\": \"Exploit Public-Facing Application\", \"tactic\": \"Initial Access\", \"count\": 64 }] }"}],"ex":"curl -s http://localhost:5000/api/mitre -H \"Authorization: Bearer $TOKEN\"","tryable":true,"tpath":"/api/mitre"},{"m":"GET","p":"/api/risk","a":"jwt","s":"Current risk score (0-100)","desc":"Calculates a weighted risk score based on alert severity in the last 24 hours. Higher severity and more recent alerts contribute more. Returns a score, label, and colour.","res":[{"c":200,"l":"Risk score","b":"{ \"score\": 72, \"label\": \"High\", \"color\": \"#f87171\", \"alert_count_24h\": 38 }"}],"ex":"curl -s http://localhost:5000/api/risk -H \"Authorization: Bearer $TOKEN\"","tryable":true,"tpath":"/api/risk"},{"m":"GET","p":"/api/anomalies","a":"jwt","s":"Statistical anomaly detection results","desc":"Runs IQR-based statistical analysis over alert data and returns IPs and time windows showing anomalous activity patterns.","res":[{"c":200,"l":"Anomalies","b":"{ \"data\": [{ \"type\": \"volume_spike\", \"source_ip\": \"1.2.3.4\", \"description\": \"3.2x normal volume\" }] }"}],"ex":"curl -s http://localhost:5000/api/anomalies -H \"Authorization: Bearer $TOKEN\""},{"m":"GET","p":"/api/ueba/anomalies","a":"jwt","s":"UEBA ML anomaly scores for active IPs","desc":"Runs the Isolation Forest UEBA model across all IPs active in the last 60 minutes. Returns IPs scoring above the anomaly threshold with contributing factors.","res":[{"c":200,"l":"UEBA results","b":"{ \"data\": [{ \"source_ip\": \"1.2.3.4\", \"anomaly_score\": 0.82, \"is_anomaly\": true, \"factors\": [\"High alert volume\", \"Activity during off-hours\"] }] }"}],"ex":"curl -s http://localhost:5000/api/ueba/anomalies -H \"Authorization: Bearer $TOKEN\"","tryable":true,"tpath":"/api/ueba/anomalies"},{"m":"GET","p":"/api/ueba/score/{ip}","a":"jwt","s":"Detailed UEBA score for one IP","desc":"Returns full anomaly analysis for a specific IP: score, is_anomaly flag, contributing factors, and feature vector (alert count, unique types, unique dests, avg severity, off-hours ratio, scan ratio).","pp":[{"n":"ip","t":"string","r":1,"d":"Source IP to score"}],"res":[{"c":200,"l":"Score","b":"{ \"ip\": \"1.2.3.4\", \"data\": { \"anomaly_score\": 0.82, \"is_anomaly\": true, \"factors\": [\"High alert volume\"], \"feature_vector\": { \"alert_count\": 42, \"unique_types\": 6 } } }"}],"ex":"curl -s http://localhost:5000/api/ueba/score/1.2.3.4 -H \"Authorization: Bearer $TOKEN\""},{"m":"POST","p":"/api/ueba/train","a":"admin","s":"Trigger UEBA model retraining","desc":"Starts a background thread to retrain the Isolation Forest models on all current alert data. Runs automatically every 5 minutes but can be triggered manually.","res":[{"c":200,"l":"Started","b":"{ \"ok\": true, \"message\": \"UEBA training started on 142 alerts\" }"}],"ex":"curl -s -X POST http://localhost:5000/api/ueba/train -H \"Authorization: Bearer $TOKEN\""}]},{"id":"g-incidents","num":"05","icon":"🔗","label":"Incidents","desc":"Correlated incident management from the correlation engine.","eps":[{"m":"GET","p":"/api/incidents","a":"jwt","s":"List correlated incidents","desc":"Returns incidents created by the correlation engine — groups of related alerts from the same source IP within time windows.","res":[{"c":200,"l":"Incidents","b":"{ \"data\": [{ \"incident_id\": \"INC-001\", \"source_ip\": \"1.2.3.4\", \"alert_count\": 7, \"severity\": \"Critical\", \"status\": \"open\" }] }"}],"ex":"curl -s http://localhost:5000/api/incidents -H \"Authorization: Bearer $TOKEN\"","tryable":true,"tpath":"/api/incidents"},{"m":"POST","p":"/api/incidents/run","a":"jwt","s":"Manually run correlation engine","desc":"Immediately evaluates all stored alerts and groups them into incidents. Returns the number of new incidents created. Also runs automatically every 5 minutes.","res":[{"c":200,"l":"Result","b":"{ \"ok\": true, \"new_incidents\": 3, \"total_incidents\": 12 }"}],"ex":"curl -s -X POST http://localhost:5000/api/incidents/run -H \"Authorization: Bearer $TOKEN\""},{"m":"PUT","p":"/api/incidents/{incident_id}/status","a":"analyst","s":"Update incident status","desc":"Change the status of an incident. Change is broadcast via SSE to connected clients.","pp":[{"n":"incident_id","t":"string","r":1,"d":"Incident ID to update"}],"body":[{"n":"status","t":"string","r":1,"d":"open | acknowledged | resolved"}],"res":[{"c":200,"l":"Updated","b":"{ \"ok\": true }"},{"c":400,"l":"Invalid status","b":"{ \"error\": \"invalid status\" }"}],"ex":"curl -s -X PUT http://localhost:5000/api/incidents/INC-001/status \\\n  -H \"Authorization: Bearer $TOKEN\" -d '{\"status\":\"resolved\"}'"},{"m":"GET","p":"/api/incidents/stats","a":"jwt","s":"Incident statistics","desc":"Returns total incident count and breakdown by status (open, acknowledged, resolved).","res":[{"c":200,"l":"Stats","b":"{ \"data\": { \"total\": 12, \"open\": 5, \"acknowledged\": 3, \"resolved\": 4 } }"}],"ex":"curl -s http://localhost:5000/api/incidents/stats -H \"Authorization: Bearer $TOKEN\""}]},{"id":"g-playbooks","num":"06","icon":"🤖","label":"Playbooks","desc":"Automated response playbooks, execution logs, and IP blocking management.","eps":[{"m":"GET","p":"/api/playbooks/list","a":"jwt","s":"List all playbook definitions","desc":"Returns all configured playbooks with their trigger alert_type, actions, severity threshold, and auto-run setting.","res":[{"c":200,"l":"Playbooks","b":"{ \"data\": [{ \"name\": \"Web Attack Response\", \"alert_type\": \"web_attack\", \"auto\": true, \"actions\": [\"block_ip\", \"notify_telegram\", \"collect_evidence\"] }] }"}],"ex":"curl -s http://localhost:5000/api/playbooks/list -H \"Authorization: Bearer $TOKEN\""},{"m":"GET","p":"/api/playbooks/log","a":"jwt","s":"Recent playbook execution log","desc":"Returns recent playbook executions with alert ID, playbook name, actions taken, and their results.","qp":[{"n":"limit","t":"integer","r":0,"d":"Max entries to return. Default: 50"}],"res":[{"c":200,"l":"Log","b":"{ \"data\": [{ \"alert_id\": \"3fa...\", \"playbook\": \"Web Attack Response\", \"actions\": [\"block_ip\"], \"ts\": \"2026-03-17T14:00Z\" }] }"}],"ex":"curl -s http://localhost:5000/api/playbooks/log -H \"Authorization: Bearer $TOKEN\""},{"m":"POST","p":"/api/playbooks/run/{alert_id}","a":"admin","s":"Manually trigger playbook for an alert","desc":"Forces the appropriate playbook to run for the given alert regardless of severity threshold or auto setting. Useful for testing or manual response.","pp":[{"n":"alert_id","t":"string","r":1,"d":"Alert ID to run playbook on"}],"res":[{"c":200,"l":"Result","b":"{ \"ok\": true, \"data\": { \"actions_run\": [\"block_ip\", \"notify_telegram\"] } }"},{"c":404,"l":"Not found","b":"{ \"error\": \"Alert not found\" }"}],"ex":"curl -s -X POST http://localhost:5000/api/playbooks/run/ALERT_ID \\\n  -H \"Authorization: Bearer $TOKEN\""},{"m":"GET","p":"/api/blocked-ips","a":"jwt","s":"List IPs currently blocked by iptables","desc":"Returns all IPs currently blocked by the playbook engine via iptables DROP rules.","res":[{"c":200,"l":"IPs","b":"{ \"ok\": true, \"data\": [\"1.2.3.4\", \"5.6.7.8\"] }"}],"ex":"curl -s http://localhost:5000/api/blocked-ips -H \"Authorization: Bearer $TOKEN\"","tryable":true,"tpath":"/api/blocked-ips"},{"m":"DELETE","p":"/api/blocked-ips/{ip}","a":"admin","s":"Unblock an IP","desc":"Removes the iptables DROP rule and removes IP from blocked_ips.json. The IP can send traffic again immediately.","pp":[{"n":"ip","t":"string","r":1,"d":"IP address to unblock"}],"res":[{"c":200,"l":"Unblocked","b":"{ \"ok\": true, \"message\": \"1.2.3.4 unblocked\" }"},{"c":200,"l":"Not blocked","b":"{ \"ok\": false, \"message\": \"1.2.3.4 is not blocked\" }"}],"ex":"curl -s -X DELETE http://localhost:5000/api/blocked-ips/1.2.3.4 \\\n  -H \"Authorization: Bearer $TOKEN\""}]},{"id":"g-reports","num":"07","icon":"📄","label":"Reports","desc":"HTML incident report generation and file management.","eps":[{"m":"POST","p":"/api/alerts/{alert_id}/report","a":"analyst","s":"Generate HTML incident report for an alert","desc":"Creates an HTML report file with MITRE ATT&CK info, log evidence, mitigation steps, and correlation reference. Returns the filename and download URL.","pp":[{"n":"alert_id","t":"string","r":1,"d":"Alert UUID to generate report for"}],"res":[{"c":200,"l":"Created","b":"{ \"message\": \"Report generated\", \"html\": \"/api/reports/SIEM_Report_3fa85f64_20260317.html\" }"},{"c":404,"l":"Not found","b":"{ \"error\": \"Alert not found\" }"}],"ex":"curl -s -X POST http://localhost:5000/api/alerts/ALERT_ID/report \\\n  -H \"Authorization: Bearer $TOKEN\""},{"m":"GET","p":"/api/reports/list","a":"jwt","s":"List all generated report files","desc":"Returns all HTML report files in siem_data/reports/ sorted by modification time, newest first.","res":[{"c":200,"l":"Files","b":"{ \"data\": [{ \"filename\": \"SIEM_Report_3fa.html\", \"url\": \"/api/reports/SIEM_Report_3fa.html\", \"size\": 14200 }] }"}],"ex":"curl -s http://localhost:5000/api/reports/list -H \"Authorization: Bearer $TOKEN\""},{"m":"GET","p":"/api/reports/{filename}","a":"jwt","s":"Download a generated report file","desc":"Serves the HTML report file as a download. Use the filename from /api/reports/list.","pp":[{"n":"filename","t":"string","r":1,"d":"Report filename from /api/reports/list"}],"res":[{"c":200,"l":"File download","b":"# Returns HTML file as attachment"},{"c":404,"l":"Not found","b":"{ \"error\": \"not found\" }"}],"ex":"curl -s http://localhost:5000/api/reports/SIEM_Report_3fa.html \\\n  -H \"Authorization: Bearer $TOKEN\" -O"}]},{"id":"g-system","num":"08","icon":"⚙️","label":"System","desc":"Health, config, Telegram setup, audit log, SSE stream, and public endpoints.","eps":[{"m":"GET","p":"/api/health","a":"jwt","s":"Server health and ES connectivity","desc":"Returns server status, Elasticsearch connection state, total alert count, hostname, and version string.","res":[{"c":200,"l":"Health","b":"{ \"status\": \"running\", \"hostname\": \"siem-server\", \"es_connected\": true, \"alerts_total\": 142, \"version\": \"3.0\" }"}],"ex":"curl -s http://localhost:5000/api/health -H \"Authorization: Bearer $TOKEN\"","tryable":true,"tpath":"/api/health"},{"m":"GET","p":"/api/config","a":"jwt","s":"Get current SIEM configuration","desc":"Returns Telegram settings (token masked), severity thresholds for alerts and notifications, and feature flags.","res":[{"c":200,"l":"Config","b":"{ \"siem_name\": \"Tysonic SIEM\", \"version\": \"3.0\", \"telegram\": { \"enabled\": true }, \"thresholds\": { \"report_on_severity\": [\"High\", \"Critical\"] } }"}],"ex":"curl -s http://localhost:5000/api/config -H \"Authorization: Bearer $TOKEN\"","tryable":true,"tpath":"/api/config"},{"m":"PUT","p":"/api/config","a":"admin","s":"Update SIEM configuration","desc":"Update Telegram bot settings and severity thresholds. Changes persist to siem_data/config.json and take effect immediately.","body":[{"n":"telegram.token","t":"string","r":0,"d":"Telegram bot token"},{"n":"telegram.chat_id","t":"string","r":0,"d":"Telegram chat ID"},{"n":"telegram.enabled","t":"boolean","r":0,"d":"Enable or disable Telegram notifications"}],"res":[{"c":200,"l":"Updated","b":"{ \"ok\": true }"},{"c":403,"l":"Forbidden","b":"{ \"error\": \"Admin role required\" }"}],"ex":"curl -s -X PUT http://localhost:5000/api/config \\\n  -H \"Authorization: Bearer $TOKEN\" \\\n  -d '{\"telegram\":{\"enabled\":true,\"token\":\"bot123\",\"chat_id\":\"-100\"}}'"},{"m":"POST","p":"/api/config/test-telegram","a":"admin","s":"Send a test Telegram message","desc":"Sends a test notification to verify the bot token and chat ID are correctly configured. Does not save the values — use PUT /api/config to save.","body":[{"n":"token","t":"string","r":1,"d":"Telegram bot token to test"},{"n":"chat_id","t":"string","r":1,"d":"Telegram chat ID to test"}],"res":[{"c":200,"l":"Sent","b":"{ \"ok\": true, \"message\": \"Test message sent\" }"},{"c":400,"l":"Missing fields","b":"{ \"error\": \"token and chat_id required\" }"}],"ex":"curl -s -X POST http://localhost:5000/api/config/test-telegram \\\n  -H \"Authorization: Bearer $TOKEN\" \\\n  -d '{\"token\":\"bot123:ABC\",\"chat_id\":\"-100\"}'"},{"m":"GET","p":"/api/audit-log","a":"admin","s":"Immutable audit trail of all SIEM actions","desc":"Returns append-only audit log entries — every alert creation, acknowledge, resolve, and config change with user and timestamp. Admin role required.","qp":[{"n":"limit","t":"integer","r":0,"d":"Max entries to return. Default: 200"}],"res":[{"c":200,"l":"Entries","b":"{ \"data\": [{ \"ts\": \"2026-03-17T14:00:00Z\", \"action\": \"alert_created\", \"user\": \"system\", \"detail\": \"web_attack High\" }] }"},{"c":403,"l":"Forbidden","b":"{ \"error\": \"Admin role required\" }"}],"ex":"curl -s \"http://localhost:5000/api/audit-log?limit=50\" -H \"Authorization: Bearer $TOKEN\""},{"m":"GET","p":"/api/stream","a":"jwt","s":"SSE real-time event stream","desc":"Server-Sent Events stream. EventSource cannot send Authorization headers — pass token as ?token= query param instead. Emits: connected, new_alert, alert_enriched, alert_updated, new_incident. Keepalive ping every 20 seconds.","qp":[{"n":"token","t":"string","r":1,"d":"JWT token (cannot use Authorization header with EventSource)"}],"res":[{"c":200,"l":"SSE stream","b":"# event: connected\ndata: {\"ts\":\"2026-03-17T14:00:00Z\",\"user\":\"admin\"}\n\n# event: new_alert\ndata: {\"alert_id\":\"3fa...\",\"alert_type\":\"web_attack\",\"severity\":\"High\"}\n\n# event: alert_enriched\ndata: {\"alert_id\":\"3fa...\",\"geo\":{...},\"intel\":{...},\"mitre\":{...}}\n\n# : ping"}],"ex":"# JavaScript EventSource\nconst es = new EventSource(`/api/stream?token=${token}`);\nes.addEventListener('new_alert', e => {\n  const alert = JSON.parse(e.data);\n  console.log('New alert:', alert);\n});\n\n# cURL\ncurl -N \"http://localhost:5000/api/stream?token=$TOKEN\""},{"m":"GET","p":"/api/search","a":"pub","s":"Public honeypot search endpoint","desc":"Intentionally unauthenticated endpoint with a ?q= query parameter. Used for testing nikto/sqlmap detection. All requests monitored by the before_request hook — will trigger scanner alerts.","qp":[{"n":"q","t":"string","r":0,"d":"Search query — monitored for SQL injection, XSS, scanner patterns"}],"res":[{"c":200,"l":"Empty results","b":"{ \"ok\": true, \"query\": \"test\", \"results\": [] }"}],"ex":"# Normal usage\ncurl \"http://localhost:5000/api/search?q=test\"\n\n# Attack test — triggers SQLi alert\ncurl \"http://localhost:5000/api/search?q=union+select+*+from+users\"","tryable":true,"tpath":"/api/search?q=test"},{"m":"GET","p":"/api/version","a":"pub","s":"SIEM version info (public, no auth required)","desc":"Returns version string and SIEM name. No authentication required. Safe to expose publicly.","res":[{"c":200,"l":"Version","b":"{ \"version\": \"3.0\", \"name\": \"Tysonic SIEM\" }"}],"ex":"curl http://localhost:5000/api/version","tryable":true,"tpath":"/api/version"}]}];

const AC={pub:'auth-pub',jwt:'auth-jwt',analyst:'auth-an',admin:'auth-adm',key:'auth-key'};
const AL={pub:'PUBLIC',jwt:'JWT',analyst:'ANALYST+',admin:'ADMIN',key:'INGEST KEY'};

function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function buildSections(){
  document.getElementById('ep-sections').innerHTML = GROUPS.map(g =>
    `<div id="${g.id}" class="section">
      <div class="sec-hdr"><span class="sec-num">${g.num}</span><span class="sec-title">${g.icon} ${g.label}</span></div>
      <div class="sec-desc">${g.desc}</div>
      ${g.eps.map((ep,i) => card(ep, g.id+'_'+i)).join('')}
    </div>`
  ).join('');
}

function card(ep, uid){
  const hasB = ep.body && ep.body.length;
  const hasQ = ep.qp   && ep.qp.length;
  const hasP = ep.pp   && ep.pp.length;
  const hasAny = hasB||hasQ||hasP;

  function rows(arr, type){
    return arr.map(f =>
      `<tr><td class="pn">${esc(f.n)}</td><td class="pt">${esc(f.t)}</td>
       <td>${type==='path'?'<span class=ptag>PATH</span>':f.r?'<span class=rtag>required</span>':'<span class=otag>optional</span>'}</td>
       <td class="pd">${esc(f.d)}</td></tr>`
    ).join('');
  }

  const tabs = [...(hasAny?['Parameters']:[]), 'Responses', 'cURL', ...(ep.tryable?['&#9654; Try It']:[])];
  const tids = [...(hasAny?['pa']:[]),          're',         'cu',  ...(ep.tryable?['tr']:[])];
  const firstTab = tids[0];

  return `<div class="ep-card">
    <div class="ep-hdr" onclick="tog('${uid}')">
      <span class="mbadge ${ep.m}">${ep.m}</span>
      <div style="flex:1;min-width:0;">
        <div class="ep-path">${esc(ep.p)}</div>
        <div class="ep-sum">${esc(ep.s)}</div>
      </div>
      <span class="achip ${AC[ep.a]}">${AL[ep.a]}</span>
      <span class="chev" id="cv-${uid}">&#9660;</span>
    </div>
    <div class="ep-body" id="bd-${uid}">
      <div class="ep-desc">${esc(ep.desc||ep.s)}</div>
      <div class="tabs" id="tb-${uid}">
        ${tabs.map((t,i)=>`<div class="tab${i===0?' active':''}" onclick="stab('${uid}','${tids[i]}')" data-t="${tids[i]}">${t}</div>`).join('')}
      </div>
      ${hasAny?`<div class="panel${firstTab==='pa'?' active':''}" id="${uid}-pa">
        <table class="dt"><tr><th>NAME</th><th>TYPE</th><th>REQUIRED</th><th>DESCRIPTION</th></tr>
        ${hasP?rows(ep.pp,'path'):''}${hasB?rows(ep.body,'body'):''}${hasQ?rows(ep.qp,'query'):''}</table></div>`:''}
      <div class="panel${firstTab==='re'?' active':''}" id="${uid}-re">
        ${ep.res.map(r=>`<div class="rrow">
          <span class="rcode s${r.c}">${r.c}</span>
          <div><div class="rdesc">${esc(r.l)}</div>
          <div class="cb" style="padding:8px 10px;margin:4px 0 0;font-size:10px;">${esc(r.b)}</div></div>
        </div>`).join('')}
      </div>
      <div class="panel${firstTab==='cu'?' active':''}" id="${uid}-cu">
        <div class="cb"><button class="cpcopy" onclick="cpc(this)">COPY</button>${esc(ep.ex)}</div>
      </div>
      ${ep.tryable?`<div class="panel${firstTab==='tr'?' active':''}" id="${uid}-tr">
        <div class="try-wrap">
          <div class="trlbl">URL</div>
          <input class="trin" id="${uid}-tu" value="http://localhost:5000${ep.tpath||ep.p.replace(/\{[^}]+\}/g,'REPLACE')}">
          <div class="trlbl">JWT TOKEN</div>
          <input class="trin" id="${uid}-tk" placeholder="">
          ${ep.tbody!=null?`<div class="trlbl">REQUEST BODY</div><textarea class="trin trta" id="${uid}-tb">${esc(ep.tbody)}</textarea>`:''}
          <div class="trrow">
            <button class="trsend" onclick="doTry('${uid}','${ep.m}',${ep.tbody!=null})">&#9654; Send ${ep.m}</button>
            <button class="trclear" onclick="clrTry('${uid}')">Clear</button>
          </div>
          <div class="trres" id="${uid}-tr-r"></div>
        </div>
      </div>`:''}
    </div>
  </div>`;
}

function tog(uid){
  const b=document.getElementById('bd-'+uid),c=document.getElementById('cv-'+uid),h=b.previousElementSibling;
  const closed=b.classList.toggle('closed');c.classList.toggle('closed',closed);h.classList.toggle('closed',closed);
}
function stab(uid,t){
  document.querySelectorAll('#tb-'+uid+' .tab').forEach(x=>x.classList.toggle('active',x.dataset.t===t));
  ['pa','re','cu','tr'].forEach(id=>{const p=document.getElementById(uid+'-'+id);if(p)p.classList.toggle('active',id===t);});
}
async function doTry(uid,method,hasBody){
  const url=document.getElementById(uid+'-tu')?.value||'';
  const tok=document.getElementById(uid+'-tk')?.value||'';
  const bel=document.getElementById(uid+'-tb');
  const res=document.getElementById(uid+'-tr-r');
  res.className='trres show';res.innerHTML='<span style="color:var(--muted)">Sending...</span>';
  try{
    const o={method,headers:{'Content-Type':'application/json'}};
    if(tok)o.headers['Authorization']='Bearer '+tok;
    if(hasBody&&bel)o.body=bel.value;
    const r=await fetch(url,o);
    const txt=await r.text();let out=txt;
    try{out=JSON.stringify(JSON.parse(txt),null,2);}catch(e){}
    res.style.borderLeftColor=r.ok?'var(--green)':'var(--red)';
    res.innerHTML='<span class="'+(r.ok?'rok':'rerr')+'">HTTP '+r.status+' '+r.statusText+'</span>\n'+out;
  }catch(e){res.style.borderLeftColor='var(--red)';res.innerHTML='<span class="rerr">Error: '+e.message+'</span>';}
}
function clrTry(uid){const r=document.getElementById(uid+'-tr-r');if(r){r.className='trres';r.innerHTML='';}}
function cpc(btn){navigator.clipboard.writeText(btn.nextSibling.textContent).then(()=>{btn.textContent='COPIED!';setTimeout(()=>btn.textContent='COPY',1800);});}
function filterNav(q){
  q=q.toLowerCase();
  document.querySelectorAll('#sidebar .nav-item').forEach(a=>{a.style.display=!q||a.textContent.toLowerCase().includes(q)?'':'none';});
  document.querySelectorAll('.ep-card').forEach(card=>{
    const t=(card.querySelector('.ep-path')?.textContent||'')+(card.querySelector('.ep-sum')?.textContent||'');
    card.style.display=!q||t.toLowerCase().includes(q)?'':'none';
  });
}
const spy=new IntersectionObserver(entries=>{
  entries.forEach(e=>{if(e.isIntersecting){const id='#'+e.target.id;document.querySelectorAll('#sidebar .nav-item').forEach(a=>{a.classList.toggle('active',a.getAttribute('href')===id);});}});
},{threshold:0.2});
const fadeO=new IntersectionObserver(entries=>{entries.forEach(e=>{if(e.isIntersecting)e.target.classList.add('visible');});},{threshold:0.05});
document.addEventListener('DOMContentLoaded',()=>{
  buildSections();
  document.querySelectorAll('.section[id]').forEach(s=>{spy.observe(s);fadeO.observe(s);});
});
</script>
</body>
</html>"""


@docs_bp.route("/api/docs")
def swagger_ui():
    """Serve API docs — Response() bypasses Jinja2 so JS is never mangled."""
    return Response(_DOCS_HTML, mimetype='text/html')