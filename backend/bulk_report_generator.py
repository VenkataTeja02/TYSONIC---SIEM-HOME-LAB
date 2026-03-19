"""
SIEM Bulk Report Generator
Generates a single HTML file containing one report container per alert.
Now protected by JWT authentication (require_auth).

Usage (from app.py):
    from bulk_report_generator import generate_bulk_report
    app.register_blueprint(bulk_report_bp)
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from flask import Blueprint, request, jsonify, current_app
from auth import require_auth, require_role

bulk_report_bp = Blueprint("bulk_report", __name__)

SEV_HEX = {
    "Critical": "#c084fc",
    "High":     "#f87171",
    "Medium":   "#fbbf24",
    "Low":      "#34d399",
}

MITIGATION_STEPS = [
    "Investigate the source of the attack",
    "Block malicious IP address",
    "Check IDS and firewall logs",
    "Patch vulnerable systems",
    "Continue monitoring network activity",
]


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _parse_tags(raw):
    if not raw:
        return "—"
    if isinstance(raw, list):
        return ", ".join(raw) or "—"
    try:
        return ", ".join(json.loads(raw)) or "—"
    except Exception:
        return str(raw) or "—"


def _safe(v):
    return str(v) if v is not None else "—"


def _filter_alerts(all_alerts, date_from, date_to, severities, alert_types):
    dt_from = _parse_dt(date_from)
    dt_to   = _parse_dt(date_to)
    result  = []
    for a in all_alerts:
        try:
            ts_val = datetime.fromisoformat(a.get("timestamp","").replace("Z","+00:00"))
            if dt_from and ts_val < dt_from: continue
            if dt_to   and ts_val > dt_to:   continue
        except Exception:
            pass
        if severities  and a.get("severity")   not in severities:  continue
        if alert_types and a.get("alert_type") not in alert_types: continue
        result.append(a)
    return result


def _counters(filtered):
    return {
        "total": len(filtered),
        "crit":  sum(1 for a in filtered if a.get("severity") == "Critical"),
        "high":  sum(1 for a in filtered if a.get("severity") == "High"),
        "med":   sum(1 for a in filtered if a.get("severity") == "Medium"),
        "low":   sum(1 for a in filtered if a.get("severity") == "Low"),
        "open":  sum(1 for a in filtered if a.get("status")   == "open"),
        "ack":   sum(1 for a in filtered if a.get("status")   == "acknowledged"),
        "res":   sum(1 for a in filtered if a.get("status")   == "resolved"),
    }


# ─────────────────────────────────────────────
# HTML Generator
# ─────────────────────────────────────────────

def generate_bulk_html(filtered, period, gen_time, out_dir):
    """
    Produces one .container block per alert — identical CSS to report_generator.py.
    Returns the saved filename (not full path).
    """
    c = _counters(filtered)
    ts_tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    containers = ""
    for idx, a in enumerate(filtered, 1):
        sev     = _safe(a.get("severity", "Low"))
        sev_col = SEV_HEX.get(sev, "#34d399")
        log_ev  = _safe(a.get("log_evidence", "")) or "— no evidence captured —"
        tags    = _parse_tags(a.get("tags", ""))
        mit_li  = "".join(f"<li>{s}</li>" for s in MITIGATION_STEPS)
        try:
            from threat_intel import get_mitre
            m = get_mitre(a.get("alert_type",""))
            mitre_badge = f"{m['id']} — {m['name']} ({m['tactic']})"
        except Exception:
            mitre_badge = "—"

        containers += f"""
<div class="container">

  <h1>&#9889; SIEM Incident Report
    <span style="font-size:14px;color:#4b5563;">#{idx} of {c['total']}</span>
  </h1>

  <div class="section">
    <div class="label">Alert ID</div>
    <div class="value">{_safe(a.get("alert_id",""))}</div>
  </div>

  <div class="section">
    <div class="label">Attack Type</div>
    <div class="value">{_safe(a.get("alert_type","")).replace("_"," ").title()}</div>
  </div>

  <div class="section">
    <div class="label">Severity</div>
    <div class="value" style="color:{sev_col};">{sev}</div>
  </div>

  <div class="section">
    <div class="label">Timestamp</div>
    <div class="value">{_safe(a.get("timestamp",""))}</div>
  </div>

  <div class="section">
    <div class="label">Source IP</div>
    <div class="value">{_safe(a.get("source_ip",""))}</div>
  </div>

  <div class="section">
    <div class="label">Destination IP</div>
    <div class="value">{_safe(a.get("dest_ip",""))}</div>
  </div>

  <div class="section">
    <div class="label">Hostname</div>
    <div class="value">{_safe(a.get("hostname",""))}</div>
  </div>

  <div class="section">
    <div class="label">Status</div>
    <div class="value">{_safe(a.get("status",""))}</div>
  </div>

  <div class="section">
    <div class="label">Tags</div>
    <div class="value">{tags}</div>
  </div>

  <div class="section">
    <div class="label">MITRE ATT&CK</div>
    <div class="value">{mitre_badge}</div>
  </div>

  <div class="section">
    <div class="label">Description</div>
    <div class="value">{_safe(a.get("description",""))}</div>
  </div>

  <div class="section">
    <div class="label">Log Evidence</div>
    <div class="log">{log_ev}</div>
  </div>

  <div class="section">
    <div class="label">Mitigation Steps</div>
    <ul>{mit_li}</ul>
  </div>

  <p style="margin-top:30px;font-size:12px;color:#6b7280;">
    Generated at: {gen_time}
  </p>

</div>
"""

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>SIEM Bulk Incident Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #0a0c10;
    color: #e2e8f0;
    padding: 40px;
}}

/* ── Summary banner ── */
.summary {{
    background: #0d1117;
    border: 1px solid #1f2937;
    border-radius: 8px;
    padding: 24px 30px;
    margin-bottom: 40px;
}}
.summary h2 {{
    color: #60a5fa;
    margin-bottom: 16px;
    font-size: 18px;
}}
.summary-meta {{
    font-family: monospace;
    font-size: 12px;
    color: #4b5563;
    margin-bottom: 20px;
    letter-spacing: 1px;
}}
.stat-row {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
}}
.stat {{
    background: #070a0e;
    border: 1px solid #1f2937;
    border-radius: 6px;
    padding: 10px 18px;
    min-width: 90px;
    text-align: center;
}}
.stat-label {{
    font-size: 9px;
    color: #4b5563;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 6px;
}}
.stat-val {{
    font-size: 20px;
    font-weight: 700;
}}

/* ── Per-alert container — identical to report_generator.py ── */
.container {{
    background: #0d1117;
    border: 1px solid #1f2937;
    padding: 30px;
    border-radius: 8px;
    margin-bottom: 32px;
}}

h1 {{
    color: #60a5fa;
}}

.section {{
    margin-top: 20px;
}}

.label {{
    font-size: 13px;
    color: #9ca3af;
}}

.value {{
    font-weight: bold;
}}

.log {{
    background: #070a0e;
    padding: 15px;
    border-radius: 5px;
    font-family: monospace;
    color: #a3e635;
    white-space: pre-wrap;
    word-break: break-all;
}}

ul {{
    margin-top: 8px;
    padding-left: 20px;
    line-height: 1.8;
}}
</style>
</head>
<body>

<div class="summary">
  <h2>&#9889; SIEM Bulk Incident Report</h2>
  <div class="summary-meta">
    PERIOD: {period} &nbsp;&middot;&nbsp;
    GENERATED: {gen_time} &nbsp;&middot;&nbsp;
    TOTAL ALERTS: {c['total']}
  </div>
  <div class="stat-row">
    <div class="stat"><div class="stat-label">Total</div><div class="stat-val" style="color:#60a5fa;">{c['total']}</div></div>
    <div class="stat"><div class="stat-label">Critical</div><div class="stat-val" style="color:#c084fc;">{c['crit']}</div></div>
    <div class="stat"><div class="stat-label">High</div><div class="stat-val" style="color:#f87171;">{c['high']}</div></div>
    <div class="stat"><div class="stat-label">Medium</div><div class="stat-val" style="color:#fbbf24;">{c['med']}</div></div>
    <div class="stat"><div class="stat-label">Low</div><div class="stat-val" style="color:#34d399;">{c['low']}</div></div>
    <div class="stat"><div class="stat-label">Open</div><div class="stat-val" style="color:#f87171;">{c['open']}</div></div>
    <div class="stat"><div class="stat-label">Acknowledged</div><div class="stat-val" style="color:#fbbf24;">{c['ack']}</div></div>
    <div class="stat"><div class="stat-label">Resolved</div><div class="stat-val" style="color:#34d399;">{c['res']}</div></div>
  </div>
</div>

{containers}

</body>
</html>"""

    fname = f"Bulk_Report_{ts_tag}.html"
    with open(Path(out_dir) / fname, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[BulkReport] HTML saved: {fname} ({c['total']} alerts)")
    return fname




# ─────────────────────────────────────────────
# Flask Route
# ─────────────────────────────────────────────

@bulk_report_bp.route("/api/reports/bulk", methods=["POST"])
@require_role("analyst", "admin")
def bulk_report_route():
    from flask import current_app

    # Pull shared objects injected by app.py
    manager  = current_app.config["SIEM_MANAGER"]
    data_dir = Path(current_app.config["SIEM_DATA_DIR"])
    out_dir  = data_dir / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)

    body        = request.get_json(force=True)
    date_from   = body.get("date_from")
    date_to     = body.get("date_to")
    severities  = body.get("severities",  [])
    alert_types = body.get("alert_types", [])

    filtered = _filter_alerts(
        manager.get_incidents(), date_from, date_to, severities, alert_types
    )

    if not filtered:
        return jsonify({"error": "No alerts match the selected filters"}), 404

    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    period   = f"{date_from[:10] if date_from else 'All time'} to {date_to[:10] if date_to else 'Now'}"

    try:
        fname    = generate_bulk_html(filtered, period, gen_time, out_dir)
        out_html = f"/api/reports/{fname}"
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "ok":    True,
        "count": len(filtered),
        "html":  out_html,
    })