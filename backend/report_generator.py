"""
SIEM Report Generator —
Generates HTML and PDF incident reports with MITRE ATT&CK badge and correlation links
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from siem_logger import get_logger

logger = get_logger(__name__)

# ─────────────────────────────────────────────

# HTML TEMPLATE (CSS braces escaped)

# ─────────────────────────────────────────────

HTML_TEMPLATE = """

<!DOCTYPE html>

<html>
<head>
<meta charset="UTF-8">
<title>SIEM Incident Report</title>

<style>
body {{
    font-family: Arial, sans-serif;
    background:#0a0c10;
    color:#e2e8f0;
    padding:40px;
}}

.container {{
    background:#0d1117;
    border:1px solid #1f2937;
    padding:30px;
    border-radius:8px;
}}

h1 {{
    color:#60a5fa;
}}

.section {{
    margin-top:20px;
}}

.label {{
    font-size:13px;
    color:#9ca3af;
}}

.value {{
    font-weight:bold;
}}

.log {{
    background:#070a0e;
    padding:15px;
    border-radius:5px;
    font-family:monospace;
    color:#a3e635;
}}

</style>

</head>

<body>

<div class="container">

<h1>⚡ SIEM Incident Report</h1>

<div class="section">
<div class="label">Alert ID</div>
<div class="value">{alert_id}</div>
</div>

<div class="section">
<div class="label">Attack Type</div>
<div class="value">{alert_type}</div>
</div>

<div class="section">
<div class="label">Severity</div>
<div class="value">{severity}</div>
</div>

<div class="section">
<div class="label">Timestamp</div>
<div class="value">{timestamp}</div>
</div>

<div class="section">
<div class="label">Source IP</div>
<div class="value">{source_ip}</div>
</div>

<div class="section">
<div class="label">Destination IP</div>
<div class="value">{dest_ip}</div>
</div>

<div class="section">
<div class="label">Hostname</div>
<div class="value">{hostname}</div>
</div>

<div class="section">
<div class="label">Description</div>
<div class="value">{description}</div>
</div>

<div class="section">
<div class="label">Log Evidence</div>
<div class="log">{log_evidence}</div>
</div>


<div class="section">
<div class="label">MITRE ATT&CK</div>
<div class="value">{mitre_id} — {mitre_name} ({mitre_tactic})</div>
</div>

<div class="section">
<div class="label">Correlation Incident</div>
<div class="value">{incident_ref}</div>
</div>

<div class="section">
<div class="label">Mitigation Steps</div>
<ul>
{mitigation_html}
</ul>
</div>

<p style="margin-top:30px;font-size:12px;color:#6b7280;">
Generated at: {generated_at}
</p>

</div>
</body>
</html>
"""

# ─────────────────────────────────────────────

# REPORT GENERATOR CLASS

# ─────────────────────────────────────────────

class ReportGenerator:

  def __init__(self, output_dir="./siem_data/reports"):
    self.output_dir = Path(output_dir)
    self.output_dir.mkdir(parents=True, exist_ok=True)

  def _filename(self, alert):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"SIEM_Report_{alert.alert_id[:8]}_{ts}"

  def _mitigation_steps(self, alert):
    """Delegate to the alert's own mitigation_steps() which uses MITIGATION_MAP."""
    try:
        return alert.mitigation_steps()
    except Exception:
        return [
            "Investigate the source of the attack",
            "Block malicious IP address",
            "Check IDS and firewall logs",
            "Patch vulnerable systems",
            "Continue monitoring network activity",
        ]

# ─────────────────────────────
# HTML REPORT
# ─────────────────────────────

  def generate_html(self, alert):

    steps = self._mitigation_steps(alert)

    mitigation_html = ""
    for step in steps:
        mitigation_html += f"<li>{step}</li>"

    # MITRE mapping
    try:
        from threat_intel import get_mitre
        mitre = get_mitre(alert.alert_type)
        mitre_id     = mitre.get("id", "—")
        mitre_name   = mitre.get("name", "—")
        mitre_tactic = mitre.get("tactic", "—")
    except Exception:
        mitre_id = mitre_name = mitre_tactic = "—"

    html = HTML_TEMPLATE.format(
        alert_id=alert.alert_id,
        alert_type=alert.alert_type,
        severity=str(alert.severity),
        timestamp=alert.timestamp,
        source_ip=alert.source_ip,
        dest_ip=alert.dest_ip,
        hostname=alert.hostname,
        description=alert.description,
        log_evidence=alert.log_evidence,
        mitigation_html=mitigation_html,
        mitre_id=mitre_id,
        mitre_name=mitre_name,
        mitre_tactic=mitre_tactic,
        incident_ref=getattr(alert, "incident_id", "—"),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    )

    filename = self._filename(alert) + ".html"
    path = self.output_dir / filename

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info("HTML report saved: %s", path)

    return str(path)

# ─────────────────────────────
# PDF REPORT
# ─────────────────────────────

  def generate_pdf(self, alert) -> Optional[str]:

    try:

        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet

        styles = getSampleStyleSheet()

        filename = self._filename(alert) + ".pdf"
        path = self.output_dir / filename

        doc = SimpleDocTemplate(str(path), pagesize=A4)

        story = []

        story.append(Paragraph("SIEM Incident Report", styles["Title"]))
        story.append(Spacer(1,20))

        story.append(Paragraph(f"Alert ID: {alert.alert_id}", styles["Normal"]))
        story.append(Paragraph(f"Attack Type: {alert.alert_type}", styles["Normal"]))
        story.append(Paragraph(f"Severity: {alert.severity}", styles["Normal"]))
        story.append(Paragraph(f"Timestamp: {alert.timestamp}", styles["Normal"]))
        story.append(Paragraph(f"Source IP: {alert.source_ip}", styles["Normal"]))
        story.append(Paragraph(f"Destination IP: {alert.dest_ip}", styles["Normal"]))
        story.append(Paragraph(f"Hostname: {alert.hostname}", styles["Normal"]))

        story.append(Spacer(1,20))

        story.append(Paragraph("Description:", styles["Heading2"]))
        story.append(Paragraph(alert.description, styles["Normal"]))

        story.append(Spacer(1,20))

        story.append(Paragraph("Log Evidence:", styles["Heading2"]))
        story.append(Paragraph(alert.log_evidence, styles["Normal"]))

        doc.build(story)

        logger.info("PDF report saved: %s", path)

        return str(path)

    except Exception as e:

        logger.error("PDF generation failed: %s", e)
        return None


logger.debug("Report Generator module loaded.")