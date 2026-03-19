# ⚡ TYSONIC SIEM v3.0

> **Full-stack Security Information and Event Management platform** — real-time network intrusion detection, automated incident response, and threat intelligence, built with Python and Flask.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.x-005571?style=flat-square&logo=elasticsearch)
![Suricata](https://img.shields.io/badge/Suricata-IDS-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 📌 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Step 1 — Install System Tools](#step-1--install-system-tools)
- [Step 2 — Install and Configure Elasticsearch](#step-2--install-and-configure-elasticsearch)
- [Step 3 — Install and Configure Suricata](#step-3--install-and-configure-suricata)
- [Step 4 — Install and Configure Filebeat](#step-4--install-and-configure-filebeat)
- [Step 5 — Clone and Set Up the SIEM](#step-5--clone-and-set-up-the-siem)
- [Step 6 — Configure Environment Variables](#step-6--configure-environment-variables)
- [Step 7 — Run the SIEM](#step-7--run-the-siem)
- [Step 8 — Access the Dashboard](#step-8--access-the-dashboard)
- [Step 9 — Configure Telegram Notifications](#step-9--configure-telegram-notifications-optional)
- [Step 10 — Test with Kali Linux](#step-10--test-with-kali-linux)
- [API Documentation](#-api-documentation)
- [Project Structure](#-project-structure)
- [Troubleshooting](#-troubleshooting)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Real-time Detection** | Ingests Suricata alerts via Elasticsearch every 500ms |
| 🛡️ **40+ Detection Rules** | SQLi, XSS, reverse shells, brute force, DDoS, phishing, malware C2, ransomware and more |
| 🤖 **Auto Response** | Automatically blocks attacker IPs via iptables |
| 📊 **UEBA / ML** | Isolation Forest anomaly detection per source IP |
| 🗺️ **Attack Map** | Real-time geo-IP visualization of attacker locations |
| ⚔️ **MITRE ATT&CK** | Every alert mapped to MITRE technique ID and tactic |
| 🔐 **JWT + MFA Auth** | Role-based access with Google Authenticator TOTP |
| 📱 **Telegram Alerts** | Instant notifications for High/Critical severity events |
| 📄 **HTML Reports** | Per-alert incident reports with mitigation steps |
| 🔌 **REST API** | 35+ endpoints with Swagger UI at `/api/docs` |
| 📡 **SSE Dashboard** | Real-time push updates — no page refresh needed |

---

## 🏗️ Architecture

```
Kali Linux (Attacker)
        │
        │ Network Traffic
        ▼
┌─────────────────┐
│   SURICATA IDS  │  ← Inspects packets, matches ET Open rules
│  /var/log/      │
│  suricata/      │
│  eve.json       │
└────────┬────────┘
         │
         │ eve.json tail
         ▼
┌─────────────────┐
│    FILEBEAT     │  ← Ships events to Elasticsearch
└────────┬────────┘
         │
         │ HTTPS → localhost:9200
         ▼
┌─────────────────┐
│ ELASTICSEARCH   │  ← Stores and indexes all events
└────────┬────────┘
         │
         │ Polled every 500ms
         ▼
┌─────────────────┐
│  TYSONIC SIEM   │  ← Detection engine, alerts, playbooks
│   (Flask App)   │
└────────┬────────┘
         │
         │ SSE / REST API
         ▼
┌─────────────────┐
│   DASHBOARD     │  ← Real-time alert table, attack map, reports
└─────────────────┘
```

---

## 📋 Prerequisites

- **OS:** Ubuntu 20.04+ or Debian 11+ (tested on Ubuntu 22.04 LTS)
- **RAM:** Minimum 4GB (8GB recommended for Elasticsearch)
- **Python:** 3.10 or higher
- **Network:** Two machines on the same network — SIEM server + Kali Linux (for testing)
- **Root/sudo access** required (for iptables blocking and Suricata)

---

## Step 1 — Install System Tools

```bash
sudo apt update && sudo apt upgrade -y

# Install required system packages
sudo apt install -y git curl wget python3 python3-pip python3-venv \
     apt-transport-https gnupg net-tools
```

---

## Step 2 — Install and Configure Elasticsearch

```bash
# Add Elastic GPG key and repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | \
     sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Install Elasticsearch
sudo apt update
sudo apt install elasticsearch -y

# Start and enable Elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Wait 30 seconds for it to start, then check status
sleep 30
sudo systemctl status elasticsearch
```

**Reset the elastic user password and save it:**
```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i
# Enter your chosen password when prompted
# Save this password — you will need it in Step 6
```

**Test Elasticsearch is running:**
```bash
curl -k -u elastic:YOUR_PASSWORD https://localhost:9200
# Should return cluster info JSON
```

---

## Step 3 — Install and Configure Suricata

```bash
# Install Suricata
sudo apt install suricata -y

# Download the latest Emerging Threats Open ruleset (free)
sudo suricata-update

# Find your network interface name
ip addr show
# Look for your main interface (e.g. eth0, ens33, enp0s3)
```

**Edit Suricata configuration:**
```bash
sudo nano /etc/suricata/suricata.yaml
```

Find and update these sections:

```yaml
# Set your network interface (replace eth0 with yours)
af-packet:
  - interface: eth0

# Make sure eve-log is enabled with these event types
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - flow
        - ssh
```

**Start Suricata:**
```bash
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata

# Verify alerts are being written (wait a minute for traffic)
sudo tail -f /var/log/suricata/eve.json
```

---

## Step 4 — Install and Configure Filebeat

```bash
# Install Filebeat
sudo apt install filebeat -y

# Enable the Suricata module
sudo filebeat modules enable suricata
```

**Configure the Suricata module:**
```bash
sudo nano /etc/filebeat/modules.d/suricata.yml
```

```yaml
- module: suricata
  eve:
    enabled: true
    var.paths: ["/var/log/suricata/eve.json"]
```

**Configure Filebeat to send to Elasticsearch:**
```bash
sudo nano /etc/filebeat/filebeat.yml
```

Find and update the output section:
```yaml
output.elasticsearch:
  hosts: ["https://localhost:9200"]
  username: "elastic"
  password: "YOUR_ES_PASSWORD"    # password from Step 2
  ssl.verification_mode: none
```

**Start Filebeat:**
```bash
# Set up index templates in Elasticsearch
sudo filebeat setup

# Start Filebeat
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo systemctl status filebeat
```

**Verify data is flowing into Elasticsearch:**
```bash
curl -k -u elastic:YOUR_PASSWORD \
  "https://localhost:9200/filebeat-*/_count" | python3 -m json.tool
# "count" should be greater than 0
```

---

## Step 5 — Clone and Set Up the SIEM

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/tysonic-siem.git
cd tysonic-siem

# Create a Python virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

---

## Step 6 — Configure Environment Variables

# Edit with your values
nano .env
```

Fill in these values:

```env
# Generate a strong secret key with this command:
# python3 -c "import secrets; print(secrets.token_hex(32))"
SIEM_SECRET_KEY=your-generated-64-char-hex-string

# Elasticsearch password from Step 2
ES_PASSWORD=your-elasticsearch-password

# Optional — AbuseIPDB API key (free at abuseipdb.com)
ABUSEIPDB_KEY=

# Optional — AlienVault OTX API key (free at otx.alienvault.com)
OTX_KEY=

# Optional — Telegram bot token from @BotFather
TELEGRAM_TOKEN=
TELEGRAM_CHAT_ID=

# Log level: DEBUG | INFO | WARNING | ERROR
SIEM_LOG_LEVEL=INFO
```

**Generate a strong secret key:**
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# Copy the output into SIEM_SECRET_KEY in your .env file
```

---

## Step 7 — Run the SIEM

**Development mode:**
```bash
# Make sure you are in the project directory with venv activated
source venv/bin/activate
python app.py
```

**Production mode (recommended):**
```bash
# Run with Gunicorn — 4 worker processes
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

**Run as a background service (optional):**
```bash
sudo nano /etc/systemd/system/tysonic-siem.service
```

```ini
[Unit]
Description=TYSONIC SIEM v3.0
After=network.target elasticsearch.service

[Service]
User=www-data
WorkingDirectory=/path/to/tysonic-siem
EnvironmentFile=/path/to/tysonic-siem/.env
ExecStart=/path/to/tysonic-siem/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable tysonic-siem
sudo systemctl start tysonic-siem
sudo systemctl status tysonic-siem
```

---

## Step 8 — Access the Dashboard

Open your browser and navigate to:

```
http://<YOUR_SIEM_IP>:5000
```

**Default login credentials:**
| Username | Password | Role |
|---|---|---|
| `admin` | `admin` | Full access |
| `analyst` | `analyst` | Alert management |

> ⚠️ **Change these passwords immediately** after first login via Settings → Change Password.

**API Documentation (Swagger UI):**
```
http://<YOUR_SIEM_IP>:5000/api/docs
```

---

## Step 9 — Configure Telegram Notifications (Optional)

1. Open Telegram and search for **@BotFather**
2. Send `/newbot` and follow the instructions
3. Copy the **bot token** given to you
4. Start a chat with your bot, then get your chat ID:
   ```bash
   curl "https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates"
   # Find "chat":{"id": YOUR_CHAT_ID} in the response
   ```
5. In the SIEM dashboard: **Settings → Telegram** — enter token and chat ID
6. Click **Test** to verify it works

---

## Step 10 — Test with Kali Linux

Run these from your Kali machine to verify alerts are being generated:

**Port Scan:**
```bash
nmap -sS -p 1-1000 <SIEM_IP>
```

**SSH Brute Force:**
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<SIEM_IP>
```

**Web Scanner (Nikto):**
```bash
nikto -h http://<SIEM_IP>:5000
```

**SQL Injection (sqlmap):**
```bash
sqlmap -u "http://<SIEM_IP>:5000/api/search?q=test" --batch --level=3
```

**Manual log injection (tests detection engine directly):**
```bash
curl -s -X POST http://<SIEM_IP>:5000/api/ingest \
  -H "X-Ingest-Key: $(cat siem_data/ingest_api_key.txt)" \
  -H "Content-Type: application/json" \
  -d '{"log":"Failed password for root from 1.2.3.4","source_ip":"1.2.3.4"}'
```

Alerts should appear on the dashboard within **1–2 seconds**.

---

## 📚 API Documentation

The full REST API is documented interactively at:
```
http://<YOUR_SIEM_IP>:5000/api/docs
```

Key endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Login and get JWT token |
| `GET` | `/api/alerts` | List all alerts |
| `POST` | `/api/ingest` | Submit a raw log for detection |
| `GET` | `/api/threat-intel/{ip}` | IP reputation lookup |
| `GET` | `/api/risk` | Current risk score |
| `GET` | `/api/stream` | Real-time SSE event stream |
| `GET` | `/api/health` | Server health status |

---

## 📁 Project Structure

```
tysonic-siem/
│
├── app.py                  # Main Flask server — all API routes
├── alert_engine.py         # Alert data models and SQLite storage
├── alert_manager.py        # Alert orchestration pipeline
├── detection_rules.py      # 40+ detection rules engine
├── threat_intel.py         # IP geo, AbuseIPDB, OTX, UEBA/ML
├── playbook_engine.py      # Automated response — iptables, Telegram
├── report_generator.py     # HTML incident report generation
├── correlation_engine.py   # Alert → Incident correlation
├── auth.py                 # JWT + MFA authentication
├── api_docs.py             # Swagger UI and OpenAPI 3.0 spec
├── siem_logger.py          # Central logging configuration
├── siem_env.py             # .env file loader
│
├── dashboard/
│   └── index.html          # Single-page dashboard UI
│
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
├── .gitignore              # Files excluded from git
└── README.md               # This file
```

---

## 🔧 Troubleshooting

**Elasticsearch connection failed:**
```bash
# Check ES is running
sudo systemctl status elasticsearch

# Check the password is correct in .env
curl -k -u elastic:YOUR_PASSWORD https://localhost:9200

# Check logs
sudo journalctl -u elasticsearch -n 50
```

**No alerts appearing on dashboard:**
```bash
# 1. Check Suricata is writing events
sudo tail -f /var/log/suricata/eve.json

# 2. Check Filebeat is shipping to ES
sudo systemctl status filebeat
sudo journalctl -u filebeat -n 20

# 3. Check ES has data
curl -k -u elastic:YOUR_PASSWORD "https://localhost:9200/filebeat-*/_count"

# 4. Test the ingest endpoint directly
curl -s -X POST http://localhost:5000/api/ingest \
  -H "X-Ingest-Key: $(cat siem_data/ingest_api_key.txt)" \
  -d '{"log":"test sql injection union select","source_ip":"1.2.3.4"}'

# 5. Check SIEM logs
tail -f siem_data/logs/siem.log
```

**Port 5000 not reachable from Kali:**
```bash
# Check Flask is binding to 0.0.0.0 not 127.0.0.1
ss -tlnp | grep 5000
# Should show: 0.0.0.0:5000

# Check firewall
sudo ufw status
sudo ufw allow 5000
```

**iptables blocking not working:**
```bash
# SIEM needs root/sudo for iptables
sudo python app.py
# or run gunicorn with sudo
```

---

## 🔒 Security Notes for Production

- Change default admin/analyst passwords immediately after setup
- Set a strong random `SIEM_SECRET_KEY` in `.env`
- Never expose port `5000` directly — put **nginx + TLS** in front
- Never expose port `9200` (Elasticsearch) to the public internet
- Add `.env` and `siem_data/` to `.gitignore` before pushing to GitHub
- Run the SIEM as a non-root user (use sudo only for iptables via a wrapper)

---

Built with ❤️ by Tyson &nbsp;·&nbsp; TYSONIC SIEM

---

Signature: BANDUGULA VENKATA TEJA
