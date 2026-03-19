"""
Advanced Detection Rules Engine
35 rules across 8 categories:
  - Network attacks (port scan, brute force, DDoS)
  - Web attacks (SQLi, XSS, LFI, RFI, SSRF, path traversal)
  - Execution (reverse shell, PowerShell, WMI abuse)
  - Malware & C2 (Cobalt Strike, Metasploit, DNS tunnel, beacon)
  - Credential attacks (pass-the-hash, Kerberoasting, LDAP recon)
  - Lateral movement (SMB, RDP, WinRM, PsExec)
  - Exfiltration (DNS tunnel, large upload, cloud storage abuse)
  - Evasion & persistence (log clearing, scheduled tasks, registry run keys)
"""

import re
import json
from datetime import datetime, timezone
from alert_engine import Severity

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _sig(event):
    # Try direct alert.signature first
    sig = event.get("alert", {}).get("signature", "")
    if sig:
        return sig.lower()
    # Unwrap Filebeat/Logstash event.original to find the signature
    original_str = (event.get("event") or {}).get("original", "")
    if original_str:
        try:
            inner = json.loads(original_str)
            sig = inner.get("alert", {}).get("signature", "")
            if sig:
                return sig.lower()
        except Exception:
            pass
    return ""

def _log(event):
    # Use log_evidence if present (manual ingest path)
    if event.get("log_evidence"):
        return str(event["log_evidence"]).lower()

    # Unwrap Filebeat/Logstash wrapped events — original Suricata JSON
    # is stored as a string under event.original
    original_str = (event.get("event") or {}).get("original", "")
    if original_str:
        try:
            inner = json.loads(original_str)
            # Merge inner fields into a combined event for matching
            merged = {**inner, **{k: v for k, v in event.items() if k != "event"}}
            event  = merged
        except Exception:
            pass

    # Build match string from evidence fields only — exclude logstash
    # tags like event_source which can contain false-positive keywords
    parts = []
    for key in ("alert", "http", "dns", "tls", "smtp", "ssh",
                "payload_printable", "app_proto", "proto",
                "src_ip", "dest_ip", "src_port", "dest_port"):
        val = event.get(key)
        if val:
            parts.append(json.dumps(val) if isinstance(val, dict) else str(val))
    return " ".join(parts).lower() if parts else json.dumps(event).lower()

def _port(event):
    return int(event.get("dest_port") or event.get("port") or 0)

def _proto(event):
    return str(event.get("proto", "") or event.get("protocol", "")).lower()

def _win_event(event, *event_ids):
    eid = str(event.get("event_id") or event.get("EventID") or "")
    return eid in [str(e) for e in event_ids]


# ─────────────────────────────────────────────
# RULES — ordered by priority (high → low)
# ─────────────────────────────────────────────

RULES = [

    # ════════════════════════════════════════════
    # CATEGORY 1: EXECUTION
    # ════════════════════════════════════════════

    {
        "id":   "R001",
        "name": "Reverse Shell",
        "match": lambda e: (
            # Suricata signature-based — most reliable, no false positives
            any(k in _sig(e) for k in ["reverse shell", "reverse_shell", "bind shell", "netcat"]) or
            # Log/payload based — only match when NOT a web/HTTP context
            # (prevents sqlmap URL payloads like ?cmd=bash+-i from triggering this)
            (
                e.get("event_type") not in ("http",) and
                not str(e.get("log_evidence", "")).startswith(("GET ", "POST ", "PUT ", "DELETE ", "http://", "https://")) and
                any(k in _log(e) for k in [
                    "bash -i", "/dev/tcp", "nc -e", "ncat", "mkfifo", "/bin/sh -i",
                    "python -c.*socket", "perl -e.*socket", "ruby -rsocket",
                ])
            )
        ),
        "alert_type":  "reverse_shell",
        "severity":    Severity.CRITICAL,
        "description": lambda e: f"Reverse shell detected from {e.get('src_ip','?')}",
        "mitre": "T1059",
    },

    {
        "id":   "R002",
        "name": "PowerShell Suspicious Execution",
        "match": lambda e: (
            e.get("event_type") not in ("http",) and
            not str(e.get("log_evidence", "")).startswith(("GET ", "POST ", "PUT ", "DELETE ", "SQLI_HTTP", "SCANNER_UA", "LFI_HTTP")) and
            any(k in _log(e) for k in [
                "powershell -enc", "powershell -e ", "iex(", "invoke-expression",
                "downloadstring", "downloadfile", "system.net.webclient",
                "-nop -w hidden", "-windowstyle hidden", "bypass -noprofile",
                "powershell -exec bypass", "invoke-mimikatz", "invoke-bloodhound",
            ])
        ),
        "alert_type":  "malware",
        "severity":    Severity.HIGH,
        "description": lambda e: f"Suspicious PowerShell execution from {e.get('src_ip','?')}",
        "mitre": "T1059.001",
    },

    {
        "id":   "R003",
        "name": "WMI / WMIC Abuse",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "wmic process call create", "wmic /node:", "win32_process",
                "invoke-wmimethod", "get-wmiobject", "wmi subscription",
            ])
        ),
        "alert_type":  "malware",
        "severity":    Severity.HIGH,
        "description": lambda e: f"WMI abuse detected from {e.get('src_ip','?')}",
        "mitre": "T1047",
    },

    {
        "id":   "R004",
        "name": "Script Interpreter Abuse (Python/Perl/Ruby)",
        "match": lambda e: (
            # Only fire when NOT a raw HTTP request log — sqlmap injects
            # python/perl one-liners into URLs which would otherwise match here
            e.get("event_type") not in ("http",) and
            not str(e.get("log_evidence", "")).startswith(("GET ", "POST ", "PUT ", "DELETE ", "http://", "https://")) and
            any(k in _log(e) for k in [
                "python -c", "perl -e", "ruby -e", "python3 -c",
                "os.system(", "subprocess.popen(", "__import__('os')",
            ])
        ),
        "alert_type":  "malware",
        "severity":    Severity.HIGH,
        "description": lambda e: f"Script interpreter abuse from {e.get('src_ip','?')}",
        "mitre": "T1059.006",
    },

    # ════════════════════════════════════════════
    # CATEGORY 2: WEB ATTACKS
    # ════════════════════════════════════════════

    {
        "id":   "R010",
        "name": "SQL Injection",
        "match": lambda e: (
            any(k in _sig(e) for k in ["sql", "injection", "sqlmap"]) or
            any(k in _log(e) for k in [
                "sqlmap", "union select", "or 1=1", "' or '", "drop table",
                "information_schema", "sleep(", "benchmark(", "waitfor delay",
                "1' and '1'='1", "admin'--", "' union all select",
                # URL-encoded variants sqlmap sends
                "%27", "%20or%20", "1%3d1", "%27or%271%27%3d%271",
                "and 1=1", "and 1=2", "order by 1", "order by 100",
                "having 1=1", "group by 1",
            ])
        ),
        "alert_type":  "web_attack",
        "severity":    Severity.HIGH,
        "description": lambda e: f"SQL injection attempt from {e.get('src_ip','?')}",
        "mitre": "T1190",
    },

    {
        "id":   "R011",
        "name": "Cross-Site Scripting (XSS)",
        "match": lambda e: (
            any(k in _sig(e) for k in ["xss", "cross-site", "script injection"]) or
            any(k in _log(e) for k in [
                "<script>", "javascript:", "onerror=", "onload=",
                "alert(", "document.cookie", "eval(", "<img src=x",
                "onmouseover=", "svg/onload=",
            ])
        ),
        "alert_type":  "web_attack",
        "severity":    Severity.MEDIUM,
        "description": lambda e: f"XSS attempt from {e.get('src_ip','?')}",
        "mitre": "T1059",
    },

    {
        "id":   "R012",
        "name": "Local / Remote File Inclusion",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "../../../", "..\\..\\..\\", "/etc/passwd", "/etc/shadow",
                "php://input", "php://filter", "expect://", "data://",
                "file:///", "include(", "require(", "?file=", "?page=../",
            ])
        ),
        "alert_type":  "web_attack",
        "severity":    Severity.HIGH,
        "description": lambda e: f"LFI/RFI attempt from {e.get('src_ip','?')}",
        "mitre": "T1190",
    },

    {
        "id":   "R013",
        "name": "SSRF (Server-Side Request Forgery)",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "169.254.169.254", "metadata.google.internal",
                "?url=http://", "?url=file://", "?redirect=http://internal",
                "localhost/admin", "127.0.0.1/admin", "ssrf",
            ])
        ),
        "alert_type":  "web_attack",
        "severity":    Severity.HIGH,
        "description": lambda e: f"SSRF attempt from {e.get('src_ip','?')}",
        "mitre": "T1190",
    },

    {
        "id":   "R014",
        "name": "Command Injection",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "; cat /etc/passwd", "| id", "&& whoami", "; ls -la",
                "`id`", "$(id)", "; wget http", "; curl http",
                "| nc ", ";/bin/bash", "%3b/bin/bash",
            ])
        ),
        "alert_type":  "web_attack",
        "severity":    Severity.CRITICAL,
        "description": lambda e: f"Command injection attempt from {e.get('src_ip','?')}",
        "mitre": "T1190",
    },

    # ════════════════════════════════════════════

    # ════════════════════════════════════════════
    # WEB SCANNER DETECTION
    # ════════════════════════════════════════════

    {
        "id":   "R092",
        "name": "Web Scanner (Nikto/Dirb/Gobuster/SQLMap)",
        "match": lambda e: (
            # Known scanner user-agents in HTTP events
            any(k in str((e.get("http") or {}).get("http_user_agent", "")).lower()
                for k in ["nikto", "nessus", "openvas", "dirbuster",
                          "gobuster", "feroxbuster", "nuclei", "wfuzz",
                          "nmap scripting", "zgrab", "masscan", "sqlmap"]) or
            # ET rule signatures for web scanners
            any(k in _sig(e) for k in [
                "nikto", "web scan", "vulnerability scan",
                "nessus", "openvas", "acunetix", "appscan", "sqlmap",
            ]) or
            # Nikto-specific probe strings in log/payload
            any(k in _log(e) for k in [
                "4DcW9V", "nikto", "web-app-scanner",
                "X-Forwarded-For: 127.0.0.1",  # nikto default header
                "/cgi-bin/test-cgi",            # nikto probe
                "/cgi-bin/printenv",            # nikto probe
                "HTTP/1.0\r\nHost:",            # nikto old-style probe
            ])
        ),
        "alert_type":  "web_attack",
        "severity":    Severity.HIGH,
        "description": lambda e: (
            f"Web scanner from {e.get('src_ip','?')} — "
            f"UA: {str((e.get('http') or {}).get('http_user_agent','unknown'))[:60]}"
        ),
        "mitre": "T1595",
    },

    {
        "id":   "R093",
        "name": "Web Directory/File Enumeration",
        "match": lambda e: (
            # Nikto probes backup/config file extensions
            any(k in _log(e) for k in [
                ".bak", ".backup", ".sql", ".db", ".config",
                "/.htaccess", "/.htpasswd", "/cgi-bin/",
                "backup.zip", "backup.tar", "dump.sql",
                ".env", "config.php", "wp-config",
            ]) or
            any(k in _sig(e) for k in [
                "backup file", "config file", "directory traversal",
                "file enumeration", "sensitive file",
            ])
        ),
        "alert_type":  "web_attack",
        "severity":    Severity.MEDIUM,
        "description": lambda e: (
            f"File/directory enumeration from {e.get('src_ip','?')} — "
            f"URL: {str((e.get('http') or {}).get('url','?'))[:80]}"
        ),
        "mitre": "T1083",
    },

    # CATEGORY 3: NETWORK RECON & SCANNING
    # ════════════════════════════════════════════

    {
        "id":   "R020",
        "name": "Port Scan (Nmap/Masscan)",
        "match": lambda e: (
            # Signature-based: Suricata ET rules
            "nmap" in _sig(e) or
            "portscan" in _sig(e) or "masscan" in _sig(e) or
            (e.get("event_type") == "alert" and "scan" in _sig(e)) or
            # HTTP user-agent based (nmap -sV, nmap NSE scripts)
            "nmap" in str((e.get("http") or {}).get("http_user_agent", "")).lower() or
            # Log/payload based
            "nmap" in _log(e) or "masscan" in _log(e) or
            # alert_type already classified as port_scan (from flow tracker)
            e.get("alert_type") == "port_scan"
        ),
        "alert_type":  "port_scan",
        "severity":    Severity.MEDIUM,
        "description": lambda e: (
            f"Port scan detected from {e.get('src_ip','?')} targeting {e.get('dest_ip','?')}"
            + (f" [{e.get('alert',{}).get('signature','')}]"
               if e.get("alert",{}).get("signature") else "")
        ),
        "mitre": "T1046",
    },

    {
        "id":   "R021",
        "name": "SSH Brute Force",
        "match": lambda e: (
            # ET rule signatures (if loaded)
            any(k in _sig(e) for k in ["brute", "hydra", "ssh login", "failed login",
                                        "ssh scan", "ssh auth"]) or
            # Suricata built-in SSH signatures (no ET rules needed)
            any(k in _sig(e) for k in [
                "suricata ssh",
                "applayer detect protocol only one direction",  # repeated = brute force
                "ssh invalid banner",
                "ssh invalid client",
                "ssh invalid server",
            ]) or
            # Log/auth file patterns (syslog, auth.log ingested via manual ingest)
            any(k in _log(e) for k in [
                "failed password", "invalid user", "authentication failure",
                "too many authentication failures", "connection closed by",
                "disconnecting: too many", "pam_unix", "sshd",
            ]) or
            # Flow-based: dest_port 22 with brute_force alert_type (set by tracker)
            (e.get("alert_type") == "brute_force" and
             int(e.get("dest_port", 0) or 0) == 22)
        ),
        "alert_type":  "brute_force",
        "severity":    Severity.HIGH,
        "description": lambda e: f"SSH brute force from {e.get('src_ip','?')} targeting {e.get('dest_ip','?')}",
        "mitre": "T1110",
    },

    {
        "id":   "R022",
        "name": "RDP Brute Force",
        "match": lambda e: (
            (_port(e) == 3389 and any(k in _log(e) for k in ["failed", "brute", "login attempt"])) or
            any(k in _log(e) for k in ["rdp brute", "xfreerdp.*failed", "rdesktop.*failed"]) or
            _win_event(e, 4625) and "3389" in _log(e)
        ),
        "alert_type":  "brute_force",
        "severity":    Severity.HIGH,
        "description": lambda e: f"RDP brute force from {e.get('src_ip','?')}",
        "mitre": "T1110",
    },

    {
        "id":   "R023",
        "name": "DNS Amplification / DDoS",
        "match": lambda e: (
            any(k in _sig(e) for k in ["dns amplification", "ddos", "flood"]) or
            any(k in _log(e) for k in ["dns amplif", "udp flood", "syn flood", "icmp flood", "amplification attack"])
        ),
        "alert_type":  "port_scan",
        "severity":    Severity.HIGH,
        "description": lambda e: f"DDoS/amplification attack from {e.get('src_ip','?')}",
        "mitre": "T1498",
    },

    # ════════════════════════════════════════════
    # CATEGORY 4: CREDENTIAL ATTACKS
    # ════════════════════════════════════════════

    {
        "id":   "R030",
        "name": "Pass-the-Hash / Pass-the-Ticket",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "pass-the-hash", "pth attack", "pass the hash",
                "pass-the-ticket", "golden ticket", "silver ticket",
                "sekurlsa::pth", "kerberos::ptt",
            ]) or _win_event(e, 4768, 4769) and "rc4" in _log(e)
        ),
        "alert_type":  "brute_force",
        "severity":    Severity.CRITICAL,
        "description": lambda e: f"Pass-the-Hash/Ticket detected from {e.get('src_ip','?')}",
        "mitre": "T1550.002",
    },

    {
        "id":   "R031",
        "name": "Kerberoasting",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "kerberoast", "spn scan", "invoke-kerberoast",
                "getuserspns", "rc4_hmac_md5",
            ]) or _win_event(e, 4769) and "0x17" in _log(e)
        ),
        "alert_type":  "brute_force",
        "severity":    Severity.HIGH,
        "description": lambda e: f"Kerberoasting attempt from {e.get('src_ip','?')}",
        "mitre": "T1558.003",
    },

    {
        "id":   "R032",
        "name": "LDAP Reconnaissance",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "ldapsearch", "ldap recon", "bloodhound", "sharphound",
                "adexplorer", "get-aduser", "get-adcomputer", "get-adgroup",
                "(objectclass=*)", "cn=domain admins",
            ])
        ),
        "alert_type":  "abnormal_login",
        "severity":    Severity.MEDIUM,
        "description": lambda e: f"LDAP/AD reconnaissance from {e.get('src_ip','?')}",
        "mitre": "T1018",
    },

    {
        "id":   "R033",
        "name": "Credential Dumping (Mimikatz / LSASS)",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "mimikatz", "sekurlsa", "lsass.exe", "lsass dump",
                "procdump.*lsass", "comsvcs.dll.*minidump",
                "wce.exe", "pwdump", "fgdump", "hashdump",
            ])
        ),
        "alert_type":  "malware",
        "severity":    Severity.CRITICAL,
        "description": lambda e: f"Credential dumping detected from {e.get('src_ip','?')}",
        "mitre": "T1003",
    },

    # ════════════════════════════════════════════
    # CATEGORY 5: LATERAL MOVEMENT
    # ════════════════════════════════════════════

    {
        "id":   "R040",
        "name": "SMB Lateral Movement / PsExec",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "psexec", "smbexec", "wmiexec", "atexec",
                "impacket", "\\\\admin$", "\\\\c$\\windows",
                "ipc$ connect", "net use \\\\",
            ]) or (_port(e) == 445 and "lateral" in _log(e))
        ),
        "alert_type":  "malicious_ip",
        "severity":    Severity.HIGH,
        "description": lambda e: f"SMB lateral movement from {e.get('src_ip','?')} to {e.get('dest_ip','?')}",
        "mitre": "T1021.002",
    },

    {
        "id":   "R041",
        "name": "RDP Lateral Movement",
        "match": lambda e: (
            (_port(e) == 3389 and "lateral" in _log(e)) or
            any(k in _log(e) for k in [
                "mstsc.exe /v:", "xfreerdp /v:", "remote desktop to internal",
            ]) or _win_event(e, 4624) and "10" in _log(e) and _port(e) == 3389
        ),
        "alert_type":  "malicious_ip",
        "severity":    Severity.HIGH,
        "description": lambda e: f"RDP lateral movement from {e.get('src_ip','?')}",
        "mitre": "T1021.001",
    },

    {
        "id":   "R042",
        "name": "WinRM / PowerShell Remoting",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "winrm", "enter-pssession", "invoke-command -computername",
                "new-pssession", "wsman",
            ]) or _port(e) in (5985, 5986)
        ),
        "alert_type":  "malicious_ip",
        "severity":    Severity.HIGH,
        "description": lambda e: f"WinRM/PSRemoting lateral movement from {e.get('src_ip','?')}",
        "mitre": "T1021.006",
    },

    # ════════════════════════════════════════════
    # CATEGORY 6: MALWARE & C2
    # ════════════════════════════════════════════

    {
        "id":   "R050",
        "name": "Malware / Trojan",
        "match": lambda e: (
            any(k in _sig(e) for k in ["trojan", "malware", "ransomware", "backdoor", "rootkit", "rat "]) or
            any(k in _log(e) for k in ["mimikatz", "meterpreter", "cobalt strike", "empire", "metasploit"])
        ),
        "alert_type":  "malware",
        "severity":    Severity.CRITICAL,
        "description": lambda e: f"Malware activity from {e.get('src_ip','?')}",
        "mitre": "T1204",
    },

    {
        "id":   "R051",
        "name": "Cobalt Strike Beacon",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "cobalt strike", "cobaltstrike", "beacon.dll",
                "cs beacon", "teamserver", "sleep_mask",
                "cs_beacon", "pipe_name.*msagent",
            ])
        ),
        "alert_type":  "malicious_ip",
        "severity":    Severity.CRITICAL,
        "description": lambda e: f"Cobalt Strike beacon detected from {e.get('src_ip','?')}",
        "mitre": "T1071.001",
    },

    {
        "id":   "R052",
        "name": "C2 Beacon / Command & Control",
        "match": lambda e: (
            any(k in _sig(e) for k in ["c2", "command and control", "beacon", "c&c"]) or
            any(k in _log(e) for k in ["beacon interval", "c2 traffic", "command & control", "c2_server"])
        ),
        "alert_type":  "malicious_ip",
        "severity":    Severity.HIGH,
        "description": lambda e: f"C2 beacon traffic from {e.get('src_ip','?')}",
        "mitre": "T1071",
    },

    {
        "id":   "R053",
        "name": "DNS Tunneling",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "dns tunnel", "dns exfil", "iodine", "dnscat",
                "dns2tcp", "txt record exfil", "base64.*dns",
                "long dns query", "dns_length_anomaly",
            ]) or (
                _proto(e) == "dns" and
                len(str(e.get("dns_query", ""))) > 100
            )
        ),
        "alert_type":  "data_exfiltration",
        "severity":    Severity.HIGH,
        "description": lambda e: f"DNS tunneling detected from {e.get('src_ip','?')}",
        "mitre": "T1071.004",
    },

    {
        "id":   "R054",
        "name": "Ransomware Activity",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "ransomware", ".encrypted", ".locked", "your files have been encrypted",
                "readme_to_decrypt", "how_to_decrypt", "vssadmin delete shadows",
                "bcdedit /set recoveryenabled no", "wbadmin delete",
            ])
        ),
        "alert_type":  "malware",
        "severity":    Severity.CRITICAL,
        "description": lambda e: f"Ransomware activity detected from {e.get('src_ip','?')}",
        "mitre": "T1486",
    },

    # ════════════════════════════════════════════
    # CATEGORY 7: EXFILTRATION
    # ════════════════════════════════════════════

    {
        "id":   "R060",
        "name": "Data Exfiltration",
        "match": lambda e: (
            any(k in _sig(e) for k in ["exfil", "data transfer", "dns tunnel", "icmp tunnel"]) or
            any(k in _log(e) for k in ["exfiltration", "data exfil", "large upload", "dns exfil"])
        ),
        "alert_type":  "data_exfiltration",
        "severity":    Severity.HIGH,
        "description": lambda e: f"Data exfiltration from {e.get('src_ip','?')} to {e.get('dest_ip','?')}",
        "mitre": "T1041",
    },

    {
        "id":   "R061",
        "name": "Cloud Storage Exfiltration (S3 / GCS / OneDrive)",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "s3.amazonaws.com", "blob.core.windows.net", "storage.googleapis.com",
                "onedrive.live.com", "dropbox.com/upload", "mega.io",
                "aws s3 cp", "gsutil cp", "azcopy",
            ]) and any(k in _log(e) for k in ["upload", "put", "post", "exfil"])
        ),
        "alert_type":  "data_exfiltration",
        "severity":    Severity.HIGH,
        "description": lambda e: f"Cloud storage exfiltration from {e.get('src_ip','?')}",
        "mitre": "T1537",
    },

    # ════════════════════════════════════════════
    # CATEGORY 8: EVASION & PERSISTENCE
    # ════════════════════════════════════════════

    {
        "id":   "R070",
        "name": "Event Log Clearing",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "wevtutil cl", "clear-eventlog", "event log cleared",
                "auditpol /clear", "security log cleared",
            ]) or _win_event(e, 1102, 104)
        ),
        "alert_type":  "malware",
        "severity":    Severity.HIGH,
        "description": lambda e: f"Event log clearing detected from {e.get('src_ip','?')}",
        "mitre": "T1070.001",
    },

    {
        "id":   "R071",
        "name": "Scheduled Task / Cron Persistence",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "schtasks /create", "at.exe", "crontab -e", "cron.d",
                "taskschd.msc", "new-scheduledtask",
            ]) or _win_event(e, 4698, 4702)
        ),
        "alert_type":  "malware",
        "severity":    Severity.MEDIUM,
        "description": lambda e: f"Persistence via scheduled task from {e.get('src_ip','?')}",
        "mitre": "T1053",
    },

    {
        "id":   "R072",
        "name": "Registry Run Key Persistence",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "hkcu\\software\\microsoft\\windows\\currentversion\\run",
                "hklm\\software\\microsoft\\windows\\currentversion\\run",
                "reg add.*run", "set-itemproperty.*run",
                "currentversion\\runonce",
            ]) or _win_event(e, 13)
        ),
        "alert_type":  "malware",
        "severity":    Severity.HIGH,
        "description": lambda e: f"Registry run key persistence from {e.get('src_ip','?')}",
        "mitre": "T1547.001",
    },

    {
        "id":   "R073",
        "name": "Defense Evasion (AMSI / AV Bypass)",
        "match": lambda e: (
            any(k in _log(e) for k in [
                "amsiutils", "amsi bypass", "set-mppreference -disablerealtimemonitoring",
                "uninstall antivirus", "kill defender", "tamper protection",
                "[ref].assembly.gettype", "amsicontext",
            ])
        ),
        "alert_type":  "malware",
        "severity":    Severity.HIGH,
        "description": lambda e: f"Defense evasion/AMSI bypass from {e.get('src_ip','?')}",
        "mitre": "T1562",
    },

    # ════════════════════════════════════════════
    # CATEGORY 9: ANOMALOUS AUTH
    # ════════════════════════════════════════════

    {
        "id":   "R080",
        "name": "Abnormal Login / Geo Anomaly",
        "match": lambda e: (
            any(k in _sig(e) for k in ["abnormal login", "geo mismatch", "impossible travel"]) or
            any(k in _log(e) for k in ["unusual location", "new device", "impossible travel",
                                        "geo anomaly", "country mismatch"])
        ),
        "alert_type":  "abnormal_login",
        "severity":    Severity.MEDIUM,
        "description": lambda e: f"Abnormal login from {e.get('src_ip','?')}",
        "mitre": "T1078",
    },

    {
        "id":   "R081",
        "name": "Multiple Failed Logins — Windows (4625)",
        "match": lambda e: _win_event(e, 4625),
        "alert_type":  "brute_force",
        "severity":    Severity.MEDIUM,
        "description": lambda e: f"Windows failed login (Event 4625) from {e.get('src_ip','?')}",
        "mitre": "T1110",
    },

    {
        "id":   "R082",
        "name": "Privilege Escalation — Windows (4672/4673)",
        "match": lambda e: _win_event(e, 4672, 4673),
        "alert_type":  "abnormal_login",
        "severity":    Severity.HIGH,
        "description": lambda e: f"Privilege escalation event from {e.get('src_ip','?')}",
        "mitre": "T1068",
    },

    # ════════════════════════════════════════════
    # CATCH-ALL
    # ════════════════════════════════════════════

    # ════════════════════════════════════════════
    # SURICATA BUILT-IN SSH / PROTOCOL ANOMALY
    # ════════════════════════════════════════════

    {
        "id":   "R090",
        "name": "Suricata SSH Protocol Anomaly (Brute Force)",
        "match": lambda e: (
            e.get("event_type") == "alert" and
            any(k in _sig(e) for k in [
                "applayer detect protocol only one direction",
                "suricata ssh",
                "ssh invalid",
            ]) and
            int(e.get("dest_port", 0) or 0) in (22, 2222, 2200)
        ),
        "alert_type":  "brute_force",
        "severity":    Severity.HIGH,
        "description": lambda e: (
            f"SSH brute force from {e.get('src_ip','?')} "
            f"[{e.get('alert',{}).get('signature','')}]"
        ),
        "mitre": "T1110",
    },

    {
        "id":   "R091",
        "name": "Suricata Protocol Anomaly on Service Port",
        "match": lambda e: (
            e.get("event_type") == "alert" and
            "applayer detect protocol only one direction" in _sig(e) and
            int(e.get("dest_port", 0) or 0) in (21, 22, 23, 25, 110, 143, 3306, 5432, 6379, 27017)
        ),
        "alert_type":  "brute_force",
        "severity":    Severity.MEDIUM,
        "description": lambda e: (
            f"Brute force / scan on port {e.get('dest_port','?')} "
            f"from {e.get('src_ip','?')}"
        ),
        "mitre": "T1110",
    },


    {
        "id":   "R099",
        "name": "Generic IDS Alert",
        "match": lambda e: e.get("event_type") == "alert" and bool(e.get("alert", {}).get("signature")),
        "alert_type":  "ids_alert",
        "severity":    Severity.LOW,
        "description": lambda e: f"IDS alert: {e.get('alert',{}).get('signature','?')[:80]}",
        "mitre": "T1040",
    },

    # ════════════════════════════════════════════
    # CATEGORY 10: PHISHING DETECTION
    # ════════════════════════════════════════════

    {
        "id":   "R100",
        "name": "Phishing URL Pattern",
        "match": lambda e: (
            # Suricata ET Phishing signatures
            any(k in _sig(e) for k in [
                "phishing", "phish", "credential harvest", "fake login",
                "suspicious redirect", "open redirect",
            ]) or
            # URL pattern matching — typosquatting, lookalike domains
            any(k in _log(e) for k in [
                # Brand impersonation patterns
                "paypa1.", "paypa1-", "paypall.", "arnazon.", "amazzon.",
                "g00gle.", "go0gle.", "micosoft.", "micros0ft.", "0utlook.",
                "icloud-", "apple-id-", "faceb00k.", "linkedln.",
                # Common phishing path patterns
                "/secure/login", "/account-verify", "/account-suspended",
                "/verify-identity", "/confirm-payment", "/update-billing",
                "/signin/v2/identifier", "password-reset-required",
                # Credential harvesting page patterns
                "username=&password=", "login.php?redirect=",
                "wp-login.php", "/phishing/", "/harvest/",
                # URL shortener abuse (common in phishing)
                "bit.ly/", "tinyurl.com/", "t.co/", "goo.gl/",
                # Suspicious TLD + brand combo
                "-paypal.com", "-amazon.com", "-apple.com",
                "-microsoft.com", "-google.com", "-facebook.com",
            ])
        ),
        "alert_type":  "phishing",
        "severity":    Severity.HIGH,
        "description": lambda e: (
            f"Phishing URL pattern detected from {e.get('src_ip','?')} "
            f"— {_sig(e) or _log(e)[:60]}"
        ),
        "mitre": "T1566.002",
    },

    {
        "id":   "R101",
        "name": "Phishing Email Indicators",
        "match": lambda e: (
            # SMTP-based phishing indicators
            any(k in _sig(e) for k in ["phishing email", "malicious attachment", "suspicious smtp"]) or
            any(k in _log(e) for k in [
                # Suspicious subject lines in SMTP logs
                "urgent: your account", "action required:", "verify your account",
                "your account has been suspended", "unusual sign-in activity",
                "you have a pending payment", "click here to confirm",
                "your password will expire", "congratulations you won",
                # Malicious attachment extensions in email
                ".exe attachment", ".vbs attachment", ".js attachment",
                ".doc attachment", ".xlsm attachment", "macro enabled",
                # Email header anomalies
                "x-mailer: massmailer", "x-php-originating-script",
                "reply-to: differs from from:",
                # Known phishing kits
                "phishing kit", "16shop", "evil-ginx", "evilginx",
                "modlishka", "gophish",
            ])
        ),
        "alert_type":  "phishing",
        "severity":    Severity.HIGH,
        "description": lambda e: f"Phishing email indicators from {e.get('src_ip','?')}",
        "mitre": "T1566.001",
    },

    {
        "id":   "R102",
        "name": "DNS Phishing / Homograph Attack",
        "match": lambda e: (
            any(k in _sig(e) for k in ["homograph", "idn homograph", "punycode", "lookalike domain"]) or
            any(k in _log(e) for k in [
                # Punycode / IDN homograph attacks (unicode lookalike domains)
                "xn--",          # punycode prefix
                "homograph",
                # Newly registered domain patterns used in phishing
                "securelogin-",  "account-update-",  "verify-account-",
                "login-secure-",  "support-helpdesk-", "billing-update-",
                # Suspicious subdomain patterns
                "login.signin.", "secure.account.", "update.verify.",
            ])
        ),
        "alert_type":  "phishing",
        "severity":    Severity.HIGH,
        "description": lambda e: f"DNS homograph/phishing domain from {e.get('src_ip','?')}",
        "mitre": "T1566.002",
    },

    # ════════════════════════════════════════════
    # CATEGORY 11: DDoS DETECTION (volumetric)
    # ════════════════════════════════════════════

    {
        "id":   "R110",
        "name": "SYN Flood / TCP DDoS",
        "match": lambda e: (
            any(k in _sig(e) for k in [
                "syn flood", "tcp flood", "dos attack", "ddos", "tcp syn",
                "possible syn flood", "tcpflood",
            ]) or
            any(k in _log(e) for k in [
                "syn flood", "tcp flood", "tcpflood", "possible dos",
                "possible ddos", "abnormal syn rate",
            ]) or
            # Suricata flow stats: very high packet count to same dest in short time
            (
                e.get("event_type") == "flow" and
                int((e.get("flow") or {}).get("pkts_toserver", 0) or 0) > 10000
            )
        ),
        "alert_type":  "ddos",
        "severity":    Severity.CRITICAL,
        "description": lambda e: (
            f"SYN/TCP flood from {e.get('src_ip','?')} "
            f"pkts={((e.get('flow') or {}).get('pkts_toserver','?'))}"
        ),
        "mitre": "T1498.001",
    },

    {
        "id":   "R111",
        "name": "UDP Flood / Amplification DDoS",
        "match": lambda e: (
            any(k in _sig(e) for k in [
                "udp flood", "dns amplification", "ntp amplification",
                "ssdp amplification", "memcached amplification",
                "chargen amplification", "snmp amplification",
            ]) or
            any(k in _log(e) for k in [
                "udp flood", "dns amplif", "ntp amplif", "ssdp amplif",
                "memcached amplif", "amplification attack",
            ]) or
            (
                e.get("event_type") == "flow" and
                _proto(e) == "udp" and
                int((e.get("flow") or {}).get("bytes_toserver", 0) or 0) > 5_000_000
            )
        ),
        "alert_type":  "ddos",
        "severity":    Severity.CRITICAL,
        "description": lambda e: (
            f"UDP flood/amplification from {e.get('src_ip','?')} "
            f"bytes={((e.get('flow') or {}).get('bytes_toserver','?'))}"
        ),
        "mitre": "T1498.002",
    },

    {
        "id":   "R112",
        "name": "HTTP Flood / Layer-7 DDoS",
        "match": lambda e: (
            any(k in _sig(e) for k in [
                "http flood", "l7 dos", "slowloris", "rudy attack",
                "slow post", "slow read", "httpflood",
            ]) or
            any(k in _log(e) for k in [
                "slowloris", "slow http", "rudy", "http flood",
                "layer 7 dos", "slow post attack", "connection exhaustion",
            ])
        ),
        "alert_type":  "ddos",
        "severity":    Severity.HIGH,
        "description": lambda e: f"HTTP flood/Layer-7 DDoS from {e.get('src_ip','?')}",
        "mitre": "T1499.002",
    },

    {
        "id":   "R113",
        "name": "ICMP Flood",
        "match": lambda e: (
            any(k in _sig(e) for k in ["icmp flood", "ping flood", "smurf"]) or
            any(k in _log(e) for k in ["icmp flood", "ping flood", "smurf attack"]) or
            (
                e.get("event_type") == "flow" and
                _proto(e) == "icmp" and
                int((e.get("flow") or {}).get("pkts_toserver", 0) or 0) > 5000
            )
        ),
        "alert_type":  "ddos",
        "severity":    Severity.HIGH,
        "description": lambda e: f"ICMP flood from {e.get('src_ip','?')}",
        "mitre": "T1498",
    },
]


# ─────────────────────────────────────────────
# Detection Engine
# ─────────────────────────────────────────────

class DetectionEngine:

    def __init__(self):
        self.rules = RULES
        self.stats = {r["id"]: 0 for r in RULES}

    def evaluate(self, event: dict):
        """
        Evaluate event against all rules.
        Returns (alert_type, severity, description, rule_id) or None.
        First matching rule wins.
        """
        for rule in self.rules:
            try:
                if rule["match"](event):
                    self.stats[rule["id"]] = self.stats.get(rule["id"], 0) + 1
                    return (
                        rule["alert_type"],
                        rule["severity"],
                        rule["description"](event),
                        rule["id"],
                    )
            except Exception:
                continue
        return None

    def evaluate_all(self, event: dict) -> list:
        """Return ALL matching rules (for correlation engine)."""
        matches = []
        for rule in self.rules:
            try:
                if rule["match"](event):
                    matches.append({
                        "rule_id":    rule["id"],
                        "rule_name":  rule["name"],
                        "alert_type": rule["alert_type"],
                        "severity":   rule["severity"],
                        "mitre":      rule.get("mitre", ""),
                    })
            except Exception:
                continue
        return matches

    def get_stats(self) -> list:
        return [
            {
                "rule_id":   rid,
                "rule_name": next((r["name"] for r in self.rules if r["id"] == rid), rid),
                "hits":      cnt,
                "category":  next((r.get("alert_type","") for r in self.rules if r["id"] == rid), ""),
            }
            for rid, cnt in sorted(self.stats.items(), key=lambda x: -x[1])
        ]

    def add_rule(self, rule: dict):
        """Dynamically add a custom rule."""
        self.rules.append(rule)
        self.stats[rule["id"]] = 0


# Singleton
engine = DetectionEngine()