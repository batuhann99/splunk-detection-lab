# 🔍 Splunk Detection Lab

A hands-on SIEM detection engineering project built on Splunk Cloud. Real attack scenarios, custom SPL detection rules, Python-based IOC enrichment, and a fully operational SOC dashboard — designed to simulate a real SOC analyst workflow.

---

## 📌 Project Overview

This project demonstrates end-to-end detection engineering using Splunk Cloud as the SIEM platform. Three realistic attack log datasets were created and ingested, covering web application attacks, Windows authentication events, and network-level threats. Custom SPL detection rules, scheduled alerts, a Python IOC enrichment script, and a multi-panel SOC dashboard were built on top of this data.

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Splunk Cloud | SIEM platform |
| SPL | Detection rule language |
| Python 3 | IOC enrichment scripting |
| VirusTotal API | IP/hash reputation lookup |
| AbuseIPDB API | IP abuse confidence scoring |
| GitHub | Version control & documentation |

---

## 📁 Project Structure

```
splunk-detection-lab/
├── detections/
│   ├── brute_force_detection.spl
│   ├── critical_events_detection.spl
│   ├── sensitive_file_access.spl
│   └── backdoor_user_creation.spl
├── enrichment/
│   ├── ioc_enricher.py
│   ├── requirements.txt
│   ├── config.example.yaml
│   └── sample_output/
│       ├── ioc_results.json
│       └── ioc_results.csv
├── dashboards/
│   └── soc_dashboard.xml
├── data/
│   └── sample_logs/
│       ├── web_attack_logs.csv
│       ├── windows_auth_logs.csv
│       └── network_scan_logs.csv
└── docs/
    └── screenshots/
```

---

## 📊 Log Datasets

Three custom attack log datasets were created and ingested into Splunk Cloud:

### 1. web_attack_logs.csv — Host: web-server-01
Web application attacks targeting a login page and search functionality.

| Attack Type | Description |
|-------------|-------------|
| SQLi | Classic and blind SQL injection attempts |
| XSS | Reflected, stored, and advanced XSS payloads |
| BruteForce | 13 failed login attempts → successful login |
| PathTraversal | Directory traversal to reach system files |
| SensitiveFile | Access to `.env`, `wp-config.php`, `backup.zip` |
| CMDInjection | OS command injection and reverse shell attempt |

### 2. windows_auth_logs.csv — Host: dc01-windows
Windows Active Directory and authentication events.

| Event | Description |
|-------|-------------|
| Account Lockout | 10 failed logins → administrator locked |
| Privilege Escalation | User added to admin group |
| Mimikatz | Credential dumping tool executed |
| Kerberoasting | Multiple RC4 service ticket requests |
| Backdoor User | `net user /add backdoor` command executed |

### 3. network_scan_logs.csv — Host: firewall-01
Network-level threats captured at the perimeter.

| Threat | Description |
|--------|-------------|
| Port Scan | Full TCP SYN scan across subnet |
| C2 Beacon | Repeated connection attempts every 30 seconds |
| DNS Tunneling | Unusually large DNS query bytes |
| Lateral Movement | SMB connections across internal hosts |
| Data Exfiltration | Large outbound transfers to external IP |

---

## 🚨 Detection Rules

### 1. Brute Force Attack Detection
**File:** `detections/brute_force_detection.spl`

Detects source IPs with more than 5 failed login attempts.

```spl
index=main sourcetype=csv attack_type=BruteForce
| stats count by src_ip
| where count > 5
| sort -count
```

**Result:** `203.0.113.42` detected with 13 attempts → successful login confirmed.

---

### 2. Critical Severity Events Monitor
**File:** `detections/critical_events_detection.spl`

Lists all events marked as CRITICAL severity across all log sources.

```spl
index=main sourcetype=csv severity=CRITICAL
| table timestamp src_ip attack_type uri
| sort timestamp
```

**Result:** 22 critical events detected including BruteForce_Success and SensitiveFile access.

---

### 3. Sensitive File Access Detection
**File:** `detections/sensitive_file_access.spl`

Detects successful HTTP access to sensitive files.

```spl
index=main sourcetype=csv attack_type=SensitiveFile
| table timestamp src_ip uri status_code severity
| sort timestamp
```

**Result:** `198.51.100.77` accessed `/.env`, `/wp-config.php`, `/backup.zip` — all returned HTTP 200.

---

### 4. Backdoor User Creation Detection
**File:** `detections/backdoor_user_creation.spl`

Detects execution of `net user /add` command on domain controllers.

```spl
index=main source=windows_auth_logs.csv
| where like(failure_reason, "%net user%")
| table timestamp host user failure_reason
```

**Result:** `administrator` on `dc01-windows` executed `net user /add backdoor Passw0rd!`

---

## 🔔 Splunk Alerts

Four scheduled alerts configured to run every hour:

| Alert | Severity | Schedule |
|-------|----------|----------|
| DETECT - Brute Force Attack | High | Hourly |
| DETECT - Critical Severity Events | Critical | Hourly |
| DETECT - Sensitive File Access | High | Hourly |
| DETECT - Backdoor User Creation | Critical | Hourly |

---

## 🐍 Python IOC Enrichment

**File:** `enrichment/ioc_enricher.py`

Automatically enriches attacker IPs using VirusTotal and AbuseIPDB APIs.

```
Input  : Attacker IPs from Splunk detection rules
Output : Verdict (MALICIOUS / SUSPICIOUS / CLEAN) + JSON + CSV report
```

### Sample Results

| IP | VT Score | Abuse Score | Country | ISP | Verdict |
|----|----------|-------------|---------|-----|---------|
| 185.220.101.45 | 17/91 | 100% | DE | Tor Exit Node | **MALICIOUS** |
| 45.33.32.156 | 4/91 | 12% | US | Linode | **SUSPICIOUS** |
| 203.0.113.42 | 0/91 | 0% | — | — | CLEAN |
| 198.51.100.77 | 0/91 | 0% | — | — | CLEAN |
| 91.108.4.100 | 0/91 | 0% | NL | Telegram | CLEAN |

> **Key Finding:** `185.220.101.45` (SQLi attacker) is a confirmed Tor Exit Node with 100% abuse confidence score and flagged by 17 VirusTotal engines.

### Usage

```bash
pip install -r requirements.txt
python ioc_enricher.py
```

---

## 📈 SOC Dashboard

**File:** `dashboards/soc_dashboard.xml`

Multi-panel dark-theme dashboard with 8 panels:

- **KPI Row** — Total Events (128), Critical Events (22), Brute Force Attempts (13), Unique Attacker IPs (12)
- **Attack Timeline** — Stacked column chart by severity over time
- **Attack Type Distribution** — Pie chart across all attack categories
- **Top Attacker IPs** — Bar chart of most active threat actors
- **Severity Breakdown** — Pie chart (CRITICAL / HIGH / MEDIUM / LOW)
- **Brute Force Top Sources** — Table with heatmap and risk scoring
- **Sensitive File Access** — Table of successful sensitive file grabs
- **Windows Auth Events** — Bar chart by event type
- **Recent Critical Events** — Live table of latest critical alerts

---

## ✅ Project Roadmap

- [x] Splunk Cloud setup
- [x] Attack log datasets created and ingested (3 sources, 128 events)
- [x] SPL detection rules written and tested (4 rules)
- [x] Splunk Alerts configured (4 alerts, hourly scheduled)
- [x] Python IOC enrichment script (VirusTotal + AbuseIPDB)
- [x] SOC Dashboard built (8 panels)
- [x] Full documentation and GitHub setup

---

## 👤 Author

**Batuhan Akkurt**  
Blue Team / SOC Analyst  
[GitHub](https://github.com/batuhann99)
