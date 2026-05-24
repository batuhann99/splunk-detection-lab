# 🔍 Splunk Detection Lab

A hands-on SIEM detection engineering project built on Splunk Cloud. Real attack scenarios, custom SPL detection rules, and Python-based IOC enrichment — designed to simulate a real SOC analyst workflow.

---

## 📌 Project Overview

This project demonstrates end-to-end detection engineering using Splunk Cloud as the SIEM platform. Three realistic attack log datasets were created and ingested, covering web application attacks, Windows authentication events, and network-level threats. Custom SPL rules were written to detect each attack pattern.

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Splunk Cloud | SIEM platform |
| SPL | Detection rule language |
| Python 3 | IOC enrichment scripting |
| VirusTotal API | IP/hash reputation lookup |
| AbuseIPDB API | IP abuse scoring |
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
│   └── config.example.yaml
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

Detects successful HTTP access to sensitive files that should not be publicly reachable.

```spl
index=main sourcetype=csv attack_type=SensitiveFile
| table timestamp src_ip uri status_code severity
| sort timestamp
```

**Result:** `198.51.100.77` accessed `/.env`, `/wp-config.php`, `/backup.zip` — all returned HTTP 200.

---

### 4. Backdoor User Creation Detection
**File:** `detections/backdoor_user_creation.spl`

Detects execution of `net user /add` command on domain controllers — a classic post-exploitation persistence technique.

```spl
index=main source=windows_auth_logs.csv
| where like(failure_reason, "%net user%")
| table timestamp host user failure_reason
```

**Result:** `administrator` account on `dc01-windows` executed `net user /add backdoor Passw0rd!` at `2024-01-15 08:11:00`.

---

## 🔄 Project Roadmap

- [x] Splunk Cloud setup
- [x] Attack log datasets created and ingested
- [x] SPL detection rules written and tested
- [ ] Splunk Alerts configured
- [ ] Python IOC enrichment script (VirusTotal + AbuseIPDB)
- [ ] SOC Dashboard built
- [ ] Full documentation and writeup

---

## 👤 Author

**Batuhan**
Blue Team / SOC Analyst  
[GitHub](https://github.com/batuhann99) • [LinkedIn](#)
