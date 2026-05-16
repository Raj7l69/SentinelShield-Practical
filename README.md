# SentinelShield: Advanced Intrusion Detection & Web Protection System

A Python-based educational toolkit that simulates a lightweight Web Application Firewall (WAF). It inspects HTTP requests, detects common web attacks, monitors traffic for brute-force behavior, logs all events, and generates a final analysis report.

Built for educational and defensive security purposes as part of a cybersecurity project.

---

## What It Does

- **Inspects** simulated HTTP requests against known attack signature rules
- **Detects** SQL Injection, XSS, LFI, Command Injection, Directory Traversal, and Sensitive File Access
- **Monitors** request frequency per IP and flags abusive behavior (rate limiting)
- **Logs** every event with timestamp, IP, method, URL, decision, category, and severity
- **Reports** a dashboard-style summary and a detailed final analysis report

---

## Project Structure

```
sentinelshield/
│
├── waf.py               # HTTP request inspection + rule-based detection engine
├── traffic_monitor.py   # Rate limiting + full request processing pipeline
├── logger.py            # Event logging (text + JSON) and log reader
├── reporter.py          # Dashboard + final report generator
│
├── sentinelshield.log          # Human-readable log (auto-generated)
├── sentinelshield_events.json  # Structured JSON log (auto-generated)
└── sentinelshield_report.txt   # Final report (auto-generated)
```

---

## Requirements

- **Python:** 3.8 or above
- **OS:** Windows / Linux / macOS
- **Dependencies:** None — uses only Python standard library (`re`, `datetime`, `json`, `os`, `collections`, `time`)

---

## How to Use

### Step 1 — Run the WAF Standalone Demo

```bash
python waf.py
```

Inspects a set of test HTTP requests and shows which are blocked and why.

---

### Step 2 — Run the Traffic Monitor

```bash
python traffic_monitor.py
```

Runs the full pipeline — WAF inspection + rate limiting — on a demo set of requests including a simulated brute-force attack. Writes results to `sentinelshield.log` and `sentinelshield_events.json`.

---

### Step 3 — View Logs

```bash
python logger.py
```

Displays the last 20 log entries and a quick summary (totals, by category, by severity, top IPs).

---

### Step 4 — Generate the Final Report

```bash
python reporter.py
```

Prints a live dashboard to the console and saves the full analysis report to `sentinelshield_report.txt`.

---

## Detected Attack Categories

| Category | Example Pattern | Severity |
|---|---|---|
| SQL_INJECTION | `' OR 1=1 --`, `UNION SELECT` | CRITICAL |
| XSS | `<script>alert()</script>`, `onerror=` | HIGH |
| LFI | `../../etc/passwd` | HIGH |
| COMMAND_INJECTION | `; cat /etc/shadow`, `| bash` | CRITICAL |
| DIRECTORY_TRAVERSAL | `../`, `%2e%2e%2f` | MEDIUM |
| SENSITIVE_FILE_ACCESS | `.env`, `.htaccess`, `wp-config.php` | MEDIUM |
| RATE_LIMIT | >10 requests / 60s per IP | HIGH |

---

## Sample Output

**WAF blocking a SQL Injection:**
```
  [2024-11-15T14:32:07] 10.0.0.5         GET    /search?q=' OR 1=1 --  → BLOCKED [SQL_INJECTION]
    → Severity : CRITICAL
    → Pattern  : (?i)(\bor\b\s+1\s*=\s*1)
```

**Rate limit triggered:**
```
  [2024-11-15T14:35:22] 10.0.0.99        POST   /login  → BLOCKED [RATE_LIMIT]  (req#11)
    → Severity : HIGH
    → Blocked until: 2024-11-15T14:40:22
```

**Dashboard summary:**
```
  TRAFFIC OVERVIEW
  ────────────────────────────────────────
  Total Requests   : 18
  Blocked          : 9  (50.0%)
  Allowed          : 9

  ATTACKS BY CATEGORY
  ────────────────────────────────────────
  RATE_LIMIT                2
  SQL_INJECTION             2
  XSS                       1
  LFI                       1
  COMMAND_INJECTION         1
  SENSITIVE_FILE_ACCESS     1
  DIRECTORY_TRAVERSAL       1
```

---

## MITRE ATT&CK / OWASP Coverage

| Attack | Reference |
|---|---|
| SQL Injection | OWASP A03:2021, CWE-89 |
| XSS | OWASP A03:2021, CWE-79 |
| LFI | OWASP A01:2021, CWE-22 |
| Command Injection | OWASP A03:2021, CWE-78 |
| Brute Force / Flooding | MITRE T1110 |

---

## Ethical Disclaimer

This toolkit is built **strictly for educational purposes**.

- No real HTTP servers are attacked
- All requests are simulated test data within the script
- Only use in **controlled lab environments** you own or have explicit permission to test on

---

## Future Enhancements

- Flask/FastAPI integration to inspect real incoming HTTP traffic
- YARA rule support for file-based payload scanning
- GeoIP blocking for known malicious IP ranges
- HTML dashboard with charts (attack timeline, IP heatmap)
- SIEM integration via syslog output
- Email/Slack alerting for CRITICAL events
