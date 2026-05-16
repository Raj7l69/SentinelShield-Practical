# waf.py — HTTP Request Inspection & Rule-Based Detection Engine
#
# Simulates a lightweight Web Application Firewall (WAF).
# Inspects incoming HTTP requests against known attack signatures
# and returns a detection result with attack category and severity.
#
# Imported by traffic_monitor.py and can also be run standalone.
#
# Usage (standalone demo):
#   python waf.py

import re
import datetime

# ─── ATTACK SIGNATURE RULES ───────────────────────────────────────────────────
#
# Format:
#   "CATEGORY": [ list of regex patterns ]
#
# Each pattern represents a known malicious string or structure.
# Sources: OWASP CRS, common WAF rule sets.

RULES = {
    "SQL_INJECTION": [
        r"(?i)(union\s+select)",
        r"(?i)(select\s+\*\s+from)",
        r"(?i)(\bor\b\s+1\s*=\s*1)",
        r"(?i)(\bdrop\s+table\b)",
        r"(?i)('--)",
        r"(?i)(;--)",
        r"(?i)(\bexec\s*\()",
        r"(?i)(xp_cmdshell)",
        r"(?i)(insert\s+into\s+\w+\s+values)",
        r"(?i)(sleep\s*\(\s*\d+\s*\))",
    ],
    "XSS": [
        r"(?i)(<script[\s>])",
        r"(?i)(javascript\s*:)",
        r"(?i)(on(load|click|mouseover|error|focus)\s*=)",
        r"(?i)(<iframe[\s>])",
        r"(?i)(document\.cookie)",
        r"(?i)(alert\s*\()",
        r"(?i)(<img[^>]+src\s*=\s*['\"]javascript)",
        r"(?i)(eval\s*\()",
    ],
    "LFI": [
        r"(\.\./){2,}",
        r"(?i)(etc/passwd)",
        r"(?i)(etc/shadow)",
        r"(?i)(proc/self/environ)",
        r"(?i)(\.\./\.\./)",
        r"(?i)(file\s*=\s*\.\.)",
        r"(?i)(include\s*=\s*\.\.)",
    ],
    "COMMAND_INJECTION": [
        r"(?i)(;\s*(ls|cat|rm|wget|curl|bash|sh|python|perl))",
        r"(?i)(\|\s*(ls|cat|rm|wget|curl|bash|sh))",
        r"(?i)(`[^`]+`)",
        r"(?i)(\$\([^)]+\))",
        r"(?i)(&&\s*(ls|cat|whoami|id|uname))",
    ],
    "DIRECTORY_TRAVERSAL": [
        r"(\.\./){1,}",
        r"(?i)(%2e%2e%2f)",
        r"(?i)(%252e%252e%252f)",
        r"(?i)(\.\.%2f)",
        r"(?i)(\.\.%5c)",
    ],
    "SENSITIVE_FILE_ACCESS": [
        r"(?i)(web\.config)",
        r"(?i)(\.env\b)",
        r"(?i)(\.htaccess)",
        r"(?i)(\.git/)",
        r"(?i)(backup\.sql)",
        r"(?i)(wp-config\.php)",
        r"(?i)(phpinfo\.php)",
    ],
}

# Severity mapping per attack category
SEVERITY = {
    "SQL_INJECTION":        "CRITICAL",
    "XSS":                  "HIGH",
    "COMMAND_INJECTION":    "CRITICAL",
    "LFI":                  "HIGH",
    "DIRECTORY_TRAVERSAL":  "MEDIUM",
    "SENSITIVE_FILE_ACCESS":"MEDIUM",
}

# ─── REQUEST INSPECTOR ────────────────────────────────────────────────────────

def inspect_request(request: dict) -> dict:
    """
    Inspect an HTTP request dict for attack patterns.

    Input request format:
    {
        "ip":      "192.168.1.10",
        "method":  "GET",
        "url":     "/search?q=...",
        "headers": { "User-Agent": "...", ... },
        "body":    "..."   (optional)
    }

    Returns a result dict with allowed, category, severity, matched pattern,
    timestamp, and the original request.
    """
    parts = [
        request.get("url", ""),
        request.get("body", ""),
    ]
    for v in request.get("headers", {}).values():
        parts.append(str(v))

    target = " ".join(parts)
    ts     = datetime.datetime.now().isoformat()

    for category, patterns in RULES.items():
        for pattern in patterns:
            if re.search(pattern, target):
                return {
                    "allowed":   False,
                    "category":  category,
                    "severity":  SEVERITY.get(category, "MEDIUM"),
                    "matched":   pattern,
                    "timestamp": ts,
                    "request":   request,
                }

    return {
        "allowed":   True,
        "category":  None,
        "severity":  None,
        "matched":   None,
        "timestamp": ts,
        "request":   request,
    }


def format_result(result: dict) -> str:
    """Format an inspection result for console display."""
    req    = result["request"]
    status = "ALLOWED" if result["allowed"] else f"BLOCKED [{result['category']}]"
    return (
        f"  [{result['timestamp']}] {req['ip']:<16} "
        f"{req['method']:<6} {req['url'][:55]:<57} → {status}"
    )


# ─── STANDALONE DEMO ──────────────────────────────────────────────────────────

TEST_REQUESTS = [
    # Normal requests
    {"ip": "192.168.1.10", "method": "GET",
     "url": "/index.html", "headers": {"User-Agent": "Mozilla/5.0"}, "body": ""},
    {"ip": "192.168.1.11", "method": "POST",
     "url": "/login", "headers": {"Content-Type": "application/json"},
     "body": '{"username": "alice", "password": "securepass"}'},
    # SQL Injection
    {"ip": "10.0.0.5", "method": "GET",
     "url": "/search?q=' OR 1=1 --",
     "headers": {"User-Agent": "sqlmap/1.0"}, "body": ""},
    # XSS
    {"ip": "10.0.0.6", "method": "GET",
     "url": "/comment?text=<script>alert('xss')</script>",
     "headers": {"User-Agent": "Mozilla/5.0"}, "body": ""},
    # LFI
    {"ip": "10.0.0.7", "method": "GET",
     "url": "/page?file=../../etc/passwd",
     "headers": {"User-Agent": "curl/7.68"}, "body": ""},
    # Command Injection
    {"ip": "10.0.0.8", "method": "POST",
     "url": "/ping", "headers": {"Content-Type": "application/x-www-form-urlencoded"},
     "body": "host=127.0.0.1; cat /etc/shadow"},
    # Sensitive File Access
    {"ip": "10.0.0.9", "method": "GET",
     "url": "/.env", "headers": {"User-Agent": "python-requests/2.25"}, "body": ""},
]

if __name__ == "__main__":
    print("=" * 80)
    print("  SENTINELSHIELD WAF — REQUEST INSPECTION DEMO")
    print("=" * 80)

    for req in TEST_REQUESTS:
        result = inspect_request(req)
        print(format_result(result))
        if not result["allowed"]:
            print(f"    → Severity : {result['severity']}")
            print(f"    → Pattern  : {result['matched']}\n")

    print("=" * 80)
