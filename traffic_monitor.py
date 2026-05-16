# traffic_monitor.py — IP-Based Rate Limiting & Traffic Behavior Monitor
#
# Tracks request frequency per IP address within a sliding time window.
# Flags IPs that exceed the allowed threshold as abusive (brute-force / flood).
# Works alongside waf.py — passes each request through the WAF first,
# then applies rate-limit checks on top.
#
# Usage:
#   python traffic_monitor.py

import datetime
import time
from collections import defaultdict
from waf import inspect_request, format_result
from logger import log_event

# ─── RATE LIMIT CONFIGURATION ─────────────────────────────────────────────────

RATE_LIMIT_THRESHOLD = 10    # max requests allowed per IP in the time window
TIME_WINDOW_SECONDS  = 60    # sliding window in seconds
BLOCK_DURATION       = 300   # seconds an abusive IP stays blocked

# ─── STATE ────────────────────────────────────────────────────────────────────

# { ip: [ timestamp, timestamp, ... ] }
request_log: dict = defaultdict(list)

# { ip: block_expiry_timestamp }
blocked_ips: dict = {}


# ─── FUNCTIONS ────────────────────────────────────────────────────────────────

def is_blocked(ip: str) -> bool:
    """Check if an IP is currently in the block list."""
    if ip in blocked_ips:
        if time.time() < blocked_ips[ip]:
            return True
        else:
            # Block expired — remove from list
            del blocked_ips[ip]
    return False


def record_request(ip: str) -> int:
    """
    Record a request timestamp for an IP.
    Prunes entries outside the current time window.
    Returns the current request count for this IP within the window.
    """
    now    = time.time()
    cutoff = now - TIME_WINDOW_SECONDS

    # Remove timestamps outside the window
    request_log[ip] = [t for t in request_log[ip] if t > cutoff]
    request_log[ip].append(now)

    return len(request_log[ip])


def check_rate_limit(ip: str) -> dict:
    """
    Check if the IP has exceeded the rate limit.
    Returns a dict: { abusive: bool, count: int, blocked_until: str or None }
    """
    count = record_request(ip)

    if count > RATE_LIMIT_THRESHOLD:
        expiry             = time.time() + BLOCK_DURATION
        blocked_ips[ip]    = expiry
        expiry_str         = datetime.datetime.fromtimestamp(expiry).isoformat()
        return {
            "abusive":      True,
            "count":        count,
            "blocked_until": expiry_str,
        }

    return {
        "abusive":      False,
        "count":        count,
        "blocked_until": None,
    }


def process_request(request: dict) -> dict:
    """
    Full pipeline for a single incoming request:
      1. Check if the IP is currently blocked
      2. Run WAF inspection
      3. Apply rate-limit check
      4. Log the event
      5. Return combined result

    Returns a result dict with all fields from WAF + rate limit status.
    """
    ip = request.get("ip", "unknown")
    ts = datetime.datetime.now().isoformat()

    # ── Step 1: IP block check ─────────────────────────────────────────────
    if is_blocked(ip):
        result = {
            "allowed":      False,
            "category":     "RATE_LIMIT_BLOCK",
            "severity":     "HIGH",
            "matched":      "IP currently blocked — exceeded rate limit",
            "timestamp":    ts,
            "request":      request,
            "abusive":      True,
            "request_count": request_log[ip].__len__(),
            "blocked_until": datetime.datetime.fromtimestamp(
                blocked_ips[ip]).isoformat(),
        }
        log_event(result)
        return result

    # ── Step 2: WAF inspection ─────────────────────────────────────────────
    waf_result = inspect_request(request)

    # ── Step 3: Rate limit check ───────────────────────────────────────────
    rate_check = check_rate_limit(ip)

    # Merge WAF result with rate limit info
    waf_result["abusive"]       = rate_check["abusive"]
    waf_result["request_count"] = rate_check["count"]
    waf_result["blocked_until"] = rate_check["blocked_until"]

    # If rate limit triggered, override decision
    if rate_check["abusive"] and waf_result["allowed"]:
        waf_result["allowed"]   = False
        waf_result["category"]  = "RATE_LIMIT"
        waf_result["severity"]  = "HIGH"
        waf_result["matched"]   = (
            f"Exceeded {RATE_LIMIT_THRESHOLD} requests "
            f"in {TIME_WINDOW_SECONDS}s window"
        )

    # ── Step 4: Log the event ──────────────────────────────────────────────
    log_event(waf_result)

    return waf_result


def print_status(result: dict):
    """Print a formatted one-line status for a processed request."""
    req    = result["request"]
    status = "ALLOWED" if result["allowed"] else f"BLOCKED [{result['category']}]"
    count  = result.get("request_count", "?")
    print(
        f"  [{result['timestamp']}] {req['ip']:<16} "
        f"{req['method']:<6} {req['url'][:45]:<47} "
        f"→ {status}  (req#{count})"
    )
    if not result["allowed"]:
        print(f"    → Severity : {result['severity']}")
        if result.get("blocked_until"):
            print(f"    → Blocked until: {result['blocked_until']}")
        print()


# ─── STANDALONE DEMO ──────────────────────────────────────────────────────────

DEMO_REQUESTS = [
    # Normal traffic
    {"ip": "192.168.1.10", "method": "GET",  "url": "/home",
     "headers": {"User-Agent": "Mozilla/5.0"}, "body": ""},
    {"ip": "192.168.1.20", "method": "GET",  "url": "/about",
     "headers": {"User-Agent": "Mozilla/5.0"}, "body": ""},
    # Attack request
    {"ip": "10.0.0.5",     "method": "GET",
     "url": "/login?user=' OR 1=1 --",
     "headers": {"User-Agent": "sqlmap"}, "body": ""},
    # Simulated brute-force from same IP (11 rapid requests)
    *[
        {"ip": "10.0.0.99", "method": "POST", "url": "/login",
         "headers": {"User-Agent": "BruteForcer/1.0"},
         "body": f"user=admin&pass=attempt{i}"}
        for i in range(12)
    ],
]

if __name__ == "__main__":
    print("=" * 80)
    print("  SENTINELSHIELD — TRAFFIC MONITOR DEMO")
    print(f"  Rate Limit: {RATE_LIMIT_THRESHOLD} requests per {TIME_WINDOW_SECONDS}s")
    print("=" * 80 + "\n")

    for req in DEMO_REQUESTS:
        result = process_request(req)
        print_status(result)

    print("\n" + "=" * 80)
    print(f"  Currently Blocked IPs: {list(blocked_ips.keys())}")
    print("=" * 80)
