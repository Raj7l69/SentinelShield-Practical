# logger.py — Event Logging Module
#
# Logs every WAF decision (blocked or allowed) to a structured log file.
# Each entry includes timestamp, IP, method, URL, decision, category,
# severity, and matched pattern.
#
# Imported by traffic_monitor.py. Can also be used standalone to
# view and parse existing logs.
#
# Usage (view logs):
#   python logger.py

import datetime
import os
import json

LOG_FILE      = "sentinelshield.log"
JSON_LOG_FILE = "sentinelshield_events.json"

# ─── LOGGING FUNCTIONS ────────────────────────────────────────────────────────

def log_event(result: dict):
    """
    Write a single WAF event to the log file.
    Logs both human-readable text and structured JSON.

    result: the dict returned by process_request() or inspect_request()
    """
    req      = result.get("request", {})
    ts       = result.get("timestamp", datetime.datetime.now().isoformat())
    decision = "BLOCKED" if not result.get("allowed") else "ALLOWED"
    category = result.get("category") or "CLEAN"
    severity = result.get("severity") or "NONE"
    matched  = result.get("matched")  or "—"
    ip       = req.get("ip",     "unknown")
    method   = req.get("method", "UNKNOWN")
    url      = req.get("url",    "/")

    # ── Human-readable log ─────────────────────────────────────────────────
    line = (
        f"[{ts}] [{decision}] [{severity}] [{category}] "
        f"IP={ip} METHOD={method} URL={url} MATCHED={matched}"
    )
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

    # ── Structured JSON log ────────────────────────────────────────────────
    entry = {
        "timestamp": ts,
        "decision":  decision,
        "severity":  severity,
        "category":  category,
        "ip":        ip,
        "method":    method,
        "url":       url,
        "matched":   matched,
        "abusive":   result.get("abusive", False),
        "request_count": result.get("request_count", 1),
    }

    events = []
    if os.path.exists(JSON_LOG_FILE):
        try:
            with open(JSON_LOG_FILE, "r") as f:
                events = json.load(f)
        except json.JSONDecodeError:
            events = []

    events.append(entry)
    with open(JSON_LOG_FILE, "w") as f:
        json.dump(events, f, indent=2)


# ─── LOG READER / PARSER ──────────────────────────────────────────────────────

def read_log(filter_decision: str = None) -> list:
    """
    Read and parse the human-readable log file.
    Optionally filter by decision: 'BLOCKED' or 'ALLOWED'.
    Returns a list of log line strings.
    """
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    if filter_decision:
        lines = [l for l in lines if f"[{filter_decision}]" in l]

    return [l.strip() for l in lines if l.strip()]


def read_json_log() -> list:
    """Read and return all events from the structured JSON log."""
    if not os.path.exists(JSON_LOG_FILE):
        return []
    try:
        with open(JSON_LOG_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []


def get_summary() -> dict:
    """
    Parse the JSON log and return a summary dict:
    {
        total, blocked, allowed,
        by_category: { category: count },
        by_ip: { ip: count },
        top_attacked_urls: [ (url, count) ]
    }
    """
    events    = read_json_log()
    summary   = {
        "total":            len(events),
        "blocked":          sum(1 for e in events if e["decision"] == "BLOCKED"),
        "allowed":          sum(1 for e in events if e["decision"] == "ALLOWED"),
        "by_category":      {},
        "by_ip":            {},
        "by_severity":      {},
    }

    for e in events:
        cat = e.get("category", "CLEAN")
        ip  = e.get("ip", "unknown")
        sev = e.get("severity", "NONE")

        summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1
        summary["by_ip"][ip]        = summary["by_ip"].get(ip, 0) + 1
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

    return summary


def clear_logs():
    """Delete both log files. Use with caution."""
    for f in [LOG_FILE, JSON_LOG_FILE]:
        if os.path.exists(f):
            os.remove(f)
    print("[+] Logs cleared.")


# ─── STANDALONE LOG VIEWER ────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 70)
    print("  SENTINELSHIELD — LOG VIEWER")
    print("=" * 70)

    lines = read_log()
    if not lines:
        print("  [!] No log entries found. Run traffic_monitor.py first.")
    else:
        print(f"\n  Total entries: {len(lines)}\n")
        for line in lines[-20:]:   # show last 20 entries
            print(f"  {line}")

    summary = get_summary()
    if summary["total"] > 0:
        print(f"\n{'─'*70}")
        print(f"  SUMMARY")
        print(f"{'─'*70}")
        print(f"  Total Events : {summary['total']}")
        print(f"  Blocked      : {summary['blocked']}")
        print(f"  Allowed      : {summary['allowed']}")
        print(f"\n  By Category  : {summary['by_category']}")
        print(f"  By Severity  : {summary['by_severity']}")
        print(f"\n  Top IPs      :")
        for ip, count in sorted(summary["by_ip"].items(),
                                key=lambda x: x[1], reverse=True)[:5]:
            print(f"    {ip:<20} {count} requests")

    print("\n" + "=" * 70)
