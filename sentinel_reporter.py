# reporter.py — Dashboard & Final Report Generator
#
# Reads structured log data from logger.py and produces:
#   1. A console dashboard with live attack metrics
#   2. A detailed final report saved to sentinelshield_report.txt
#
# Usage:
#   python reporter.py

import datetime
import os
from logger import get_summary, read_log, JSON_LOG_FILE, LOG_FILE

REPORT_FILE = "sentinelshield_report.txt"

# ─── DASHBOARD ────────────────────────────────────────────────────────────────

def print_dashboard():
    """Print a terminal dashboard summarizing all logged events."""
    summary = get_summary()
    now     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("=" * 70)
    print("  SENTINELSHIELD — LIVE DASHBOARD")
    print(f"  Generated : {now}")
    print("=" * 70)

    if summary["total"] == 0:
        print("\n  [!] No events logged yet. Run traffic_monitor.py first.\n")
        print("=" * 70)
        return

    # ── Traffic overview ───────────────────────────────────────────────────
    block_rate = round((summary["blocked"] / summary["total"]) * 100, 1) if summary["total"] else 0
    print(f"\n  TRAFFIC OVERVIEW")
    print(f"  {'─'*40}")
    print(f"  Total Requests   : {summary['total']}")
    print(f"  Blocked          : {summary['blocked']}  ({block_rate}%)")
    print(f"  Allowed          : {summary['allowed']}")

    # ── Attacks by category ────────────────────────────────────────────────
    print(f"\n  ATTACKS BY CATEGORY")
    print(f"  {'─'*40}")
    cats = {k: v for k, v in summary["by_category"].items() if k != "CLEAN"}
    if cats:
        for cat, count in sorted(cats.items(), key=lambda x: x[1], reverse=True):
            bar = "█" * min(count, 30)
            print(f"  {cat:<25} {count:>4}  {bar}")
    else:
        print("  No attacks detected.")

    # ── Alerts by severity ─────────────────────────────────────────────────
    print(f"\n  ALERTS BY SEVERITY")
    print(f"  {'─'*40}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
        count = summary["by_severity"].get(sev, 0)
        if count:
            print(f"  {sev:<12} : {count}")

    # ── Top offending IPs ──────────────────────────────────────────────────
    print(f"\n  TOP OFFENDING IPs")
    print(f"  {'─'*40}")
    top_ips = sorted(summary["by_ip"].items(), key=lambda x: x[1], reverse=True)[:8]
    for ip, count in top_ips:
        print(f"  {ip:<22} {count:>4} requests")

    print("\n" + "=" * 70)


# ─── REPORT GENERATOR ─────────────────────────────────────────────────────────

def generate_report():
    """Build the final analysis report and save to file."""
    summary = get_summary()
    now     = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines   = []

    lines.append("=" * 70)
    lines.append("  SENTINELSHIELD: ADVANCED INTRUSION DETECTION & WEB PROTECTION")
    lines.append("  FINAL ANALYSIS REPORT")
    lines.append("=" * 70)
    lines.append(f"  Report Generated : {now}")
    lines.append(f"  Log File         : {LOG_FILE}")
    lines.append(f"  JSON Log         : {JSON_LOG_FILE}")
    lines.append("=" * 70)

    if summary["total"] == 0:
        lines.append("\n  No events to report. Run traffic_monitor.py first.")
    else:
        block_rate = round((summary["blocked"] / summary["total"]) * 100, 1)

        # ── Summary ────────────────────────────────────────────────────────
        lines.append("\n[TRAFFIC SUMMARY]")
        lines.append("-" * 50)
        lines.append(f"  Total Requests   : {summary['total']}")
        lines.append(f"  Blocked          : {summary['blocked']}  ({block_rate}%)")
        lines.append(f"  Allowed          : {summary['allowed']}")

        # ── Category breakdown ─────────────────────────────────────────────
        lines.append("\n[ATTACK CATEGORY BREAKDOWN]")
        lines.append("-" * 50)
        cats = {k: v for k, v in summary["by_category"].items() if k != "CLEAN"}
        if cats:
            lines.append(f"  {'CATEGORY':<28} {'COUNT':>6}")
            lines.append(f"  {'─'*28} {'─'*6}")
            for cat, count in sorted(cats.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  {cat:<28} {count:>6}")
        else:
            lines.append("  No attack categories detected.")

        # ── Severity breakdown ─────────────────────────────────────────────
        lines.append("\n[SEVERITY BREAKDOWN]")
        lines.append("-" * 50)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
            count = summary["by_severity"].get(sev, 0)
            lines.append(f"  {sev:<12} : {count}")

        # ── Top IPs ────────────────────────────────────────────────────────
        lines.append("\n[TOP OFFENDING IPs]")
        lines.append("-" * 50)
        lines.append(f"  {'IP ADDRESS':<22} {'REQUESTS':>8}")
        lines.append(f"  {'─'*22} {'─'*8}")
        for ip, count in sorted(
                summary["by_ip"].items(), key=lambda x: x[1], reverse=True)[:10]:
            lines.append(f"  {ip:<22} {count:>8}")

        # ── Recent blocked events ──────────────────────────────────────────
        lines.append("\n[RECENT BLOCKED EVENTS (last 15)]")
        lines.append("-" * 50)
        blocked_lines = read_log(filter_decision="BLOCKED")
        for line in blocked_lines[-15:]:
            lines.append(f"  {line}")

        # ── Analysis notes ─────────────────────────────────────────────────
        lines.append("\n[SECURITY ANALYSIS NOTES]")
        lines.append("-" * 50)
        notes = [
            "SQL Injection attempts suggest automated scanning tools (e.g., sqlmap).",
            "XSS attempts typically target input fields — ensure output encoding is applied.",
            "LFI attempts indicate reconnaissance for sensitive system files.",
            "Command Injection attempts suggest an attacker testing for RCE vulnerabilities.",
            "Rate-limited IPs likely represent automated scanners or brute-force tools.",
            "Sensitive file access attempts (.env, .git) indicate configuration harvesting.",
        ]
        for note in notes:
            lines.append(f"  • {note}")

        # ── Recommendations ────────────────────────────────────────────────
        lines.append("\n[SECURITY RECOMMENDATIONS]")
        lines.append("-" * 50)
        recs = [
            "Expand SQL Injection patterns to cover encoded variants (e.g., URL-encoded payloads).",
            "Integrate behavioral analysis — flag IPs showing multi-category attacks.",
            "Add geo-based blocking for IPs from unexpected regions.",
            "Reduce the rate-limit window for login endpoints specifically.",
            "Set up automated alerting (email/Slack) for CRITICAL severity events.",
            "Integrate with a SIEM for centralized log aggregation and correlation.",
        ]
        for rec in recs:
            lines.append(f"  • {rec}")

    lines.append("\n" + "=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70)

    report_text = "\n".join(lines)
    print(report_text)

    with open(REPORT_FILE, "w") as f:
        f.write(report_text)

    print(f"\n[+] Report saved to: {REPORT_FILE}")


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print_dashboard()
    print()
    generate_report()
