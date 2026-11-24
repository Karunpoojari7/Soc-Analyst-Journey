import csv
import json
import hashlib
from pathlib import Path
from datetime import datetime

BASE = Path(__file__).resolve().parents[1]

def load_csv(relative_path):
    path = BASE / relative_path
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def load_json(relative_path):
    path = BASE / relative_path
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return json.load(f)

browser = load_csv("evidence/browser-logs/browser-events.csv")
sessions = load_csv("evidence/session-logs/session-lifecycle.csv")
messages = load_csv("evidence/messaging-audit/account-activity.csv")
alerts = load_json("output/detection-alerts.json")

timeline_path = BASE / "timeline/correlated-timeline.csv"
timeline_count = 0

if timeline_path.exists():
    timeline_count = len(load_csv("timeline/correlated-timeline.csv"))

hash_path = BASE / "output/evidence-sha256.txt"
hash_results = []

for line in hash_path.read_text(encoding="utf-8").splitlines():
    expected, relative_path = line.split("  ", 1)
    actual = hashlib.sha256((BASE / relative_path).read_bytes()).hexdigest()
    hash_results.append(expected == actual)

active_after_tab_close = sum(
    1 for event in sessions
    if event["event"] == "browser_tab_closed"
    and event["session_status"] == "active"
)

revoked_sessions = sum(
    1 for event in sessions
    if event["event"] in ("session_revoked", "explicit_logout")
)

report = f"""# Day 38 — SOC Investigation Report

## Case Information

Case ID: SOC-D38-WWA-001
Case: WhatsApp Web Session Security Investigation
Environment: Android Termux
Data: Synthetic training evidence
Status: Educational simulation

## Executive Summary

This investigation examined a simulated scenario involving
an authenticated browser session left active after tab closure.

The evidence demonstrates a possible risk associated with
unattended authenticated sessions.

## Evidence Summary

- Browser events: {len(browser)}
- Session events: {len(sessions)}
- Messaging events: {len(messages)}
- Correlated timeline events: {timeline_count}
- Generated detection alerts: {len(alerts)}

## Session Findings

- Sessions recorded active after tab closure: {active_after_tab_close}
- Session termination or revocation events: {revoked_sessions}

## Detection Findings

"""

for alert in alerts:
    report += (
        f"- {alert.get('rule_id', 'Unknown')} | "
        f"{alert.get('severity', 'Unknown')} | "
        f"{alert.get('description', '')}\n"
    )

report += f"""

## Evidence Integrity

Files checked: {len(hash_results)}
Successful hash matches: {sum(hash_results)}
Failed hash matches: {len(hash_results) - sum(hash_results)}

## Incident Assessment

The synthetic evidence demonstrates a sequence consistent
with possible misuse of an unattended authenticated session.

The records do not establish the identity of an operator,
actual account compromise, or real-world data exposure.

## Recommended Actions

1. Explicitly log out of browser sessions.
2. Review linked devices.
3. Revoke unfamiliar sessions.
4. Secure account authentication.
5. Preserve relevant incident evidence.
6. Monitor suspicious account activity.

## Limitations

- All evidence is synthetic.
- No actual WhatsApp internal telemetry was accessed.
- Detection rules are educational examples.
- Detection validation is limited to the tests performed.

## Final Conclusion

This exercise demonstrates session-security investigation,
Python-based detection, evidence correlation and incident
response documentation.

Confirmed real-world compromise: Not established.
"""

output = BASE / "output/FINAL-SOC-INVESTIGATION-REPORT.md"
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(report, encoding="utf-8")

print("===== DAY 38 REPORT GENERATION =====")
print("Browser events:", len(browser))
print("Session events:", len(sessions))
print("Messaging events:", len(messages))
print("Alerts:", len(alerts))
print("Timeline events:", timeline_count)
print("SHA-256 checks:", sum(hash_results), "/", len(hash_results))
print("[CREATED] output/FINAL-SOC-INVESTIGATION-REPORT.md")
