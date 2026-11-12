#!/usr/bin/env python3

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "evidence/working/incident-events-working.json"
OUTPUT = BASE / "output/triage-summary.json"
TIMELINE = BASE / "output/incident-timeline.json"

with INPUT.open() as file:
    events = json.load(file)

events.sort(
    key=lambda event: datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    )
)

event_counts = Counter(
    event["event_type"] for event in events
)

hosts = sorted({
    event["host"] for event in events if event.get("host")
})

accounts = sorted({
    event["username"] for event in events if event.get("username")
})

sources = sorted({
    event["source_ip"]
    for event in events if event.get("source_ip")
})

failed_logins = [
    event for event in events
    if event["event_type"] == "ssh_failed_login"
]

successful_logins = [
    event for event in events
    if event["event_type"] == "ssh_successful_login"
]

sessions = [
    event for event in events
    if event["event_type"] == "session_opened"
]

privileged_activity = [
    event for event in events
    if event["event_type"] == "privileged_command"
]

process_activity = [
    event for event in events
    if event["event_type"] == "process_execution"
]

outbound_activity = [
    event for event in events
    if event["event_type"] == "outbound_connection"
]

account_changes = [
    event for event in events
    if event["event_type"] == "account_activity"
]

timeline = []

for event in events:
    timeline.append({
        "event_id": event["event_id"],
        "timestamp": event["timestamp"],
        "host": event["host"],
        "event_type": event["event_type"],
        "username": event.get("username"),
        "source_ip": event.get("source_ip"),
        "process": event.get("process"),
        "message": event.get("message")
    })

summary = {
    "incident_id": "SOC-2026-026",
    "dataset_type": "SYNTHETIC TRAINING EVIDENCE",
    "total_events": len(events),
    "affected_hosts": hosts,
    "accounts_observed": accounts,
    "source_ips_observed": sources,
    "event_counts": dict(event_counts),
    "authentication": {
        "failed_logins": len(failed_logins),
        "successful_logins": len(successful_logins),
        "sessions_opened": len(sessions)
    },
    "post_login_activity": {
        "privileged_command_events": len(privileged_activity),
        "process_execution_events": len(process_activity),
        "outbound_connection_events": len(outbound_activity),
        "account_activity_events": len(account_changes)
    },
    "investigation_leads": [
        "Repeated SSH authentication failures",
        "Successful login following authentication failures",
        "Privileged command activity",
        "Unusual process execution",
        "Outbound TLS connection",
        "Account configuration activity"
    ],
    "initial_assessment": "HIGH_PRIORITY_REVIEW",
    "classification": "UNDER_INVESTIGATION",
    "compromise_confirmed": False,
    "limitations": [
        "All events are synthetic",
        "Event relationships require further validation",
        "Outbound connection purpose is unknown",
        "Privileged command execution outcome is unknown",
        "Process execution details are incomplete",
        "Account configuration change details are incomplete"
    ]
}

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w") as file:
    json.dump(summary, file, indent=4)

with TIMELINE.open("w") as file:
    json.dump(timeline, file, indent=4)

print("===== SOC ALERT TRIAGE =====")
print(f"Incident: {summary['incident_id']}")
print(f"Total events: {len(events)}")
print(f"Affected hosts: {hosts}")
print(f"Accounts observed: {accounts}")
print(f"Source IPs: {sources}")

print("\n===== AUTHENTICATION =====")
print(f"Failed logins: {len(failed_logins)}")
print(f"Successful logins: {len(successful_logins)}")
print(f"Sessions opened: {len(sessions)}")

print("\n===== POST-LOGIN ACTIVITY =====")
print(f"Privileged commands: {len(privileged_activity)}")
print(f"Process executions: {len(process_activity)}")
print(f"Outbound connections: {len(outbound_activity)}")
print(f"Account activity events: {len(account_changes)}")

print("\n===== INITIAL ASSESSMENT =====")
print("Priority: HIGH_PRIORITY_REVIEW")
print("Classification: UNDER_INVESTIGATION")
print("Confirmed compromise: NO")

print("\nTriage summary:", OUTPUT.relative_to(BASE))
print("Incident timeline:", TIMELINE.relative_to(BASE))
