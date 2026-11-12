#!/usr/bin/env python3

import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "evidence/working/incident-events-working.json"
OUTPUT = BASE / "output/event-correlation-report.json"

with INPUT.open() as file:
    events = json.load(file)

def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

events.sort(key=lambda e: parse_time(e["timestamp"]))

groups = defaultdict(list)

for event in events:
    key = (event["host"], event.get("username"))
    groups[key].append(event)

correlations = []

for (host, username), group in groups.items():
    if not username:
        continue

    group.sort(key=lambda e: parse_time(e["timestamp"]))

    for index, event in enumerate(group):
        if event["event_type"] != "ssh_successful_login":
            continue

        login_time = parse_time(event["timestamp"])
        related = []

        for later in group[index + 1:]:
            later_time = parse_time(later["timestamp"])
            elapsed = (later_time - login_time).total_seconds()

            if 0 <= elapsed <= 900:
                related.append({
                    "event_id": later["event_id"],
                    "event_type": later["event_type"],
                    "timestamp": later["timestamp"],
                    "seconds_after_login": int(elapsed),
                    "process": later.get("process"),
                    "source_ip": later.get("source_ip"),
                    "message": later.get("message")
                })

        correlations.append({
            "host": host,
            "username": username,
            "successful_login": {
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "source_ip": event.get("source_ip")
            },
            "subsequent_events_within_15_minutes": related,
            "attribution": "TEMPORAL_AND_ACCOUNT_CORRELATION_ONLY"
        })

report = {
    "incident_id": "SOC-2026-026",
    "dataset_type": "SYNTHETIC TRAINING EVIDENCE",
    "correlation_method": [
        "Host",
        "Username",
        "Timestamp",
        "15-minute post-login window"
    ],
    "correlations": correlations,
    "evidence_gaps": [
        "Session identifiers are unavailable",
        "Process IDs are incomplete",
        "Process command lines are unavailable",
        "Process parent-child relationships are unavailable",
        "Sudo command and exit status are unavailable",
        "Outbound connection purpose is unknown",
        "Exact account configuration changes are unavailable"
    ],
    "conclusion": (
        "Post-login events are temporally associated with the "
        "successful account login. Stronger session and process "
        "attribution requires additional endpoint telemetry."
    )
}

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w") as file:
    json.dump(report, file, indent=4)

print("===== EVENT CORRELATION =====")
print(f"Correlated login sequences: {len(correlations)}")

for item in correlations:
    print(f"\nHost: {item['host']}")
    print(f"Account: {item['username']}")
    print(f"Successful login: {item['successful_login']['timestamp']}")
    print("Subsequent related events:")

    for related in item["subsequent_events_within_15_minutes"]:
        print(
            f"  {related['event_id']} | "
            f"{related['event_type']} | "
            f"+{related['seconds_after_login']} seconds"
        )

print("\nAttribution: TEMPORAL_AND_ACCOUNT_CORRELATION_ONLY")
print("Conclusion: Further evidence required")
print(f"Output: {OUTPUT.relative_to(BASE)}")
