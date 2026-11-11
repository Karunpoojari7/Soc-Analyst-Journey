#!/usr/bin/env python3

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "evidence/working/normalized-ssh-events.json"
OUTPUT = BASE / "output/ssh-username-enumeration-results.json"

THRESHOLD = 5
DISTINCT_USERNAMES = 3
WINDOW_SECONDS = 600
ASSUMED_YEAR = 2026


def parse_timestamp(value):
    parsed = datetime.strptime(
        f"{ASSUMED_YEAR} {value}",
        "%Y %b %d %H:%M:%S"
    )
    return parsed.replace(tzinfo=timezone.utc)


with INPUT.open() as file:
    events = json.load(file)

sources = defaultdict(list)

for event in events:
    if event.get("event_type") != "failed_login":
        continue

    source_ip = event.get("source_ip")
    username = event.get("username")

    if not source_ip or not username:
        continue

    sources[source_ip].append({
        "timestamp": parse_timestamp(event["timestamp"]),
        "username": username
    })

findings = []

for source_ip, attempts in sources.items():
    attempts.sort(key=lambda item: item["timestamp"])

    for index, current in enumerate(attempts):
        window_start = current["timestamp"]
        window_end = window_start.timestamp() + WINDOW_SECONDS

        window_events = [
            event for event in attempts[index:]
            if event["timestamp"].timestamp() <= window_end
        ]

        usernames = sorted({
            event["username"] for event in window_events
        })

        if (
            len(window_events) >= THRESHOLD
            and len(usernames) >= DISTINCT_USERNAMES
        ):
            findings.append({
                "detection_id": "DET-SSH-002",
                "detection_name": "SSH Multiple Username Attempts",
                "source_ip": source_ip,
                "failed_attempts": len(window_events),
                "distinct_usernames": len(usernames),
                "usernames": usernames,
                "first_failure": window_events[0]["timestamp"].isoformat(),
                "last_failure": window_events[-1]["timestamp"].isoformat(),
                "window_seconds": WINDOW_SECONDS,
                "severity": "medium",
                "mitre_attack": "T1110",
                "assessment": "REVIEW_REQUIRED"
            })
            break

result = {
    "dataset_type": "SYNTHETIC TRAINING EVIDENCE",
    "assumed_year": ASSUMED_YEAR,
    "rule": {
        "id": "DET-SSH-002",
        "threshold": THRESHOLD,
        "distinct_usernames": DISTINCT_USERNAMES,
        "window_seconds": WINDOW_SECONDS,
        "group_by": "source_ip"
    },
    "total_events": len(events),
    "findings": findings,
    "assessment": "ALERT_GENERATED" if findings else "NO_ALERT"
}

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w") as file:
    json.dump(result, file, indent=4)

print("DETECTION ENGINE: COMPLETE")
print(f"Findings: {len(findings)}")

for finding in findings:
    print(f"\nDetection: {finding['detection_id']}")
    print(f"Source: {finding['source_ip']}")
    print(f"Failed attempts: {finding['failed_attempts']}")
    print(f"Distinct usernames: {finding['distinct_usernames']}")
    print(f"Usernames: {finding['usernames']}")
    print(f"Assessment: {finding['assessment']}")

print(f"\nOverall assessment: {result['assessment']}")
print(f"Output: {OUTPUT.relative_to(BASE)}")
print("NOTE: Year and UTC are assumed lab metadata.")
