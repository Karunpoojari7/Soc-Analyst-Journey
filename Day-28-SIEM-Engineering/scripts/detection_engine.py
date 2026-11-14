#!/usr/bin/env python3

import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
INPUT = BASE / "data/normalized/enriched-events.jsonl"
OUTPUT = BASE / "output/siem-alerts.json"


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_events():
    with INPUT.open() as file:
        events = [json.loads(line) for line in file if line.strip()]
    return sorted(events, key=lambda event: event["timestamp"])


def detect(events):
    alerts = []
    failures = defaultdict(list)

    for event in events:
        if event["event_type"] == "AUTH_FAILURE":
            key = (event["host"], event["username"], event["source_ip"])
            failures[key].append(event)

    correlated_success_ids = set()

    for key, attempts in failures.items():
        attempts.sort(key=lambda event: event["timestamp"])

        for current in attempts:
            end = parse_time(current["timestamp"])
            window = [
                item for item in attempts
                if end - timedelta(seconds=600)
                <= parse_time(item["timestamp"]) <= end
            ]

            if len(window) < 5:
                continue

            success = next(
                (
                    event for event in events
                    if event["event_type"] == "AUTH_SUCCESS"
                    and event["host"] == key[0]
                    and event["username"] == key[1]
                    and event["source_ip"] == key[2]
                    and parse_time(event["timestamp"]) > end
                    and parse_time(event["timestamp"]) <= end + timedelta(minutes=15)
                ),
                None
            )

            alert_id = f"SIEM-001-{current['event_id']}"
            if not any(a["alert_id"] == alert_id for a in alerts):
                alerts.append({
                    "alert_id": alert_id,
                    "rule_id": "SIEM-001",
                    "title": "Repeated authentication failures",
                    "severity": "HIGH",
                    "host": key[0],
                    "username": key[1],
                    "source_ip": key[2],
                    "failure_count": len(window),
                    "window_seconds": 600,
                    "classification": "REVIEW_REQUIRED"
                })

            if success:
                correlated_success_ids.add(success["event_id"])
            break

    for event in events:
        if event["event_type"] == "AUTH_SUCCESS":
            if event["event_id"] in correlated_success_ids:
                alerts.append({
                    "alert_id": f"SIEM-002-{event['event_id']}",
                    "rule_id": "SIEM-002",
                    "title": "Successful login after repeated failures",
                    "severity": "HIGH",
                    "host": event["host"],
                    "username": event["username"],
                    "source_ip": event["source_ip"],
                    "success_event": event["event_id"],
                    "classification": "REVIEW_REQUIRED"
                })

    for success_id in correlated_success_ids:
        success = next(e for e in events if e["event_id"] == success_id)

        for event in events:
            if (
                event["event_type"] == "PRIVILEGED_ACTIVITY"
                and event["host"] == success["host"]
                and event["username"] == success["username"]
            ):
                delta = (
                    parse_time(event["timestamp"])
                    - parse_time(success["timestamp"])
                ).total_seconds()

                if 0 <= delta <= 900:
                    alerts.append({
                        "alert_id": f"SIEM-003-{event['event_id']}",
                        "rule_id": "SIEM-003",
                        "title": "Privileged activity after suspicious login",
                        "severity": "HIGH",
                        "host": event["host"],
                        "username": event["username"],
                        "privileged_event": event["event_id"],
                        "related_success_event": success_id,
                        "classification": "REVIEW_REQUIRED"
                    })

    for event in events:
        if event["event_type"] == "NETWORK_CONNECTION":
            alerts.append({
                "alert_id": f"SIEM-004-{event['event_id']}",
                "rule_id": "SIEM-004",
                "title": "Outbound connection requires review",
                "severity": "MEDIUM",
                "host": event["host"],
                "source_ip": event["source_ip"],
                "destination_ip": event["destination_ip"],
                "destination_port": event["destination_port"],
                "process_name": event["process_name"],
                "classification": "REVIEW_REQUIRED"
            })

    return alerts


def main():
    events = load_events()
    alerts = detect(events)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    result = {
        "project": "NEXORA-SIEM-LAB",
        "dataset": "SYNTHETIC",
        "events_processed": len(events),
        "alerts_generated": len(alerts),
        "alerts": alerts,
        "compromise_confirmed": False
    }

    with OUTPUT.open("w") as file:
        json.dump(result, file, indent=4)

    print("SIEM detection engine completed.")
    print("Events processed:", len(events))
    print("Alerts generated:", len(alerts))
    print("Output:", OUTPUT.relative_to(BASE))


if __name__ == "__main__":
    main()
