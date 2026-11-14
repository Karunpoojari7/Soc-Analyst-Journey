#!/usr/bin/env python3

import json
from datetime import timedelta, datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

EVENTS = BASE / "data/normalized/normalized-events.jsonl"
ALERTS = BASE / "output/alerts.json"
OUTPUT = BASE / "output/correlation-results.json"


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main():
    events = [
        json.loads(line)
        for line in EVENTS.read_text().splitlines()
        if line.strip()
    ]

    alerts = json.loads(ALERTS.read_text())["alerts"]

    sequences = []

    for alert in alerts:
        if not alert["successful_login_after_failures"]:
            continue

        login_time = parse_time(alert["successful_login_time"])

        related = []

        for event in events:
            if (
                event["host"] == "nexora-linux-01"
                and event["user"] == alert["user"]
                and event["source_ip"] == alert["source_ip"]
                and login_time < parse_time(event["timestamp"])
                <= login_time + timedelta(minutes=10)
            ):
                if event["event_category"] != "authentication":
                    related.append(event)

        sequences.append({
            "alert_id": alert["alert_id"],
            "correlation_type": "TEMPORAL_AND_ACCOUNT_CONTEXT",
            "related_event_ids": [
                event["event_id"] for event in related
            ],
            "related_event_count": len(related),
            "confirmed_session_linkage": False,
            "confirmed_causation": False,
            "classification": "REQUIRES_INVESTIGATION"
        })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w") as file:
        json.dump({
            "correlation_count": len(sequences),
            "sequences": sequences
        }, file, indent=4)

    print("Event correlation completed.")
    print("Correlated sequences:", len(sequences))


if __name__ == "__main__":
    main()
