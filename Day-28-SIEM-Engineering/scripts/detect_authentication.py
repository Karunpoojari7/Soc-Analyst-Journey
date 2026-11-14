#!/usr/bin/env python3

import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

SOURCE = BASE / "data/normalized/normalized-events.jsonl"
RULES = BASE / "rules/detection-rules.json"
OUTPUT = BASE / "output/alerts.json"


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def detect(events, rule):
    groups = defaultdict(list)

    for event in events:
        if (
            event["event_category"] == "authentication"
            and event["event_outcome"] == "failure"
        ):
            key = (event["source_ip"], event["user"])
            groups[key].append(event)

    alerts = []

    for (source_ip, user), failures in groups.items():
        failures.sort(key=lambda event: parse_time(event["timestamp"]))

        for index, first in enumerate(failures):
            start = parse_time(first["timestamp"])

            window = [
                event for event in failures[index:]
                if (
                    parse_time(event["timestamp"]) - start
                ).total_seconds() <= rule["window_seconds"]
            ]

            if len(window) < rule["threshold"]:
                continue

            last_failure = parse_time(window[-1]["timestamp"])

            successes = [
                event for event in events
                if (
                    event["event_category"] == "authentication"
                    and event["event_outcome"] == "success"
                    and event["source_ip"] == source_ip
                    and event["user"] == user
                    and last_failure <= parse_time(event["timestamp"])
                    <= last_failure + timedelta(
                        seconds=rule["window_seconds"]
                    )
                )
            ]

            alert = {
                "alert_id": "ALERT-" + first["event_id"],
                "rule_id": rule["rule_id"],
                "source_ip": source_ip,
                "user": user,
                "failed_attempts": len(window),
                "first_failure": window[0]["timestamp"],
                "last_failure": window[-1]["timestamp"],
                "successful_login_after_failures": bool(successes),
                "severity": rule["severity"],
                "classification": "REVIEW_REQUIRED",
                "confirmed_compromise": False
            }

            if successes:
                alert["correlation_rule"] = "COR-SSH-001"
                alert["successful_login_time"] = successes[0]["timestamp"]

            alerts.append(alert)
            break

    return alerts


def main():
    events = [
        json.loads(line)
        for line in SOURCE.read_text().splitlines()
        if line.strip()
    ]

    rules = json.loads(RULES.read_text())["rules"]
    rule = next(item for item in rules if item["rule_id"] == "DET-SSH-001")

    alerts = detect(events, rule)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w") as file:
        json.dump({
            "detection_engine": "NEXORA SIEM",
            "rules_evaluated": len(rules),
            "alert_count": len(alerts),
            "alerts": alerts
        }, file, indent=4)

    print("Detection completed.")
    print("Rules evaluated:", len(rules))
    print("Alerts generated:", len(alerts))


if __name__ == "__main__":
    main()
