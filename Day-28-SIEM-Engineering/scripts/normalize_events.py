#!/usr/bin/env python3

import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

SOURCE = BASE / "data/raw/security-events.jsonl"
OUTPUT = BASE / "data/normalized/normalized-events.jsonl"

ALLOWED_TYPES = {
    "authentication",
    "session",
    "privileged_command",
    "process_execution",
    "network_connection"
}

ALLOWED_OUTCOMES = {"success", "failure", "observed"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}


def normalize(event):
    if event["event_type"] not in ALLOWED_TYPES:
        raise ValueError("Unsupported event type")

    if event["outcome"] not in ALLOWED_OUTCOMES:
        raise ValueError("Unsupported outcome")

    if event["severity"] not in ALLOWED_SEVERITIES:
        raise ValueError("Unsupported severity")

    timestamp = datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    )

    if timestamp.tzinfo is None:
        raise ValueError("Timestamp must include timezone")

    return {
        "event_id": str(event["event_id"]),
        "timestamp": timestamp.astimezone(
            timezone.utc
        ).isoformat().replace("+00:00", "Z"),
        "host": str(event["host"]),
        "event_category": event["event_type"],
        "user": str(event["username"]),
        "source_ip": str(event["src_ip"]),
        "event_outcome": event["outcome"],
        "severity": event["severity"],
        "pipeline_status": "NORMALIZED"
    }


def main():
    count = 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with SOURCE.open() as source, OUTPUT.open("w") as destination:
        for line in source:
            if not line.strip():
                continue

            event = json.loads(line)
            normalized = normalize(event)

            destination.write(
                json.dumps(normalized) + "\n"
            )

            count += 1

    print("Normalization completed.")
    print("Normalized events:", count)
    print("Output:", OUTPUT.relative_to(BASE))


if __name__ == "__main__":
    main()
