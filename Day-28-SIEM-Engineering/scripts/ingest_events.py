#!/usr/bin/env python3

import json
from pathlib import Path
from datetime import datetime, timezone

BASE = Path(__file__).resolve().parent.parent
SOURCE = BASE / "data/raw/security-events.jsonl"
OUTPUT = BASE / "output/ingestion-summary.json"

REQUIRED_FIELDS = {
    "event_id",
    "timestamp",
    "host",
    "event_type",
    "username",
    "src_ip",
    "outcome",
    "severity"
}


def ingest():
    events = []
    errors = []

    with SOURCE.open() as file:
        for line_number, line in enumerate(file, start=1):
            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    raise ValueError("Event must be a JSON object")

                missing = REQUIRED_FIELDS - event.keys()

                if missing:
                    raise ValueError(
                        "Missing fields: " + ", ".join(sorted(missing))
                    )

                datetime.fromisoformat(
                    event["timestamp"].replace("Z", "+00:00")
                )

                events.append(event)

            except (json.JSONDecodeError, ValueError) as error:
                errors.append({
                    "line": line_number,
                    "error": str(error)
                })

    summary = {
        "pipeline": "NEXORA SIEM",
        "collection_time_utc": datetime.now(timezone.utc).isoformat(),
        "source": "synthetic JSONL dataset",
        "events_received": len(events) + len(errors),
        "events_accepted": len(events),
        "events_rejected": len(errors),
        "errors": errors,
        "status": "SUCCESS" if not errors else "PARTIAL"
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w") as file:
        json.dump(summary, file, indent=4)

    print("===== SIEM INGESTION =====")
    print("Received:", summary["events_received"])
    print("Accepted:", summary["events_accepted"])
    print("Rejected:", summary["events_rejected"])
    print("Status:", summary["status"])


if __name__ == "__main__":
    ingest()
