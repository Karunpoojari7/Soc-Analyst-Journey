import csv
from pathlib import Path
from datetime import datetime, timezone

BASE = Path(__file__).resolve().parent.parent
EVIDENCE = BASE / "evidence"
OUTPUT = BASE / "timeline" / "correlated-timeline.csv"

events = []

def parse_time(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

def add_event(source, event):
    timestamp = event.get("timestamp")

    events.append({
        "timestamp": timestamp,
        "source": source,
        "event_id": event.get("event_id", ""),
        "username": (
            event.get("username")
            or event.get("actor")
            or ""
        ),
        "source_ip": event.get("source_ip", ""),
        "event_type": (
            event.get("event_type")
            or event.get("endpoint")
            or event.get("process")
            or ""
        ),
        "details": str(event)
    })

files = {
    "identity": "identity-logs/identity-events.csv",
    "api": "api-logs/api-events.csv",
    "cloud": "cloud-logs/cloud-events.csv",
    "endpoint": "endpoint-logs/endpoint-events.csv",
    "network": "network-logs/network-events.csv"
}

for source, relative_path in files.items():
    path = EVIDENCE / relative_path

    with path.open(newline="", encoding="utf-8") as f:
        for event in csv.DictReader(f):
            add_event(source, event)

events.sort(key=lambda e: parse_time(e["timestamp"]))

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "timestamp",
            "source",
            "event_id",
            "username",
            "source_ip",
            "event_type",
            "details"
        ]
    )

    writer.writeheader()
    writer.writerows(events)

print("=" * 55)
print("DAY 39 - CROSS-SOURCE EVENT CORRELATION")
print("=" * 55)

print("Total timeline events:", len(events))

for event in events:
    print(
        event["timestamp"],
        event["source"],
        event["event_id"],
        event["username"],
        event["source_ip"]
    )

print("\nTimeline saved:", OUTPUT.relative_to(BASE))
