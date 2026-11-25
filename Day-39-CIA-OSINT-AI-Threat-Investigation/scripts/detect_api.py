import csv
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta

BASE = Path(__file__).resolve().parent.parent

LOG_FILE = BASE / "evidence/api-logs/api-events.csv"
OUTPUT = BASE / "output/api-alerts.json"

WINDOW_SECONDS = 60
REQUEST_THRESHOLD = 3
EXPORT_THRESHOLD = 100

def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

with LOG_FILE.open(newline="", encoding="utf-8") as f:
    events = list(csv.DictReader(f))

events.sort(key=lambda e: parse_time(e["timestamp"]))

alerts = []
groups = defaultdict(list)

for event in events:
    key = (event["username"], event["source_ip"])
    groups[key].append(event)

# Rule 1: Rapid API requests
for (username, source_ip), records in groups.items():

    for current in records:
        current_time = parse_time(current["timestamp"])

        window_events = [
            event for event in records
            if timedelta(0) <= current_time - parse_time(event["timestamp"])
            <= timedelta(seconds=WINDOW_SECONDS)
        ]

        if len(window_events) >= REQUEST_THRESHOLD:
            event_ids = [event["event_id"] for event in window_events]

            alerts.append({
                "alert_id": "D39-004",
                "severity": "HIGH",
                "username": username,
                "source_ip": source_ip,
                "timestamp": current["timestamp"],
                "evidence": f"{len(window_events)} API requests within 60 seconds",
                "event_ids": event_ids
            })
            break

# Rule 2: Large API export
for event in events:
    count = int(event["request_count"])

    if (
        event["endpoint"].endswith("/export")
        and count >= EXPORT_THRESHOLD
    ):
        alerts.append({
            "alert_id": "D39-005",
            "severity": "HIGH",
            "username": event["username"],
            "source_ip": event["source_ip"],
            "timestamp": event["timestamp"],
            "evidence": f"Export request for {count} records",
            "event_ids": [event["event_id"]]
        })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(alerts, indent=2), encoding="utf-8")

print("=" * 50)
print("DAY 39 - API THREAT DETECTION")
print("=" * 50)

for alert in alerts:
    print(f"\n[{alert['severity']}] {alert['alert_id']}")
    print("Account:", alert["username"])
    print("Source:", alert["source_ip"])
    print("Evidence:", alert["evidence"])
    print("Events:", ", ".join(alert["event_ids"]))

print("\nTotal API alerts:", len(alerts))
print("Output:", OUTPUT.relative_to(BASE))
