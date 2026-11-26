import json
from pathlib import Path
from datetime import datetime

INPUT = Path("logs/github-audit-events.jsonl")
ALERTS = Path("output/github-correlation-alerts-v2.json")
OUTPUT = Path("output/incident-timeline.json")

with INPUT.open() as f:
    events = [json.loads(line) for line in f if line.strip()]

with ALERTS.open() as f:
    alerts = json.load(f)

# Support the alert list in the generated JSON.
if isinstance(alerts, dict):
    alerts = alerts.get("alerts", [])

timeline = []

for alert in alerts:
    event_ids = set(alert.get("correlated_events", []))

    matched = [
        event for event in events
        if event.get("event_id") in event_ids
    ]

    matched.sort(
        key=lambda event: datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )
    )

    for event in matched:
        timeline.append({
            "incident_id": alert.get("alert_id"),
            "timestamp": event.get("timestamp"),
            "event_id": event.get("event_id"),
            "actor": event.get("actor"),
            "action": event.get("action"),
            "repository": event.get("repository"),
            "source_ip": event.get("source_ip"),
            "status": event.get("status")
        })

timeline.sort(key=lambda event: event["timestamp"] or "")

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(timeline, indent=2) + "\n")

print(f"Events in timeline: {len(timeline)}")
print(f"Output: {OUTPUT}")
for item in timeline:
    print(
        f'{item["timestamp"]} | {item["event_id"]} | '
        f'{item["actor"]} | {item["action"]}'
    )
