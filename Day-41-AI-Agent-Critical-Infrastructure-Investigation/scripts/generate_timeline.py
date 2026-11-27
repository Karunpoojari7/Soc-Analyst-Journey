import json
from pathlib import Path

files = [
    "authentication.jsonl",
    "api-access.jsonl",
    "firewall.jsonl"
]

events = []

for filename in files:
    path = Path("logs/raw") / filename

    for line in path.read_text().splitlines():
        if not line.strip():
            continue

        event = json.loads(line)
        event["log_source"] = filename
        events.append(event)

events.sort(key=lambda event: event["timestamp"])

timeline = {
    "case_id": "DAY41-CASE-001",
    "dataset_type": "synthetic",
    "event_count": len(events),
    "timeline": events
}

output = Path("output/incident-timeline.json")
output.write_text(json.dumps(timeline, indent=2) + "\n")

print("Timeline generated:", output)
print("Events:", len(events))

for event in events:
    print(
        event["timestamp"],
        event["log_source"],
        event.get("id"),
        event.get("source_ip")
    )
