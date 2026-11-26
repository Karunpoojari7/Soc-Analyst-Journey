import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

INPUT = Path("logs/github-audit-events.jsonl")
OUTPUT = Path("output/github-correlation-alerts-v2.json")

REQUIRED_SEQUENCE = [
    "token.created",
    "repo.permission.changed",
    "workflow.modified",
    "workflow.run"
]

MAX_WINDOW_SECONDS = 3600

def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

with INPUT.open() as f:
    events = [
        json.loads(line)
        for line in f
        if line.strip()
    ]

groups = defaultdict(list)

for event in events:
    if event.get("status") != "success":
        continue

    key = (
        event.get("actor"),
        event.get("repository"),
        event.get("source_ip")
    )

    if all(key):
        groups[key].append(event)

alerts = []

for (actor, repository, source_ip), records in groups.items():
    records.sort(key=lambda e: parse_time(e["timestamp"]))

    selected = []
    next_index = 0

    for event in records:
        if (
            next_index < len(REQUIRED_SEQUENCE)
            and event.get("action") == REQUIRED_SEQUENCE[next_index]
        ):
            selected.append(event)
            next_index += 1

    if next_index != len(REQUIRED_SEQUENCE):
        continue

    start = parse_time(selected[0]["timestamp"])
    end = parse_time(selected[-1]["timestamp"])

    duration = (end - start).total_seconds()

    if duration < 0 or duration > MAX_WINDOW_SECONDS:
        continue

    alerts.append({
        "alert_id": f"D40-V2-{len(alerts) + 1:03d}",
        "severity": "HIGH",
        "actor": actor,
        "repository": repository,
        "source_ip": source_ip,
        "correlated_events": [
            event["event_id"] for event in selected
        ],
        "sequence_duration_seconds": duration,
        "detection_rule": "STRICT_TOKEN_PERMISSION_WORKFLOW_CHAIN",
        "assessment": (
            "Ordered suspicious activity sequence detected. "
            "Analyst validation required; not proof of compromise."
        )
    })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(alerts, indent=2))

print("Improved correlation completed")
print("Input events:", len(events))
print("Incidents detected:", len(alerts))
print("Output:", OUTPUT)
