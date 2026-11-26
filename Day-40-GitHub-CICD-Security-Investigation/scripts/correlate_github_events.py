import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

INPUT = Path("logs/github-audit-events.jsonl")
OUTPUT = Path("output/github-correlation-alerts.json")

events = []

with INPUT.open() as f:
    for line in f:
        if line.strip():
            events.append(json.loads(line))

# Group events by actor and repository.
groups = defaultdict(list)

for event in events:
    if event.get("status") != "success":
        continue

    key = (event.get("actor"), event.get("repository"))
    groups[key].append(event)

alerts = []

for (actor, repository), records in groups.items():
    records.sort(key=lambda e: e["timestamp"])

    actions = [e["action"] for e in records]

    required = [
        "token.created",
        "repo.permission.changed",
        "workflow.modified",
        "workflow.run"
    ]

    if not all(action in actions for action in required):
        continue

    selected = []
    for action in required:
        selected.append(next(
            e for e in records if e["action"] == action
        ))

    timestamps = [
        datetime.fromisoformat(
            e["timestamp"].replace("Z", "+00:00")
        )
        for e in selected
    ]

    duration = (timestamps[-1] - timestamps[0]).total_seconds()

    if duration > 3600:
        continue

    ips = {e.get("source_ip") for e in selected}

    alerts.append({
        "alert_id": f"D40-CORR-{len(alerts) + 1:03d}",
        "severity": "HIGH",
        "actor": actor,
        "repository": repository,
        "source_ips": sorted(ip for ip in ips if ip),
        "correlated_events": [
            e["event_id"] for e in selected
        ],
        "sequence_duration_seconds": duration,
        "detection_rule": "TOKEN_PERMISSION_WORKFLOW_CHAIN",
        "assessment": (
            "Suspicious activity sequence requiring investigation. "
            "This is not proof of account compromise."
        )
    })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(alerts, indent=2))

print("GitHub event correlation completed")
print("Events analysed:", len(events))
print("Correlated incidents:", len(alerts))
print("Output:", OUTPUT)
