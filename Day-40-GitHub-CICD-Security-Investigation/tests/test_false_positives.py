import json
from collections import defaultdict

path = "tests/benign-github-events.jsonl"

with open(path) as f:
    events = [json.loads(line) for line in f if line.strip()]

groups = defaultdict(list)

for event in events:
    if event.get("status") == "success":
        groups[(event["actor"], event["repository"])].append(event)

required = {
    "token.created",
    "repo.permission.changed",
    "workflow.modified",
    "workflow.run"
}

alerts = []

for (actor, repository), records in groups.items():
    actions = {event["action"] for event in records}

    if required.issubset(actions):
        alerts.append({
            "actor": actor,
            "repository": repository
        })

print("Events tested:", len(events))
print("Benign false-positive alerts:", len(alerts))

if alerts:
    print("TEST FAILED: Benign activity triggered an alert")
    raise SystemExit(1)

print("TEST PASSED: No complete suspicious sequence detected")
