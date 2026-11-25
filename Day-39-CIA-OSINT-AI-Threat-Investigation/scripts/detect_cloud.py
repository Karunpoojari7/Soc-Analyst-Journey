import csv
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

LOG_FILE = BASE / "evidence/cloud-logs/cloud-events.csv"
OUTPUT = BASE / "output/cloud-alerts.json"

alerts = []

with LOG_FILE.open(newline="", encoding="utf-8") as f:
    events = list(csv.DictReader(f))

for event in events:

    event_type = event["event_type"]
    actor = event["actor"]

    # Rule 1: IAM role modification
    if event_type == "iam_role_change" and event["result"] == "success":
        alerts.append({
            "alert_id": "D39-006",
            "severity": "CRITICAL",
            "category": "IAM",
            "actor": actor,
            "source_ip": event["source_ip"],
            "timestamp": event["timestamp"],
            "resource": event["resource"],
            "event_id": event["event_id"],
            "evidence": "Successful IAM role modification"
        })

    # Rule 2: Cloud storage export
    elif event_type == "storage_export" and event["result"] == "success":
        alerts.append({
            "alert_id": "D39-007",
            "severity": "HIGH",
            "category": "DATA_ACCESS",
            "actor": actor,
            "source_ip": event["source_ip"],
            "timestamp": event["timestamp"],
            "resource": event["resource"],
            "event_id": event["event_id"],
            "evidence": "Successful cloud storage export"
        })

    # Rule 3: Storage access for investigation
    elif event_type == "storage_access" and event["result"] == "success":
        print(
            f"[REVIEW] Storage access by {actor} "
            f"to {event['resource']} ({event['event_id']})"
        )

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(alerts, indent=2), encoding="utf-8")

print("\n" + "=" * 50)
print("DAY 39 - CLOUD SECURITY INVESTIGATION")
print("=" * 50)

for alert in alerts:
    print(f"\n[{alert['severity']}] {alert['alert_id']}")
    print("Actor:", alert["actor"])
    print("Resource:", alert["resource"])
    print("Evidence:", alert["evidence"])

print("\nTotal cloud alerts:", len(alerts))
print("Output:", OUTPUT.relative_to(BASE))
