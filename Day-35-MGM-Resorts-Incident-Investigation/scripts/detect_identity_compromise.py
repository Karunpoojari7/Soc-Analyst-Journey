import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

SOURCE = Path("evidence/identity/authentication.csv")
OUTPUT = Path("output/identity-alerts.json")

with SOURCE.open(newline="") as file:
    events = list(csv.DictReader(file))

accounts = defaultdict(list)

for event in events:
    accounts[event["username"]].append(event)

alerts = []

for username, records in accounts.items():
    records.sort(key=lambda e: e["timestamp"])

    for success in records:
        if success["event_type"] != "LOGIN" or success["result"] != "SUCCESS":
            continue

        login_time = datetime.fromisoformat(
            success["timestamp"].replace("Z", "+00:00")
        )

        prior_failures = [
            e for e in records
            if e["event_type"] == "LOGIN"
            and e["result"] == "FAILURE"
            and e["source_ip"] != success["source_ip"]
            and 0 <= (
                login_time - datetime.fromisoformat(
                    e["timestamp"].replace("Z", "+00:00")
                )
            ).total_seconds() <= 600
        ]

        subsequent = []

        for event in records:
            event_time = datetime.fromisoformat(
                event["timestamp"].replace("Z", "+00:00")
            )

            elapsed = (event_time - login_time).total_seconds()

            if (
                0 <= elapsed <= 600
                and event["source_ip"] == success["source_ip"]
            ):
                subsequent.append(event)

        event_types = {e["event_type"] for e in subsequent}

        if (
            len(prior_failures) >= 3
            and "MFA_REGISTRATION" in event_types
            and "PRIVILEGE_CHANGE" in event_types
        ):
            alerts.append({
                "alert_id": f"DAY35-{username}",
                "username": username,
                "severity": "HIGH",
                "failed_login_count": len(prior_failures),
                "successful_login_time": success["timestamp"],
                "source_ip": success["source_ip"],
                "mfa_registration_observed": True,
                "privilege_change_observed": True,
                "assessment": "Suspicious identity activity requiring investigation",
                "evidence_type": "SYNTHETIC_TRAINING_DATA"
            })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(alerts, indent=2) + "\n")

print(json.dumps(alerts, indent=2))
print(f"\nAlerts saved to {OUTPUT}")
