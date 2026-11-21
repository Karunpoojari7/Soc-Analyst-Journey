import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

def detect(events):
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
                and timedelta(0) <= (
                    login_time - datetime.fromisoformat(
                        e["timestamp"].replace("Z", "+00:00")
                    )
                ) <= timedelta(minutes=10)
            ]

            subsequent = []

            for event in records:
                event_time = datetime.fromisoformat(
                    event["timestamp"].replace("Z", "+00:00")
                )

                if (
                    timedelta(0) <= event_time - login_time <= timedelta(minutes=10)
                    and event["source_ip"] == success["source_ip"]
                ):
                    subsequent.append(event)

            event_types = {e["event_type"] for e in subsequent}

            if (
                len(prior_failures) >= 3
                and "MFA_REGISTRATION" in event_types
                and "PRIVILEGE_CHANGE" in event_types
            ):
                alerts.append(username)
                break

    return alerts


def load_events(path):
    with open(path, newline="") as file:
        return list(csv.DictReader(file))


suspicious = load_events("evidence/identity/authentication.csv")
benign = load_events("tests/benign-authentication.csv")

assert "employee01" in detect(suspicious), "Suspicious scenario was missed"
assert detect(benign) == [], "Benign scenario generated an unexpected alert"

print("PASS: Suspicious scenario detected")
print("PASS: Benign scenario produced no alert")
print("PASS: Detection tests completed")
