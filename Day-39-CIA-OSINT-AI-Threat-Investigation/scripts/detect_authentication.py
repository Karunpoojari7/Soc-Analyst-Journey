import csv
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta

BASE = Path(__file__).resolve().parent.parent
LOG_FILE = BASE / "evidence/identity-logs/identity-events.csv"
OUTPUT = BASE / "output/authentication-alerts.json"

WINDOW_MINUTES = 10
FAILURE_THRESHOLD = 2

def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

with LOG_FILE.open(newline="", encoding="utf-8") as f:
    events = list(csv.DictReader(f))

events.sort(key=lambda e: parse_time(e["timestamp"]))

failures = defaultdict(list)
alerts = []

for event in events:
    user = event["username"]
    ip = event["source_ip"]
    timestamp = parse_time(event["timestamp"])

    if event["event_type"] == "login" and event["status"] == "failure":
        failures[(user, ip)].append(timestamp)

    elif event["event_type"] == "login" and event["status"] == "success":
        previous = [
            t for t in failures[(user, ip)]
            if timedelta(0) <= timestamp - t <= timedelta(minutes=WINDOW_MINUTES)
        ]

        if len(previous) >= FAILURE_THRESHOLD:
            alerts.append({
                "alert_id": "D39-001",
                "severity": "HIGH",
                "username": user,
                "source_ip": ip,
                "timestamp": event["timestamp"],
                "evidence": f"{len(previous)} failures followed by successful login",
                "event_id": event["event_id"]
            })

    elif event["event_type"] == "privilege_change" and event["status"] == "success":
        alerts.append({
            "alert_id": "D39-003",
            "severity": "CRITICAL",
            "username": user,
            "source_ip": ip,
            "timestamp": event["timestamp"],
            "evidence": event["details"],
            "event_id": event["event_id"]
        })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(alerts, indent=2), encoding="utf-8")

print("=" * 50)
print("DAY 39 - AUTHENTICATION DETECTION")
print("=" * 50)

for alert in alerts:
    print(f"[{alert['severity']}] {alert['alert_id']}")
    print(f"Account: {alert['username']}")
    print(f"Source: {alert['source_ip']}")
    print(f"Evidence: {alert['evidence']}")
    print("-" * 40)

print(f"Total alerts: {len(alerts)}")
print(f"Output: {OUTPUT.relative_to(BASE)}")
