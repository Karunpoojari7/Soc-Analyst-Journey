import csv
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

ENDPOINT_FILE = BASE / "evidence/endpoint-logs/endpoint-events.csv"
NETWORK_FILE = BASE / "evidence/network-logs/network-events.csv"

OUTPUT = BASE / "output/endpoint-network-alerts.json"

alerts = []

# Endpoint investigation
with ENDPOINT_FILE.open(newline="", encoding="utf-8") as f:
    endpoint_events = list(csv.DictReader(f))

for event in endpoint_events:
    process = event["process"].lower()
    parent = event["parent_process"].lower()

    if process == "curl" and parent == "python":
        alerts.append({
            "alert_id": "D39-008",
            "severity": "MEDIUM",
            "category": "ENDPOINT",
            "event_id": event["event_id"],
            "hostname": event["hostname"],
            "username": event["username"],
            "process": event["process"],
            "parent_process": event["parent_process"],
            "evidence": "curl process launched by Python"
        })

# Network investigation
with NETWORK_FILE.open(newline="", encoding="utf-8") as f:
    network_events = list(csv.DictReader(f))

for event in network_events:
    bytes_out = int(event["bytes_out"])

    if bytes_out >= 10_000_000:
        alerts.append({
            "alert_id": "D39-009",
            "severity": "HIGH",
            "category": "NETWORK",
            "event_id": event["event_id"],
            "source_ip": event["source_ip"],
            "destination_ip": event["destination_ip"],
            "destination_port": event["destination_port"],
            "bytes_out": bytes_out,
            "evidence": "Outbound transfer exceeded 10 MB"
        })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(alerts, indent=2), encoding="utf-8")

print("=" * 55)
print("DAY 39 - ENDPOINT AND NETWORK INVESTIGATION")
print("=" * 55)

for alert in alerts:
    print(f"\n[{alert['severity']}] {alert['alert_id']}")
    print("Category:", alert["category"])
    print("Event:", alert["event_id"])
    print("Evidence:", alert["evidence"])

print("\nTotal alerts:", len(alerts))
print("Output:", OUTPUT.relative_to(BASE))
print("\nFindings require further investigation.")
