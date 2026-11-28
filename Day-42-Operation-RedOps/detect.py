import json
from collections import defaultdict
from pathlib import Path

events = [
    json.loads(line)
    for line in Path("data/authentication.jsonl").read_text().splitlines()
]

failures = defaultdict(set)
alerts = []

for event in events:
    if event["event"] == "login_failed":
        failures[event["src_ip"]].add(event["username"])

for ip, users in failures.items():
    if len(users) >= 3:
        alerts.append({
            "alert": "Possible Password Spraying",
            "source_ip": ip,
            "targeted_accounts": sorted(users),
            "severity": "HIGH"
        })

for event in events:
    if (event["event"] == "ssh_connection"
            and event.get("destination_port") == 443):
        alerts.append({
            "alert": "SSH Connection Over Port 443",
            "source_ip": event["src_ip"],
            "username": event["username"],
            "severity": "MEDIUM"
        })

print(json.dumps(alerts, indent=4))
print(f"\nTotal alerts: {len(alerts)}")
