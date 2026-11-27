import json
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

BASE = Path("logs/raw")
OUTPUT = Path("output/infrastructure-alerts.json")

def load_events(filename):
    path = BASE / filename
    with path.open() as f:
        return [json.loads(line) for line in f if line.strip()]

auth = load_events("authentication.jsonl")
api = load_events("api-access.jsonl")
firewall = load_events("firewall.jsonl")

alerts = []

# DET001: Repeated login failures followed by success.
by_ip = defaultdict(list)

for event in auth:
    by_ip[event["source_ip"]].append(event)

for ip, events in by_ip.items():
    events.sort(key=lambda e: e["timestamp"])
    failures = [e for e in events if e["event"] == "login_failure"]
    successes = [e for e in events if e["event"] == "login_success"]

    for success in successes:
        previous = [
            failure for failure in failures
            if failure["timestamp"] < success["timestamp"]
            and (
                datetime.fromisoformat(success["timestamp"].replace("Z", "+00:00"))
                - datetime.fromisoformat(failure["timestamp"].replace("Z", "+00:00"))
            ).total_seconds() <= 600
        ]

        if len(previous) >= 3:
            alerts.append({
                "rule_id": "DET001",
                "severity": "HIGH",
                "source_ip": ip,
                "evidence": [e["id"] for e in previous] + [success["id"]],
                "description": "Repeated authentication failures followed by success."
            })
            break

# DET002: Successful access to administrative API settings.
for event in api:
    if event["path"].startswith("/api/v1/admin/") and event["status_code"] == 200:
        alerts.append({
            "rule_id": "DET002",
            "severity": "HIGH",
            "source_ip": event["source_ip"],
            "evidence": [event["id"]],
            "description": "Successful administrative API endpoint access."
        })

# DET003: Firewall activity targeting industrial control services.
for event in firewall:
    if "control-network:" in event["destination"]:
        alerts.append({
            "rule_id": "DET003",
            "severity": "HIGH" if event["action"] == "ALLOW" else "MEDIUM",
            "source_ip": event["source_ip"],
            "evidence": [event["id"]],
            "description": "Connection attempt targeting the control network.",
            "firewall_action": event["action"]
        })

# DET004: Correlate multiple log sources by source IP.
all_ips = set(by_ip)

for ip in all_ips:
    auth_matches = [e for e in auth if e["source_ip"] == ip]
    api_matches = [e for e in api if e["source_ip"] == ip]
    firewall_matches = [e for e in firewall if e["source_ip"] == ip]

    if auth_matches and api_matches and firewall_matches:
        alerts.append({
            "rule_id": "DET004",
            "severity": "HIGH",
            "source_ip": ip,
            "evidence": (
                [e["id"] for e in auth_matches]
                + [e["id"] for e in api_matches]
                + [e["id"] for e in firewall_matches]
            ),
            "description": "Activity correlated across authentication, API and firewall logs."
        })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(alerts, indent=2) + "\n")

print("Infrastructure Detection Engine")
print("===============================")
print("Authentication events:", len(auth))
print("API events:", len(api))
print("Firewall events:", len(firewall))
print("Total alerts:", len(alerts))

for alert in alerts:
    print(
        alert["rule_id"],
        "|", alert["severity"],
        "|", alert["source_ip"],
        "|", alert["description"]
    )

print("Output:", OUTPUT)
