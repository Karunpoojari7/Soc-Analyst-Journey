import json
from collections import Counter, defaultdict
from pathlib import Path

DATA = Path("data/soc-2026-030-events.jsonl")
OUTPUT = Path("reports/analysis-results.json")

with DATA.open() as f:
    events = [json.loads(line) for line in f if line.strip()]

events.sort(key=lambda e: e["timestamp"])

counts = Counter(e["event_type"] for e in events)
failures = defaultdict(list)
successes = []

for event in events:
    if event["event_type"] == "AUTH_FAILURE":
        failures[event["username"]].append(event)
    elif event["event_type"] == "AUTH_SUCCESS":
        successes.append(event)

findings = []

for username, failed_events in failures.items():
    if len(failed_events) >= 5:
        findings.append({
            "id": "D30-DET-001",
            "severity": "HIGH",
            "title": "Repeated authentication failures",
            "account": username,
            "count": len(failed_events),
            "source_ips": sorted({
                e["src_ip"] for e in failed_events if e["src_ip"]
            }),
            "description": "Five or more authentication failures observed."
        })

for success in successes:
    prior = [
        e for e in failures.get(success["username"], [])
        if e["timestamp"] < success["timestamp"]
    ]

    if len(prior) >= 5:
        findings.append({
            "id": "D30-DET-002",
            "severity": "HIGH",
            "title": "Successful login after repeated failures",
            "account": success["username"],
            "success_event": success["event_id"],
            "description": "Successful authentication followed earlier failures."
        })

for event in events:
    if event["event_type"] == "PRIVILEGED_ACTIVITY":
        findings.append({
            "id": "D30-DET-003",
            "severity": "MEDIUM",
            "title": "Privileged activity requires validation",
            "account": event["username"],
            "event_id": event["event_id"],
            "command": event["command"]
        })

    elif event["event_type"] == "PROCESS_EXECUTION":
        findings.append({
            "id": "D30-DET-004",
            "severity": "MEDIUM",
            "title": "Process execution requires investigation",
            "account": event["username"],
            "process": event["process_name"],
            "event_id": event["event_id"]
        })

    elif event["event_type"] == "NETWORK_CONNECTION":
        findings.append({
            "id": "D30-DET-005",
            "severity": "MEDIUM",
            "title": "Outbound network connection requires review",
            "account": event["username"],
            "destination": event["dest_ip"],
            "destination_port": event["dest_port"],
            "process": event["process_name"],
            "event_id": event["event_id"]
        })

result = {
    "case_id": "SOC-2026-030",
    "case_name": "NEXORA Linux Account Investigation",
    "dataset_type": "synthetic",
    "host": "nexora-linux-01",
    "total_events": len(events),
    "event_counts": dict(counts),
    "findings": findings,
    "assessment": {
        "priority": "HIGH",
        "status": "UNDER_INVESTIGATION",
        "compromise_confirmed": False,
        "recommended_action": "Tier 2 investigation",
        "limitations": [
            "Synthetic dataset only.",
            "No session identifier proves event-to-session attribution.",
            "No process parent-child relationship is provided.",
            "Outbound connection destination reputation is not established.",
            "Event correlation does not prove causation."
        ]
    }
}

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(result, indent=2) + "\n")

print("Case:", result["case_id"])
print("Total events:", result["total_events"])
print("Findings:", len(findings))
print("Priority:", result["assessment"]["priority"])
print("Compromise confirmed:", result["assessment"]["compromise_confirmed"])
print("Results saved to:", OUTPUT)
