import json
from pathlib import Path

events = [
    ("EVT-001", "10:00:01", "AUTH_FAILURE", "failure", "198.51.100.23"),
    ("EVT-002", "10:01:10", "AUTH_FAILURE", "failure", "198.51.100.23"),
    ("EVT-003", "10:02:20", "AUTH_FAILURE", "failure", "198.51.100.23"),
    ("EVT-004", "10:03:30", "AUTH_FAILURE", "failure", "198.51.100.23"),
    ("EVT-005", "10:04:40", "AUTH_FAILURE", "failure", "198.51.100.23"),
    ("EVT-006", "10:05:50", "AUTH_FAILURE", "failure", "198.51.100.23"),
    ("EVT-007", "10:06:20", "AUTH_SUCCESS", "success", "198.51.100.23"),
    ("EVT-008", "10:07:00", "SESSION", "observed", "198.51.100.23"),
    ("EVT-009", "10:08:10", "PRIVILEGED_ACTIVITY", "observed", "198.51.100.23"),
    ("EVT-010", "10:09:20", "PROCESS_EXECUTION", "observed", "198.51.100.23"),
    ("EVT-011", "10:10:30", "NETWORK_CONNECTION", "observed", "198.51.100.23"),
]

records = []

for event_id, clock, event_type, outcome, source_ip in events:
    event = {
        "event_id": event_id,
        "timestamp": f"2026-11-15T{clock}Z",
        "host": "nexora-linux-01",
        "event_type": event_type,
        "username": "svc-backup",
        "src_ip": source_ip,
        "outcome": outcome,
        "severity": "medium"
    }

    if event_type == "PRIVILEGED_ACTIVITY":
        event["command"] = "sudo systemctl status ssh"

    if event_type == "PROCESS_EXECUTION":
        event["process_name"] = "python3"
        event["process_id"] = 4312

    if event_type == "NETWORK_CONNECTION":
        event["dest_ip"] = "203.0.113.80"
        event["dest_port"] = 443
        event["process_name"] = "python3"

    records.append(event)

output = Path("data/raw/nexora-security-events.jsonl")
output.parent.mkdir(parents=True, exist_ok=True)

with output.open("w") as file:
    for record in records:
        file.write(json.dumps(record) + "\n")

print("Dataset created:", output)
print("Total events:", len(records))
print("All events are synthetic.")
