import json
from pathlib import Path

events = [
    ("2026-11-16T10:00:01Z", "AUTH_FAILURE", "svc-backup", "198.51.100.45", None, None, None, "failure"),
    ("2026-11-16T10:00:20Z", "AUTH_FAILURE", "svc-backup", "198.51.100.45", None, None, None, "failure"),
    ("2026-11-16T10:01:05Z", "AUTH_FAILURE", "svc-backup", "198.51.100.45", None, None, None, "failure"),
    ("2026-11-16T10:02:10Z", "AUTH_FAILURE", "svc-backup", "198.51.100.45", None, None, None, "failure"),
    ("2026-11-16T10:03:40Z", "AUTH_FAILURE", "svc-backup", "198.51.100.45", None, None, None, "failure"),
    ("2026-11-16T10:04:15Z", "AUTH_SUCCESS", "svc-backup", "198.51.100.45", None, None, None, "success"),
    ("2026-11-16T10:04:30Z", "SESSION", "svc-backup", "198.51.100.45", None, None, None, "opened"),
    ("2026-11-16T10:05:10Z", "PRIVILEGED_ACTIVITY", "svc-backup", None, None, None, "sudo systemctl status ssh", "observed"),
    ("2026-11-16T10:05:45Z", "PROCESS_EXECUTION", "svc-backup", None, None, None, "python3", "observed"),
    ("2026-11-16T10:06:20Z", "NETWORK_CONNECTION", "svc-backup", None, "203.0.113.90", 443, "python3", "observed"),
    ("2026-11-16T10:07:00Z", "DNS_QUERY", "svc-backup", None, "updates.example.test", None, None, "observed"),
    ("2026-11-16T10:08:10Z", "AUTH_FAILURE", "admin", "198.51.100.45", None, None, None, "failure"),
    ("2026-11-16T10:09:00Z", "AUTH_SUCCESS", "backup-operator", "192.0.2.25", None, None, None, "success"),
    ("2026-11-16T10:09:30Z", "PROCESS_EXECUTION", "backup-operator", None, None, None, "backup-agent", "observed"),
    ("2026-11-16T10:10:00Z", "NETWORK_CONNECTION", "backup-operator", None, "192.0.2.80", 443, "backup-agent", "observed"),
]

records = []

for i, row in enumerate(events, 1):
    timestamp, event_type, username, src_ip, dest_ip, dest_port, process_name, outcome = row

    command = None
    if event_type == "PRIVILEGED_ACTIVITY":
        command = process_name
    elif event_type == "PROCESS_EXECUTION":
        command = process_name

    records.append({
        "event_id": f"D30-E{i:03}",
        "timestamp": timestamp,
        "host": "nexora-linux-01",
        "event_type": event_type,
        "username": username,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "process_name": process_name,
        "command": command,
        "outcome": outcome
    })

output = Path("data/soc-2026-030-events.jsonl")
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(
    "".join(json.dumps(event) + "\n" for event in records)
)

print(f"Generated {len(records)} synthetic events.")
print(f"Output: {output}")
