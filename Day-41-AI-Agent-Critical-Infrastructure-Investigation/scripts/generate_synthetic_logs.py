import json
from pathlib import Path

BASE = Path("logs/raw")
BASE.mkdir(parents=True, exist_ok=True)

auth_events = [
    {"id":"AUTH001","timestamp":"2026-11-27T09:00:00Z","user":"operator01","source_ip":"192.0.2.44","event":"login_success","status":"success"},
    {"id":"AUTH002","timestamp":"2026-11-27T09:10:00Z","user":"admin","source_ip":"198.51.100.77","event":"login_failure","status":"failure"},
    {"id":"AUTH003","timestamp":"2026-11-27T09:10:08Z","user":"admin","source_ip":"198.51.100.77","event":"login_failure","status":"failure"},
    {"id":"AUTH004","timestamp":"2026-11-27T09:10:16Z","user":"admin","source_ip":"198.51.100.77","event":"login_failure","status":"failure"},
    {"id":"AUTH005","timestamp":"2026-11-27T09:10:24Z","user":"admin","source_ip":"198.51.100.77","event":"login_success","status":"success"},
    {"id":"AUTH006","timestamp":"2026-11-27T09:12:00Z","user":"admin","source_ip":"198.51.100.77","event":"privilege_change","status":"success"},
    {"id":"AUTH007","timestamp":"2026-11-27T09:20:00Z","user":"operator01","source_ip":"192.0.2.44","event":"login_success","status":"success"}
]

api_events = [
    {"id":"API001","timestamp":"2026-11-27T09:09:00Z","source_ip":"198.51.100.77","method":"GET","path":"/robots.txt","status_code":200},
    {"id":"API002","timestamp":"2026-11-27T09:09:02Z","source_ip":"198.51.100.77","method":"GET","path":"/api/v1/status","status_code":200},
    {"id":"API003","timestamp":"2026-11-27T09:09:04Z","source_ip":"198.51.100.77","method":"GET","path":"/api/v1/assets","status_code":200},
    {"id":"API004","timestamp":"2026-11-27T09:09:06Z","source_ip":"198.51.100.77","method":"GET","path":"/api/v1/users","status_code":403},
    {"id":"API005","timestamp":"2026-11-27T09:09:08Z","source_ip":"198.51.100.77","method":"GET","path":"/api/v1/config","status_code":200},
    {"id":"API006","timestamp":"2026-11-27T09:13:00Z","source_ip":"198.51.100.77","method":"POST","path":"/api/v1/admin/settings","status_code":200},
    {"id":"API007","timestamp":"2026-11-27T09:21:00Z","source_ip":"192.0.2.44","method":"GET","path":"/api/v1/status","status_code":200}
]

firewall_events = [
    {"id":"FW001","timestamp":"2026-11-27T09:08:58Z","source_ip":"198.51.100.77","destination":"web-gateway:443","action":"ALLOW"},
    {"id":"FW002","timestamp":"2026-11-27T09:09:01Z","source_ip":"198.51.100.77","destination":"api-gateway:443","action":"ALLOW"},
    {"id":"FW003","timestamp":"2026-11-27T09:11:00Z","source_ip":"198.51.100.77","destination":"admin-service:8443","action":"ALLOW"},
    {"id":"FW004","timestamp":"2026-11-27T09:14:00Z","source_ip":"198.51.100.77","destination":"control-network:502","action":"BLOCK"},
    {"id":"FW005","timestamp":"2026-11-27T09:22:00Z","source_ip":"192.0.2.44","destination":"web-gateway:443","action":"ALLOW"}
]

datasets = {
    "authentication.jsonl": auth_events,
    "api-access.jsonl": api_events,
    "firewall.jsonl": firewall_events
}

for filename, events in datasets.items():
    path = BASE / filename
    with path.open("w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
    print(f"{filename}: {len(events)} events")

print("Synthetic log generation complete.")
