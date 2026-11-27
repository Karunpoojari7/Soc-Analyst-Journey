import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

RAW = Path("logs/raw")
ALERT_FILE = Path("output/infrastructure-alerts.json")
OUTPUT = Path("output/correlated-incidents.json")

WINDOW_SECONDS = 600

def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def load_jsonl(filename):
    path = RAW / filename
    if not path.exists():
        raise SystemExit(f"Missing log file: {path}")

    events = []
    for line in path.read_text().splitlines():
        if line.strip():
            event = json.loads(line)
            event["log_source"] = filename
            events.append(event)
    return events

auth = load_jsonl("authentication.jsonl")
api = load_jsonl("api-access.jsonl")
firewall = load_jsonl("firewall.jsonl")

if not ALERT_FILE.exists():
    raise SystemExit("Detection alert file is missing. Run detection first.")

alerts = json.loads(ALERT_FILE.read_text())

events = auth + api + firewall

by_ip = defaultdict(list)
for event in events:
    by_ip[event.get("source_ip", "UNKNOWN")].append(event)

alerts_by_ip = defaultdict(list)
for alert in alerts:
    alerts_by_ip[alert["source_ip"]].append(alert)

incidents = []

for ip, ip_events in sorted(by_ip.items()):
    if ip not in alerts_by_ip:
        continue

    ip_events.sort(key=lambda e: parse_time(e["timestamp"]))

    # Build time-window groups without merging unrelated periods.
    windows = []

    for event in ip_events:
        event_time = parse_time(event["timestamp"])

        if not windows or (
            event_time - parse_time(windows[-1][0]["timestamp"])
        ).total_seconds() > WINDOW_SECONDS:
            windows.append([event])
        else:
            windows[-1].append(event)

    for group in windows:
        sources = sorted({e["log_source"] for e in group})
        evidence_ids = sorted({
            e["id"] for e in group if e.get("id")
        })

        group_alerts = [
            alert for alert in alerts_by_ip[ip]
            if set(alert.get("evidence", [])) & set(evidence_ids)
        ]

        if not group_alerts:
            continue

        incident = {
            "incident_id": f"INC-DAY41-{len(incidents) + 1:03d}",
            "source_ip": ip,
            "window_seconds": WINDOW_SECONDS,
            "start_time": group[0]["timestamp"],
            "end_time": group[-1]["timestamp"],
            "log_sources": sources,
            "event_count": len(group),
            "evidence_ids": evidence_ids,
            "detection_rules": sorted({
                a["rule_id"] for a in group_alerts
            }),
            "severity": (
                "HIGH"
                if len({a["severity"] for a in group_alerts}) > 1
                or any(a["severity"] == "HIGH" for a in group_alerts)
                else "MEDIUM"
            ),
            "cross_source_activity": len(sources) > 1,
            "assessment": (
                "Suspicious activity correlated across multiple log sources."
                if len(sources) > 1
                else "Suspicious activity detected in one log source."
            )
        }

        incidents.append(incident)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(incidents, indent=2) + "\n")

print("Advanced Incident Correlation")
print("=============================")
print("Raw events:", len(events))
print("Detection alerts:", len(alerts))
print("Correlated incidents:", len(incidents))

for incident in incidents:
    print(
        incident["incident_id"],
        incident["source_ip"],
        incident["severity"],
        incident["log_sources"],
        incident["detection_rules"]
    )

print("Output:", OUTPUT)
