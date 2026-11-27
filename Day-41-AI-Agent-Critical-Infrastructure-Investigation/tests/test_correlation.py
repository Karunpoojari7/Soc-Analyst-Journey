import json
import sys
from pathlib import Path
from datetime import datetime

ROOT = Path(".")
INCIDENT_FILE = ROOT / "output/correlated-incidents.json"
ALERT_FILE = ROOT / "output/infrastructure-alerts.json"

def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def fail(message):
    print("[FAIL]", message)
    sys.exit(1)

def passed(message):
    print("[PASS]", message)

if not INCIDENT_FILE.exists():
    fail("Correlation output missing")

if not ALERT_FILE.exists():
    fail("Detection alert output missing")

incidents = json.loads(INCIDENT_FILE.read_text())
alerts = json.loads(ALERT_FILE.read_text())

if not isinstance(incidents, list):
    fail("Incident output must be a JSON list")

if not isinstance(alerts, list):
    fail("Alert output must be a JSON list")

passed("JSON output structures are valid")

# Incident identifiers must be unique.
ids = [i.get("incident_id") for i in incidents]

if None in ids or len(ids) != len(set(ids)):
    fail("Incident IDs are missing or duplicated")

passed("Incident identifiers are unique")

# Validate each incident.
required = {
    "incident_id",
    "source_ip",
    "start_time",
    "end_time",
    "log_sources",
    "event_count",
    "evidence_ids",
    "detection_rules",
    "severity"
}

for incident in incidents:
    missing = required - incident.keys()

    if missing:
        fail(f"{incident.get('incident_id')}: missing {sorted(missing)}")

    if not incident["evidence_ids"]:
        fail(f"{incident['incident_id']}: no evidence identifiers")

    if not incident["detection_rules"]:
        fail(f"{incident['incident_id']}: no detection rules")

    start = parse_time(incident["start_time"])
    end = parse_time(incident["end_time"])

    if end < start:
        fail(f"{incident['incident_id']}: invalid time range")

    if incident["event_count"] != len(incident["evidence_ids"]):
        fail(f"{incident['incident_id']}: event count mismatch")

passed("Incident schema and time ranges are valid")

# Every correlated evidence ID must exist in the raw logs.
raw_files = [
    "logs/raw/authentication.jsonl",
    "logs/raw/api-access.jsonl",
    "logs/raw/firewall.jsonl"
]

raw_ids = set()

for filename in raw_files:
    path = ROOT / filename

    if not path.exists():
        fail(f"Missing raw log: {filename}")

    for line in path.read_text().splitlines():
        if line.strip():
            raw_ids.add(json.loads(line)["id"])

for incident in incidents:
    unknown = set(incident["evidence_ids"]) - raw_ids

    if unknown:
        fail(
            f"{incident['incident_id']}: unknown evidence IDs {sorted(unknown)}"
        )

passed("All incident evidence IDs exist in raw logs")

# Every incident detection rule must exist in the alert output.
known_rules = {a.get("rule_id") for a in alerts}

for incident in incidents:
    unknown = set(incident["detection_rules"]) - known_rules

    if unknown:
        fail(
            f"{incident['incident_id']}: unknown detection rules {sorted(unknown)}"
        )

passed("Incident detection rules match generated alerts")

print()
print("======================================")
print("CORRELATION TEST SUMMARY")
print("======================================")
print("Incidents validated:", len(incidents))
print("Alerts available:", len(alerts))
print("Raw evidence IDs:", len(raw_ids))
print("RESULT: PASS")
