import json
import sys
from pathlib import Path
from datetime import datetime

ROOT = Path(".")
checks = []

def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    checks.append(condition)
    print(f"[{status}] {name}")
    if detail:
        print(f"       {detail}")

def load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception as exc:
        print(f"[FAIL] Could not read {path}: {exc}")
        return None

print("=" * 60)
print("DAY 41 — SOC INVESTIGATION QUALITY REVIEW")
print("=" * 60)

# 1. Input log validation
log_files = [
    "logs/raw/authentication.jsonl",
    "logs/raw/api-access.jsonl",
    "logs/raw/firewall.jsonl"
]

all_events = []
log_valid = True

for filename in log_files:
    path = ROOT / filename
    if not path.exists():
        log_valid = False
        continue

    try:
        events = [
            json.loads(line)
            for line in path.read_text().splitlines()
            if line.strip()
        ]
        all_events.extend(events)
        print(f"[INFO] {filename}: {len(events)} events")
    except Exception:
        log_valid = False

check("Raw log files exist and contain valid JSON", log_valid and len(all_events) > 0)

# 2. Detection output
alerts = load_json("output/infrastructure-alerts.json")
alert_valid = isinstance(alerts, list)

check("Detection output is a JSON list", alert_valid)

if alert_valid:
    required = {"rule_id", "severity", "source_ip", "evidence", "description"}
    schema_valid = all(required.issubset(a) for a in alerts)
    check("Alert schema validation", schema_valid)

    rule_ids = {a.get("rule_id") for a in alerts}
    check("Detection rule identifiers present", len(rule_ids) > 0,
          ", ".join(sorted(str(x) for x in rule_ids)))

# 3. Incident correlation
incidents = load_json("output/correlated-incidents.json")
incident_valid = isinstance(incidents, list)

check("Correlated incident output is valid", incident_valid)

if incident_valid:
    check(
        "Incident evidence identifiers present",
        all(bool(i.get("evidence_ids")) for i in incidents)
        if incidents else True
    )

# 4. Timeline validation
timeline = load_json("output/incident-timeline.json")
timeline_valid = isinstance(timeline, dict) and isinstance(
    timeline.get("timeline"), list
)

check("Timeline structure valid", timeline_valid)

if timeline_valid:
    events = timeline["timeline"]
    timestamps_valid = True

    try:
        timestamps = [
            datetime.fromisoformat(
                e["timestamp"].replace("Z", "+00:00")
            )
            for e in events
        ]
    except (KeyError, ValueError, TypeError):
        timestamps_valid = False
        timestamps = []

    sorted_timestamps = (
        timestamps == sorted(timestamps)
        if timestamps_valid else False
    )

    check("Timeline timestamps valid", timestamps_valid)
    check("Timeline chronological ordering", sorted_timestamps)

    timeline_ids = {e.get("id") for e in events}
    check(
        "Timeline event identifiers are unique",
        len(timeline_ids) == len(events)
    )

# 5. Evidence manifest
manifest = ROOT / "evidence/sha256-manifest.txt"
check("SHA-256 manifest exists", manifest.exists())

# 6. Documentation
documentation = [
    "README.md",
    "detections/detection-rules.md",
    "docs/analyst-assessment.md",
    "docs/attack-timeline.md",
    "docs/mitre-attack-mapping.md",
    "reports/day-41-incident-report.md"
]

for filename in documentation:
    path = ROOT / filename
    check(f"Documentation exists: {filename}", path.exists() and path.stat().st_size > 0)

print("\n" + "=" * 60)
passed = sum(checks)
failed = len(checks) - passed
print(f"QUALITY REVIEW: {passed} PASSED / {failed} FAILED")
print("=" * 60)

sys.exit(0 if failed == 0 else 1)
