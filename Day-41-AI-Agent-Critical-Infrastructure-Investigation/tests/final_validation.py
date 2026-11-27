import json
import sys
from pathlib import Path

ROOT = Path(".")
failures = []

def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}")
    if detail:
        print("       ", detail)
    if not condition:
        failures.append(name)

def read_json(path):
    try:
        return json.loads((ROOT / path).read_text())
    except Exception as exc:
        print(f"[ERROR] {path}: {exc}")
        return None

print("=" * 60)
print("DAY 41 — FINAL INVESTIGATION VALIDATION")
print("=" * 60)

# Raw logs
log_files = [
    "logs/raw/authentication.jsonl",
    "logs/raw/api-access.jsonl",
    "logs/raw/firewall.jsonl"
]

raw_ids = set()
raw_valid = True

for filename in log_files:
    path = ROOT / filename

    if not path.exists():
        raw_valid = False
        continue

    try:
        for line in path.read_text().splitlines():
            if line.strip():
                event = json.loads(line)
                if not event.get("id"):
                    raw_valid = False
                raw_ids.add(event.get("id"))
    except Exception:
        raw_valid = False

check("Raw logs valid", raw_valid, f"{len(raw_ids)} event IDs")

# Alerts
alerts = read_json("output/infrastructure-alerts.json")
check("Detection output valid", isinstance(alerts, list))

if isinstance(alerts, list):
    alert_ids = {
        event_id
        for alert in alerts
        for event_id in alert.get("evidence", [])
    }
    check(
        "Alert evidence exists in raw logs",
        alert_ids.issubset(raw_ids),
        f"{len(alert_ids)} referenced IDs"
    )

# Incidents
incidents = read_json("output/correlated-incidents.json")
check("Incident output valid", isinstance(incidents, list))

if isinstance(incidents, list):
    incident_ids = [i.get("incident_id") for i in incidents]
    check(
        "Incident identifiers unique",
        len(incident_ids) == len(set(incident_ids))
    )

    incident_evidence = {
        event_id
        for incident in incidents
        for event_id in incident.get("evidence_ids", [])
    }

    check(
        "Incident evidence exists in raw logs",
        incident_evidence.issubset(raw_ids)
    )

# Timeline
timeline = read_json("output/incident-timeline.json")
check(
    "Timeline output valid",
    isinstance(timeline, dict)
    and isinstance(timeline.get("timeline"), list)
)

if isinstance(timeline, dict) and isinstance(timeline.get("timeline"), list):
    timeline_events = timeline["timeline"]
    timeline_ids = [e.get("id") for e in timeline_events]

    check(
        "Timeline event count matches raw logs",
        len(timeline_events) == len(raw_ids)
    )
    check(
        "Timeline identifiers unique",
        len(timeline_ids) == len(set(timeline_ids))
    )
    check(
        "Timeline contains known evidence",
        set(timeline_ids).issubset(raw_ids)
    )

# Required deliverables
required_files = [
    "README.md",
    "run_investigation.sh",
    "detections/detection-rules.md",
    "tests/test_detection.py",
    "tests/test_correlation.py",
    "tests/test_detection_scenarios.py",
    "tests/quality_review.py",
    "scripts/generate_final_report.py",
    "docs/analyst-assessment.md",
    "docs/attack-timeline.md",
    "docs/mitre-attack-mapping.md",
    "docs/detection-evasion-analysis.md",
    "reports/day-41-incident-report.md",
    "evidence/sha256-manifest.txt"
]

for filename in required_files:
    path = ROOT / filename
    check(f"Required file: {filename}", path.exists() and path.stat().st_size > 0)

print("\n" + "=" * 60)
print("FINAL VALIDATION SUMMARY")
print("=" * 60)
print("Checks failed:", len(failures))

if failures:
    print("Review the failed checks before publishing.")
    sys.exit(1)

print("All structural and evidence-reference checks passed.")
