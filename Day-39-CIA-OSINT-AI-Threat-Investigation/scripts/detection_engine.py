import json
from pathlib import Path
from collections import Counter

BASE = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE / "output"

INPUT_FILES = [
    "authentication-alerts.json",
    "api-alerts.json",
    "cloud-alerts.json",
    "endpoint-network-alerts.json"
]

SEVERITY_PRIORITY = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

all_alerts = []
missing_files = []

for filename in INPUT_FILES:
    path = OUTPUT_DIR / filename

    if not path.exists():
        missing_files.append(filename)
        continue

    try:
        alerts = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        raise SystemExit(f"Invalid JSON file: {filename}")

    if not isinstance(alerts, list):
        raise SystemExit(f"Expected a JSON list in {filename}")

    for alert in alerts:
        alert["source_file"] = filename
        all_alerts.append(alert)

if missing_files:
    print("Missing detection outputs:")
    for filename in missing_files:
        print("-", filename)
    raise SystemExit("Run the earlier detection labs first.")

all_alerts.sort(
    key=lambda x: SEVERITY_PRIORITY.get(x.get("severity", "LOW"), 0),
    reverse=True
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

output_file = OUTPUT_DIR / "detection-alerts.json"
output_file.write_text(
    json.dumps(all_alerts, indent=2),
    encoding="utf-8"
)

counts = Counter(
    alert.get("severity", "UNKNOWN")
    for alert in all_alerts
)

print("=" * 55)
print("DAY 39 - UNIFIED SOC DETECTION ENGINE")
print("=" * 55)

print("Total alerts:", len(all_alerts))

print("\nSeverity summary:")
for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    print(f"{severity}: {counts.get(severity, 0)}")

print("\nConsolidated alerts:")
for alert in all_alerts:
    print(
        f"[{alert.get('severity')}] "
        f"{alert.get('alert_id')} | "
        f"{alert.get('username', alert.get('actor', 'N/A'))}"
    )

print("\nOutput:", output_file.relative_to(BASE))
print("Detection consolidation completed.")
