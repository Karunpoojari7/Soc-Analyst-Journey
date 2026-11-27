import json
import sys
from pathlib import Path

alerts_path = Path("output/infrastructure-alerts.json")
required_rules = {"DET001", "DET002", "DET003", "DET004"}

if not alerts_path.exists():
    print("FAIL: Alert output does not exist.")
    sys.exit(1)

alerts = json.loads(alerts_path.read_text())

if not isinstance(alerts, list):
    print("FAIL: Alert output is not a JSON list.")
    sys.exit(1)

detected_rules = {a.get("rule_id") for a in alerts}
missing = required_rules - detected_rules

print("Total alerts:", len(alerts))
print("Detected rules:", sorted(detected_rules))

if missing:
    print("REVIEW: Rules without alerts:", sorted(missing))
else:
    print("PASS: All four detection rules generated alerts.")

for alert in alerts:
    required = ["rule_id", "severity", "source_ip", "evidence", "description"]
    absent = [key for key in required if key not in alert]

    if absent:
        print("FAIL:", alert.get("rule_id"), "missing", absent)
        sys.exit(1)

print("PASS: Alert schema validation.")
