import csv
import json
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"
TIMELINE_FILE = BASE_DIR / "timeline" / "correlated-timeline.csv"
ALERT_FILE = OUTPUT_DIR / "detection-alerts.json"
REPORT_FILE = OUTPUT_DIR / "FINAL-SOC-INVESTIGATION-REPORT.md"

def read_csv(path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))

def read_json(path):
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)

timeline = read_csv(TIMELINE_FILE)
alerts_data = read_json(ALERT_FILE)

if alerts_data is None:
    print("[ERROR] Unified detection alerts are missing.")
    print("Run Lab 7 before generating this report.")
    raise SystemExit(1)

if isinstance(alerts_data, dict):
    alerts = alerts_data.get("alerts", [])
elif isinstance(alerts_data, list):
    alerts = alerts_data
else:
    print("[ERROR] Unexpected alert JSON structure.")
    raise SystemExit(1)

severity_counts = {}
for alert in alerts:
    severity = str(alert.get("severity", "UNKNOWN")).upper()
    severity_counts[severity] = severity_counts.get(severity, 0) + 1

source_counts = {}
for event in timeline:
    source = event.get("source", "UNKNOWN")
    source_counts[source] = source_counts.get(source, 0) + 1

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

lines = [
    "# Final SOC Investigation Report",
    "",
    "## 1. Investigation Overview",
    "",
    "**Case:** Day 39 — CIA / OSINT System Security Investigation",
    "**Environment:** Synthetic educational SOC simulation",
    f"**Report generated:** {generated_at}",
    "**Investigation type:** Multi-source security event analysis",
    "",
    "This report documents the analysis of synthetic identity, API, cloud,",
    "endpoint and network events. It is not based on actual CIA or ODNI",
    "telemetry and does not reconstruct a confirmed real-world intrusion.",
    "",
    "## 2. Evidence Summary",
    "",
    f"- Timeline events processed: {len(timeline)}",
    f"- Detection alerts consolidated: {len(alerts)}",
    "",
    "### Events by source",
    ""
]

for source, count in sorted(source_counts.items()):
    lines.append(f"- {source}: {count}")

lines += [
    "",
    "## 3. Detection Summary",
    "",
    "### Alerts by severity",
    ""
]

for severity, count in sorted(severity_counts.items()):
    lines.append(f"- {severity}: {count}")

lines += [
    "",
    "### Alert details",
    ""
]

for alert in alerts:
    lines.append(
        f"- **{alert.get('rule_id', 'Unknown rule')}** — "
        f"{alert.get('severity', 'Unknown severity')}: "
        f"{alert.get('description', alert.get('message', 'No description provided'))}"
    )

lines += [
    "",
    "## 4. Key Investigative Observations",
    "",
    "- Repeated authentication failures followed by a successful login "
    "require account and session review.",
    "- Privilege or IAM role modifications require verification against "
    "approved change records.",
    "- Rapid API requests and large export requests require authorization "
    "and application-level review.",
    "- Python and curl process activity may warrant endpoint investigation.",
    "- Large outbound network transfers warrant destination and process "
    "attribution checks.",
    "",
    "These are investigative leads from synthetic data, not proof of a "
    "successful compromise or data theft.",
    "",
    "## 5. Evidence Limitations",
    "",
    "- All evidence in this exercise is synthetic.",
    "- Endpoint events do not establish a reliable source-IP relationship.",
    "- Network events do not identify the responsible process.",
    "- The exact contents or sensitivity of exported records are unknown.",
    "- The dataset does not prove that data exfiltration occurred.",
    "- The exercise does not establish an attacker identity or attribution.",
    "- The reported association with ARTEX is not demonstrated by this dataset.",
    "",
    "## 6. Recommended SOC Response",
    "",
    "1. Preserve original logs and document evidence collection.",
    "2. Validate suspicious authentication activity with identity records.",
    "3. Review privilege changes against approved administrative requests.",
    "4. Inspect API export activity and relevant application audit records.",
    "5. Review cloud storage access and export authorization.",
    "6. Investigate endpoint process ancestry and execution context.",
    "7. Correlate network transfers with endpoint and cloud telemetry.",
    "8. Escalate only when corroborating evidence supports escalation.",
    "",
    "## 7. Validation Status",
    "",
    "Lab 9 benign-test execution has not been independently confirmed. "
    "Validation remains PENDING until the test output is reviewed.",
    "",
    "## 8. Final Assessment",
    "",
    "The synthetic dataset contains multiple security signals across "
    "identity, API, cloud, endpoint and network sources. These signals "
    "justify further investigation in this training scenario.",
    "",
    "No confirmed real-world intrusion, successful exfiltration, attacker "
    "identity or connection to an actual CIA/ODNI incident is established.",
    "",
    "---",
    "",
    "**Prepared as:** Day 39 SOC Analyst Learning Portfolio",
    "",
    "**Classification:** Educational synthetic investigation — not an "
    "official intelligence or incident report."
]

REPORT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("[OK] Final SOC report generated.")
print(f"[INFO] Timeline events: {len(timeline)}")
print(f"[INFO] Alerts: {len(alerts)}")
print(f"[SAVED] {REPORT_FILE}")
