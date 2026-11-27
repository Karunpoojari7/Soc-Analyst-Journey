import json
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

ROOT = Path(".")
REPORT = ROOT / "reports/day-41-incident-report.md"

def load_json(path):
    path = ROOT / path
    if not path.exists():
        raise SystemExit(f"Required file missing: {path}")
    return json.loads(path.read_text())

def load_jsonl(path):
    path = ROOT / path
    if not path.exists():
        raise SystemExit(f"Required file missing: {path}")
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]

auth = load_jsonl("logs/raw/authentication.jsonl")
api = load_jsonl("logs/raw/api-access.jsonl")
firewall = load_jsonl("logs/raw/firewall.jsonl")

alerts = load_json("output/infrastructure-alerts.json")
incidents = load_json("output/correlated-incidents.json")
timeline_data = load_json("output/incident-timeline.json")

all_events = auth + api + firewall
rule_counts = Counter(a.get("rule_id", "UNKNOWN") for a in alerts)
severity_counts = Counter(a.get("severity", "UNKNOWN") for a in alerts)

source_counts = Counter(
    event.get("source_ip", "UNKNOWN") for event in all_events
)

timeline = timeline_data.get("timeline", [])
timestamps = [e.get("timestamp") for e in timeline if e.get("timestamp")]

def safe(value):
    return str(value).replace("|", "\\|").replace("\n", " ")

lines = [
    "# Day 41 — Critical Infrastructure Security Investigation",
    "",
    "## 1. Case information",
    "",
    "- Case ID: DAY41-CASE-001",
    "- Investigation: AI-agent-associated activity hypotheses",
    "- Environment: Fictional electricity utility",
    "- Dataset: Synthetic security telemetry",
    f"- Report generated (UTC): {datetime.now(timezone.utc).isoformat()}",
    "",
    "## 2. Executive summary",
    "",
    "This investigation analyses synthetic authentication, API and firewall",
    "events to identify suspicious activity and correlate evidence across",
    "multiple security data sources.",
    "",
    "This is a controlled training scenario, not an investigation of an",
    "actual Swiss victim or production critical infrastructure.",
    "",
    "## 3. Dataset overview",
    "",
    "| Log source | Events |",
    "|---|---:|",
    f"| Authentication | {len(auth)} |",
    f"| API access | {len(api)} |",
    f"| Firewall | {len(firewall)} |",
    f"| **Total** | **{len(all_events)}** |",
    "",
    "## 4. Source IP distribution",
    "",
    "| Source IP | Event count |",
    "|---|---:|",
]

for ip, count in source_counts.most_common():
    lines.append(f"| {safe(ip)} | {count} |")

lines += [
    "",
    "## 5. Detection results",
    "",
    f"- Total generated alerts: {len(alerts)}",
    "",
    "| Detection rule | Alert count |",
    "|---|---:|",
]

for rule, count in sorted(rule_counts.items()):
    lines.append(f"| {safe(rule)} | {count} |")

lines += [
    "",
    "### Severity distribution",
    "",
    "| Severity | Alert count |",
    "|---|---:|",
]

for severity, count in sorted(severity_counts.items()):
    lines.append(f"| {safe(severity)} | {count} |")

lines += [
    "",
    "## 6. Correlated incidents",
    "",
    f"Total correlated incident records: {len(incidents)}",
    "",
]

if incidents:
    lines += [
        "| Incident | Source IP | Severity | Rules | Evidence count |",
        "|---|---|---|---|---:|",
    ]
    for incident in incidents:
        lines.append(
            f"| {safe(incident.get('incident_id'))} "
            f"| {safe(incident.get('source_ip'))} "
            f"| {safe(incident.get('severity'))} "
            f"| {safe(', '.join(incident.get('detection_rules', [])))} "
            f"| {len(incident.get('evidence_ids', []))} |"
        )
else:
    lines.append("No correlated incident records were generated.")

lines += [
    "",
    "## 7. Timeline overview",
    "",
    f"- Timeline events: {len(timeline)}",
    f"- Earliest timestamp: {min(timestamps) if timestamps else 'Unavailable'}",
    f"- Latest timestamp: {max(timestamps) if timestamps else 'Unavailable'}",
    "",
    "See `docs/attack-timeline.md` for the event-by-event timeline.",
    "",
    "## 8. Investigation assessment",
    "",
    "The detection rules identify suspicious patterns in the supplied",
    "synthetic telemetry. Each alert requires analyst review and validation",
    "against account ownership, authorised activity, network architecture",
    "and relevant endpoint or application evidence.",
    "",
    "A shared source IP or chronological sequence does not independently",
    "prove that events were performed by the same operator.",
    "",
    "## 9. AI-agent attribution limitations",
    "",
    "The available logs do not establish whether an AI agent was involved.",
    "Additional evidence would be required, including automation identities,",
    "agent execution audit trails, endpoint process telemetry and identity",
    "provider records.",
    "",
    "## 10. Impact assessment",
    "",
    "No real operational impact can be inferred from this synthetic dataset.",
    "A connection attempt does not prove successful access to an industrial",
    "control system.",
    "",
    "## 11. Recommendations",
    "",
    "- Enforce MFA for privileged accounts.",
    "- Monitor repeated authentication failures and unusual login success.",
    "- Restrict administrative API access.",
    "- Apply network segmentation between IT and OT environments.",
    "- Monitor industrial protocol access attempts.",
    "- Preserve endpoint, identity and automation audit logs.",
    "- Validate alerts against authorised maintenance and administrative activity.",
    "",
    "## 12. Evidence integrity",
    "",
    "SHA-256 manifest: `evidence/sha256-manifest.txt`.",
    "Run `sha256sum -c evidence/sha256-manifest.txt` to verify the listed files.",
    "",
    "## 13. Analyst conclusion",
    "",
    "This lab demonstrates a synthetic multi-source SOC investigation workflow.",
    "The final conclusions must remain limited to the events and detections",
    "actually present in the generated dataset. AI-agent attribution and",
    "real-world compromise are not established.",
    "",
]

REPORT.write_text("\n".join(lines))
print("Report generated:", REPORT)
print("Raw events:", len(all_events))
print("Alerts:", len(alerts))
print("Correlated incidents:", len(incidents))
print("Timeline events:", len(timeline))
