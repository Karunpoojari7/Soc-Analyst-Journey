import json
from pathlib import Path

alerts_file = Path("output/github-correlation-alerts-v2.json")
timeline_file = Path("output/incident-timeline.json")
report_file = Path("output/incident-investigation-report.md")

for path in (alerts_file, timeline_file):
    if not path.exists():
        raise SystemExit(f"Missing required file: {path}")

alerts_data = json.loads(alerts_file.read_text())
timeline = json.loads(timeline_file.read_text())

if isinstance(alerts_data, dict):
    alerts = alerts_data.get("alerts", [])
else:
    alerts = alerts_data

if not alerts:
    raise SystemExit("No correlated alerts found. Report not generated.")

if not timeline:
    raise SystemExit("Timeline is empty. Report not generated.")

lines = [
    "# SOC Incident Investigation Report",
    "",
    "## 1. Case Overview",
    "",
    "- **Case:** Day 40 — GitHub CI/CD Security Investigation",
    "- **Dataset:** Synthetic training audit events",
    "- **Detection:** Ordered GitHub event correlation",
    "- **Assessment:** Suspicious activity requiring analyst validation",
    "",
    "## 2. Detection Summary",
    "",
    f"- Correlated alerts: {len(alerts)}",
    f"- Timeline events: {len(timeline)}",
    "",
]

for alert in alerts:
    lines.extend([
        f"### {alert.get('alert_id', 'Unknown incident')}",
        "",
        f"- **Severity:** {alert.get('severity', 'Not specified')}",
        f"- **Actor:** {alert.get('actor', 'Not specified')}",
        f"- **Repository:** {alert.get('repository', 'Not specified')}",
        f"- **Source IP:** {alert.get('source_ip', 'Not specified')}",
        f"- **Duration:** {alert.get('sequence_duration_seconds', 'Not specified')} seconds",
        f"- **Event IDs:** {', '.join(alert.get('correlated_events', []))}",
        "",
        alert.get(
            "assessment",
            "Correlated suspicious sequence; analyst validation required."
        ),
        "",
    ])

lines.extend([
    "## 3. Event Timeline",
    "",
    "| Timestamp (UTC) | Event ID | Actor | Action | Source IP |",
    "|---|---|---|---|---|",
])

for event in timeline:
    lines.append(
        f"| {event.get('timestamp', '')} "
        f"| {event.get('event_id', '')} "
        f"| {event.get('actor', '')} "
        f"| {event.get('action', '')} "
        f"| {event.get('source_ip', '')} |"
    )

lines.extend([
    "",
    "## 4. Analyst Assessment",
    "",
    "The synthetic dataset contains a correlated sequence of token creation, "
    "repository permission modification, workflow modification, and workflow "
    "execution. The sequence is a detection lead, not proof of unauthorized "
    "access or compromise.",
    "",
    "## 5. Recommended Defensive Actions",
    "",
    "1. Verify the identity and authorization of the actor.",
    "2. Review token creation details, scopes, and subsequent use.",
    "3. Validate repository permission changes against approved change records.",
    "4. Inspect workflow changes and compare them with trusted versions.",
    "5. Review workflow execution logs and any resulting deployments.",
    "6. Revoke suspicious credentials and contain affected workflows if "
    "unauthorized activity is confirmed.",
    "",
    "## 6. Evidence and Limitations",
    "",
    "- Evidence is synthetic and generated for this training lab.",
    "- No real 1Password, GitHub customer, or production telemetry was analysed.",
    "- The source IP addresses belong to documentation ranges used in examples.",
    "- No conclusion about a real-world compromise can be drawn from this lab.",
    "",
    "## 7. Conclusion",
    "",
    "The correlation rule successfully identified the configured suspicious "
    "event sequence in the synthetic dataset. Further identity, authorization, "
    "and workflow evidence would be required to confirm an actual incident.",
    "",
])

report_file.parent.mkdir(parents=True, exist_ok=True)
report_file.write_text("\n".join(lines))

print(f"Report generated: {report_file}")
print(f"Alerts included: {len(alerts)}")
print(f"Timeline events included: {len(timeline)}")
