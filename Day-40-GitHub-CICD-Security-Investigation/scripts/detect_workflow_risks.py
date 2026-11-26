import re
import json
from pathlib import Path
from datetime import datetime, timezone

WORKFLOW_DIR = Path(".github/workflows")
ALERT_FILE = Path("output/ci-cd-alerts.json")

alerts = []

def add_alert(file, rule, severity, evidence, description):
    alerts.append({
        "alert_id": f"D40-CI-{len(alerts) + 1:03d}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file": str(file),
        "rule": rule,
        "severity": severity,
        "evidence": evidence,
        "description": description
    })

for file in WORKFLOW_DIR.glob("*"):
    if file.suffix not in (".yml", ".yaml"):
        continue

    content = file.read_text(errors="replace")

    if re.search(r"permissions\s*:\s*write-all", content):
        add_alert(
            file,
            "CI001",
            "HIGH",
            "permissions: write-all",
            "Workflow grants broad write permissions."
        )

    if re.search(r"pull_request_target\s*:", content):
        add_alert(
            file,
            "CI002",
            "HIGH",
            "pull_request_target",
            "Review whether untrusted pull-request code can execute."
        )

    for line in content.splitlines():
        match = re.search(r"uses:\s*([^\s#]+)", line)

        if not match:
            continue

        reference = match.group(1)

        if re.search(r"@(v\d+|main|master)$", reference):
            add_alert(
                file,
                "CI003",
                "MEDIUM",
                reference,
                "Action uses a floating reference instead of a full commit SHA."
            )

    if re.search(r"^\s+[A-Za-z0-9_-]+:\s*write\s*$",
                 content, re.MULTILINE):
        add_alert(
            file,
            "CI004",
            "MEDIUM",
            "Write permission detected",
            "Review whether this write permission is necessary."
        )

ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)
ALERT_FILE.write_text(json.dumps(alerts, indent=2))

print("CI/CD workflow analysis completed")
print(f"Workflows scanned: {len(list(WORKFLOW_DIR.glob('*.yml'))) + len(list(WORKFLOW_DIR.glob('*.yaml')))}")
print(f"Alerts generated: {len(alerts)}")
print(f"Output: {ALERT_FILE}")
