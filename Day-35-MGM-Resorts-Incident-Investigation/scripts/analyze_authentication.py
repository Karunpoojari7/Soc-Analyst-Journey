import csv
from collections import Counter, defaultdict
from pathlib import Path

SOURCE = Path("evidence/identity/authentication.csv")
OUTPUT = Path("output/authentication-analysis.txt")

with SOURCE.open(newline="") as file:
    events = list(csv.DictReader(file))

counts = Counter(event["event_type"] for event in events)
failures = defaultdict(list)

for event in events:
    if event["result"] == "FAILURE":
        failures[event["username"]].append(event)

findings = []

for event in events:
    if event["event_type"] in {
        "MFA_REGISTRATION",
        "PRIVILEGE_CHANGE",
        "ADMIN_ACCESS",
    }:
        findings.append(event)

lines = [
    "DAY 35 - AUTHENTICATION INVESTIGATION",
    "=" * 45,
    f"Total authentication events: {len(events)}",
    "",
    "EVENT SUMMARY",
]

for event_type, count in sorted(counts.items()):
    lines.append(f"{event_type}: {count}")

lines.append("")
lines.append("FAILED AUTHENTICATION ATTEMPTS")

for username, records in sorted(failures.items()):
    lines.append(f"{username}: {len(records)}")

lines.append("")
lines.append("SUSPICIOUS EVENT REVIEW")

for event in findings:
    lines.append(
        f'{event["timestamp"]} | {event["username"]} | '
        f'{event["event_type"]} | {event["source_ip"]}'
    )

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text("\n".join(lines) + "\n")

print("\n".join(lines))
print(f"\nReport saved: {OUTPUT}")
