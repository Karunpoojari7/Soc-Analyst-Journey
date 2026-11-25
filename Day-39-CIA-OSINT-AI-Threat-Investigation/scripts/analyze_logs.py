import csv
from pathlib import Path
from collections import Counter

BASE = Path(__file__).resolve().parent.parent
EVIDENCE = BASE / "evidence"

total_events = 0
source_counts = Counter()
ip_counts = Counter()
user_counts = Counter()
findings = []

for file in sorted(EVIDENCE.rglob("*.csv")):
    source = file.parent.name

    with file.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    source_counts[source] += len(rows)
    total_events += len(rows)

    for row in rows:
        ip = row.get("source_ip")
        if ip:
            ip_counts[ip] += 1

        user = row.get("username") or row.get("actor")
        if user:
            user_counts[user] += 1

        if row.get("status") == "failure":
            findings.append(
                f"Authentication failure: {user} from {ip}"
            )

        if row.get("event_type") in (
            "privilege_change",
            "iam_role_change"
        ):
            findings.append(
                f"Privilege-related event: {row.get('event_id')} "
                f"by {user}"
            )

        if row.get("event_type") == "storage_export":
            findings.append(
                f"Cloud storage export: {row.get('event_id')}"
            )

        if row.get("bytes_out") and int(row["bytes_out"]) > 10_000_000:
            findings.append(
                f"Large outbound transfer: {row.get('event_id')} "
                f"({row['bytes_out']} bytes)"
            )

print("=" * 55)
print("DAY 39 - MULTI-SOURCE SOC LOG ANALYSIS")
print("=" * 55)

print(f"\nTotal events analysed: {total_events}")

print("\nEvents by source:")
for source, count in sorted(source_counts.items()):
    print(f"  {source}: {count}")

print("\nEvents by source IP:")
for ip, count in ip_counts.most_common():
    print(f"  {ip}: {count}")

print("\nEvents by account:")
for user, count in user_counts.most_common():
    print(f"  {user}: {count}")

print("\nInvestigation findings:")
for finding in findings:
    print(f"  [REVIEW] {finding}")

print("\nAnalysis completed.")
print("Findings are investigative leads, not proof of compromise.")
