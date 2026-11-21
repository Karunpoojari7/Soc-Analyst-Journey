import csv
from collections import defaultdict
from pathlib import Path
from datetime import datetime

SOURCE = Path("evidence/identity/authentication.csv")
OUTPUT = Path("output/identity-correlation.txt")

with SOURCE.open(newline="") as file:
    events = list(csv.DictReader(file))

accounts = defaultdict(list)

for event in events:
    accounts[event["username"]].append(event)

findings = []

for username, records in accounts.items():
    records.sort(key=lambda item: item["timestamp"])

    failed = [
        event for event in records
        if event["event_type"] == "LOGIN"
        and event["result"] == "FAILURE"
    ]

    successful = [
        event for event in records
        if event["event_type"] == "LOGIN"
        and event["result"] == "SUCCESS"
    ]

    mfa = [
        event for event in records
        if event["event_type"] == "MFA_REGISTRATION"
    ]

    privilege = [
        event for event in records
        if event["event_type"] == "PRIVILEGE_CHANGE"
    ]

    if failed and successful and mfa and privilege:
        first_success = successful[0]
        first_mfa = mfa[0]
        first_privilege = privilege[0]

        source_changed = (
            failed[-1]["source_ip"] != first_success["source_ip"]
        )

        sequence_valid = (
            first_success["timestamp"]
            <= first_mfa["timestamp"]
            <= first_privilege["timestamp"]
        )

        if source_changed and sequence_valid:
            findings.append({
                "username": username,
                "failed_count": len(failed),
                "successful_login": first_success["timestamp"],
                "source_ip": first_success["source_ip"],
                "mfa_registration": first_mfa["timestamp"],
                "privilege_change": first_privilege["timestamp"],
            })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w") as report:
    report.write("IDENTITY EVENT CORRELATION REPORT\n")
    report.write("=" * 45 + "\n")

    if not findings:
        report.write("No matching event sequence detected.\n")

    for finding in findings:
        report.write(
            f'\nAccount: {finding["username"]}\n'
            f'Failed logins: {finding["failed_count"]}\n'
            f'Successful login: {finding["successful_login"]}\n'
            f'Source IP: {finding["source_ip"]}\n'
            f'MFA registration: {finding["mfa_registration"]}\n'
            f'Privilege change: {finding["privilege_change"]}\n'
            "Assessment: Suspicious identity activity requiring investigation.\n"
        )

print(OUTPUT.read_text() if OUTPUT.exists() else "Correlation complete.")
print(f"Saved report: {OUTPUT}")
