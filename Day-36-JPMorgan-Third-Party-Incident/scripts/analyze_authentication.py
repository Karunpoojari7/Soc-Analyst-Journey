import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path

INPUT = Path("evidence/identity-logs/identity-events.csv")
OUTPUT = Path("output/authentication-analysis.txt")


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main():
    events = []

    with INPUT.open(newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            row["parsed_time"] = parse_time(row["timestamp_utc"])
            events.append(row)

    events.sort(key=lambda event: event["parsed_time"])

    failures = defaultdict(list)
    successes = defaultdict(list)
    accounts = defaultdict(set)

    for event in events:
        username = event["username"]
        source_ip = event["source_ip"]

        accounts[username].add(source_ip)

        if event["event_type"] != "AUTHENTICATION":
            continue

        key = (username, source_ip)

        if event["result"] == "FAILED":
            failures[key].append(event)
        elif event["result"] == "SUCCESS":
            successes[key].append(event)

    findings = []

    for key, failed_events in failures.items():
        username, source_ip = key

        for success in successes[key]:
            preceding_failures = [
                failed for failed in failed_events
                if 0 <= (
                    success["parsed_time"] - failed["parsed_time"]
                ).total_seconds() <= 600
            ]

            if preceding_failures:
                findings.append(
                    f"SUCCESS AFTER FAILURES: {username} from "
                    f"{source_ip}; failed attempts="
                    f"{len(preceding_failures)}; "
                    f"success time={success['timestamp_utc']}"
                )

    lines = [
        "DAY 36 - AUTHENTICATION INVESTIGATION",
        "Evidence: synthetic training dataset",
        f"Total identity events: {len(events)}",
        "",
        "ACCOUNT SOURCE IP SUMMARY",
    ]

    for username, ips in sorted(accounts.items()):
        lines.append(f"{username}: {', '.join(sorted(ips))}")

    lines.extend(["", "AUTHENTICATION FINDINGS"])

    if findings:
        lines.extend(findings)
    else:
        lines.append("No failed-login-to-success sequences detected.")

    lines.extend([
        "",
        "INVESTIGATION LIMITATIONS",
        "- A successful login does not prove account compromise.",
        "- Source IP changes require contextual investigation.",
        "- MFA challenge success does not prove MFA manipulation.",
        "- All IP addresses are documentation ranges.",
        "- These events are synthetic training evidence.",
    ])

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))
    print(f"\nReport saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
