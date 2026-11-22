import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path

IDENTITY_FILE = Path("evidence/identity-logs/identity-events.csv")
DATA_FILE = Path("evidence/vendor-logs/customer-data-access.csv")
OUTPUT_FILE = Path("output/customer-data-analysis.txt")

EXPORT_THRESHOLD = 1000


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_csv(path):
    with path.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def main():
    identity_events = load_csv(IDENTITY_FILE)
    data_events = load_csv(DATA_FILE)

    successful_logins = {}

    for event in identity_events:
        if (
            event["event_type"] == "AUTHENTICATION"
            and event["result"] == "SUCCESS"
        ):
            successful_logins[
                (event["username"], event["source_ip"])
            ] = parse_time(event["timestamp_utc"])

    findings = []
    totals = defaultdict(int)

    for event in data_events:
        username = event["username"]
        source_ip = event["source_ip"]
        action = event["action"]
        records = int(event["records_accessed"])
        event_time = parse_time(event["timestamp_utc"])

        totals[(username, source_ip)] += records

        login_time = successful_logins.get((username, source_ip))

        if login_time and event_time >= login_time:
            if action == "EXPORT" and records >= EXPORT_THRESHOLD:
                findings.append(
                    f"HIGH-VOLUME EXPORT: account={username}; "
                    f"source={source_ip}; records={records}; "
                    f"time={event['timestamp_utc']}"
                )

    lines = [
        "DAY 36 - CUSTOMER DATA ACCESS INVESTIGATION",
        "Evidence: synthetic training dataset",
        f"Identity events reviewed: {len(identity_events)}",
        f"Data access events reviewed: {len(data_events)}",
        "",
        "ACTIVITY VOLUME BY ACCOUNT AND SOURCE",
    ]

    for (username, source_ip), total in sorted(totals.items()):
        lines.append(
            f"{username} | {source_ip} | "
            f"{total} record-activity units"
        )

    lines.extend(["", "HIGH-VOLUME EXPORT FINDINGS"])

    if findings:
        lines.extend(findings)
    else:
        lines.append("No high-volume exports detected.")

    lines.extend([
        "",
        "INVESTIGATION LIMITATIONS",
        "- Record counts represent logged activity, not unique customers.",
        "- READ and EXPORT counts may overlap.",
        "- A large export is not proof of unauthorized exfiltration.",
        "- Shared source IPs do not prove the same person operated accounts.",
        "- The dataset is synthetic and does not represent real vendor logs.",
    ])

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )

    print("\n".join(lines))
    print(f"\nReport saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
