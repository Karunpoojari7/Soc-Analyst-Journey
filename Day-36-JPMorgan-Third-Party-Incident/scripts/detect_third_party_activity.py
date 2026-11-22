import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

IDENTITY = Path("evidence/identity-logs/identity-events.csv")
DATA_ACCESS = Path("evidence/vendor-logs/customer-data-access.csv")
NETWORK = Path("evidence/network-logs/network-events.csv")
ENDPOINT = Path("evidence/endpoint-logs/endpoint-events.csv")
OUTPUT = Path("output/detection-alerts.json")

FAILED_LOGIN_THRESHOLD = 2
EXPORT_THRESHOLD = 1000
NETWORK_THRESHOLD = 1_000_000

REVIEW_PROCESSES = {
    "powershell.exe",
    "archive-tool.exe",
    "unknown.exe",
}


def load_csv(path):
    with path.open(newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def create_alert(rule, severity, title, description, evidence):
    return {
        "rule_id": rule,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "status": "REQUIRES_ANALYST_REVIEW",
        "evidence_type": "SYNTHETIC_TRAINING_DATA",
    }


def main():
    identity = load_csv(IDENTITY)
    data_access = load_csv(DATA_ACCESS)
    network = load_csv(NETWORK)
    endpoint = load_csv(ENDPOINT)

    alerts = []
    suspicious_sources = set()

    failures = defaultdict(list)
    successes = defaultdict(list)

    # Rule 1: Failed authentication followed by success.
    for event in identity:
        if event["event_type"] != "AUTHENTICATION":
            continue

        key = (event["username"], event["source_ip"])

        if event["result"] == "FAILED":
            failures[key].append(event)
        elif event["result"] == "SUCCESS":
            successes[key].append(event)

    for key, failed_events in failures.items():
        username, source_ip = key

        for success in successes[key]:
            preceding = [
                failed for failed in failed_events
                if 0 <= (
                    parse_time(success["timestamp_utc"])
                    - parse_time(failed["timestamp_utc"])
                ).total_seconds() <= 600
            ]

            if len(preceding) >= FAILED_LOGIN_THRESHOLD:
                suspicious_sources.add(source_ip)

                alerts.append(create_alert(
                    "D36-AUTH-001",
                    "MEDIUM",
                    "Repeated failed logins followed by success",
                    f"{username} had {len(preceding)} failed attempts "
                    f"followed by success from {source_ip}.",
                    {
                        "username": username,
                        "source_ip": source_ip,
                        "failed_event_ids": [
                            event["event_id"] for event in preceding
                        ],
                        "success_event_id": success["event_id"],
                    }
                ))

    # Rule 2: Privilege grant from suspicious source.
    for event in identity:
        if (
            event["event_type"] == "ROLE_CHANGE"
            and event["result"] == "PRIVILEGE_GRANTED"
            and event["source_ip"] in suspicious_sources
        ):
            alerts.append(create_alert(
                "D36-PRIV-001",
                "HIGH",
                "Privilege grant from suspicious source",
                "Privilege grant originated from a source associated "
                "with suspicious authentication activity.",
                {
                    "event_id": event["event_id"],
                    "username": event["username"],
                    "source_ip": event["source_ip"],
                    "timestamp_utc": event["timestamp_utc"],
                }
            ))

    # Rule 3: High-volume customer data export.
    for event in data_access:
        if (
            event["action"] == "EXPORT"
            and int(event["records_accessed"]) >= EXPORT_THRESHOLD
        ):
            alerts.append(create_alert(
                "D36-DATA-001",
                "HIGH",
                "High-volume customer data export",
                "Export exceeded the configured training threshold.",
                {
                    "event_id": event["event_id"],
                    "username": event["username"],
                    "source_ip": event["source_ip"],
                    "records_accessed": int(event["records_accessed"]),
                    "timestamp_utc": event["timestamp_utc"],
                }
            ))

    # Rule 4: Large outbound network connection.
    for event in network:
        if int(event["bytes_sent"]) >= NETWORK_THRESHOLD:
            alerts.append(create_alert(
                "D36-NET-001",
                "HIGH",
                "Large outbound network connection",
                "Outbound connection exceeded the training threshold. "
                "Data exfiltration is not established.",
                {
                    "event_id": event["event_id"],
                    "source_ip": event["source_ip"],
                    "destination_ip": event["destination_ip"],
                    "destination_port": int(event["destination_port"]),
                    "bytes_sent": int(event["bytes_sent"]),
                    "timestamp_utc": event["timestamp_utc"],
                }
            ))

    # Rule 5: Endpoint process review.
    for event in endpoint:
        if event["process_name"].lower() in REVIEW_PROCESSES:
            alerts.append(create_alert(
                "D36-ENDPOINT-001",
                "MEDIUM",
                "Endpoint process requires investigation",
                "Process requires analyst review; its name alone "
                "does not prove malicious execution.",
                {
                    "event_id": event["event_id"],
                    "hostname": event["hostname"],
                    "username": event["username"],
                    "process_name": event["process_name"],
                    "event_type": event["event_type"],
                    "timestamp_utc": event["timestamp_utc"],
                }
            ))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(alerts, indent=4) + "\n",
        encoding="utf-8"
    )

    print("DAY 36 - THIRD-PARTY ACTIVITY DETECTION")
    print("Evidence: synthetic training datasets")
    print(f"Total alerts generated: {len(alerts)}")

    for alert in alerts:
        print(
            f"[{alert['severity']}] "
            f"{alert['rule_id']} - {alert['title']}"
        )

    print(f"\nAlerts saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
