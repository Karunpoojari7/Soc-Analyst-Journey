import csv
from pathlib import Path
from datetime import datetime

OUTPUT = Path("timeline/correlated-timeline.csv")

DATASETS = {
    "evidence/vendor-logs/vendor-access.csv": "VENDOR",
    "evidence/identity-logs/identity-events.csv": "IDENTITY",
    "evidence/vendor-logs/customer-data-access.csv": "CUSTOMER_DATA",
    "evidence/network-logs/network-events.csv": "NETWORK",
    "evidence/endpoint-logs/endpoint-events.csv": "ENDPOINT",
}


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def describe_event(source, row):
    if source == "VENDOR":
        return (
            f"{row['event_type']} {row['result']} "
            f"on {row['device']}"
        )

    if source == "IDENTITY":
        return (
            f"{row['event_type']} {row['result']}"
        )

    if source == "CUSTOMER_DATA":
        return (
            f"{row['action']} {row['records_accessed']} "
            f"records ({row['result']})"
        )

    if source == "NETWORK":
        return (
            f"Connection to {row['destination_ip']}:"
            f"{row['destination_port']} "
            f"sent {row['bytes_sent']} bytes"
        )

    if source == "ENDPOINT":
        return (
            f"{row['event_type']} - {row['process_name']} "
            f"({row['severity']})"
        )

    return "Unknown event"


def main():
    timeline = []

    for filename, source in DATASETS.items():
        path = Path(filename)

        with path.open(newline="", encoding="utf-8") as file:
            for row in csv.DictReader(file):
                timeline.append({
                    "timestamp_utc": row["timestamp_utc"],
                    "source": source,
                    "event_id": row["event_id"],
                    "username": row.get("username", ""),
                    "source_ip": row.get("source_ip", ""),
                    "event_description": describe_event(source, row),
                })

    timeline.sort(
        key=lambda event: parse_time(event["timestamp_utc"])
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "timestamp_utc",
        "source",
        "event_id",
        "username",
        "source_ip",
        "event_description",
    ]

    with OUTPUT.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(timeline)

    print("DAY 36 - CORRELATED INCIDENT TIMELINE")
    print("Evidence: synthetic training datasets")
    print(f"Total correlated events: {len(timeline)}")
    print()

    for event in timeline:
        print(
            f"{event['timestamp_utc']} | "
            f"{event['source']} | "
            f"{event['event_id']} | "
            f"{event['username'] or 'N/A'} | "
            f"{event['event_description']}"
        )

    print(f"\nTimeline saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
