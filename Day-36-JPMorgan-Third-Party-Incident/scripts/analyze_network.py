import csv
from collections import defaultdict
from pathlib import Path

INPUT = Path("evidence/network-logs/network-events.csv")
OUTPUT = Path("output/network-analysis.txt")

# Training threshold: 1 MB per connection
BYTE_THRESHOLD = 1_000_000


def main():
    events = []

    with INPUT.open(newline="", encoding="utf-8") as file:
        events = list(csv.DictReader(file))

    findings = []
    source_totals = defaultdict(int)

    for event in events:
        source = event["source_ip"]
        destination = event["destination_ip"]
        bytes_sent = int(event["bytes_sent"])

        source_totals[source] += bytes_sent

        if bytes_sent >= BYTE_THRESHOLD:
            findings.append(
                f"HIGH-VOLUME CONNECTION: "
                f"time={event['timestamp_utc']}; "
                f"source={source}; "
                f"destination={destination}; "
                f"port={event['destination_port']}; "
                f"bytes_sent={bytes_sent}"
            )

    lines = [
        "DAY 36 - NETWORK TRAFFIC INVESTIGATION",
        "Evidence: synthetic training dataset",
        f"Network events reviewed: {len(events)}",
        "",
        "TOTAL OUTBOUND BYTES BY SOURCE",
    ]

    for source, total in sorted(source_totals.items()):
        lines.append(f"{source}: {total:,} bytes")

    lines.extend(["", "HIGH-VOLUME CONNECTION FINDINGS"])

    if findings:
        lines.extend(findings)
    else:
        lines.append("No connections exceeded the training threshold.")

    lines.extend([
        "",
        "INVESTIGATION LIMITATIONS",
        "- Byte volume alone does not prove data exfiltration.",
        "- Destination ownership has not been established.",
        "- Port 443 indicates the destination port, not verified TLS content.",
        "- Network records do not prove that customer data was transferred.",
        "- All IP addresses are documentation ranges.",
        "- The dataset is synthetic training evidence.",
    ])

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )

    print("\n".join(lines))
    print(f"\nReport saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
