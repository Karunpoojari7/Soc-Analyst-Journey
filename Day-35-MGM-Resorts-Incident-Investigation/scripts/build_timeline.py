import csv
from pathlib import Path

FILES = [
    Path("evidence/identity/authentication.csv"),
    Path("evidence/endpoint/endpoint-events.csv"),
    Path("evidence/network/network-events.csv"),
]

timeline = []

for path in FILES:
    with path.open(newline="") as file:
        for event in csv.DictReader(file):
            event["evidence_source"] = str(path)
            timeline.append(event)

timeline.sort(
    key=lambda event: (
        event["timestamp"],
        event["event_id"]
    )
)

OUTPUT = Path("timeline/correlated-timeline.csv")
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

fields = ["timestamp", "event_id", "evidence_source", "event_details"]

with OUTPUT.open("w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()

    for event in timeline:
        details = " | ".join(
            f"{key}={value}"
            for key, value in event.items()
            if key not in {
                "timestamp",
                "event_id",
                "evidence_source",
            }
        )

        writer.writerow({
            "timestamp": event["timestamp"],
            "event_id": event["event_id"],
            "evidence_source": event["evidence_source"],
            "event_details": details,
        })

print(f"Total correlated events: {len(timeline)}")
print(f"Timeline saved: {OUTPUT}")
