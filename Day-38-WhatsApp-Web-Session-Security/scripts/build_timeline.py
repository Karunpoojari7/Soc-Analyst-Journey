import csv
from pathlib import Path
from datetime import datetime

BASE = Path(__file__).resolve().parents[1]

SOURCES = {
    "browser": "evidence/browser-logs/browser-events.csv",
    "session": "evidence/session-logs/session-lifecycle.csv",
    "messaging": "evidence/messaging-audit/account-activity.csv",
}

events = []

for source, relative_path in SOURCES.items():
    path = BASE / relative_path

    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            events.append({
                "timestamp": row["timestamp"],
                "source": source,
                "user_id": row["user_id"],
                "device_id": row["device_id"],
                "event": row["event"],
                "details": row.get("details", "")
            })

events.sort(
    key=lambda x: datetime.fromisoformat(x["timestamp"])
)

output = BASE / "timeline/correlated-timeline.csv"
output.parent.mkdir(parents=True, exist_ok=True)

with output.open("w", newline="", encoding="utf-8") as f:
    fields = [
        "timestamp", "source", "user_id",
        "device_id", "event", "details"
    ]
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(events)

print("===== CORRELATED INVESTIGATION TIMELINE =====")
print("Total events:", len(events))

for item in events:
    print(
        item["timestamp"], "|",
        item["source"], "|",
        item["user_id"], "|",
        item["device_id"], "|",
        item["event"]
    )

print("\n[CREATED] timeline/correlated-timeline.csv")
print("[NOTICE] All events are synthetic.")
