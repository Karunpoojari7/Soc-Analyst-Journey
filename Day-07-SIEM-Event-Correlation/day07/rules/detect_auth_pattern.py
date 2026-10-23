#!/usr/bin/env python3

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re

LOG_FILE = Path("logs/auth-events.log")
THRESHOLD = 3
WINDOW = timedelta(minutes=5)

pattern = re.compile(
    r"^(?P<ts>\S+)\s+source=(?P<source>\S+)\s+"
    r"event=(?P<event>\S+)\s+user=(?P<user>\S+)\s+"
    r"src_ip=(?P<ip>\S+)$"
)

events = defaultdict(list)

for line_number, line in enumerate(
    LOG_FILE.read_text(encoding="utf-8").splitlines(), start=1
):
    match = pattern.match(line.strip())
    if not match:
        print(f"WARNING: Could not parse line {line_number}")
        continue

    record = match.groupdict()
    try:
        timestamp = datetime.fromisoformat(
            record["ts"].replace("Z", "+00:00")
        )
        if timestamp.tzinfo is None:
            raise ValueError("Timestamp has no timezone")
        timestamp = timestamp.astimezone(timezone.utc)
    except ValueError:
        print(f"WARNING: Invalid timestamp on line {line_number}")
        continue

    key = (record["user"], record["ip"])
    events[key].append({
        "timestamp": timestamp,
        "event": record["event"],
        "source": record["source"],
    })

alerts = []

for (user, ip), records in events.items():
    records.sort(key=lambda item: item["timestamp"])
    failures = []

    for record in records:
        if record["event"] == "LOGIN_FAILED":
            failures.append(record["timestamp"])
        elif record["event"] == "LOGIN_SUCCESS":
            recent = [
                timestamp for timestamp in failures
                if timedelta(0) <= record["timestamp"] - timestamp <= WINDOW
            ]

            if len(recent) >= THRESHOLD:
                alerts.append(
                    f"ALERT user={user} src_ip={ip} "
                    f"failed_count={len(recent)} "
                    f"success_time={record['timestamp'].isoformat()} "
                    f"window=5m"
                )

            failures = []

if alerts:
    print("\n".join(alerts))
else:
    print("No matching authentication patterns detected.")
