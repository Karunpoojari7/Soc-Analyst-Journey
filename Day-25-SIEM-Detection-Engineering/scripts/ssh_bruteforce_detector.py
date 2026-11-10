import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

INPUT = Path("evidence/working/normalized-ssh-events.json")
OUTPUT = Path("output/ssh-detection-results.json")

THRESHOLD = 5
WINDOW_SECONDS = 600
ASSUMED_YEAR = 2026

events = json.loads(INPUT.read_text())

def event_time(timestamp):
    parsed = datetime.strptime(
        f"{ASSUMED_YEAR} {timestamp}",
        "%Y %b %d %H:%M:%S"
    )
    parsed = parsed.replace(tzinfo=timezone.utc)

    # Resolve a December-to-January year boundary in ordered lab data.
    return parsed

failures = defaultdict(list)
successes = defaultdict(list)

previous_time = None
year_offset = 0

for event in events:
    source = event.get("source_ip")
    if not source:
        continue

    current_time = event_time(event["timestamp"])
    if previous_time and current_time < previous_time:
        if previous_time - current_time > timedelta(days=180):
            year_offset += 1
    current_time = current_time.replace(year=ASSUMED_YEAR + year_offset)
    previous_time = current_time

    record = {
        "time": current_time.timestamp(),
        "timestamp": current_time.isoformat(),
        "username": event["username"],
    }

    if event["event_type"] == "failed_login":
        failures[source].append(record)
    elif event["event_type"] == "successful_login":
        successes[source].append(record)

findings = []

for source, attempts in failures.items():
    attempts.sort(key=lambda item: item["time"])
    source_successes = sorted(
        successes.get(source, []),
        key=lambda item: item["time"]
    )

    for index, current in enumerate(attempts):
        window_start = current["time"] - WINDOW_SECONDS
        window = [
            item for item in attempts[:index + 1]
            if window_start <= item["time"] <= current["time"]
        ]

        if len(window) < THRESHOLD:
            continue

        qualifying_successes = [
            item for item in source_successes
            if current["time"] < item["time"] <=
            current["time"] + WINDOW_SECONDS
        ]

        findings.append({
            "detection_id": "DET-SSH-001",
            "detection_name": "SSH Multiple Authentication Failures",
            "source_ip": source,
            "failed_attempts": len(window),
            "window_seconds": WINDOW_SECONDS,
            "first_failure": window[0]["timestamp"],
            "threshold_reached": current["timestamp"],
            "successful_login_after_threshold": bool(qualifying_successes),
            "successful_login_details": qualifying_successes,
            "severity": "high",
            "mitre_attack": "T1110",
            "assessment": "REVIEW_REQUIRED",
        })
        break

result = {
    "dataset_type": "SYNTHETIC TRAINING EVIDENCE",
    "assumed_year": ASSUMED_YEAR,
    "rule": {
        "id": "DET-SSH-001",
        "threshold": THRESHOLD,
        "window_seconds": WINDOW_SECONDS,
        "group_by": "source_ip",
    },
    "total_events": len(events),
    "sources_with_failed_logins": len(failures),
    "findings": findings,
    "sources_triggered": [item["source_ip"] for item in findings],
    "assessment": "ALERT_GENERATED" if findings else "NO_ALERT",
    "limitations": [
        "Synthetic training dataset",
        "2026 is an assumed year, not verified source metadata",
        "UTC is an assumed timezone, not verified source metadata",
        "Year rollover handling assumes events are chronologically ordered",
        "A detection finding does not prove account compromise",
    ],
}

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(result, indent=2) + "\n")

print("DETECTION ENGINE: COMPLETE")
print("Total events:", len(events))
print("Detection findings:", len(findings))

for finding in findings:
    print("\nDetection:", finding["detection_id"])
    print("Source:", finding["source_ip"])
    print("Failed attempts:", finding["failed_attempts"])
    print("Successful login after threshold:",
          finding["successful_login_after_threshold"])
    print("Assessment:", finding["assessment"])

print("\nOverall assessment:", result["assessment"])
print("Output:", OUTPUT)
