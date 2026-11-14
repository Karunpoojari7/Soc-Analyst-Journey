#!/usr/bin/env python3

import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
RAW = BASE / "data/raw/security-events.jsonl"
NORMALIZED = BASE / "data/normalized/events.jsonl"


def first(record, *keys):
    for key in keys:
        value = record.get(key)
        if value is not None:
            return value
    return None


def normalize_event(record):
    timestamp = first(record, "timestamp", "@timestamp")
    if not timestamp:
        raise ValueError("Missing timestamp")

    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include timezone")

    action = str(first(record, "event.action", "event_type") or "").lower()
    outcome = str(first(record, "event.outcome", "outcome") or "").lower()

    if action in {"authentication", "login", "auth_failure",
                  "auth_success", "authentication_failure"}:
        if outcome == "failure" or action in {
            "auth_failure", "authentication_failure"
        }:
            event_type = "AUTH_FAILURE"
        elif outcome == "success" or action == "auth_success":
            event_type = "AUTH_SUCCESS"
        else:
            event_type = "AUTHENTICATION_UNKNOWN"

    elif action in {"session", "session_start", "session_end"}:
        event_type = "SESSION"

    elif action in {"privileged_command", "sudo", "privileged_activity"}:
        event_type = "PRIVILEGED_ACTIVITY"

    elif action in {"process_execution", "process_started"}:
        event_type = "PROCESS_EXECUTION"

    elif action in {"network_connection", "connection"}:
        event_type = "NETWORK_CONNECTION"

    elif action == "service_started":
        event_type = "SERVICE_STARTED"

    else:
        event_type = action.upper() or "UNKNOWN"

    return {
        "event_id": first(record, "event_id", "id"),
        "timestamp": parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "host": first(record, "host", "host.name"),
        "event_type": event_type,
        "source_ip": first(record, "source.ip", "src_ip"),
        "destination_ip": first(record, "destination.ip", "dest_ip", "destination_ip"),
        "destination_port": first(record, "destination.port", "dest_port", "destination_port"),
        "username": first(record, "user.name", "username", "user"),
        "process_name": first(record, "process.name", "process_name", "process"),
        "command": first(record, "process.command_line", "command"),
        "provider": first(record, "event.provider", "provider"),
        "outcome": outcome or None,
        "severity": first(record, "severity")
    }


def main():
    NORMALIZED.parent.mkdir(parents=True, exist_ok=True)
    count = 0

    with RAW.open() as source, NORMALIZED.open("w") as destination:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                event = normalize_event(json.loads(line))
                destination.write(json.dumps(event) + "\n")
                count += 1
            except (json.JSONDecodeError, ValueError) as error:
                raise SystemExit(
                    f"Normalization failed on line {line_number}: {error}"
                )

    print("Normalization completed.")
    print("Events normalized:", count)
    print("Output:", NORMALIZED.relative_to(BASE))


if __name__ == "__main__":
    main()
