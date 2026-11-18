
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone, timedelta

BASE_DIR = Path(__file__).resolve().parents[1]
RAW_DIR = BASE_DIR / "data" / "raw"
ALERT_DIR = BASE_DIR / "output" / "alerts"

ALERT_DIR.mkdir(parents=True, exist_ok=True)

AUTH_FILE = RAW_DIR / "authentication.jsonl"

# Detection configuration
FAILURE_THRESHOLD = 3
CORRELATION_WINDOW_MINUTES = 10


def load_jsonl(path):
    records = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                print(f"[ERROR] Invalid JSON at line {line_number}: {error}")

    return records


def parse_timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def create_alert(rule_id, severity, title, username, source_ip,
                 description, evidence):

    return {
        "alert_id": f"DAY32-{rule_id}-{len(alerts) + 1:03}",
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "username": username,
        "source_ip": source_ip,
        "description": description,
        "evidence": evidence,
        "generated_at": datetime.now(timezone.utc).isoformat()
    }


events = load_jsonl(AUTH_FILE)
events.sort(key=lambda event: parse_timestamp(event["timestamp"]))

alerts = []

# -------------------------------------------------
# DETECTION 01: MULTIPLE FAILED LOGIN ATTEMPTS
# -------------------------------------------------

failures_by_user_ip = defaultdict(list)

for event in events:
    if event["status"] == "failure":
        key = (event["username"], event["source_ip"])
        failures_by_user_ip[key].append(event)

for (username, source_ip), failures in failures_by_user_ip.items():

    if len(failures) >= FAILURE_THRESHOLD:
        alerts.append(create_alert(
            "AUTH-001",
            "HIGH",
            "Multiple Failed Authentication Attempts",
            username,
            source_ip,
            "Repeated failed login attempts detected.",
            {
                "failure_count": len(failures),
                "first_failure": failures[0]["timestamp"],
                "last_failure": failures[-1]["timestamp"],
                "event_ids": [event["event_id"] for event in failures]
            }
        ))


# -------------------------------------------------
# DETECTION 02: FAILURE FOLLOWED BY SUCCESS
# -------------------------------------------------

for (username, source_ip), failures in failures_by_user_ip.items():

    for event in events:
        if (
            event["username"] == username
            and event["source_ip"] == source_ip
            and event["status"] == "success"
        ):
            success_time = parse_timestamp(event["timestamp"])

            recent_failures = [
                failure for failure in failures
                if timedelta(0) <= (
                    success_time - parse_timestamp(failure["timestamp"])
                ) <= timedelta(minutes=CORRELATION_WINDOW_MINUTES)
            ]

            if len(recent_failures) >= FAILURE_THRESHOLD:
                alerts.append(create_alert(
                    "AUTH-002",
                    "CRITICAL",
                    "Successful Login Following Repeated Failures",
                    username,
                    source_ip,
                    "Successful authentication followed multiple failed attempts from the same IP.",
                    {
                        "failed_attempts": len(recent_failures),
                        "successful_event": event["event_id"],
                        "success_timestamp": event["timestamp"],
                        "device_id": event["device_id"],
                        "session_id": event["session_id"]
                    }
                ))


# -------------------------------------------------
# DETECTION 03: MULTIPLE ACCOUNTS FROM ONE IP
# -------------------------------------------------

accounts_by_ip = defaultdict(set)

for event in events:
    if event["status"] == "success":
        accounts_by_ip[event["source_ip"]].add(event["username"])

for source_ip, usernames in accounts_by_ip.items():

    if len(usernames) >= 2:
        alerts.append(create_alert(
            "AUTH-003",
            "HIGH",
            "Multiple Accounts Authenticated From One IP",
            ",".join(sorted(usernames)),
            source_ip,
            "Multiple user accounts successfully authenticated from the same source IP.",
            {
                "accounts": sorted(usernames),
                "account_count": len(usernames)
            }
        ))


# -------------------------------------------------
# WRITE ALERTS
# -------------------------------------------------

output_file = ALERT_DIR / "authentication-alerts.json"

with output_file.open("w", encoding="utf-8") as file:
    json.dump(alerts, file, indent=4)

print("\n========== AUTHENTICATION INVESTIGATION ==========")

print(f"Total authentication events : {len(events)}")
print(f"Total generated alerts      : {len(alerts)}")

for alert in alerts:
    print("\n------------------------------------")
    print(f"Alert ID  : {alert['alert_id']}")
    print(f"Rule ID   : {alert['rule_id']}")
    print(f"Severity  : {alert['severity']}")
    print(f"Title     : {alert['title']}")
    print(f"Username  : {alert['username']}")
    print(f"Source IP : {alert['source_ip']}")
    print(f"Details   : {alert['description']}")

print("\n[+] Investigation completed.")
print(f"[+] Alerts saved to: {output_file}")
