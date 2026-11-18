
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta, timezone

BASE_DIR = Path(__file__).resolve().parents[1]
RAW_DIR = BASE_DIR / "data" / "raw"
ALERT_DIR = BASE_DIR / "output" / "alerts"

ALERT_DIR.mkdir(parents=True, exist_ok=True)

AUTH_FILE = RAW_DIR / "authentication.jsonl"
MFA_FILE = RAW_DIR / "mfa-events.jsonl"

REQUEST_THRESHOLD = 3
WINDOW_MINUTES = 10


def load_jsonl(path):
    records = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON in {path.name}, line {line_number}: {error}"
                )

    return records


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def save_alert(rule_id, severity, title, username,
               source_ip, description, evidence):

    alerts.append({
        "alert_id": f"DAY32-{rule_id}-{len(alerts) + 1:03}",
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "username": username,
        "source_ip": source_ip,
        "description": description,
        "evidence": evidence,
        "generated_at": datetime.now(timezone.utc).isoformat()
    })


authentication = load_jsonl(AUTH_FILE)
mfa_events = load_jsonl(MFA_FILE)

authentication.sort(key=lambda x: parse_time(x["timestamp"]))
mfa_events.sort(key=lambda x: parse_time(x["timestamp"]))

alerts = []

# -------------------------------------------------
# BUILD AN OBSERVED DEVICE BASELINE
# -------------------------------------------------
# Use the first successful login per user as the
# reference device in this synthetic dataset.
# This is not proof of a real trusted device.

baseline_devices = {}

for event in authentication:
    if event["status"] == "success":
        baseline_devices.setdefault(
            event["username"], event["device_id"]
        )

# -------------------------------------------------
# MFA-001: EXCESSIVE MFA REQUESTS
# -------------------------------------------------

requests_by_user = defaultdict(list)

for event in mfa_events:
    if event["event_type"] == "MFA_REQUEST":
        requests_by_user[event["username"]].append(event)

for username, requests in requests_by_user.items():

    for current in requests:
        current_time = parse_time(current["timestamp"])

        recent = [
            item for item in requests
            if timedelta(0) <= current_time - parse_time(
                item["timestamp"]
            ) <= timedelta(minutes=WINDOW_MINUTES)
        ]

        if len(recent) >= REQUEST_THRESHOLD:
            save_alert(
                "MFA-001",
                "HIGH",
                "Excessive MFA Requests",
                username,
                current["source_ip"],
                "Multiple MFA requests detected within the configured time window.",
                {
                    "request_count": len(recent),
                    "window_minutes": WINDOW_MINUTES,
                    "event_ids": [item["event_id"] for item in recent]
                }
            )
            break

# -------------------------------------------------
# MFA-002: APPROVAL FROM UNFAMILIAR DEVICE
# -------------------------------------------------

for event in mfa_events:

    if event["event_type"] != "MFA_APPROVED":
        continue

    username = event["username"]
    observed_device = event["device_id"]
    baseline = baseline_devices.get(username)

    if baseline is None or observed_device != baseline:
        save_alert(
            "MFA-002",
            "HIGH",
            "MFA Approval Outside Observed Device Baseline",
            username,
            event["source_ip"],
            "MFA approval originated from a device different from the observed baseline, or no baseline exists.",
            {
                "event_id": event["event_id"],
                "observed_device": observed_device,
                "baseline_device": baseline,
                "session_id": event["session_id"]
            }
        )

# -------------------------------------------------
# MFA-003: APPROVAL FOLLOWING REPEATED REQUESTS
# -------------------------------------------------

for approval in mfa_events:

    if approval["event_type"] != "MFA_APPROVED":
        continue

    approval_time = parse_time(approval["timestamp"])

    preceding_requests = [
        event for event in mfa_events
        if (
            event["username"] == approval["username"]
            and event["source_ip"] == approval["source_ip"]
            and event["event_type"] == "MFA_REQUEST"
            and timedelta(0) <= approval_time - parse_time(
                event["timestamp"]
            ) <= timedelta(minutes=WINDOW_MINUTES)
        )
    ]

    if len(preceding_requests) >= REQUEST_THRESHOLD:
        save_alert(
            "MFA-003",
            "CRITICAL",
            "MFA Approval Following Repeated Requests",
            approval["username"],
            approval["source_ip"],
            "MFA approval followed multiple requests from the same account and IP.",
            {
                "approval_event": approval["event_id"],
                "preceding_request_count": len(preceding_requests),
                "request_event_ids": [
                    event["event_id"] for event in preceding_requests
                ],
                "session_id": approval["session_id"]
            }
        )

# -------------------------------------------------
# MFA-004: MULTIPLE ACCOUNTS APPROVED FROM
# THE SAME IP AND DEVICE
# -------------------------------------------------

approvals_by_context = defaultdict(list)

for event in mfa_events:
    if event["event_type"] == "MFA_APPROVED":
        key = (event["source_ip"], event["device_id"])
        approvals_by_context[key].append(event)

for (source_ip, device_id), approvals in approvals_by_context.items():

    usernames = sorted({event["username"] for event in approvals})

    if len(usernames) >= 2:
        save_alert(
            "MFA-004",
            "CRITICAL",
            "Multiple Accounts Approved From Same IP and Device",
            ",".join(usernames),
            source_ip,
            "Multiple user accounts received MFA approval from the same IP and device.",
            {
                "accounts": usernames,
                "device_id": device_id,
                "approval_event_ids": [
                    event["event_id"] for event in approvals
                ]
            }
        )

# -------------------------------------------------
# WRITE RESULTS
# -------------------------------------------------

output_file = ALERT_DIR / "mfa-alerts.json"

with output_file.open("w", encoding="utf-8") as file:
    json.dump(alerts, file, indent=4)

print("\n========== MFA INVESTIGATION ==========")
print(f"Authentication records : {len(authentication)}")
print(f"MFA records            : {len(mfa_events)}")
print(f"Observed device baselines: {len(baseline_devices)}")
print(f"Total MFA alerts       : {len(alerts)}")

for alert in alerts:
    print("\n---------------------------------------")
    print(f"Alert ID : {alert['alert_id']}")
    print(f"Rule     : {alert['rule_id']}")
    print(f"Severity : {alert['severity']}")
    print(f"Title    : {alert['title']}")
    print(f"User     : {alert['username']}")
    print(f"Source IP: {alert['source_ip']}")

print("\n[+] MFA investigation completed.")
print(f"[+] Alerts saved to: {output_file}")
