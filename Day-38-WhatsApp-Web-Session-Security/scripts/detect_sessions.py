import csv
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

BASE = Path(__file__).resolve().parents[1]

def load_csv(relative_path):
    with (BASE / relative_path).open(
        newline="", encoding="utf-8"
    ) as f:
        return list(csv.DictReader(f))

browser = load_csv("evidence/browser-logs/browser-events.csv")
sessions = load_csv("evidence/session-logs/session-lifecycle.csv")
messages = load_csv("evidence/messaging-audit/account-activity.csv")

alerts = []

def alert(rule_id, severity, user, device, timestamp, description):
    alerts.append({
        "rule_id": rule_id,
        "severity": severity,
        "user_id": user,
        "device_id": device,
        "timestamp": timestamp,
        "description": description,
        "evidence_type": "synthetic_training_data"
    })

# Rule WWA-001:
# Browser tab closed while session remains active.
for event in browser:
    if event["event"] != "tab_closed":
        continue

    user = event["user_id"]
    device = event["device_id"]

    active = [
        s for s in sessions
        if s["user_id"] == user
        and s["device_id"] == device
        and s["timestamp"] >= event["timestamp"]
        and s["event"] == "browser_tab_closed"
        and s["session_status"] == "active"
    ]

    if active:
        alert(
            "WWA-001", "MEDIUM", user, device,
            event["timestamp"],
            "Browser tab closed while authenticated session remained active."
        )

# Rule WWA-002:
# Session accessed after tab closure and before revocation.
for event in sessions:
    if event["event"] != "session_accessed":
        continue

    user = event["user_id"]
    device = event["device_id"]

    tab_closures = [
        b for b in browser
        if b["user_id"] == user
        and b["device_id"] == device
        and b["event"] == "tab_closed"
        and b["timestamp"] < event["timestamp"]
    ]

    revocations = [
        s for s in sessions
        if s["user_id"] == user
        and s["device_id"] == device
        and s["event"] in ("session_revoked", "explicit_logout")
        and s["timestamp"] > event["timestamp"]
    ]

    if tab_closures and (not revocations or
                         min(r["timestamp"] for r in revocations) > event["timestamp"]):
        alert(
            "WWA-002", "HIGH", user, device,
            event["timestamp"],
            "Authenticated session accessed after browser tab closure."
        )

# Rule WWA-003:
# Unusually high messaging recipient count.
for event in messages:
    recipients = int(event["recipient_count"])

    if recipients >= 10:
        alert(
            "WWA-003", "HIGH",
            event["user_id"], event["device_id"],
            event["timestamp"],
            f"Unusual messaging volume: {recipients} recipients."
        )

# Rule WWA-004:
# Suspicious activity associated with a shared workstation.
shared_devices = {
    "shared_pc_01"
}

for event in messages:
    if event["device_id"] in shared_devices and (
        int(event["recipient_count"]) >= 10
        or event["event"] == "link_shared"
    ):
        alert(
            "WWA-004", "MEDIUM",
            event["user_id"], event["device_id"],
            event["timestamp"],
            "Suspicious account activity associated with a shared workstation."
        )

output = BASE / "output/detection-alerts.json"
output.parent.mkdir(parents=True, exist_ok=True)

with output.open("w", encoding="utf-8") as f:
    json.dump(alerts, f, indent=4)

print("=" * 55)
print("DAY 38 - SESSION SECURITY DETECTION ENGINE")
print("=" * 55)

print("Total alerts:", len(alerts))

for item in alerts:
    print(
        item["rule_id"], "|",
        item["severity"], "|",
        item["user_id"], "|",
        item["description"]
    )

print("\n[CREATED] output/detection-alerts.json")
print("[NOTICE] All findings use synthetic training evidence.")
