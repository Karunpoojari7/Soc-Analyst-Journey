#!/usr/bin/env python3

import csv
import sys

EVENT_NAMES = {
    "4728": "Global security group membership addition",
    "4732": "Local security group membership addition",
    "4756": "Universal security group membership addition",
    "4729": "Global security group membership removal",
    "4733": "Local security group membership removal",
    "4757": "Universal security group membership removal",
}

SENSITIVE_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "backup operators",
    "account operators",
}


def investigate(path):
    with open(path, newline="", encoding="utf-8") as file:
        events = list(csv.DictReader(file))

    print("========== AD PRIVILEGED GROUP HUNT ==========")
    print(f"Events analysed: {len(events)}")

    additions = 0
    removals = 0
    sensitive_findings = 0

    for event in events:
        event_id = event["EventID"]
        group = event["TargetGroupName"].strip()
        group_lower = group.lower()

        if event_id not in EVENT_NAMES:
            continue

        if event_id in {"4728", "4732", "4756"}:
            additions += 1
            action = "MEMBERSHIP ADDITION"
        else:
            removals += 1
            action = "MEMBERSHIP REMOVAL"

        print(f"\n[{action}]")
        print(f"  Event: {event_id} - {EVENT_NAMES[event_id]}")
        print(f"  Actor: {event['SubjectUserName']}")
        print(f"  Member: {event['MemberName']}")
        print(f"  Group: {group}")
        print(f"  Computer: {event['Computer']}")

        if action == "MEMBERSHIP ADDITION" and group_lower in SENSITIVE_GROUPS:
            sensitive_findings += 1
            print("  [HIGH PRIORITY REVIEW] Sensitive group membership added")

    print("\n========== INVESTIGATION SUMMARY ==========")
    print(f"Membership additions: {additions}")
    print(f"Membership removals: {removals}")
    print(f"Sensitive group additions: {sensitive_findings}")
    print("\nDataset status: SIMULATED TRAINING DATA")
    print("A sensitive group addition is not proof of unauthorized activity.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 privileged_group_hunt.py <events.csv>")
        sys.exit(1)

    investigate(sys.argv[1])
