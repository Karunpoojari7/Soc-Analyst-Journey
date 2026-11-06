#!/usr/bin/env python3

import csv
import sys
from collections import defaultdict
from datetime import datetime

ACCOUNT_EVENTS = {
    "4720": "Account created",
    "4722": "Account enabled",
    "4724": "Password reset attempted",
}

GROUP_EVENTS = {"4728", "4732", "4756"}

SENSITIVE_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "backup operators",
    "account operators",
}

WINDOW_MINUTES = 15


def investigate(path):
    with open(path, newline="", encoding="utf-8") as file:
        events = list(csv.DictReader(file))

    for event in events:
        event["parsed_time"] = datetime.fromisoformat(event["TimeCreated"])

    events.sort(key=lambda event: event["parsed_time"])

    account_activity = defaultdict(list)
    sensitive_additions = []

    print("========== AD EVENT CORRELATION ==========")
    print(f"Events analysed: {len(events)}")

    for event in events:
        event_id = event["EventID"]
        actor = event["SubjectUserName"]
        target = event["TargetUserName"]
        group = event["TargetGroupName"].strip()

        if event_id in ACCOUNT_EVENTS:
            account_activity[target].append(event)

        if event_id in GROUP_EVENTS and group.lower() in SENSITIVE_GROUPS:
            sensitive_additions.append(event)

    correlated = 0

    for group_event in sensitive_additions:
        target = group_event["TargetUserName"]
        actor = group_event["SubjectUserName"]
        group = group_event["TargetGroupName"]
        group_time = group_event["parsed_time"]

        related = [
            event for event in account_activity.get(target, [])
            if event["SubjectUserName"] == actor
            and 0 <= (group_time - event["parsed_time"]).total_seconds()
            <= WINDOW_MINUTES * 60
        ]

        print(f"\n[ SENSITIVE GROUP CHANGE ]")
        print(f"Actor: {actor}")
        print(f"Target account: {target}")
        print(f"Group: {group}")

        if related:
            correlated += 1
            print("[CORRELATION] Related account lifecycle activity found:")

            for event in related:
                print(
                    f"  Event {event['EventID']}: "
                    f"{ACCOUNT_EVENTS[event['EventID']]} "
                    f"at {event['TimeCreated']}"
                )
        else:
            print("[NO MATCH] No matching account lifecycle event in scope.")

    print("\n========== CORRELATION SUMMARY ==========")
    print(f"Sensitive group additions: {len(sensitive_additions)}")
    print(f"Correlated account sequences: {correlated}")
    print(f"Correlation window: {WINDOW_MINUTES} minutes")
    print("Dataset status: SIMULATED TRAINING DATA")
    print("Correlation is an investigation lead, not proof of compromise.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ad_event_correlation.py <events.csv>")
        sys.exit(1)

    investigate(sys.argv[1])
