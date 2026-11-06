#!/usr/bin/env python3

import csv
import sys
from collections import defaultdict
from datetime import datetime

RC4 = {"0x17", "23"}
WINDOW_MINUTES = 10
SERVICE_THRESHOLD = 3


def parse_time(value):
    return datetime.fromisoformat(value)


def investigate(path):
    events = []

    with open(path, newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            events.append(row)

    print("========== KERBEROS SECURITY HUNT ==========")
    print(f"Events analysed: {len(events)}")

    asrep_count = 0
    rc4_count = 0
    service_requests = defaultdict(list)

    for event in events:
        event_id = event["EventID"]
        user = event["TargetUserName"]
        timestamp = parse_time(event["TimeCreated"])

        # AS-REP Roasting exposure indicator
        if event_id == "4768" and event["PreAuthType"] == "0":
            asrep_count += 1
            print(
                f"[HIGH-PRIORITY REVIEW] AS-REP indicator: "
                f"user={user}, time={timestamp}"
            )

        # RC4 service-ticket indicator
        if event_id == "4769":
            encryption = event["TicketEncryptionType"].lower()

            if encryption in RC4:
                rc4_count += 1
                print(
                    f"[REVIEW] RC4 service ticket: "
                    f"user={user}, service={event['ServiceName']}"
                )

            service_requests[user].append(
                (timestamp, event["ServiceName"])
            )

    # Multiple distinct service requests within a time window
    for user, requests in service_requests.items():
        requests.sort(key=lambda item: item[0])

        for index, (start, _) in enumerate(requests):
            window = [
                service for timestamp, service in requests[index:]
                if (timestamp - start).total_seconds()
                <= WINDOW_MINUTES * 60
            ]

            distinct_services = set(window)

            if len(distinct_services) >= SERVICE_THRESHOLD:
                print(
                    f"[REVIEW] Multiple service tickets: "
                    f"user={user}, distinct_services={len(distinct_services)}, "
                    f"window={WINDOW_MINUTES} minutes"
                )
                break

    print("\n========== HUNT SUMMARY ==========")
    print(f"AS-REP indicators: {asrep_count}")
    print(f"RC4 ticket indicators: {rc4_count}")
    print("Note: Indicators require contextual investigation.")
    print("Dataset status: SIMULATED TRAINING DATA")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 kerberos_hunt.py <events.csv>")
        sys.exit(1)

    investigate(sys.argv[1])
