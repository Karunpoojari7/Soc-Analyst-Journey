from datetime import datetime, timezone
from collections import defaultdict

def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def detect_brute_force(events, threshold=3, window_seconds=600):
    grouped = defaultdict(list)

    for event in events:
        grouped[(event["source_ip"], event["user"])].append(event)

    findings = []

    for (ip, user), records in grouped.items():
        records.sort(key=lambda e: timestamp(e["timestamp"]))

        failures = [
            e for e in records
            if e["event"] == "login_failure"
        ]

        successes = [
            e for e in records
            if e["event"] == "login_success"
        ]

        for success in successes:
            success_time = timestamp(success["timestamp"])

            recent_failures = [
                failure for failure in failures
                if 0 <= (
                    success_time - timestamp(failure["timestamp"])
                ).total_seconds() <= window_seconds
            ]

            if len(recent_failures) >= threshold:
                findings.append({
                    "source_ip": ip,
                    "user": user,
                    "failure_count": len(recent_failures),
                    "success_event": success["id"]
                })
                break

    return findings


def event(event_id, ip, user, event_type, time):
    return {
        "id": event_id,
        "source_ip": ip,
        "user": user,
        "event": event_type,
        "timestamp": time
    }


tests = [
    {
        "name": "Repeated failures followed by success",
        "events": [
            event("T001", "198.51.100.10", "admin", "login_failure", "2026-11-27T09:00:00Z"),
            event("T002", "198.51.100.10", "admin", "login_failure", "2026-11-27T09:01:00Z"),
            event("T003", "198.51.100.10", "admin", "login_failure", "2026-11-27T09:02:00Z"),
            event("T004", "198.51.100.10", "admin", "login_success", "2026-11-27T09:03:00Z")
        ],
        "expected": 1
    },
    {
        "name": "Legitimate successful login",
        "events": [
            event("T005", "192.0.2.10", "operator", "login_success", "2026-11-27T10:00:00Z")
        ],
        "expected": 0
    },
    {
        "name": "Slow failures outside correlation window",
        "events": [
            event("T006", "198.51.100.20", "admin", "login_failure", "2026-11-27T09:00:00Z"),
            event("T007", "198.51.100.20", "admin", "login_failure", "2026-11-27T09:20:00Z"),
            event("T008", "198.51.100.20", "admin", "login_failure", "2026-11-27T09:40:00Z"),
            event("T009", "198.51.100.20", "admin", "login_success", "2026-11-27T09:41:00Z")
        ],
        "expected": 0
    },
    {
        "name": "Failures and success from different IP addresses",
        "events": [
            event("T010", "198.51.100.30", "admin", "login_failure", "2026-11-27T09:00:00Z"),
            event("T011", "198.51.100.30", "admin", "login_failure", "2026-11-27T09:01:00Z"),
            event("T012", "198.51.100.30", "admin", "login_failure", "2026-11-27T09:02:00Z"),
            event("T013", "198.51.100.31", "admin", "login_success", "2026-11-27T09:03:00Z")
        ],
        "expected": 0
    }
]

passed = 0

print("=" * 65)
print("DAY 41 — DETECTION SCENARIO TESTS")
print("=" * 65)

for test in tests:
    findings = detect_brute_force(test["events"])
    actual = len(findings)
    expected = test["expected"]
    result = actual == expected

    print(
        f"[{'PASS' if result else 'FAIL'}] {test['name']}"
        f" | Expected: {expected} | Actual: {actual}"
    )

    if result:
        passed += 1

print("=" * 65)
print(f"RESULT: {passed}/{len(tests)} tests passed")

if passed != len(tests):
    raise SystemExit(1)
