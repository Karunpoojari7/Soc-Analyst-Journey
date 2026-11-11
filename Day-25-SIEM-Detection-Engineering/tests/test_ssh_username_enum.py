#!/usr/bin/env python3

import json
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
INPUT = BASE / "evidence/working/normalized-ssh-events.json"
OUTPUT = BASE / "output/ssh-username-enumeration-results.json"
DETECTOR = BASE / "scripts/ssh_username_enum_detector.py"

original_data = INPUT.read_bytes()

def make_events(usernames, seconds):
    events = []

    for i, (username, second) in enumerate(zip(usernames, seconds)):
        minute, remainder = divmod(second, 60)
        timestamp = f"Nov 10 02:{minute:02d}:{remainder:02d}"

        events.append({
            "timestamp": timestamp,
            "hostname": "lab-server",
            "process_id": 6000 + i,
            "event_type": "failed_login",
            "username": username,
            "source_ip": "198.51.100.23",
            "authentication_method": "password",
            "raw_message": f"Failed password for {username}"
        })

    return events


tests = [
    (
        "TC-05: Five failures and three usernames",
        ["admin", "test", "backup", "admin", "backup"],
        [0, 60, 120, 180, 240],
        True
    ),
    (
        "TC-06: Four failures and three usernames",
        ["admin", "test", "backup", "admin"],
        [0, 60, 120, 180],
        False
    ),
    (
        "TC-07: Five failures and only two usernames",
        ["admin", "test", "admin", "test", "admin"],
        [0, 60, 120, 180, 240],
        False
    ),
    (
        "TC-08: Five failures spread across fifteen minutes",
        ["admin", "test", "backup", "admin", "backup"],
        [0, 180, 360, 540, 900],
        False
    )
]

passed = 0
failed = 0
results = []

try:
    for name, usernames, seconds, expected in tests:
        INPUT.write_text(json.dumps(
            make_events(usernames, seconds), indent=4
        ))

        subprocess.run(
            [sys.executable, "-B", str(DETECTOR)],
            check=True,
            capture_output=True,
            text=True
        )

        result = json.loads(OUTPUT.read_text())
        actual = len(result["findings"]) > 0
        success = actual == expected

        if success:
            passed += 1
        else:
            failed += 1

        status = "PASS" if success else "FAIL"
        print(f"{status}: {name} | alert={actual}")

        results.append({
            "test": name,
            "expected_alert": expected,
            "actual_alert": actual,
            "result": status
        })

finally:
    INPUT.write_bytes(original_data)

    subprocess.run(
        [sys.executable, "-B", str(DETECTOR)],
        check=True
    )

    print("\nOriginal evidence restored.")
    print("Original DET-SSH-002 output regenerated.")

summary = {
    "detection_id": "DET-SSH-002",
    "total_tests": len(tests),
    "passed": passed,
    "failed": failed,
    "results": results,
    "dataset_type": "SYNTHETIC CONTROLLED TEST CASES"
}

test_output = BASE / "output/username-enumeration-test-results.json"
test_output.write_text(json.dumps(summary, indent=4))

print("\n===== TEST SUMMARY =====")
print(f"Passed: {passed}/{len(tests)}")
print(f"Failed: {failed}/{len(tests)}")
print(f"Results: {test_output.relative_to(BASE)}")

if failed:
    sys.exit(1)
