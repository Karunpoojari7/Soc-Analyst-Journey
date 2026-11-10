import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone

DETECTOR = Path("scripts/ssh_bruteforce_detector.py")
INPUT = Path("evidence/working/normalized-ssh-events.json")
OUTPUT = Path("output/ssh-detection-results.json")

def make_event(minute, second, event_type, username="testuser"):
    timestamp = datetime(
        2026, 11, 10, 2, minute, second, tzinfo=timezone.utc
    )
    return {
        "timestamp": timestamp.strftime("%b %d %H:%M:%S"),
        "hostname": "test-server",
        "process_id": 6000 + minute,
        "event_type": event_type,
        "username": username,
        "source_ip": "198.51.100.99",
        "authentication_method": (
            "password" if event_type == "failed_login"
            else "password" if event_type == "successful_login"
            else None
        ),
        "raw_message": "synthetic test event",
    }

def run_case(name, events, expected_alert, expected_success=False):
    INPUT.write_text(json.dumps(events, indent=2))

    result = subprocess.run(
        [sys.executable, "-B", str(DETECTOR)],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"FAIL: {name} - detector execution error")
        print(result.stderr)
        return False

    data = json.loads(OUTPUT.read_text())
    alert = bool(data["findings"])
    success = (
        data["findings"][0]["successful_login_after_threshold"]
        if alert else False
    )

    passed = alert == expected_alert and success == expected_success

    print(
        f"{'PASS' if passed else 'FAIL'}: {name} | "
        f"alert={alert} | success_after_threshold={success}"
    )

    return passed

cases = []

# Five failures within five minutes.
cases.append(run_case(
    "TC-01: Five failures within threshold window",
    [make_event(i, 0, "failed_login") for i in range(5)],
    True
))

# Four failures only.
cases.append(run_case(
    "TC-02: Four failures below threshold",
    [make_event(i, 0, "failed_login") for i in range(4)],
    False
))

# Five failures spread over fifteen minutes.
cases.append(run_case(
    "TC-03: Five failures outside time window",
    [
        make_event(0, 0, "failed_login"),
        make_event(3, 0, "failed_login"),
        make_event(6, 0, "failed_login"),
        make_event(9, 0, "failed_login"),
        make_event(15, 0, "failed_login"),
    ],
    False
))

# Five failures followed by successful authentication.
cases.append(run_case(
    "TC-04: Failures followed by successful login",
    [
        *[make_event(i, 0, "failed_login") for i in range(5)],
        make_event(5, 30, "successful_login"),
    ],
    True,
    True
))

print("\n===== TEST SUMMARY =====")
print(f"Passed: {sum(cases)}/{len(cases)}")
print(f"Failed: {len(cases) - sum(cases)}")

# Restore the original lab evidence before exiting.
subprocess.run(
    [sys.executable, "-B", "scripts/normalize_ssh_logs.py"],
    check=True
)
subprocess.run(
    [sys.executable, "-B", str(DETECTOR)],
    check=True
)

sys.exit(0 if all(cases) else 1)
