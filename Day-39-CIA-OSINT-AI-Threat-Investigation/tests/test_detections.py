import csv
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
FILE = BASE / "tests/benign-events.csv"

with FILE.open(newline="", encoding="utf-8") as f:
    events = list(csv.DictReader(f))

checks = []

# Test 1: Authentication failure threshold
failed_logins = [
    e for e in events
    if e["event_type"] == "login"
    and e["status"] == "failure"
]

checks.append((
    "Authentication failure threshold",
    len(failed_logins) < 2
))

# Test 2: Rapid API request threshold
api_events = [
    e for e in events
    if e["event_type"] == "api_request"
]

rapid_api_detected = any(
    int(e["request_count"]) >= 3
    for e in api_events
)

checks.append((
    "API request threshold",
    not rapid_api_detected
))

# Test 3: Bulk export threshold
exports = [
    e for e in events
    if e["endpoint"].endswith("/export")
    and int(e["request_count"]) >= 100
]

checks.append((
    "Bulk export threshold",
    len(exports) == 0
))

# Test 4: Large outbound transfer
large_transfers = [
    e for e in events
    if int(e["bytes_out"]) >= 10_000_000
]

checks.append((
    "Large outbound transfer threshold",
    len(large_transfers) == 0
))

print("=" * 55)
print("DAY 39 - BENIGN DETECTION VALIDATION")
print("=" * 55)

passed = 0

for name, result in checks:
    print("[PASS]" if result else "[FAIL]", name)
    passed += int(result)

print("\nTests passed:", passed)
print("Tests failed:", len(checks) - passed)
print("Benign records:", len(events))

if passed != len(checks):
    raise SystemExit("Validation failed")

print("\nBenign threshold tests completed.")
