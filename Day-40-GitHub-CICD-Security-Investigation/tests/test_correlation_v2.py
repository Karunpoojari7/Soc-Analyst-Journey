import json
import subprocess
import tempfile
from pathlib import Path

DETECTOR = Path("scripts/correlate_github_events_v2.py")

BASE = [
    {
        "event_id": "T001",
        "timestamp": "2026-11-26T09:00:00Z",
        "actor": "test-user",
        "action": "token.created",
        "repository": "test-app",
        "source_ip": "198.51.100.10",
        "status": "success"
    },
    {
        "event_id": "T002",
        "timestamp": "2026-11-26T09:02:00Z",
        "actor": "test-user",
        "action": "repo.permission.changed",
        "repository": "test-app",
        "source_ip": "198.51.100.10",
        "status": "success"
    },
    {
        "event_id": "T003",
        "timestamp": "2026-11-26T09:04:00Z",
        "actor": "test-user",
        "action": "workflow.modified",
        "repository": "test-app",
        "source_ip": "198.51.100.10",
        "status": "success"
    },
    {
        "event_id": "T004",
        "timestamp": "2026-11-26T09:08:00Z",
        "actor": "test-user",
        "action": "workflow.run",
        "repository": "test-app",
        "source_ip": "198.51.100.10",
        "status": "success"
    }
]

def run_test(name, events, expected):
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        input_file = temp / "events.jsonl"
        output_file = temp / "alerts.json"

        input_file.write_text(
            "".join(json.dumps(e) + "\n" for e in events)
        )

        # Create a temporary copy with test-specific paths.
        source = DETECTOR.read_text()
        source = source.replace(
            'Path("logs/github-audit-events.jsonl")',
            f'Path({str(input_file)!r})'
        )
        source = source.replace(
            'Path("output/github-correlation-alerts-v2.json")',
            f'Path({str(output_file)!r})'
        )

        test_detector = temp / "detector.py"
        test_detector.write_text(source)

        result = subprocess.run(
            ["python3", str(test_detector)],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(name, "ERROR")
            print(result.stderr)
            return False

        alerts = json.loads(output_file.read_text())
        passed = len(alerts) == expected

        print(
            f"{name}: {'PASS' if passed else 'FAIL'} "
            f"(expected={expected}, actual={len(alerts)})"
        )

        return passed

# Test 1: Correct sequence should alert.
test1 = run_test("Correct sequence", BASE, 1)

# Test 2: Different source IPs should not correlate.
different_ip = [dict(e) for e in BASE]
different_ip[2]["source_ip"] = "198.51.100.20"
test2 = run_test("Different source IPs", different_ip, 0)

# Test 3: Missing workflow modification should not alert.
missing_event = [e for e in BASE if e["action"] != "workflow.modified"]
test3 = run_test("Incomplete sequence", missing_event, 0)

# Test 4: Wrong chronological order should not alert.
wrong_order = [dict(e) for e in BASE]
wrong_order[1]["timestamp"] = "2026-11-26T09:09:00Z"
test4 = run_test("Out-of-order sequence", wrong_order, 0)

print("\nOverall:", "PASS" if all(
    [test1, test2, test3, test4]
) else "FAIL")
