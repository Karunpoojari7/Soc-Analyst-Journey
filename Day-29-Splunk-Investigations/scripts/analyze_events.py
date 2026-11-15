import json
from collections import Counter
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data/raw/nexora-security-events.jsonl"
OUTPUT = BASE / "reports/analysis-results.json"

def load_events():
    events = []

    with DATA.open(encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            if not line.strip():
                continue

            event = json.loads(line)
            event["_time"] = datetime.fromisoformat(
                event["timestamp"].replace("Z", "+00:00")
            )
            events.append(event)

    return sorted(events, key=lambda e: e["_time"])

def analyze(events):
    counts = Counter(e["event_type"] for e in events)

    failures = [e for e in events if e["event_type"] == "AUTH_FAILURE"]
    successes = [e for e in events if e["event_type"] == "AUTH_SUCCESS"]

    success_after_failures = (
        bool(failures and successes)
        and max(e["_time"] for e in successes)
        > max(e["_time"] for e in failures)
    )

    return {
        "case_id": "SOC-2026-029",
        "dataset": "synthetic",
        "total_events": len(events),
        "event_type_counts": dict(counts),
        "authentication_failures": len(failures),
        "authentication_successes": len(successes),
        "success_after_failures": success_after_failures,
        "privileged_activity": [
            e.get("command") for e in events
            if e["event_type"] == "PRIVILEGED_ACTIVITY"
        ],
        "process_execution": [
            {
                "process_name": e.get("process_name"),
                "process_id": e.get("process_id")
            }
            for e in events
            if e["event_type"] == "PROCESS_EXECUTION"
        ],
        "network_connections": [
            {
                "source": e.get("src_ip"),
                "destination": e.get("dest_ip"),
                "destination_port": e.get("dest_port"),
                "process": e.get("process_name")
            }
            for e in events
            if e["event_type"] == "NETWORK_CONNECTION"
        ],
        "assessment": "HIGH_PRIORITY_INVESTIGATION",
        "compromise_confirmed": False,
        "limitations": [
            "Synthetic events only",
            "No session identifier linking the events",
            "No process tree or parent-child evidence",
            "No packet or TLS evidence",
            "Temporal correlation does not prove causation"
        ]
    }

def main():
    events = load_events()
    result = analyze(events)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8"
    )

    print("===== DAY 29 INVESTIGATION =====")
    print("Case:", result["case_id"])
    print("Total events:", result["total_events"])
    print("Event distribution:", result["event_type_counts"])
    print("Authentication failures:", result["authentication_failures"])
    print("Authentication successes:", result["authentication_successes"])
    print("Success after failures:", result["success_after_failures"])
    print("Privileged activity:", result["privileged_activity"])
    print("Process execution:", result["process_execution"])
    print("Network connections:", result["network_connections"])
    print("Assessment:", result["assessment"])
    print("Compromise confirmed:", result["compromise_confirmed"])
    print("Saved:", OUTPUT)

if __name__ == "__main__":
    main()
