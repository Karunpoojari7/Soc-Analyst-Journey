import csv
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DETECTION_SCRIPT = "scripts/detect_third_party_activity.py"


def write_csv(path, headers, rows):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def run_detection(project):
    result = subprocess.run(
        ["python3", DETECTION_SCRIPT],
        cwd=project,
        capture_output=True,
        text=True,
        check=True,
    )

    output = project / "output/detection-alerts.json"
    with output.open(encoding="utf-8") as file:
        alerts = json.load(file)

    return result.stdout, alerts


def create_benign_evidence(project):
    base = project / "evidence"

    write_csv(
        base / "identity-logs/identity-events.csv",
        ["event_id", "timestamp_utc", "username", "source_ip",
         "event_type", "result"],
        [{
            "event_id": "I-B01",
            "timestamp_utc": "2026-11-19T09:00:00Z",
            "username": "vendor_user02",
            "source_ip": "192.0.2.15",
            "event_type": "AUTHENTICATION",
            "result": "SUCCESS",
        }]
    )

    write_csv(
        base / "vendor-logs/customer-data-access.csv",
        ["event_id", "timestamp_utc", "username", "source_ip",
         "records_accessed", "action", "result"],
        [{
            "event_id": "D-B01",
            "timestamp_utc": "2026-11-19T09:05:00Z",
            "username": "vendor_user02",
            "source_ip": "192.0.2.15",
            "records_accessed": "20",
            "action": "READ",
            "result": "SUCCESS",
        }]
    )

    write_csv(
        base / "network-logs/network-events.csv",
        ["event_id", "timestamp_utc", "source_ip", "destination_ip",
         "destination_port", "protocol", "bytes_sent",
         "connection_status"],
        [{
            "event_id": "N-B01",
            "timestamp_utc": "2026-11-19T09:06:00Z",
            "source_ip": "192.0.2.15",
            "destination_ip": "203.0.113.30",
            "destination_port": "443",
            "protocol": "TCP",
            "bytes_sent": "18000",
            "connection_status": "ESTABLISHED",
        }]
    )

    write_csv(
        base / "endpoint-logs/endpoint-events.csv",
        ["event_id", "timestamp_utc", "hostname", "username",
         "process_name", "event_type", "severity"],
        [{
            "event_id": "E-B01",
            "timestamp_utc": "2026-11-19T09:07:00Z",
            "hostname": "Vendor-Server-02",
            "username": "vendor_user02",
            "process_name": "browser.exe",
            "event_type": "USER_SESSION",
            "severity": "LOW",
        }]
    )


def main():
    # Test 1: Original suspicious training evidence.
    _, suspicious_alerts = run_detection(ROOT)

    print("Suspicious scenario:")
    print(f"Alerts generated: {len(suspicious_alerts)}")

    if len(suspicious_alerts) != 9:
        raise AssertionError("Expected 9 suspicious-scenario alerts")

    print("PASS: Suspicious scenario detected")

    # Test 2: Isolated benign evidence in a temporary copy.
    with tempfile.TemporaryDirectory() as temporary:
        project = Path(temporary) / "lab"

        shutil.copytree(
            ROOT / "scripts",
            project / "scripts",
            ignore=shutil.ignore_patterns("__pycache__"),
        )

        create_benign_evidence(project)

        _, benign_alerts = run_detection(project)

        print("\nBenign scenario:")
        print(f"Alerts generated: {len(benign_alerts)}")

        if benign_alerts:
            raise AssertionError(
                "Benign scenario unexpectedly generated alerts"
            )

        print("PASS: Benign scenario produced no alerts")

    print("\nPASS: All detection tests completed")


if __name__ == "__main__":
    main()
