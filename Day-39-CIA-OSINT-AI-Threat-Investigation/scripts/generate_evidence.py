import csv
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

datasets = {
    "evidence/identity-logs/identity-events.csv": [
        ["event_id", "timestamp", "username", "source_ip", "event_type", "status", "details"],
        ["ID001", "2026-11-25T09:00:01Z", "analyst01", "192.0.2.10", "login", "success", "Normal login"],
        ["ID002", "2026-11-25T09:02:10Z", "service01", "198.51.100.20", "login", "failure", "Invalid credentials"],
        ["ID003", "2026-11-25T09:02:12Z", "service01", "198.51.100.20", "login", "failure", "Invalid credentials"],
        ["ID004", "2026-11-25T09:02:14Z", "service01", "198.51.100.20", "login", "success", "Authentication succeeded"],
        ["ID005", "2026-11-25T09:03:01Z", "service01", "198.51.100.20", "privilege_change", "success", "Role changed to elevated"],
        ["ID006", "2026-11-25T09:10:00Z", "analyst02", "192.0.2.30", "login", "success", "Normal login"]
    ],

    "evidence/api-logs/api-events.csv": [
        ["event_id", "timestamp", "username", "source_ip", "endpoint", "method", "status_code", "request_count"],
        ["API001", "2026-11-25T09:04:00Z", "service01", "198.51.100.20", "/api/search", "GET", "200", "1"],
        ["API002", "2026-11-25T09:04:01Z", "service01", "198.51.100.20", "/api/search", "GET", "200", "1"],
        ["API003", "2026-11-25T09:04:02Z", "service01", "198.51.100.20", "/api/search", "GET", "200", "1"],
        ["API004", "2026-11-25T09:04:03Z", "service01", "198.51.100.20", "/api/records/export", "POST", "200", "250"],
        ["API005", "2026-11-25T09:11:00Z", "analyst02", "192.0.2.30", "/api/search", "GET", "200", "1"]
    ],

    "evidence/cloud-logs/cloud-events.csv": [
        ["event_id", "timestamp", "actor", "source_ip", "event_type", "resource", "result"],
        ["CL001", "2026-11-25T09:03:01Z", "service01", "198.51.100.20", "iam_role_change", "research-role", "success"],
        ["CL002", "2026-11-25T09:05:00Z", "service01", "198.51.100.20", "storage_access", "research-bucket", "success"],
        ["CL003", "2026-11-25T09:06:00Z", "service01", "198.51.100.20", "storage_export", "research-bucket", "success"],
        ["CL004", "2026-11-25T09:12:00Z", "analyst02", "192.0.2.30", "storage_access", "public-reports", "success"]
    ],

    "evidence/endpoint-logs/endpoint-events.csv": [
        ["event_id", "timestamp", "hostname", "username", "process", "parent_process", "event_type"],
        ["EP001", "2026-11-25T09:00:00Z", "ANALYST-01", "analyst01", "browser.exe", "explorer.exe", "process_start"],
        ["EP002", "2026-11-25T09:03:30Z", "APP-SERVER-01", "service01", "python", "service.exe", "process_start"],
        ["EP003", "2026-11-25T09:04:30Z", "APP-SERVER-01", "service01", "curl", "python", "process_start"],
        ["EP004", "2026-11-25T09:10:00Z", "ANALYST-02", "analyst02", "browser.exe", "explorer.exe", "process_start"]
    ],

    "evidence/network-logs/network-events.csv": [
        ["event_id", "timestamp", "source_ip", "destination_ip", "destination_port", "protocol", "bytes_out", "action"],
        ["NW001", "2026-11-25T09:00:10Z", "192.0.2.10", "203.0.113.10", "443", "TCP", "1200", "allowed"],
        ["NW002", "2026-11-25T09:07:00Z", "198.51.100.20", "203.0.113.50", "443", "TCP", "85000000", "allowed"],
        ["NW003", "2026-11-25T09:12:00Z", "192.0.2.30", "203.0.113.10", "443", "TCP", "2500", "allowed"]
    ]
}

for relative_path, rows in datasets.items():
    path = BASE / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerows(rows)

    print(f"[CREATED] {relative_path}: {len(rows) - 1} events")

print(f"\nTotal datasets: {len(datasets)}")
print("Evidence generation completed.")
print("All records are synthetic training data.")
