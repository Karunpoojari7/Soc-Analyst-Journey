#!/usr/bin/env python3

import json
import os
import platform
import pwd
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
OUTPUT = BASE / "evidence/working/endpoint-baseline.json"


def run_command(args):
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )
        return result.stdout.strip().splitlines()
    except (OSError, subprocess.TimeoutExpired):
        return []


def collect_processes():
    rows = run_command([
        "ps", "-eo", "pid,ppid,user,comm", "--no-headers"
    ])

    processes = []

    for row in rows:
        parts = row.strip().split(None, 3)

        if len(parts) == 4:
            processes.append({
                "pid": parts[0],
                "ppid": parts[1],
                "user": "REDACTED",
                "name": parts[3]
            })

    return processes


def collect_listeners():
    rows = run_command(["ss", "-lntuH"])
    listeners = []

    for row in rows:
        parts = row.split()

        if len(parts) >= 5:
            listeners.append({
                "protocol": parts[0],
                "state": parts[1],
                "local_endpoint": "REDACTED",
            })

    return listeners


def collect_connections():
    rows = run_command(["ss", "-tunH"])
    connections = []

    for row in rows:
        parts = row.split()

        if len(parts) >= 5:
            connections.append({
                "protocol": parts[0],
                "state": parts[1],
                "local_endpoint": "REDACTED",
                "remote_endpoint": "REDACTED"
            })

    return connections


def collect_services():
    rows = run_command([
        "systemctl", "--type=service", "--state=running",
        "--no-legend", "--no-pager"
    ])

    services = []

    for row in rows:
        parts = row.split()

        if parts:
            services.append(parts[0])

    return services


def collect_sessions():
    rows = run_command(["who"])
    return len(rows)


def collect_cron_directories():
    locations = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly"
    ]

    results = []

    for location in locations:
        path = Path(location)

        if path.exists():
            results.append({
                "location": location,
                "entry_count": sum(1 for _ in path.iterdir())
            })

    return results


def main():
    evidence = {
        "collection_time_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_type": "SANITIZED REAL ENDPOINT TELEMETRY",
        "platform": platform.system(),
        "kernel": platform.release(),
        "processes": collect_processes(),
        "listening_sockets": collect_listeners(),
        "network_connections": collect_connections(),
        "running_services": collect_services(),
        "active_session_count": collect_sessions(),
        "cron_directories": collect_cron_directories()
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w") as file:
        json.dump(evidence, file, indent=4)

    print("Endpoint telemetry collection completed.")
    print("Processes:", len(evidence["processes"]))
    print("Listening sockets:", len(evidence["listening_sockets"]))
    print("Network connections:", len(evidence["network_connections"]))
    print("Running services:", len(evidence["running_services"]))
    print("Active sessions:", evidence["active_session_count"])
    print("Output:", OUTPUT.relative_to(BASE))


if __name__ == "__main__":
    main()
