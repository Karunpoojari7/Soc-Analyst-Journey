#!/usr/bin/env python3

import json
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
OUTPUT = BASE / "output/persistence-findings.json"

LOCATIONS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly"
]


def main():
    entries = []

    for location in LOCATIONS:
        path = Path(location)

        if path.exists():
            for item in path.iterdir():
                entries.append({
                    "location": location,
                    "entry_type": "DIRECTORY" if item.is_dir() else "FILE",
                    "name": item.name
                })

    timers = subprocess.run(
        ["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False
    )

    result = {
        "hunt": "PERSISTENCE_HUNT",
        "cron_entries": entries,
        "cron_entry_count": len(entries),
        "systemd_timer_output_available": timers.returncode == 0,
        "systemd_timer_count": len(timers.stdout.splitlines()),
        "classification": "REVIEW_REQUIRED",
        "limitations": [
            "Entries are not automatically malicious.",
            "File contents are not collected.",
            "User-specific and alternate persistence locations are not fully covered."
        ]
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w") as file:
        json.dump(result, file, indent=4)

    print("Persistence hunt completed.")
    print("Cron entries:", len(entries))
    print("Systemd timer lines:", result["systemd_timer_count"])


if __name__ == "__main__":
    main()
