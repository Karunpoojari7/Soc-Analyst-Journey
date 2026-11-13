#!/usr/bin/env python3

import json
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
OUTPUT = BASE / "output/authentication-findings.json"


def main():
    result = subprocess.run(
        [
            "journalctl", "--since", "24 hours ago",
            "--no-pager", "-o", "cat"
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False
    )

    lines = result.stdout.splitlines()

    keywords = (
        "failed password",
        "authentication failure",
        "accepted password",
        "accepted publickey"
    )

    matches = [
        line for line in lines
        if any(word in line.lower() for word in keywords)
    ]

    output = {
        "hunt": "AUTHENTICATION_HUNT",
        "collection_source": "systemd journal",
        "matching_event_count": len(matches),
        "events": [],
        "raw_log_exported": False,
        "limitations": [
            "Authentication events may be incomplete.",
            "No username or source IP is exported.",
            "Journal retention affects investigation coverage."
        ]
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w") as file:
        json.dump(output, file, indent=4)

    print("Authentication hunt completed.")
    print("Matching events:", len(matches))
    print("Raw logs exported: No")


if __name__ == "__main__":
    main()
