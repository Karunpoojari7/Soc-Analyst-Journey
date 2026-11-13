#!/usr/bin/env python3

import json
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

SCRIPTS = [
    "collect_endpoint.py",
    "hunt_processes.py",
    "hunt_network.py",
    "hunt_authentication.py",
    "hunt_persistence.py"
]


def main():
    results = []

    for script in SCRIPTS:
        path = BASE / "scripts" / script

        run = subprocess.run(
            [sys.executable, "-B", str(path)],
            capture_output=True,
            text=True,
            timeout=45,
            check=False
        )

        results.append({
            "script": script,
            "return_code": run.returncode,
            "status": "PASS" if run.returncode == 0 else "FAIL"
        })

        print(run.stdout)

        if run.returncode != 0:
            print(run.stderr)
            raise SystemExit(f"Investigation failed: {script}")

    report = {
        "project": "Day 27 Linux Threat Hunting",
        "dataset_type": "SANITIZED REAL ENDPOINT TELEMETRY",
        "execution_status": "COMPLETED",
        "confirmed_compromise": False,
        "investigation_modules": results,
        "interpretation": (
            "The automation produces investigation candidates. "
            "It does not independently establish compromise."
        )
    }

    output = BASE / "output/final-hunt-results.json"

    with output.open("w") as file:
        json.dump(report, file, indent=4)

    print("===== THREAT HUNT SUMMARY =====")

    for result in results:
        print(result["script"], result["status"])

    print("Final report:", output.relative_to(BASE))


if __name__ == "__main__":
    main()
