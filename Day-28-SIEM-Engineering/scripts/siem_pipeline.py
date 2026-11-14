#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

PIPELINE = [
    "ingest_events.py",
    "normalize_events.py",
    "detect_authentication.py",
    "correlate_events.py"
]


def main():
    print("================================")
    print(" NEXORA LOCAL SIEM PIPELINE")
    print("================================")

    for script in PIPELINE:
        path = BASE / "scripts" / script

        print("\nExecuting:", script)

        result = subprocess.run(
            [sys.executable, "-B", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )

        print(result.stdout)

        if result.returncode != 0:
            print(result.stderr)
            raise SystemExit("Pipeline failed at " + script)

    print("================================")
    print(" SIEM PIPELINE COMPLETED")
    print("================================")


if __name__ == "__main__":
    main()
