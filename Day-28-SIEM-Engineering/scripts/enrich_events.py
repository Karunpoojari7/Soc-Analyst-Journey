#!/usr/bin/env python3

import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "data/normalized/events.jsonl"
ASSETS = BASE / "data/asset-inventory.json"
OUTPUT = BASE / "data/normalized/enriched-events.jsonl"


def main():
    with ASSETS.open() as file:
        inventory = json.load(file)

    count = 0

    with INPUT.open() as source, OUTPUT.open("w") as destination:
        for line in source:
            if not line.strip():
                continue

            event = json.loads(line)

            asset = inventory.get(event["host"], {})

            event["enrichment"] = {
                "asset_criticality": asset.get(
                    "asset_criticality", "UNKNOWN"
                ),
                "asset_type": asset.get("asset_type", "UNKNOWN"),
                "environment": asset.get("environment", "UNKNOWN"),
                "known_service_account": (
                    event["username"] == "svc-backup"
                )
            }

            destination.write(json.dumps(event) + "\n")
            count += 1

    print("Event enrichment completed.")
    print("Events enriched:", count)


if __name__ == "__main__":
    main()
