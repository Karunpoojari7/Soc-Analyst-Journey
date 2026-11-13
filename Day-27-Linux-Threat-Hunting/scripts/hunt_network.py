#!/usr/bin/env python3

import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

INPUT = BASE / "evidence/working/endpoint-baseline.json"
OUTPUT = BASE / "output/network-findings.json"


def main():
    with INPUT.open() as file:
        data = json.load(file)

    listeners = data["listening_sockets"]
    connections = data["network_connections"]

    result = {
        "hunt": "NETWORK_HUNT",
        "listening_socket_count": len(listeners),
        "active_connection_count": len(connections),
        "findings": [],
        "classification": "BASELINE_REVIEW_REQUIRED",
        "limitations": [
            "Endpoint addresses were intentionally redacted.",
            "Socket ownership was not collected.",
            "No external reputation checks were performed."
        ]
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w") as file:
        json.dump(result, file, indent=4)

    print("Network hunt completed.")
    print("Listening sockets:", len(listeners))
    print("Connections:", len(connections))


if __name__ == "__main__":
    main()
