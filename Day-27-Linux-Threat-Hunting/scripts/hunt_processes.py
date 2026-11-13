#!/usr/bin/env python3

import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
INPUT = BASE / "evidence/working/endpoint-baseline.json"
OUTPUT = BASE / "output/process-findings.json"


def main():
    with INPUT.open() as file:
        data = json.load(file)

    processes = data["processes"]

    findings = []

    for process in processes:
        name = process["name"].lower()

        reasons = []

        if name in {"nc", "ncat", "netcat"}:
            reasons.append("Network utility requires contextual review")

        if name in {"socat", "chisel"}:
            reasons.append("Tunnelling utility requires contextual review")

        if name in {"xmrig", "minerd"}:
            reasons.append("Known mining-related process name requires validation")

        if reasons:
            findings.append({
                "pid": process["pid"],
                "process_name": process["name"],
                "classification": "REVIEW_REQUIRED",
                "reasons": reasons
            })

    result = {
        "hunt": "PROCESS_HUNT",
        "total_processes": len(processes),
        "findings": findings,
        "finding_count": len(findings),
        "confirmed_malicious": False
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w") as file:
        json.dump(result, file, indent=4)

    print("Process hunt completed.")
    print("Processes reviewed:", len(processes))
    print("Review candidates:", len(findings))
    print("Confirmed malicious:", False)


if __name__ == "__main__":
    main()
