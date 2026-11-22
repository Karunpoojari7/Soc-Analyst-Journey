import csv
from collections import Counter
from pathlib import Path

INPUT = Path("evidence/endpoint-logs/endpoint-events.csv")
OUTPUT = Path("output/endpoint-analysis.txt")

SUSPICIOUS_PROCESSES = {
    "powershell.exe",
    "archive-tool.exe",
    "unknown.exe",
}

def main():
    with INPUT.open(newline="", encoding="utf-8") as file:
        events = list(csv.DictReader(file))

    findings = []
    process_counts = Counter()

    for event in events:
        process = event["process_name"].lower()
        process_counts[process] += 1

        if process in SUSPICIOUS_PROCESSES:
            findings.append(
                f"REVIEW REQUIRED: "
                f"time={event['timestamp_utc']}; "
                f"host={event['hostname']}; "
                f"user={event['username']}; "
                f"process={process}; "
                f"activity={event['event_type']}; "
                f"severity={event['severity']}"
            )

    lines = [
        "DAY 36 - ENDPOINT INVESTIGATION",
        "Evidence: synthetic training dataset",
        f"Endpoint events reviewed: {len(events)}",
        "",
        "PROCESS FREQUENCY",
    ]

    for process, count in sorted(process_counts.items()):
        lines.append(f"{process}: {count}")

    lines.extend(["", "PROCESS INVESTIGATION FINDINGS"])

    if findings:
        lines.extend(findings)
    else:
        lines.append("No configured process review indicators found.")

    lines.extend([
        "",
        "INVESTIGATION LIMITATIONS",
        "- Process names alone do not establish malicious execution.",
        "- No executable hashes or digital signatures are available.",
        "- No command-line arguments or parent-process details are available.",
        "- Archive activity requires file-level investigation.",
        "- Events are synthetic training evidence.",
    ])

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))
    print(f"\nReport saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
