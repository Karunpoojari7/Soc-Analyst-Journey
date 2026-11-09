#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<message>.*)$"
)

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()

def parse_event(line, line_number):
    match = PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    message = data["message"]

    event_type = "other"
    username = None
    source_ip = None

    failed = re.search(
        r"Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)",
        message
    )
    accepted = re.search(
        r"Accepted (?:password|publickey) for (\S+) from ([0-9a-fA-F:.]+)",
        message
    )
    invalid = re.search(
        r"Invalid user (\S+) from ([0-9a-fA-F:.]+)",
        message
    )
    session = re.search(
        r"session opened for user (\S+)",
        message
    )

    if failed:
        event_type = "failed_login"
        username, source_ip = failed.groups()
    elif accepted:
        event_type = "successful_login"
        username, source_ip = accepted.groups()
    elif invalid:
        event_type = "invalid_user"
        username, source_ip = invalid.groups()
    elif session:
        event_type = "session_opened"
        username = session.group(1)

    return {
        "line_number": line_number,
        "timestamp": data["timestamp"],
        "host": data["host"],
        "pid": data["pid"],
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "message": message
    }

def analyze(path):
    events = []
    unmatched_lines = 0

    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        event = parse_event(line, number)
        if event:
            events.append(event)
        else:
            unmatched_lines += 1

    counts = Counter(event["event_type"] for event in events)
    failures_by_ip = defaultdict(int)
    successes_by_ip = defaultdict(int)

    for event in events:
        ip = event["source_ip"]
        if not ip:
            continue
        if event["event_type"] == "failed_login":
            failures_by_ip[ip] += 1
        elif event["event_type"] == "successful_login":
            successes_by_ip[ip] += 1

    correlations = []
    for success in events:
        if success["event_type"] != "successful_login":
            continue

        ip = success["source_ip"]
        username = success["username"]

        prior_failures = [
            event for event in events
            if event["event_type"] == "failed_login"
            and event["source_ip"] == ip
            and event["timestamp"] <= success["timestamp"]
        ]

        if prior_failures:
            correlations.append({
                "source_ip": ip,
                "username": username,
                "successful_login_time": success["timestamp"],
                "prior_failed_attempts_from_source": len(prior_failures),
                "assessment": "REVIEW_REQUIRED"
            })

    indicators = []
    if sum(failures_by_ip.values()) >= 5:
        indicators.append("Five or more failed login events observed")
    if correlations:
        indicators.append("Successful authentication followed failures from the same source")

    assessment = "REVIEW REQUIRED" if indicators else "NO SELECTED INDICATORS"

    return {
        "dataset_type": "SYNTHETIC TRAINING EVIDENCE",
        "source_file": path.name,
        "source_sha256": sha256_file(path),
        "total_parsed_events": len(events),
        "unmatched_lines": unmatched_lines,
        "event_counts": dict(counts),
        "failed_attempts_by_source": dict(failures_by_ip),
        "successful_logins_by_source": dict(successes_by_ip),
        "correlations": correlations,
        "investigation_indicators": indicators,
        "assessment": assessment,
        "events": events,
        "limitations": [
            "Synthetic training data, not real host telemetry",
            "Correlation uses source IP and event ordering only",
            "No account owner or business context was validated",
            "No endpoint, network, or identity telemetry was correlated",
            "A successful login after failures does not prove compromise",
            "Timestamp year and timezone were not independently verified"
        ]
    }

def main():
    parser = argparse.ArgumentParser(
        description="Offline Linux SSH authentication incident analyzer"
    )
    parser.add_argument("log_file")
    parser.add_argument(
        "--output",
        default="output/ir-auth-investigation.json"
    )
    args = parser.parse_args()

    source = Path(args.log_file)
    output = Path(args.output)

    if not source.is_file():
        parser.error("Input evidence file does not exist")

    if source.resolve() == output.resolve():
        parser.error("Output cannot overwrite original evidence")

    report = analyze(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=4) + "\n", encoding="utf-8")

    print(json.dumps({
        "dataset_type": report["dataset_type"],
        "total_parsed_events": report["total_parsed_events"],
        "event_counts": report["event_counts"],
        "failed_attempts_by_source": report["failed_attempts_by_source"],
        "correlations": report["correlations"],
        "investigation_indicators": report["investigation_indicators"],
        "assessment": report["assessment"],
        "output": str(output)
    }, indent=4))

if __name__ == "__main__":
    main()
