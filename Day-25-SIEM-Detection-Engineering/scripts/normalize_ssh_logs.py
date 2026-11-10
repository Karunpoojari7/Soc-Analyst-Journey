import json
import re
from pathlib import Path

INPUT = Path("evidence/raw/ssh-auth-events.log")
OUTPUT = Path("evidence/working/normalized-ssh-events.json")

PREFIX = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)

FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<source_ip>\S+)"
)

ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<username>\S+) "
    r"from (?P<source_ip>\S+)"
)

SESSION = re.compile(r"session opened for user (?P<username>\S+)")

events = []

for line_number, line in enumerate(INPUT.read_text().splitlines(), 1):
    match = PREFIX.match(line)

    if not match:
        print(f"WARNING: Unparsed line {line_number}")
        continue

    data = match.groupdict()
    message = data["message"]

    event = {
        "timestamp": data["timestamp"],
        "hostname": data["hostname"],
        "process_id": int(data["pid"]),
        "event_type": "unknown",
        "username": None,
        "source_ip": None,
        "authentication_method": None,
        "raw_message": message,
    }

    failed = FAILED.search(message)
    accepted = ACCEPTED.search(message)
    session = SESSION.search(message)

    if failed:
        event.update({
            "event_type": "failed_login",
            "username": failed.group("username"),
            "source_ip": failed.group("source_ip"),
            "authentication_method": "password",
        })
    elif accepted:
        event.update({
            "event_type": "successful_login",
            "username": accepted.group("username"),
            "source_ip": accepted.group("source_ip"),
            "authentication_method": accepted.group("method"),
        })
    elif session:
        event.update({
            "event_type": "session_opened",
            "username": session.group("username"),
        })

    events.append(event)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(events, indent=2) + "\n")

from collections import Counter

print("DATASET: SYNTHETIC TRAINING EVIDENCE")
print(f"Input lines: {len(INPUT.read_text().splitlines())}")
print(f"Parsed events: {len(events)}")
print(f"Event counts: {dict(Counter(e['event_type'] for e in events))}")
print(f"Output: {OUTPUT}")
