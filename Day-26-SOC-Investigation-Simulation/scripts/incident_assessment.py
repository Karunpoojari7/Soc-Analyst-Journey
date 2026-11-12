#!/usr/bin/env python3

import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

TRIAGE = BASE / "output/triage-summary.json"
CORRELATION = BASE / "output/event-correlation-report.json"
OUTPUT = BASE / "output/incident-assessment.json"

with TRIAGE.open() as f:
    triage = json.load(f)

with CORRELATION.open() as f:
    correlation = json.load(f)

auth = triage["authentication"]
activity = triage["post_login_activity"]

findings = {
    "repeated_authentication_failures": auth["failed_logins"] >= 5,
    "successful_login": auth["successful_logins"] > 0,
    "session_opened": auth["sessions_opened"] > 0,
    "privileged_activity": activity["privileged_command_events"] > 0,
    "process_execution": activity["process_execution_events"] > 0,
    "outbound_connection": activity["outbound_connection_events"] > 0,
    "account_activity": activity["account_activity_events"] > 0
}

missing_evidence = correlation["evidence_gaps"]

recommendations = [
    "Escalate to Tier 2 SOC for investigation.",
    "Validate the svc-backup account owner and expected access.",
    "Review authentication records and session identifiers.",
    "Obtain complete sudo command and execution status.",
    "Collect process command line, hash and parent process.",
    "Review outbound connection destination and traffic metadata.",
    "Investigate the exact account configuration changes.",
    "Preserve original evidence and maintain chain of custody."
]

if findings["successful_login"] and findings["repeated_authentication_failures"]:
    priority = "HIGH"
else:
    priority = "MEDIUM"

assessment = {
    "incident_id": "SOC-2026-026",
    "host": "nexora-linux-01",
    "account": "svc-backup",
    "source_ip": "198.51.100.23",
    "dataset_type": "SYNTHETIC TRAINING EVIDENCE",
    "observed_findings": findings,
    "investigation_priority": priority,
    "classification": "UNDER_INVESTIGATION",
    "compromise_confirmed": False,
    "escalation": {
        "required": True,
        "destination": "Tier 2 SOC / Incident Response Team",
        "reason": "Successful authentication followed by multiple suspicious activity indicators."
    },
    "missing_evidence": missing_evidence,
    "recommended_actions": recommendations,
    "containment": {
        "status": "RECOMMENDATION_ONLY",
        "actions": [
            "Review and validate account access.",
            "Consider session revocation if unauthorised access is confirmed.",
            "Consider endpoint isolation if compromise is confirmed.",
            "Preserve evidence before remediation."
        ]
    }
}

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w") as f:
    json.dump(assessment, f, indent=4)

print("===== INCIDENT ASSESSMENT =====")
print("Incident:", assessment["incident_id"])
print("Priority:", priority)
print("Classification:", assessment["classification"])
print("Confirmed compromise:", assessment["compromise_confirmed"])
print("Escalation required:", assessment["escalation"]["required"])
print("Missing evidence:", len(missing_evidence))
print("Recommended actions:", len(recommendations))
print("Output:", OUTPUT.relative_to(BASE))
