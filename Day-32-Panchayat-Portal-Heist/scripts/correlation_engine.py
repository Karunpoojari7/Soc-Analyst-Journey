
import json
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parents[1]
RAW_DIR = BASE_DIR / "data" / "raw"
ALERT_DIR = BASE_DIR / "output" / "alerts"
REPORT_DIR = BASE_DIR / "investigation"

REPORT_DIR.mkdir(parents=True, exist_ok=True)

AUTH_FILE = RAW_DIR / "authentication.jsonl"
MFA_FILE = RAW_DIR / "mfa-events.jsonl"
TXN_FILE = RAW_DIR / "transactions.jsonl"

AUTH_ALERTS_FILE = ALERT_DIR / "authentication-alerts.json"
MFA_ALERTS_FILE = ALERT_DIR / "mfa-alerts.json"
TXN_ALERTS_FILE = ALERT_DIR / "financial-fraud-alerts.json"


def load_jsonl(path):
    records = []
    with path.open(encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON in {path.name}, "
                    f"line {line_number}: {error}"
                ) from error
    return records


def load_json(path):
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# LOAD EVIDENCE

auth_events = load_jsonl(AUTH_FILE)
mfa_events = load_jsonl(MFA_FILE)
transactions = load_jsonl(TXN_FILE)

auth_alerts = load_json(AUTH_ALERTS_FILE)
mfa_alerts = load_json(MFA_ALERTS_FILE)
txn_alerts = load_json(TXN_ALERTS_FILE)


# IDENTIFY SUSPICIOUS INDICATORS

suspicious_sessions = set()

for alert in auth_alerts + mfa_alerts + txn_alerts:
    session_id = alert.get("evidence", {}).get("session_id")
    if session_id:
        suspicious_sessions.add(session_id)

suspicious_users = set()
suspicious_ips = set()

for alert in auth_alerts + mfa_alerts:
    if alert.get("severity") in ("HIGH", "CRITICAL"):
        username = alert.get("username")
        source_ip = alert.get("source_ip")

        if username:
            suspicious_users.update(
                item.strip() for item in username.split(",")
                if item.strip()
            )

        if source_ip:
            suspicious_ips.add(source_ip)


# DEFINE THE INCIDENT WINDOW
# Start at the first suspicious account/IP authentication event.
# End at the last transaction associated with a suspicious session.

anchor_events = [
    event for event in auth_events
    if event.get("username") in suspicious_users
    and event.get("source_ip") in suspicious_ips
    and (
        event.get("status", "").lower() == "failure"
        or event.get("session_id") in suspicious_sessions
    )
]

correlated_transaction_candidates = [
    event for event in transactions
    if event.get("session_id") in suspicious_sessions
]

if anchor_events and correlated_transaction_candidates:
    incident_start = min(
        parse_time(event["timestamp"]) for event in anchor_events
    )
    incident_end = max(
        parse_time(event["timestamp"])
        for event in correlated_transaction_candidates
    )
else:
    incident_start = None
    incident_end = None


def classify_event(event):
    session_id = event.get("session_id")

    # Exact suspicious session linkage is the strongest
    # available correlation in this synthetic telemetry.
    if session_id and session_id in suspicious_sessions:
        return "STRONG"

    username = event.get("username")
    source_ip = event.get("source_ip")

    if (
        incident_start is not None
        and incident_end is not None
        and username in suspicious_users
        and source_ip in suspicious_ips
    ):
        event_time = parse_time(event["timestamp"])

        if incident_start <= event_time <= incident_end:
            return "SUPPORTING"

    return None


# BUILD CORRELATED TIMELINE

timeline = []

for event in auth_events:
    evidence_level = classify_event(event)

    if evidence_level:
        timeline.append({
            "timestamp": event["timestamp"],
            "category": "AUTHENTICATION",
            "event_id": event["event_id"],
            "description": (
                f"{event['username']} authentication "
                f"{event['status']} from {event['source_ip']}"
            ),
            "session_id": event.get("session_id"),
            "source_ip": event.get("source_ip"),
            "evidence_level": evidence_level
        })


for event in mfa_events:
    evidence_level = classify_event(event)

    if evidence_level:
        timeline.append({
            "timestamp": event["timestamp"],
            "category": "MFA",
            "event_id": event["event_id"],
            "description": (
                f"{event['username']} "
                f"{event['event_type']} from {event['source_ip']}"
            ),
            "session_id": event.get("session_id"),
            "source_ip": event.get("source_ip"),
            "evidence_level": evidence_level
        })


correlated_transactions = []

for event in transactions:
    if event.get("session_id") in suspicious_sessions:
        correlated_transactions.append(event)

        timeline.append({
            "timestamp": event["timestamp"],
            "category": "FINANCIAL_TRANSACTION",
            "event_id": event["transaction_id"],
            "description": (
                f"{event['status']} payment of "
                f"INR {event['amount_inr']:,} to "
                f"{event['beneficiary_id']}"
            ),
            "session_id": event.get("session_id"),
            "source_ip": None,
            "evidence_level": "STRONG"
        })


timeline.sort(
    key=lambda event: parse_time(event["timestamp"])
)


# CALCULATE FINANCIAL EXPOSURE

approved_transactions = [
    event for event in correlated_transactions
    if event["status"] == "approved"
]

financial_exposure = sum(
    event["amount_inr"] for event in approved_transactions
)

new_beneficiaries = sorted({
    event["beneficiary_id"]
    for event in correlated_transactions
    if event["beneficiary_status"] == "new"
})

strong_count = sum(
    event["evidence_level"] == "STRONG"
    for event in timeline
)

supporting_count = sum(
    event["evidence_level"] == "SUPPORTING"
    for event in timeline
)


# BUILD UNIFIED INCIDENT

incident = {
    "incident_id": "INC-DAY32-001",
    "incident_title": "Suspected Financial Portal Account Takeover",
    "severity": "CRITICAL",
    "status": "OPEN - INVESTIGATION REQUIRED",
    "classification": "SIMULATED SECURITY INCIDENT",
    "generated_at": datetime.now(timezone.utc).isoformat(),

    "suspicious_users": sorted(suspicious_users),
    "suspicious_ips": sorted(suspicious_ips),
    "suspicious_sessions": sorted(suspicious_sessions),

    "evidence_summary": {
        "authentication_events": len(auth_events),
        "mfa_events": len(mfa_events),
        "authentication_alerts": len(auth_alerts),
        "mfa_alerts": len(mfa_alerts),
        "financial_alerts": len(txn_alerts),
        "correlated_transactions": len(correlated_transactions),
        "approved_transactions": len(approved_transactions),
        "strong_timeline_events": strong_count,
        "supporting_timeline_events": supporting_count
    },

    "financial_exposure_inr": financial_exposure,
    "new_beneficiaries": new_beneficiaries,

    "transaction_ids": [
        event["transaction_id"]
        for event in correlated_transactions
    ],

    "timeline": timeline,

    "investigation_assessment": (
        "The synthetic evidence shows authentication and MFA activity "
        "associated with a session subsequently used for multiple "
        "financial transactions. Exact session linkage is classified "
        "as strong correlation within this dataset. Related account "
        "and IP activity outside that session is supporting evidence. "
        "These findings justify further investigation but do not "
        "establish the real-world cause of authentication approval "
        "or prove criminal intent."
    ),

    "recommended_actions": [
        "Preserve original authentication, MFA and transaction logs.",
        "Request authorised suspension of affected sessions.",
        "Ask payment operations to review and hold pending transfers.",
        "Verify beneficiary changes and approvals with authorised officials.",
        "Review maker-checker access and audit records.",
        "Notify authorised incident response and banking teams."
    ]
}


# SAVE UNIFIED INCIDENT

incident_file = REPORT_DIR / "unified-incident.json"

with incident_file.open("w", encoding="utf-8") as file:
    json.dump(incident, file, indent=4)


# GENERATE ATTACK TIMELINE REPORT

timeline_file = REPORT_DIR / "attack-timeline.md"

with timeline_file.open("w", encoding="utf-8") as file:
    file.write("# Day 32 - Correlated Incident Timeline\n\n")
    file.write("Synthetic defensive SOC investigation.\n\n")
    file.write("| Timestamp | Category | Evidence | Event ID | Description |\n")
    file.write("|---|---|---|---|---|\n")

    for event in timeline:
        description = event["description"].replace("|", "\\|")
        file.write(
            f"| {event['timestamp']} "
            f"| {event['category']} "
            f"| {event['evidence_level']} "
            f"| {event['event_id']} "
            f"| {description} |\n"
        )

    file.write("\n## Evidence Summary\n\n")
    file.write(f"- Strong timeline events: {strong_count}\n")
    file.write(f"- Supporting timeline events: {supporting_count}\n")
    file.write(f"- Correlated transactions: {len(correlated_transactions)}\n")
    file.write(f"- Approved financial exposure: INR {financial_exposure:,}\n")

print("Correlation engine completed successfully.")
print("Incident:", incident["incident_id"])
print("Suspicious sessions:", len(suspicious_sessions))
print("Correlated transactions:", len(correlated_transactions))
print("Financial exposure: INR", f"{financial_exposure:,}")
print("Strong timeline events:", strong_count)
print("Supporting timeline events:", supporting_count)
print("Total timeline events:", len(timeline))
print("Incident saved:", incident_file)
print("Timeline saved:", timeline_file)
