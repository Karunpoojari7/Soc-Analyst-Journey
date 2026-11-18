
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta, timezone

BASE_DIR = Path(__file__).resolve().parents[1]

RAW_DIR = BASE_DIR / "data" / "raw"
ALERT_DIR = BASE_DIR / "output" / "alerts"

ALERT_DIR.mkdir(parents=True, exist_ok=True)

TRANSACTION_FILE = RAW_DIR / "transactions.jsonl"
AUTH_ALERT_FILE = ALERT_DIR / "authentication-alerts.json"
MFA_ALERT_FILE = ALERT_DIR / "mfa-alerts.json"

# Configurable detection thresholds
HIGH_VALUE_THRESHOLD = 1_000_000
BURST_WINDOW_MINUTES = 15
BURST_MINIMUM_TRANSACTIONS = 3
PAIR_MINIMUM_TRANSACTIONS = 3

alerts = []


def load_jsonl(path):
    records = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON in {path.name}, line {line_number}: {error}"
                )

    return records


def load_json(path):
    if not path.exists():
        print(f"[!] Optional alert file not found: {path.name}")
        return []

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def add_alert(rule_id, severity, title, description, evidence):

    alerts.append({
        "alert_id": f"DAY32-{rule_id}-{len(alerts) + 1:03}",
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "generated_at": datetime.now(timezone.utc).isoformat()
    })


# -------------------------------------------------
# LOAD TRANSACTION DATA
# -------------------------------------------------

transactions = load_jsonl(TRANSACTION_FILE)

transactions.sort(
    key=lambda event: parse_time(event["timestamp"])
)

authentication_alerts = load_json(AUTH_ALERT_FILE)
mfa_alerts = load_json(MFA_ALERT_FILE)

print("\n========== FINANCIAL FRAUD INVESTIGATION ==========")

print(f"Transactions loaded: {len(transactions)}")


# -------------------------------------------------
# RULE TXN-001:
# HIGH-VALUE PAYMENTS TO NEW BENEFICIARIES
# -------------------------------------------------

for transaction in transactions:

    if (
        transaction["beneficiary_status"] == "new"
        and transaction["amount_inr"] >= HIGH_VALUE_THRESHOLD
        and transaction["status"] == "approved"
    ):
        add_alert(
            "TXN-001",
            "HIGH",
            "High-Value Payment to New Beneficiary",
            "An approved high-value payment was made to a newly introduced beneficiary.",
            {
                "transaction_id": transaction["transaction_id"],
                "beneficiary_id": transaction["beneficiary_id"],
                "amount_inr": transaction["amount_inr"],
                "maker": transaction["maker"],
                "checker": transaction["checker"],
                "timestamp": transaction["timestamp"]
            }
        )


# -------------------------------------------------
# RULE TXN-002:
# RAPID HIGH-VALUE TRANSACTIONS
# -------------------------------------------------

high_value_transactions = [
    transaction for transaction in transactions
    if transaction["amount_inr"] >= HIGH_VALUE_THRESHOLD
    and transaction["status"] == "approved"
]

# Group transactions by maker.
maker_groups = defaultdict(list)

for transaction in high_value_transactions:
    maker_groups[transaction["maker"]].append(transaction)

# Merge overlapping rolling transaction windows.
for maker, maker_transactions in maker_groups.items():

    maker_transactions.sort(
        key=lambda event: parse_time(event["timestamp"])
    )

    clusters = []
    current_cluster = []

    for transaction in maker_transactions:

        if not current_cluster:
            current_cluster.append(transaction)
            continue

        previous_time = parse_time(
            current_cluster[-1]["timestamp"]
        )

        current_time = parse_time(transaction["timestamp"])

        if current_time - previous_time <= timedelta(
            minutes=BURST_WINDOW_MINUTES
        ):
            current_cluster.append(transaction)
        else:
            clusters.append(current_cluster)
            current_cluster = [transaction]

    if current_cluster:
        clusters.append(current_cluster)

    # Generate one alert per merged cluster.
    for cluster in clusters:

        if len(cluster) < BURST_MINIMUM_TRANSACTIONS:
            continue

        transaction_ids = [
            transaction["transaction_id"]
            for transaction in cluster
        ]

        total_amount = sum(
            transaction["amount_inr"]
            for transaction in cluster
        )

        add_alert(
            "TXN-002",
            "CRITICAL",
            "Rapid High-Value Transaction Burst",
            "Multiple high-value approved transactions by one maker "
            "were detected in overlapping transaction windows.",
            {
                "maker": maker,
                "transaction_count": len(cluster),
                "transaction_ids": transaction_ids,
                "total_amount_inr": total_amount,
                "window_minutes": BURST_WINDOW_MINUTES,
                "window_start": cluster[0]["timestamp"],
                "window_end": cluster[-1]["timestamp"],
                "correlation_method": "overlapping_window_merge"
            }
        )


# -------------------------------------------------
# RULE TXN-003:
# REPEATED MAKER-CHECKER PAIRING
# -------------------------------------------------

pair_groups = defaultdict(list)

for transaction in transactions:

    if (
        transaction["beneficiary_status"] == "new"
        and transaction["amount_inr"] >= HIGH_VALUE_THRESHOLD
        and transaction["status"] == "approved"
    ):
        pair = (
            transaction["maker"],
            transaction["checker"]
        )

        pair_groups[pair].append(transaction)

for (maker, checker), group in pair_groups.items():

    if len(group) >= PAIR_MINIMUM_TRANSACTIONS:

        add_alert(
            "TXN-003",
            "HIGH",
            "Repeated Maker-Checker Pairing",
            "The same maker-checker pair approved multiple high-value payments to new beneficiaries.",
            {
                "maker": maker,
                "checker": checker,
                "transaction_count": len(group),
                "transaction_ids": [
                    transaction["transaction_id"]
                    for transaction in group
                ],
                "total_amount_inr": sum(
                    transaction["amount_inr"]
                    for transaction in group
                )
            }
        )


# -------------------------------------------------
# BUILD SUSPICIOUS SESSION INTELLIGENCE
# -------------------------------------------------

suspicious_sessions = set()

for alert in authentication_alerts + mfa_alerts:

    evidence = alert.get("evidence", {})

    session_id = evidence.get("session_id")

    if session_id:
        suspicious_sessions.add(session_id)

    # AUTH-002 stores its session in successful-event evidence.
    # MFA-003 stores its session in approval-event evidence.


# -------------------------------------------------
# RULE TXN-004:
# TRANSACTION LINKED TO SUSPICIOUS SESSION
# -------------------------------------------------

for transaction in transactions:

    session_id = transaction.get("session_id")

    if (
        session_id in suspicious_sessions
        and transaction["status"] == "approved"
    ):
        add_alert(
            "TXN-004",
            "CRITICAL",
            "Financial Transaction Linked to Suspicious Session",
            "An approved financial transaction used a session associated with authentication or MFA alerts.",
            {
                "transaction_id": transaction["transaction_id"],
                "session_id": session_id,
                "maker": transaction["maker"],
                "beneficiary_id": transaction["beneficiary_id"],
                "amount_inr": transaction["amount_inr"],
                "timestamp": transaction["timestamp"]
            }
        )


# -------------------------------------------------
# FINANCIAL EXPOSURE CALCULATION
# -------------------------------------------------

approved_total = sum(
    transaction["amount_inr"]
    for transaction in transactions
    if transaction["status"] == "approved"
)

new_beneficiary_total = sum(
    transaction["amount_inr"]
    for transaction in transactions
    if (
        transaction["beneficiary_status"] == "new"
        and transaction["status"] == "approved"
    )
)

suspicious_session_total = sum(
    transaction["amount_inr"]
    for transaction in transactions
    if (
        transaction.get("session_id") in suspicious_sessions
        and transaction["status"] == "approved"
    )
)


# -------------------------------------------------
# SAVE ALERTS AND SUMMARY
# -------------------------------------------------

alert_file = ALERT_DIR / "financial-fraud-alerts.json"

with alert_file.open("w", encoding="utf-8") as file:
    json.dump(alerts, file, indent=4)

summary = {
    "total_transactions": len(transactions),
    "approved_transaction_value_inr": approved_total,
    "new_beneficiary_value_inr": new_beneficiary_total,
    "suspicious_session_value_inr": suspicious_session_total,
    "suspicious_sessions": sorted(suspicious_sessions),
    "alerts_generated": len(alerts)
}

summary_file = BASE_DIR / "output" / "financial-summary.json"

with summary_file.open("w", encoding="utf-8") as file:
    json.dump(summary, file, indent=4)


# -------------------------------------------------
# DISPLAY RESULTS
# -------------------------------------------------

print("\n========== INVESTIGATION SUMMARY ==========")

print(f"Total transactions       : {len(transactions)}")
print(f"Approved transaction value: ₹{approved_total:,}")
print(f"New beneficiary value    : ₹{new_beneficiary_total:,}")
print(f"Suspicious session value : ₹{suspicious_session_total:,}")
print(f"Suspicious sessions      : {len(suspicious_sessions)}")
print(f"Alerts generated         : {len(alerts)}")

for alert in alerts:

    print("\n-------------------------------------------")
    print(f"Alert ID : {alert['alert_id']}")
    print(f"Rule     : {alert['rule_id']}")
    print(f"Severity : {alert['severity']}")
    print(f"Title    : {alert['title']}")

print("\n[+] Financial investigation completed.")
print(f"[+] Alerts: {alert_file}")
print(f"[+] Summary: {summary_file}")
