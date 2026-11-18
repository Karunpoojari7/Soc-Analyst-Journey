
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

BASE_DIR = Path(__file__).resolve().parents[1]
RAW_DIR = BASE_DIR / "data" / "raw"
RAW_DIR.mkdir(parents=True, exist_ok=True)

BASE_TIME = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)


def timestamp(minutes):
    return (BASE_TIME + timedelta(minutes=minutes)).isoformat()


def write_jsonl(filename, records):
    path = RAW_DIR / filename

    with path.open("w", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record) + "\n")

    print(f"[+] Created {filename}: {len(records)} events")


# -------------------------------------------------
# 1. AUTHENTICATION EVENTS
# -------------------------------------------------

authentication = [
    {
        "event_id": "AUTH-001",
        "timestamp": timestamp(0),
        "username": "bdo_mandapam_01",
        "source_ip": "192.0.2.10",
        "device_id": "DEVICE-M01",
        "status": "success",
        "session_id": "SESSION-M001"
    },
    {
        "event_id": "AUTH-002",
        "timestamp": timestamp(2),
        "username": "bdo_dharapuram_01",
        "source_ip": "192.0.2.20",
        "device_id": "DEVICE-D01",
        "status": "success",
        "session_id": "SESSION-D001"
    },
    {
        "event_id": "AUTH-003",
        "timestamp": timestamp(5),
        "username": "bdo_nagapattinam_01",
        "source_ip": "192.0.2.30",
        "device_id": "DEVICE-N01",
        "status": "success",
        "session_id": "SESSION-N001"
    },
]

# Repeated failures followed by successful authentication
for index in range(4):
    authentication.append({
        "event_id": f"AUTH-{10 + index:03}",
        "timestamp": timestamp(15 + index),
        "username": "bdo_mandapam_01",
        "source_ip": "198.51.100.25",
        "device_id": "UNKNOWN-DEVICE-77",
        "status": "failure",
        "session_id": None
    })

authentication.extend([
    {
        "event_id": "AUTH-020",
        "timestamp": timestamp(20),
        "username": "bdo_mandapam_01",
        "source_ip": "198.51.100.25",
        "device_id": "UNKNOWN-DEVICE-77",
        "status": "success",
        "session_id": "SESSION-SIM-777"
    },
    {
        "event_id": "AUTH-021",
        "timestamp": timestamp(21),
        "username": "finance_checker_01",
        "source_ip": "198.51.100.25",
        "device_id": "UNKNOWN-DEVICE-77",
        "status": "success",
        "session_id": "SESSION-SIM-778"
    },
    {
        "event_id": "AUTH-022",
        "timestamp": timestamp(30),
        "username": "bdo_dharapuram_01",
        "source_ip": "192.0.2.20",
        "device_id": "DEVICE-D01",
        "status": "success",
        "session_id": "SESSION-D002"
    },
])

authentication.sort(key=lambda event: event["timestamp"])


# -------------------------------------------------
# 2. MFA / OTP EVENTS
# -------------------------------------------------

mfa_events = [
    {
        "event_id": "MFA-001",
        "timestamp": timestamp(0),
        "username": "bdo_mandapam_01",
        "event_type": "MFA_APPROVED",
        "source_ip": "192.0.2.10",
        "device_id": "DEVICE-M01",
        "session_id": "SESSION-M001"
    },
    {
        "event_id": "MFA-002",
        "timestamp": timestamp(2),
        "username": "bdo_dharapuram_01",
        "event_type": "MFA_APPROVED",
        "source_ip": "192.0.2.20",
        "device_id": "DEVICE-D01",
        "session_id": "SESSION-D001"
    },
]

for index in range(5):
    mfa_events.append({
        "event_id": f"MFA-{10 + index:03}",
        "timestamp": timestamp(19 + index),
        "username": "bdo_mandapam_01",
        "event_type": "MFA_REQUEST",
        "source_ip": "198.51.100.25",
        "device_id": "UNKNOWN-DEVICE-77",
        "session_id": "SESSION-SIM-777"
    })

mfa_events.extend([
    {
        "event_id": "MFA-020",
        "timestamp": timestamp(24),
        "username": "bdo_mandapam_01",
        "event_type": "MFA_APPROVED",
        "source_ip": "198.51.100.25",
        "device_id": "UNKNOWN-DEVICE-77",
        "session_id": "SESSION-SIM-777"
    },
    {
        "event_id": "MFA-021",
        "timestamp": timestamp(25),
        "username": "finance_checker_01",
        "event_type": "MFA_APPROVED",
        "source_ip": "198.51.100.25",
        "device_id": "UNKNOWN-DEVICE-77",
        "session_id": "SESSION-SIM-778"
    },
    {
        "event_id": "MFA-022",
        "timestamp": timestamp(30),
        "username": "bdo_dharapuram_01",
        "event_type": "MFA_APPROVED",
        "source_ip": "192.0.2.20",
        "device_id": "DEVICE-D01",
        "session_id": "SESSION-D002"
    },
])

mfa_events.sort(key=lambda event: event["timestamp"])


# -------------------------------------------------
# 3. FINANCIAL TRANSACTION EVENTS
# -------------------------------------------------

transactions = [
    {
        "transaction_id": "TXN-001",
        "timestamp": timestamp(5),
        "maker": "bdo_mandapam_01",
        "checker": "finance_checker_01",
        "beneficiary_id": "BEN-001",
        "beneficiary_status": "existing",
        "amount_inr": 25000,
        "status": "approved",
        "session_id": "SESSION-M001"
    },
    {
        "transaction_id": "TXN-002",
        "timestamp": timestamp(10),
        "maker": "bdo_dharapuram_01",
        "checker": "finance_checker_02",
        "beneficiary_id": "BEN-002",
        "beneficiary_status": "existing",
        "amount_inr": 45000,
        "status": "approved",
        "session_id": "SESSION-D001"
    },
    {
        "transaction_id": "TXN-003",
        "timestamp": timestamp(27),
        "maker": "bdo_mandapam_01",
        "checker": "finance_checker_01",
        "beneficiary_id": "BEN-SIM-901",
        "beneficiary_status": "new",
        "amount_inr": 2500000,
        "status": "approved",
        "session_id": "SESSION-SIM-777"
    },
    {
        "transaction_id": "TXN-004",
        "timestamp": timestamp(29),
        "maker": "bdo_mandapam_01",
        "checker": "finance_checker_01",
        "beneficiary_id": "BEN-SIM-902",
        "beneficiary_status": "new",
        "amount_inr": 3000000,
        "status": "approved",
        "session_id": "SESSION-SIM-777"
    },
    {
        "transaction_id": "TXN-005",
        "timestamp": timestamp(32),
        "maker": "bdo_mandapam_01",
        "checker": "finance_checker_01",
        "beneficiary_id": "BEN-SIM-903",
        "beneficiary_status": "new",
        "amount_inr": 1800000,
        "status": "approved",
        "session_id": "SESSION-SIM-777"
    },
    {
        "transaction_id": "TXN-006",
        "timestamp": timestamp(35),
        "maker": "bdo_dharapuram_01",
        "checker": "finance_checker_02",
        "beneficiary_id": "BEN-002",
        "beneficiary_status": "existing",
        "amount_inr": 35000,
        "status": "approved",
        "session_id": "SESSION-D002"
    },
    {
        "transaction_id": "TXN-007",
        "timestamp": timestamp(38),
        "maker": "bdo_mandapam_01",
        "checker": "finance_checker_01",
        "beneficiary_id": "BEN-SIM-904",
        "beneficiary_status": "new",
        "amount_inr": 2200000,
        "status": "approved",
        "session_id": "SESSION-SIM-777"
    },
    {
        "transaction_id": "TXN-008",
        "timestamp": timestamp(40),
        "maker": "bdo_nagapattinam_01",
        "checker": "finance_checker_03",
        "beneficiary_id": "BEN-003",
        "beneficiary_status": "existing",
        "amount_inr": 60000,
        "status": "approved",
        "session_id": "SESSION-N001"
    },
]

transactions.sort(key=lambda event: event["timestamp"])


# -------------------------------------------------
# WRITE DATASETS
# -------------------------------------------------

write_jsonl("authentication.jsonl", authentication)
write_jsonl("mfa-events.jsonl", mfa_events)
write_jsonl("transactions.jsonl", transactions)

print("\n[+] Day 32 synthetic log generation completed.")
print("[!] All identities, events and financial records are fictional.")
print("[!] These records do not represent actual government transactions.")
