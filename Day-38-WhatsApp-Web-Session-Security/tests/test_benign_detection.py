import csv
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
path = BASE / "tests/benign-account-activity.csv"

with path.open(newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))

alerts = []

for row in rows:
    recipients = int(row["recipient_count"])

    if recipients >= 10:
        alerts.append(row)

print("===== BENIGN DATASET TEST =====")
print("Total events:", len(rows))
print("Unexpected messaging alerts:", len(alerts))

if alerts:
    print("[FAIL] Benign activity generated unexpected alerts.")
else:
    print("[PASS] No high-volume messaging alerts from benign dataset.")

print("[INFO] This test validates only the messaging-volume threshold.")
