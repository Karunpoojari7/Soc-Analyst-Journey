import csv
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]

rows = [
    ["timestamp", "user_id", "device_id", "event",
     "recipient_count", "details"],

    ["2026-11-24T11:00:00", "user_101", "personal_pc_01",
     "message_sent", "1", "Normal personal message"],

    ["2026-11-24T11:05:00", "user_101", "personal_pc_01",
     "message_sent", "3", "Normal group communication"],

    ["2026-11-24T11:10:00", "user_101", "personal_pc_01",
     "browser_tab_closed", "0", "Browser tab closed"],

    ["2026-11-24T11:15:00", "user_102", "personal_pc_02",
     "message_sent", "2", "Normal communication"],

    ["2026-11-24T11:20:00", "user_102", "personal_pc_02",
     "logout", "0", "Explicit session logout"],
]

path = BASE / "tests/benign-account-activity.csv"
path.parent.mkdir(parents=True, exist_ok=True)

with path.open("w", newline="", encoding="utf-8") as f:
    csv.writer(f).writerows(rows)

print("[PASS] Benign dataset generated")
print("[INFO] Records:", len(rows) - 1)
print("[NOTICE] All records are synthetic.")
