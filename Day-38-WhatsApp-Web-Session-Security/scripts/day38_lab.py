import csv
import hashlib
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]

DATASETS = {
    "browser": (
        "evidence/browser-logs/browser-events.csv",
        [
            ["timestamp", "user_id", "device_id", "event", "browser", "details"],
            ["2026-11-24T09:00:00", "user_001", "shared_pc_01", "browser_opened", "Chrome", "Workstation started"],
            ["2026-11-24T09:02:00", "user_001", "shared_pc_01", "web_login", "Chrome", "QR-based login completed"],
            ["2026-11-24T09:15:00", "user_001", "shared_pc_01", "tab_closed", "Chrome", "Browser tab closed"],
            ["2026-11-24T09:20:00", "user_002", "shared_pc_01", "browser_opened", "Chrome", "Another user accessed workstation"],
            ["2026-11-24T09:22:00", "user_002", "shared_pc_01", "page_accessed", "Chrome", "Previously authenticated page accessed"],
            ["2026-11-24T10:00:00", "user_003", "personal_pc_02", "browser_opened", "Firefox", "Personal workstation"],
            ["2026-11-24T10:02:00", "user_003", "personal_pc_02", "web_login", "Firefox", "Training login event"],
            ["2026-11-24T10:30:00", "user_003", "personal_pc_02", "logout", "Firefox", "Explicit logout completed"],
        ],
    ),
    "session": (
        "evidence/session-logs/session-lifecycle.csv",
        [
            ["timestamp", "user_id", "device_id", "event", "session_status", "details"],
            ["2026-11-24T09:02:00", "user_001", "shared_pc_01", "session_created", "active", "Synthetic authenticated session"],
            ["2026-11-24T09:15:00", "user_001", "shared_pc_01", "browser_tab_closed", "active", "Tab closure did not revoke session"],
            ["2026-11-24T09:22:00", "user_001", "shared_pc_01", "session_accessed", "active", "Synthetic access after tab closure"],
            ["2026-11-24T09:25:00", "user_001", "shared_pc_01", "session_revoked", "revoked", "Training responder revoked session"],
            ["2026-11-24T10:02:00", "user_003", "personal_pc_02", "session_created", "active", "Synthetic authenticated session"],
            ["2026-11-24T10:30:00", "user_003", "personal_pc_02", "explicit_logout", "terminated", "Session explicitly terminated"],
        ],
    ),
    "account": (
        "evidence/messaging-audit/account-activity.csv",
        [
            ["timestamp", "user_id", "device_id", "event", "recipient_count", "details"],
            ["2026-11-24T09:05:00", "user_001", "shared_pc_01", "message_sent", "1", "Normal training message"],
            ["2026-11-24T09:23:00", "user_001", "shared_pc_01", "message_sent", "18", "Unexpected bulk messaging pattern"],
            ["2026-11-24T09:24:00", "user_001", "shared_pc_01", "link_shared", "18", "Synthetic suspicious link distribution"],
            ["2026-11-24T10:10:00", "user_003", "personal_pc_02", "message_sent", "1", "Normal training message"],
        ],
    ),
}

def write_csv(relative_path, rows):
    path = BASE / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerows(rows)

    return path

def main():
    created = []

    for _, (relative_path, rows) in DATASETS.items():
        path = write_csv(relative_path, rows)
        created.append(path)
        print(f"[CREATED] {path.relative_to(BASE)} ({len(rows)-1} events)")

    manifest = BASE / "output/evidence-sha256.txt"
    manifest.parent.mkdir(parents=True, exist_ok=True)

    with manifest.open("w", encoding="utf-8") as file:
        for path in created:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            file.write(f"{digest}  {path.relative_to(BASE)}\n")

    print(f"\n[CREATED] {manifest.relative_to(BASE)}")
    print(f"[SUMMARY] {len(created)} datasets generated")
    print("[NOTICE] All records are synthetic training evidence.")

if __name__ == "__main__":
    main()
