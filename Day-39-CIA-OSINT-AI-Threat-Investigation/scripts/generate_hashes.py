import hashlib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = BASE_DIR / "evidence"
OUTPUT_FILE = BASE_DIR / "output" / "evidence-sha256.txt"

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

files = sorted(EVIDENCE_DIR.rglob("*.csv"))

if not files:
    print("[ERROR] No evidence CSV files found.")
    raise SystemExit(1)

with OUTPUT_FILE.open("w", encoding="utf-8") as report:
    for file_path in files:
        digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
        relative_path = file_path.relative_to(BASE_DIR)
        report.write(f"{digest}  {relative_path}\n")
        print(f"[HASHED] {relative_path}")

print(f"\n[OK] Hash report saved: {OUTPUT_FILE}")
print(f"[INFO] Files hashed: {len(files)}")

