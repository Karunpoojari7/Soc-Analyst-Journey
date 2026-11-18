
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = BASE_DIR / "data" / "raw"
OUTPUT_DIR = BASE_DIR / "data" / "evidence"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

manifest = {
    "case_id": "INC-DAY32-001",
    "classification": "SYNTHETIC TRAINING EVIDENCE",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "files": []
}

for path in sorted(EVIDENCE_DIR.glob("*.jsonl")):

    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            sha256.update(chunk)

    manifest["files"].append({
        "filename": path.name,
        "sha256": sha256.hexdigest(),
        "size_bytes": path.stat().st_size,
        "algorithm": "SHA-256"
    })

output_file = OUTPUT_DIR / "evidence-manifest.json"

with output_file.open("w", encoding="utf-8") as file:
    json.dump(manifest, file, indent=4)

print("\n========== EVIDENCE INTEGRITY ==========")

for item in manifest["files"]:
    print(f"\nFile: {item['filename']}")
    print(f"SHA256: {item['sha256']}")
    print(f"Size: {item['size_bytes']} bytes")

print("\n[+] Evidence integrity manifest created.")
print(f"[+] Saved to: {output_file}")
