import hashlib
from pathlib import Path

root = Path(".")
manifest = root / "evidence/sha256-manifest.txt"

targets = [
    "logs/raw/authentication.jsonl",
    "logs/raw/api-access.jsonl",
    "logs/raw/firewall.jsonl",
    "output/infrastructure-alerts.json",
    "output/correlated-incidents.json",
    "output/incident-timeline.json"
]

lines = []

for name in targets:
    path = root / name

    if not path.exists():
        print("MISSING:", name)
        continue

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lines.append(f"{digest}  {name}")
    print(digest, name)

manifest.write_text("\n".join(lines) + "\n")
print("\nManifest:", manifest)
