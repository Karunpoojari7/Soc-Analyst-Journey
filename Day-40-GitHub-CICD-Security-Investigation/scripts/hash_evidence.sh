#!/bin/bash
set -euo pipefail

FILES=(
    "logs/github-audit-events.jsonl"
    "output/github-correlation-alerts-v2.json"
    "output/incident-timeline.json"
    "output/incident-investigation-report.md"
)

mkdir -p evidence
MANIFEST="evidence/sha256-manifest.txt"

: > "$MANIFEST"

for file in "${FILES[@]}"; do
    if [[ -f "$file" ]]; then
        sha256sum "$file" | tee -a "$MANIFEST"
    else
        echo "MISSING: $file" >&2
    fi
done

echo
echo "Hash manifest: $MANIFEST"
