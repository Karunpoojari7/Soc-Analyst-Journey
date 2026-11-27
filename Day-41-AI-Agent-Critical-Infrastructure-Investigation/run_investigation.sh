#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo " DAY 41 - SOC INVESTIGATION PIPELINE"
echo "=========================================="

echo "[1/6] Validating Python scripts..."
python3 -m compileall -q scripts tests

echo "[Detection scenario tests]"
python3 tests/test_detection_scenarios.py

echo "[2/6] Running detection engine..."
python3 scripts/detect_infrastructure_threats.py

echo "[3/6] Validating detections..."
python3 tests/test_detection.py

echo "[4/6] Correlating incidents..."
python3 scripts/correlate_incidents.py

echo "[Correlation validation]"
python3 tests/test_correlation.py

echo "[5/6] Generating investigation timeline..."
python3 scripts/generate_timeline.py

echo "[6/6] Generating evidence hashes..."
python3 scripts/hash_evidence.py

echo
echo "=========================================="
echo " PIPELINE COMPLETED"
echo "=========================================="

echo "Verify evidence integrity:"
sha256sum -c evidence/sha256-manifest.txt
