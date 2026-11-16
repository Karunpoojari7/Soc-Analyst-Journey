import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class FinalSOCIncidentTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(
            [sys.executable, "scripts/generate_events.py"],
            cwd=ROOT, check=True, capture_output=True
        )

        subprocess.run(
            [sys.executable, "scripts/analyze_incident.py"],
            cwd=ROOT, check=True, capture_output=True
        )

        with (ROOT / "reports/analysis-results.json").open() as f:
            cls.result = json.load(f)

    def test_case_identifier(self):
        self.assertEqual(self.result["case_id"], "SOC-2026-030")

    def test_total_event_count(self):
        self.assertEqual(self.result["total_events"], 15)

    def test_authentication_failures(self):
        self.assertEqual(self.result["event_counts"]["AUTH_FAILURE"], 6)

    def test_successful_authentication(self):
        self.assertEqual(self.result["event_counts"]["AUTH_SUCCESS"], 2)

    def test_repeated_failure_detection(self):
        ids = {x["id"] for x in self.result["findings"]}
        self.assertIn("D30-DET-001", ids)

    def test_success_after_failures_detection(self):
        ids = {x["id"] for x in self.result["findings"]}
        self.assertIn("D30-DET-002", ids)

    def test_compromise_not_assumed(self):
        self.assertFalse(
            self.result["assessment"]["compromise_confirmed"]
        )

    def test_priority(self):
        self.assertEqual(self.result["assessment"]["priority"], "HIGH")

    def test_evidence_limitations_documented(self):
        self.assertGreaterEqual(
            len(self.result["assessment"]["limitations"]), 3
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)
