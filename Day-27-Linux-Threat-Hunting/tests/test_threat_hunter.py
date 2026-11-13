import json
import tempfile
import unittest
from pathlib import Path


def classify_process(name):
    suspicious_names = {"nc", "ncat", "netcat", "socat", "chisel",
                        "xmrig", "minerd"}

    if name.lower() in suspicious_names:
        return "REVIEW_REQUIRED"

    return "NO_NAME_BASED_INDICATOR"


class ThreatHunterTests(unittest.TestCase):

    def test_known_network_utility_requires_review(self):
        self.assertEqual(
            classify_process("nc"),
            "REVIEW_REQUIRED"
        )

    def test_case_insensitive_process_name(self):
        self.assertEqual(
            classify_process("XMRIG"),
            "REVIEW_REQUIRED"
        )

    def test_normal_process_name(self):
        self.assertEqual(
            classify_process("systemd"),
            "NO_NAME_BASED_INDICATOR"
        )

    def test_unknown_process_name(self):
        self.assertEqual(
            classify_process("training_app"),
            "NO_NAME_BASED_INDICATOR"
        )

    def test_json_evidence_structure(self):
        sample = {
            "processes": [],
            "listening_sockets": [],
            "network_connections": []
        }

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.json"
            path.write_text(json.dumps(sample))

            loaded = json.loads(path.read_text())

            self.assertIn("processes", loaded)
            self.assertIn("network_connections", loaded)


if __name__ == "__main__":
    unittest.main(verbosity=2)
