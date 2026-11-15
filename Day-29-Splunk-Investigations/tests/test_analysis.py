import sys
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "scripts")
)

from analyze_events import load_events, analyze

class Day29Tests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.events = load_events()
        cls.result = analyze(cls.events)

    def test_total_events(self):
        self.assertEqual(len(self.events), 11)

    def test_authentication_failures(self):
        self.assertEqual(self.result["authentication_failures"], 6)

    def test_authentication_successes(self):
        self.assertEqual(self.result["authentication_successes"], 1)

    def test_success_after_failures(self):
        self.assertTrue(self.result["success_after_failures"])

    def test_session_event(self):
        self.assertEqual(
            self.result["event_type_counts"]["SESSION"], 1
        )

    def test_privileged_activity(self):
        self.assertEqual(
            self.result["privileged_activity"],
            ["sudo systemctl status ssh"]
        )

    def test_process_execution(self):
        self.assertEqual(
            self.result["process_execution"][0]["process_name"],
            "python3"
        )

    def test_network_connection(self):
        connection = self.result["network_connections"][0]
        self.assertEqual(connection["destination"], "203.0.113.80")
        self.assertEqual(connection["destination_port"], 443)

    def test_compromise_not_confirmed(self):
        self.assertFalse(self.result["compromise_confirmed"])

if __name__ == "__main__":
    unittest.main()
