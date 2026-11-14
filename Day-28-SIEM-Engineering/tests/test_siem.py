#!/usr/bin/env python3

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "scripts"))

from normalize_events import normalize
from detect_authentication import detect


def make_event(number, minute, outcome, username="svc-backup",
               source_ip="198.51.100.23"):
    timestamp = datetime(
        2026, 11, 14, 10, 0, tzinfo=timezone.utc
    ) + timedelta(minutes=minute)

    return {
        "event_id": f"TEST-{number}",
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "host": "nexora-linux-01",
        "event_type": "authentication",
        "username": username,
        "src_ip": source_ip,
        "outcome": outcome,
        "severity": "medium"
    }


RULE = {
    "rule_id": "DET-SSH-001",
    "threshold": 5,
    "window_seconds": 600,
    "severity": "high"
}


class SIEMTests(unittest.TestCase):

    def test_event_normalization(self):
        event = make_event(1, 0, "failure")
        result = normalize(event)

        self.assertEqual(result["event_category"], "authentication")
        self.assertEqual(result["event_outcome"], "failure")
        self.assertEqual(result["pipeline_status"], "NORMALIZED")

    def test_five_failures_trigger_alert(self):
        events = [
            normalize(make_event(i, i - 1, "failure"))
            for i in range(1, 6)
        ]

        self.assertEqual(len(detect(events, RULE)), 1)

    def test_four_failures_do_not_trigger_alert(self):
        events = [
            normalize(make_event(i, i - 1, "failure"))
            for i in range(1, 5)
        ]

        self.assertEqual(len(detect(events, RULE)), 0)

    def test_failures_outside_window_do_not_trigger_alert(self):
        minutes = [0, 3, 6, 9, 15]

        events = [
            normalize(make_event(i, minute, "failure"))
            for i, minute in enumerate(minutes, start=1)
        ]

        self.assertEqual(len(detect(events, RULE)), 0)

    def test_unrelated_source_does_not_combine(self):
        events = [
            normalize(make_event(i, i, "failure"))
            for i in range(1, 4)
        ]

        events.extend([
            normalize(make_event(i, i, "failure", source_ip="203.0.113.45"))
            for i in range(4, 6)
        ])

        self.assertEqual(len(detect(events, RULE)), 0)

    def test_success_after_threshold_is_correlated(self):
        events = [
            normalize(make_event(i, i - 1, "failure"))
            for i in range(1, 6)
        ]

        events.append(normalize(make_event(6, 6, "success")))

        alerts = detect(events, RULE)

        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["successful_login_after_failures"])
        self.assertEqual(
            alerts[0]["correlation_rule"],
            "COR-SSH-001"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
