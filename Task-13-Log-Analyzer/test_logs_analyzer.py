
import unittest
import tempfile
import os
from datetime import datetime

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from log_analyzer import analyze_logs, load_logs


def make_log(time, username, ip, event):
    return {
        "timestamp": datetime.fromisoformat(time),
        "username": username,
        "source_ip": ip,
        "event": event
    }


class TestLogAnalyzer(unittest.TestCase):

    def test_five_failed_logins_trigger_alert(self):
        logs = [
            make_log(f"2026-10-30T09:0{i}:00", "alice",
                     "203.0.113.10", "FAILURE")
            for i in range(5)
        ]

        alerts = analyze_logs(logs)

        self.assertTrue(
            any(a["type"] == "REPEATED_FAILED_LOGINS" for a in alerts)
        )

    def test_success_after_repeated_failures(self):
        logs = [
            make_log(f"2026-10-30T09:0{i}:00", "alice",
                     "203.0.113.10", "FAILURE")
            for i in range(3)
        ]

        logs.append(
            make_log("2026-10-30T09:04:00", "alice",
                     "203.0.113.10", "SUCCESS")
        )

        alerts = analyze_logs(logs)

        self.assertTrue(
            any(
                a["type"] == "SUCCESS_AFTER_REPEATED_FAILURES"
                for a in alerts
            )
        )

    def test_failures_outside_time_window(self):
        logs = [
            make_log("2026-10-30T09:00:00", "alice",
                     "203.0.113.10", "FAILURE"),
            make_log("2026-10-30T09:20:00", "alice",
                     "203.0.113.10", "FAILURE")
        ]

        alerts = analyze_logs(logs)

        self.assertEqual(len(alerts), 0)

    def test_different_accounts_are_separate(self):
        logs = []

        for i in range(3):
            logs.append(
                make_log(f"2026-10-30T09:0{i}:00", "alice",
                         "203.0.113.10", "FAILURE")
            )
            logs.append(
                make_log(f"2026-10-30T09:0{i}:00", "bob",
                         "203.0.113.10", "FAILURE")
            )

        alerts = analyze_logs(logs)

        self.assertEqual(len(alerts), 0)

    def test_invalid_event_is_rejected(self):
        csv_content = (
            "timestamp,username,source_ip,event\n"
            "2026-10-30T09:00:00,alice,203.0.113.10,UNKNOWN\n"
        )

        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".csv",
                newline="", encoding="utf-8", delete=False
            ) as temp_file:
                temp_file.write(csv_content)
                temp_path = temp_file.name

            with self.assertRaises(ValueError):
                load_logs(temp_path)

        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
