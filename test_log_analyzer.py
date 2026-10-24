import tempfile
import unittest
from pathlib import Path

from log_analyzer import analyze_log


class TestLogAnalyzer(unittest.TestCase):

    def setUp(self):
        
        #* Create an isolated temporary directory for each test
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.log_path = Path(self.temp_dir.name) / "test.csv"

    def write_log(self, content):
        self.log_path.write_text(content, encoding="utf-8")

    def test_detects_repeated_failures(self):
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:01:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:02:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:03:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:04:00,192.0.2.10,FAILED\n"
        )

        report = analyze_log(self.log_path)

        self.assertEqual(len(report["suspicious_ips"]), 1)
        self.assertEqual(
            report["suspicious_ips"][0]["ip"],
            "192.0.2.10",
        )

    def test_ignores_failures_below_threshold(self):
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:01:00,192.0.2.10,FAILED\n"
        )

        report = analyze_log(self.log_path)

        self.assertEqual(report["suspicious_ips"], [])

    def test_counts_malformed_rows(self):
        self.write_log(
            "timestamp,ip,event\n"
            "not-a-date,192.0.2.10,FAILED\n"
        )

        report = analyze_log(self.log_path)

        self.assertEqual(report["summary"]["malformed_rows"], 1)

    def test_missing_file_raises_error(self):
        missing_path = Path(self.temp_dir.name) / "missing.csv"

        with self.assertRaises(FileNotFoundError):
            analyze_log(missing_path)

    def test_failures_outside_window_do_not_trigger_alert(self):
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:05:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:20:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:30:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:40:00,192.0.2.10,FAILED\n"
        )

        report = analyze_log(
            self.log_path,
            threshold=5,
            window_minutes=10,
        )

        self.assertEqual(report["suspicious_ips"], [])

    def test_custom_threshold(self):
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:01:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:02:00,192.0.2.10,FAILED\n"
        )

        report = analyze_log(
            self.log_path,
            threshold=3,
            window_minutes=10,
        )

        self.assertEqual(len(report["suspicious_ips"]), 1)
        self.assertEqual(
            report["suspicious_ips"][0]["max_failures_in_window"],
            3,
        )    

if __name__ == "__main__":
    unittest.main()