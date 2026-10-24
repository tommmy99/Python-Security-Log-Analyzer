import tempfile
import unittest
from pathlib import Path

from log_analyzer import analyze_log


class TestLogAnalyzer(unittest.TestCase):

    def setUp(self):

        #* Create an isolated temporary directory for each test
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        #* Each test uses its own CSV file to avoid modifying project data.
        self.log_path = Path(self.temp_dir.name) / "test.csv"

    #! Write CSV content to the temporary test file
    def write_log(self, content):
        self.log_path.write_text(content, encoding="utf-8")

    def test_detects_repeated_failures(self):

        #* Five failures from the same IP within ten minutes should trigger an alert
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:01:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:02:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:03:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:04:00,192.0.2.10,FAILED\n"
        )

        report = analyze_log(self.log_path)

        #* Verify that one suspicious IP is reported and matches the test data
        self.assertEqual(len(report["suspicious_ips"]), 1)
        self.assertEqual(
            report["suspicious_ips"][0]["ip"],
            "192.0.2.10",
        )

    def test_ignores_failures_below_threshold(self):

        #* Two failures are insufficient to reach the default threshold of five
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:01:00,192.0.2.10,FAILED\n"
        )

        report = analyze_log(self.log_path)

        #* No suspicious IP should be reported
        self.assertEqual(report["suspicious_ips"], [])

    def test_counts_malformed_rows(self):

        #* An invalid timestamp makes this row malformed
        self.write_log(
            "timestamp,ip,event\n"
            "not-a-date,192.0.2.10,FAILED\n"
        )

        report = analyze_log(self.log_path)

        #* Malformed rows should be counted rather than analyzed as valid events
        self.assertEqual(report["summary"]["malformed_rows"], 1)

    def test_missing_file_raises_error(self):

        #* Reference a file that does not exist in the temporary directory
        missing_path = Path(self.temp_dir.name) / "missing.csv"

        #* The analyzer should report the missing input file
        with self.assertRaises(FileNotFoundError):
            analyze_log(missing_path)

    def test_failures_outside_window_do_not_trigger_alert(self):

        #* Five failures spread over forty minutes must not trigger a five-failures-within-ten-minutes alert
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

        #* The maximum number of failures in any ten-minute window is below five
        self.assertEqual(report["suspicious_ips"], [])

    def test_custom_threshold(self):

        #* Three failures should trigger an alert when the threshold is set to three
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

        #* Verify that the alert is generated and records the expected maximum
        self.assertEqual(len(report["suspicious_ips"]), 1)
        self.assertEqual(
            report["suspicious_ips"][0]["max_failures_in_window"],
            3,
        )


    def test_invalid_ip_is_counted_as_malformed(self):

        #* An invalid IP address must not be analyzed as a valid event
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,not-an-ip,FAILED\n"
        )

        report = analyze_log(self.log_path)

        self.assertEqual(report["summary"]["malformed_rows"], 1)
        self.assertEqual(report["summary"]["total_valid_events"], 0)

    def test_unknown_event_is_counted_as_malformed(self):

        #* Only FAILED and SUCCESS events are supported
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.10,UNKNOWN\n"
        )

        report = analyze_log(self.log_path)

        self.assertEqual(report["summary"]["malformed_rows"], 1)
        self.assertEqual(report["summary"]["total_valid_events"], 0)

    def test_missing_required_columns_raises_error(self):

        #* The CSV must contain all required column names
        self.write_log(
            "timestamp,ip\n"
            "2026-10-24T09:00:00,192.0.2.10\n"
        )

        with self.assertRaisesRegex(ValueError, "CSV must contain"):
            analyze_log(self.log_path)

    def test_invalid_detection_settings_raise_error(self):

        #* Threshold and window duration must both be positive
        self.write_log(
            "timestamp,ip,event\n"
        )

        invalid_settings = [
            (0, 10),
            (-1, 10),
            (5, 0),
            (5, -1),
        ]

        for threshold, window_minutes in invalid_settings:
            with self.subTest(
                threshold=threshold,
                window_minutes=window_minutes,
            ):
                with self.assertRaisesRegex(
                    ValueError, "must be positive"
                ):
                    analyze_log(
                        self.log_path,
                        threshold=threshold,
                        window_minutes=window_minutes,
                    )

    def test_failures_exactly_at_window_boundary_trigger_alert(self):

        #* Attempts exactly ten minutes apart belong to the same window
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:05:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:10:00,192.0.2.10,FAILED\n"
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

    def test_timestamps_with_different_timezones_are_normalized(self):

        #* These timestamps represent 09:00, 09:05 and 09:10 UTC
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00+00:00,192.0.2.10,FAILED\n"
            "2026-10-24T11:05:00+02:00,192.0.2.10,FAILED\n"
            "2026-10-24T10:10:00+01:00,192.0.2.10,FAILED\n"
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

    def test_successful_logins_do_not_reset_failure_window(self):

        #* Successful logins are counted but do not clear recent failures
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:01:00,192.0.2.10,SUCCESS\n"
            "2026-10-24T09:02:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:03:00,192.0.2.10,SUCCESS\n"
            "2026-10-24T09:04:00,192.0.2.10,FAILED\n"
        )

        report = analyze_log(
            self.log_path,
            threshold=3,
            window_minutes=10,
        )

        self.assertEqual(len(report["suspicious_ips"]), 1)
        self.assertEqual(report["summary"]["successful_events"], 2)
        self.assertEqual(report["summary"]["failed_events"], 3)

    def test_empty_log_with_headers_returns_empty_summary(self):
        #* A header-only CSV is valid but contains no authentication events
        self.write_log("timestamp,ip,event\n")

        report = analyze_log(self.log_path)

        self.assertEqual(report["summary"]["total_valid_events"], 0)
        self.assertEqual(report["summary"]["malformed_rows"], 0)
        self.assertEqual(report["suspicious_ips"], [])

    def test_incomplete_row_is_counted_as_malformed(self):
        # A row missing a required field must be rejected
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.10\n"
        )

        report = analyze_log(self.log_path)

        self.assertEqual(report["summary"]["malformed_rows"], 1)
        self.assertEqual(report["summary"]["total_valid_events"], 0)


    def test_alert_contains_expected_rule_metadata(self):
        """Verify that alerts expose the expected detection rule and settings."""
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

        alert = report["suspicious_ips"][0]

        self.assertEqual(alert["rule_id"], "AUTH-001")
        self.assertEqual(alert["threshold"], 3)
        self.assertEqual(alert["window_minutes"], 10)
        self.assertEqual(alert["failed_attempts"], 3)
        self.assertEqual(alert["max_failures_in_window"], 3)
        self.assertEqual(
            alert["detection_window_start"],
            "2026-10-24T09:00:00+00:00",
        )
        self.assertEqual(
            alert["detection_window_end"],
            "2026-10-24T09:02:00+00:00",
        )

    def test_alert_tracks_first_and_last_failure(self):
        """Verify that an alert records the full failure history for its IP."""
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:01:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:02:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:20:00,192.0.2.10,FAILED\n"
        )

        report = analyze_log(
            self.log_path,
            threshold=3,
            window_minutes=10,
        )

        alert = report["suspicious_ips"][0]

        self.assertEqual(alert["failed_attempts"], 4)
        self.assertEqual(
            alert["first_failure"],
            "2026-10-24T09:00:00+00:00",
        )
        self.assertEqual(
            alert["last_failure"],
            "2026-10-24T09:20:00+00:00",
        )
        self.assertEqual(alert["max_failures_in_window"], 3)

    def test_suspicious_ips_are_sorted_by_severity_then_ip(self):
        """Verify deterministic ordering when alerts have equal severity."""
        self.write_log(
            "timestamp,ip,event\n"
            "2026-10-24T09:00:00,192.0.2.20,FAILED\n"
            "2026-10-24T09:01:00,192.0.2.20,FAILED\n"
            "2026-10-24T09:02:00,192.0.2.20,FAILED\n"
            "2026-10-24T09:00:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:01:00,192.0.2.10,FAILED\n"
            "2026-10-24T09:02:00,192.0.2.10,FAILED\n"
        )

        report = analyze_log(
            self.log_path,
            threshold=3,
            window_minutes=10,
        )

        alerts = report["suspicious_ips"]

        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            [alert["ip"] for alert in alerts],
            ["192.0.2.10", "192.0.2.20"],
        )
        self.assertEqual(
            [alert["max_failures_in_window"] for alert in alerts],
            [3, 3],
        )

if __name__ == "__main__":
    unittest.main()
