import csv
import tempfile
import unittest
from pathlib import Path

from src.analyzer import analyze_lines, parse_log_line, write_csv_report


class TestSecurityLoginAnalyzer(unittest.TestCase):
    def test_parse_valid_log_line(self):
        self.assertEqual(
            parse_log_line("2026-10-01T08:01:00Z 192.168.1.10 SUCCESS"),
            ("192.168.1.10", "SUCCESS"),
        )

    def test_malformed_input_is_counted_and_skipped(self):
        result = analyze_lines(["bad record", "2026-10-01T08:01:00Z 10.0.0.1 FAIL"])
        self.assertEqual(result["malformed_entries"], 1)
        self.assertEqual(result["counts_by_ip"]["10.0.0.1"]["failed"], 1)

    def test_threshold_detection(self):
        lines = [f"2026-10-01T08:0{i}:00Z 10.0.0.2 FAIL" for i in range(1, 6)]
        result = analyze_lines(lines, threshold=5)
        self.assertEqual(result["flagged_ips"], [
            {"ip_address": "10.0.0.2", "failed_attempts": 5}
        ])

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze_lines([], threshold=0)

    def test_csv_export(self):
        rows = [{"ip_address": "10.0.0.3", "failed_attempts": 6}]
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "flagged.csv"
            write_csv_report(rows, output)
            with output.open(newline="", encoding="utf-8") as file:
                data = list(csv.DictReader(file))
        self.assertEqual(data[0]["ip_address"], "10.0.0.3")
        self.assertEqual(data[0]["failed_attempts"], "6")


if __name__ == "__main__":
    unittest.main()
