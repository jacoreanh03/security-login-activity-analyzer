"""Command-line entry point for the Security Login Activity Analyzer."""
import argparse
from pathlib import Path

from analyzer import analyze_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze synthetic login activity.")
    parser.add_argument("--input", default="data/sample_auth.log", help="Path to input log")
    parser.add_argument("--output", default="reports/flagged_ips.csv", help="CSV report path")
    parser.add_argument("--threshold", type=int, default=5, help="Failed-login threshold")
    args = parser.parse_args()
    result = analyze_file(args.input, args.output, args.threshold)
    total_success = sum(v["success"] for v in result["counts_by_ip"].values())
    total_failed = sum(v["failed"] for v in result["counts_by_ip"].values())
    print("Security Login Activity Analyzer")
    print(f"Successful logins: {total_success}")
    print(f"Failed logins: {total_failed}")
    print(f"Malformed entries skipped: {result['malformed_entries']}")
    print(f"Flagged IP addresses: {len(result['flagged_ips'])}")
    print(f"CSV report saved to: {Path(args.output)}")


if __name__ == "__main__":
    main()
