"""Analyze synthetic authentication logs and report repeated failed logins."""
from __future__ import annotations

import csv
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<status>SUCCESS|FAIL)$"
)


def parse_log_line(line: str) -> tuple[str, str] | None:
    """Return (IP address, status) for a valid line; otherwise return None."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    ip = match.group("ip")
    if any(int(part) > 255 for part in ip.split(".")):
        return None
    return ip, match.group("status")


def analyze_lines(lines: Iterable[str], threshold: int = 5) -> dict:
    """Count login outcomes by IP and flag IPs with failures >= threshold."""
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 1:
        raise ValueError("threshold must be a positive integer")
    counts = defaultdict(lambda: {"success": 0, "failed": 0})
    malformed = 0
    for line in lines:
        parsed = parse_log_line(line)
        if parsed is None:
            malformed += 1
            continue
        ip, status = parsed
        key = "success" if status == "SUCCESS" else "failed"
        counts[ip][key] += 1
    flagged = [
        {"ip_address": ip, "failed_attempts": values["failed"]}
        for ip, values in counts.items()
        if values["failed"] >= threshold
    ]
    flagged.sort(key=lambda row: (-row["failed_attempts"], row["ip_address"]))
    return {
        "counts_by_ip": dict(counts),
        "flagged_ips": flagged,
        "malformed_entries": malformed,
        "threshold": threshold,
    }


def write_csv_report(flagged_ips: list[dict], output_path: str | Path) -> None:
    """Write flagged IP addresses and failed-attempt counts to CSV."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["ip_address", "failed_attempts"])
        writer.writeheader()
        writer.writerows(flagged_ips)


def analyze_file(input_path: str | Path, output_path: str | Path, threshold: int = 5) -> dict:
    """Analyze a log file and export the flagged IP report."""
    with Path(input_path).open(encoding="utf-8") as log_file:
        result = analyze_lines(log_file, threshold=threshold)
    write_csv_report(result["flagged_ips"], output_path)
    return result
