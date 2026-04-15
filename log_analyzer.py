from collections import Counter
from pathlib import Path
import argparse
import csv
import re
from typing import List

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"
)

def extract_failed_ips(log_path: Path) -> List[str]:
    failed_ips: List[str] = []

    with log_path.open("r", encoding="utf-8") as file:
        for line in file:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                failed_ips.append(match.group(1))

    return failed_ips

def print_summary(ip_counts: Counter, threshold: int) -> None:
    print("\nSuspicious IP Summary")
    print("-" * 30)

    found = False
    for ip, count in ip_counts.most_common():
        if count >= threshold:
            found = True
            print(f"{ip:<16} -> {count} failed attempts")

    if not found:
        print("No IPs met the alert threshold.")

def export_csv(ip_counts: Counter, output_file: Path) -> None:
    with output_file.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["ip_address", "failed_attempts"])
        for ip, count in ip_counts.most_common():
            writer.writerow([ip, count])

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for repeated failed logins."
    )
    parser.add_argument(
        "logfile",
        type=Path,
        help="Path to the log file to analyze"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Minimum failed attempts needed to flag an IP"
    )
    parser.add_argument(
        "--export",
        type=Path,
        help="Optional CSV output file"
    )

    args = parser.parse_args()

    if not args.logfile.exists():
        print("Error: log file not found.")
        return

    failed_ips = extract_failed_ips(args.logfile)
    ip_counts = Counter(failed_ips)

    print_summary(ip_counts, args.threshold)

    if args.export:
        export_csv(ip_counts, args.export)
        print(f"\nCSV report saved to: {args.export}")

if __name__ == "__main__":
    main()
