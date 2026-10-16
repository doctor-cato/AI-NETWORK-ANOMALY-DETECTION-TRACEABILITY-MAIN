#!/usr/bin/env python3
"""Validate dataset — checks presence, basic schema, and reports status.

Status: planned; will fully verify when UNSW-NB15 is downloaded.
"""
import argparse
import sys
from pathlib import Path

from network_anomaly.config import DATA_RAW


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="UNSW-NB15.csv", help="Expected file name")
    args = parser.parse_args()
    target = DATA_RAW / args.file
    print(f"[validate_data] Checking {target}")
    if not target.exists():
        print(f"[validate_data] NOT FOUND: dataset not yet downloaded.")
        print("[validate_data] Action: download UNSW-NB15 to data/raw/ per docs/DATASET.md")
        # Do not exit with error when dataset is expected but missing — this is planned state.
        sys.exit(0)
    # If present, basic checks would go here
    print(f"[validate_data] FOUND: {target.name} — basic checks not fully implemented yet.")
    print("[validate_data] Planned checks: schema, labels, missing values, duplicates, leakage audit.")


if __name__ == "__main__":
    main()
