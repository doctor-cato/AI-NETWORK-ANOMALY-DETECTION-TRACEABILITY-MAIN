#!/usr/bin/env python3
"""Validate dataset — checks presence, basic schema, and reports status.

Status: basic checks implemented; full schema / leakage audit planned when dataset arrives.
"""
import argparse
import sys
from pathlib import Path

from network_anomaly.config import DATA_RAW

EXPECTED_COLUMNS = {"label", "src_ip", "dst_ip", "proto"}  # minimal expected set


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", default="UNSW-NB15.csv", help="Expected file name")
    args = parser.parse_args()
    target = DATA_RAW / args.file
    print(f"[validate_data] Checking {target}")
    if not target.exists():
        print(f"[validate_data] NOT FOUND: dataset not yet downloaded.")
        print("[validate_data] INTENTIONAL SKIP — download UNSW-NB15 to data/raw/ per docs/DATASET.md")
        sys.exit(0)
    # Basic checks when dataset present
    try:
        size = target.stat().st_size
    except Exception as e:
        print(f"[validate_data] ERROR reading file: {e}")
        sys.exit(1)
    if size == 0:
        print("[validate_data] ERROR: file is empty.")
        sys.exit(1)
    # Minimal content check
    with target.open("r", encoding="utf-8", errors="ignore") as f:
        first = f.readline()
    if not first or "," not in first:
        print("[validate_data] WARNING: file may not be CSV (no commas in header).")
    else:
        header = first.strip().split(",")
        header_lower = {h.strip().lower() for h in header}
        if not EXPECTED_COLUMNS.intersection(header_lower):
            print(f"[validate_data] ERROR: expected columns not found in header. Found: {header_lower}")
            sys.exit(1)
    print(f"[validate_data] FOUND: {target.name} — basic checks passed (size={size}, header checked).")
    print("[validate_data] Planned: full schema, labels, missing values, duplicates, leakage audit.")
    sys.exit(0)


if __name__ == "__main__":
    main()
