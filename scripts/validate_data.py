#!/usr/bin/env python3
"""Validate dataset — checks presence, basic schema, and reports status.

Status: basic checks implemented; full schema / leakage audit planned when dataset arrives.
"""
import argparse
import csv

from network_anomaly.config import DATA_RAW

EXPECTED_COLUMNS = {"label", "proto"}  # Minimal header shared by supported CSV variants
DEFAULT_FILES = ("UNSW-NB15.csv", "UNSW-NB15_training_set.csv")


def validate_file(target):
    """Check CSV structure only; full dataset validation remains future work."""
    print(f"[validate_data] Checking {target}")
    try:
        with target.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.reader(stream, strict=True)
            header = [name.strip().lower() for name in next(reader, [])]
            if not header or any(not name for name in header) or len(set(header)) != len(header):
                raise ValueError("empty or duplicate column names")
            missing = EXPECTED_COLUMNS.difference(header)
            if missing:
                raise ValueError(f"missing required columns: {', '.join(sorted(missing))}")
            rows = 0
            for row in reader:
                if not row:
                    continue
                if len(row) != len(header):
                    raise ValueError(f"wrong column count at CSV line {reader.line_num}")
                rows += 1
            if not rows:
                raise ValueError("no data rows")
    except (OSError, UnicodeError, csv.Error, ValueError) as error:
        print(f"[validate_data] ERROR: {target.name}: {error}")
        return False
    print(f"[validate_data] FOUND: {target.name} - basic CSV checks passed (rows={rows}).")
    print("[validate_data] Planned: full schema, label values, missing values, duplicates, leakage audit.")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="CSV name under data/raw/, or an explicit absolute path")
    args = parser.parse_args(argv)
    if args.file is not None:
        targets = [DATA_RAW / args.file]
    else:
        targets = [DATA_RAW / name for name in DEFAULT_FILES if (DATA_RAW / name).exists()]
        if not targets:
            print("[validate_data] SKIPPED (INTENTIONAL SKIP): UNSW-NB15 not downloaded.")
            print("[validate_data] Download per docs/DATASET.md; no real-data validation performed.")
            print("::notice title=Dataset skipped::UNSW-NB15 is absent, so no real-data "
                  "validation ran. SKIPPED is not a PASS.")
            return 0
    valid = True
    for target in targets:
        if not validate_file(target):
            valid = False
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
