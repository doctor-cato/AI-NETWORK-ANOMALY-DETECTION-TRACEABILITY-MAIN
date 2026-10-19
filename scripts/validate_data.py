#!/usr/bin/env python3
"""Stream and validate the selected UNSW-NB15 train/test CSV layout."""

import argparse
import csv
import hashlib
import json
import math
import os
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_RAW = PROJECT_ROOT / "data" / "raw"

SKIPPED_NOT_A_PASS = (
    "No real-data validation performed; SKIPPED is not PASS. "
    "Download the dataset with scripts/fetch_unsw_nb15.py before treating CI as evidence."
)

DEFAULT_FILES = ("UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv")
EXPECTED_ROWS = {
    "UNSW_NB15_training-set.csv": 175341,
    "UNSW_NB15_testing-set.csv": 82332,
}
COLUMNS = (
    "id dur proto service state spkts dpkts sbytes dbytes rate sttl dttl sload dload "
    "sloss dloss sinpkt dinpkt sjit djit swin stcpb dtcpb dwin tcprtt synack ackdat "
    "smean dmean trans_depth response_body_len ct_srv_src ct_state_ttl ct_dst_ltm "
    "ct_src_dport_ltm ct_dst_sport_ltm ct_dst_src_ltm is_ftp_login ct_ftp_cmd "
    "ct_flw_http_mthd ct_src_ltm ct_srv_dst is_sm_ips_ports attack_cat label"
).split()
TEXT_COLUMNS = {"proto", "service", "state", "attack_cat"}
ATTACK_CATEGORIES = {
    "Normal",
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
}
INTEGER_COLUMNS = {
    "id",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "sttl",
    "dttl",
    "sloss",
    "dloss",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
    "label",
}


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_blank_line(row):
    """True for a physical line carrying no delimiter and no value.

    A line that does contain delimiters is never blank here: an all-empty row of the
    full width is a missing-value defect, and a short all-empty row is a width defect.
    """
    return len(row) == 0 or (len(row) == 1 and not row[0].strip())


def validate_file(target, expected_sha256=None, expected_size=None, expected_rows=None):
    """Return a report for a valid CSV; raise for a blocking defect."""
    digest = sha256_file(target)
    if expected_size is not None and target.stat().st_size != expected_size:
        raise ValueError(f"size mismatch: {target.name}")
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError(f"SHA-256 mismatch: expected {expected_sha256}, got {digest}")
    with target.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream, strict=True)
        header = next(reader, [])
        if header != COLUMNS:
            raise ValueError("schema mismatch: expected the 45 train/test columns in order")
        counts = Counter()
        attack_counts = Counter()
        missing = Counter()
        seen = set()
        duplicates = 0
        rows = 0
        blank_lines = 0
        blank_positions = []
        for row in reader:
            # Blank lines are counted and rejected, never silently dropped, so the
            # row/missing/duplicate/class counters below stay exact.
            if is_blank_line(row):
                blank_lines += 1
                if len(blank_positions) < 5:
                    blank_positions.append(reader.line_num)
                continue
            if len(row) != len(COLUMNS):
                raise ValueError(f"wrong column count at CSV line {reader.line_num}")
            record = dict(zip(COLUMNS, row))
            if record["label"] not in {"0", "1"}:
                raise ValueError(
                    f"invalid label at CSV line {reader.line_num}: {record['label']!r}"
                )
            category = record["attack_cat"].strip()
            if category not in ATTACK_CATEGORIES:
                raise ValueError(f"invalid attack_cat at CSV line {reader.line_num}: {category!r}")
            is_normal = category == "Normal"
            if (record["label"] == "0") != is_normal:
                raise ValueError(
                    "inconsistent label/attack_cat at CSV line "
                    f"{reader.line_num}: label={record['label']!r}, attack_cat={category!r}"
                )
            for name, value in record.items():
                if not value.strip():
                    missing[name] += 1
                    if name in {"label", "proto", "state", "attack_cat"}:
                        raise ValueError(
                            f"missing required value {name} at CSV line {reader.line_num}"
                        )
                    continue
                if name in TEXT_COLUMNS:
                    continue
                try:
                    number = int(value) if name in INTEGER_COLUMNS else float(value)
                except ValueError as error:
                    raise ValueError(
                        f"invalid numeric value in {name} at CSV line {reader.line_num}: {value!r}"
                    ) from error
                if not math.isfinite(number):
                    raise ValueError(f"non-finite value in {name} at CSV line {reader.line_num}")
            # The split's id is a row identifier, not a traffic attribute.
            signature = tuple(row[1:])
            if signature in seen:
                duplicates += 1
            else:
                seen.add(signature)
            counts[record["label"]] += 1
            attack_counts[category] += 1
            rows += 1
        if blank_lines:
            shown = ", ".join(str(line) for line in blank_positions)
            if blank_lines > len(blank_positions):
                shown += ", ..."
            raise ValueError(
                f"{blank_lines} blank CSV line(s) with no delimiter and no value "
                f"at line(s) {shown}"
            )
        if not rows:
            raise ValueError("no data rows")
        if expected_rows is not None and rows != expected_rows:
            raise ValueError(f"row count mismatch: expected {expected_rows}, got {rows}")
    return {
        "file": target.name,
        "sha256": digest,
        "size_bytes": target.stat().st_size,
        "rows": rows,
        "blank_lines": blank_lines,
        "columns": len(COLUMNS),
        "schema_matches_profile": True,
        "expected_rows": expected_rows,
        "row_count_matches_expected": expected_rows is None or rows == expected_rows,
        "invalid_labels": 0,
        "invalid_attack_categories": 0,
        "label_attack_category_inconsistencies": 0,
        "label_distribution": dict(sorted(counts.items())),
        "attack_category_distribution": dict(sorted(attack_counts.items())),
        "class_ratio": (max(counts.values()) / min(counts.values()) if len(counts) == 2 else None),
        "missing_by_column": dict(sorted(missing.items())),
        "duplicate_rows": duplicates,
        "warnings": [
            message
            for condition, message in (
                (bool(missing), "missing feature values require review before preprocessing"),
                (duplicates > 0, "duplicate records require leakage review before splitting"),
                (len(counts) < 2, "only one binary class observed"),
                (
                    len(counts) == 2 and max(counts.values()) / min(counts.values()) > 10,
                    "class imbalance exceeds 10:1",
                ),
            )
            if condition
        ],
        "limitations": "Structural and value checks only; no leakage audit or feature selection.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", help="CSV under data/raw/, or an explicit path")
    parser.add_argument(
        "--manifest", type=Path, help="Local manifest produced by dataset_manifest.py"
    )
    parser.add_argument("--report", type=Path, help="Write JSON report after successful validation")
    parser.add_argument(
        "--no-row-count",
        action="store_true",
        help="Skip the published row count of the default splits (fixtures and subsets)",
    )
    args = parser.parse_args(argv)
    if args.file:
        targets = [DATA_RAW / args.file]
    else:
        present = [name for name in DEFAULT_FILES if (DATA_RAW / name).exists()]
        if not present:
            print("[validate_data] SKIPPED: UNSW-NB15 train/test CSV files are absent.")
            print(f"[validate_data] {SKIPPED_NOT_A_PASS}")
            if os.environ.get("GITHUB_ACTIONS") == "true":
                print(f"::warning title=SKIPPED is not a PASS::{SKIPPED_NOT_A_PASS}")
            return 0
        if len(present) != len(DEFAULT_FILES):
            missing = set(DEFAULT_FILES) - set(present)
            print(f"[validate_data] ERROR: incomplete split; missing {', '.join(sorted(missing))}")
            return 1
        targets = [DATA_RAW / name for name in DEFAULT_FILES]
    try:
        if args.report:
            # The validator never mutates dataset bytes or its own provenance record, so
            # a report path that resolves to an input file or to the manifest must be
            # refused before anything is written.
            report_path = args.report.resolve()
            protected = list(targets) + ([args.manifest] if args.manifest else [])
            for protected_path in protected:
                if report_path == protected_path.resolve() or (
                    report_path.exists() and os.path.samefile(report_path, protected_path)
                ):
                    raise ValueError(
                        f"report path {args.report} resolves to {protected_path.name}; "
                        f"refusing to overwrite it"
                    )
        manifest = json.loads(args.manifest.read_text(encoding="utf-8")) if args.manifest else None
        reports = []
        for target in targets:
            expected = None
            expected_size = None
            if manifest is not None:
                entries = {entry["file"]: entry for entry in manifest["files"]}
                if target.name not in entries:
                    raise ValueError(f"manifest has no entry for {target.name}")
                expected = entries[target.name]["sha256"]
                expected_size = entries[target.name]["size_bytes"]
            expected_rows = None
            if not args.no_row_count:
                if manifest is not None:
                    expected_rows = entries[target.name].get("expected_rows")
                if expected_rows is None:
                    # The published row count is a property of the split itself, so it is
                    # enforced even without a manifest; a non-default file has no known
                    # count. --no-row-count is applied first, so it also silences a count
                    # that came from a manifest.
                    expected_rows = EXPECTED_ROWS.get(target.name)
            report = validate_file(target, expected, expected_size, expected_rows)
            reports.append(report)
            summary = (
                f"[validate_data] PASS: {target.name} rows={report['rows']} "
                f"sha256={report['sha256']}"
            )
            print(summary)
            for warning in report["warnings"]:
                print(f"[validate_data] WARNING: {warning}")
        payload = {
            "schema_profile": list(COLUMNS),
            "cross_file_schema_consistent": (
                all(report["schema_matches_profile"] for report in reports)
                if len(reports) == len(DEFAULT_FILES)
                else None
            ),
            "files": reports,
        }
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        else:
            print(json.dumps(payload, indent=2))
    except (OSError, UnicodeError, csv.Error, ValueError, KeyError, TypeError) as error:
        print(f"[validate_data] ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
