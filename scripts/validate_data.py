#!/usr/bin/env python3
"""Stream and audit the official NF-UNSW-NB15-v3 CSV without loading it in RAM."""

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import os
import sqlite3
import tempfile
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_MANIFEST.json"
DATASET_PATH = PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
REPORT_PATH = PROJECT_ROOT / "reports" / "data_quality" / "nf_unsw_nb15_v3_validation.json"
SKIPPED_MESSAGE = (
    "NF-UNSW-NB15-v3 bytes are absent; real-data validation is SKIPPED, not PASS. "
    "Run python scripts/fetch_nf_unsw_nb15_v3.py first."
)
IP_COLUMNS = ("IPV4_SRC_ADDR", "IPV4_DST_ADDR")
PORT_COLUMNS = ("L4_SRC_PORT", "L4_DST_PORT")
TIMESTAMP_COLUMNS = ("FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS")
TARGET_COLUMNS = ("Label", "Attack")
NON_FEATURE_COLUMNS = set(IP_COLUMNS + PORT_COLUMNS + TIMESTAMP_COLUMNS + TARGET_COLUMNS)
VALID_ATTACKS = {
    "Benign",
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
MAX_EXAMPLES = 20


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_contract(manifest_path):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("dataset") != "NF-UNSW-NB15-v3":
        raise ValueError("manifest dataset is not NF-UNSW-NB15-v3")
    columns = manifest["schema"]["columns_in_order"]
    if len(columns) != 55 or len(set(columns)) != 55:
        raise ValueError("manifest must define 55 distinct ordered columns")
    if columns[-2:] != list(TARGET_COLUMNS):
        raise ValueError("manifest target columns must be Label and Attack")
    csv_entry = next(
        entry for entry in manifest["files"] if entry.get("file") == "data/NF-UNSW-NB15-v3.csv"
    )
    return manifest, columns, csv_entry


def verify_dataset_bytes(path, entry):
    if path.stat().st_size != entry["size_bytes"]:
        raise ValueError(
            f"dataset size mismatch: expected {entry['size_bytes']}, got {path.stat().st_size}"
        )
    digest = sha256_file(path)
    if digest != entry["sha256"]:
        raise ValueError(f"dataset SHA-256 mismatch: expected {entry['sha256']}, got {digest}")
    return digest


def add_example(examples, issue, line_number):
    values = examples.setdefault(issue, [])
    if len(values) < MAX_EXAMPLES:
        values.append(line_number)


def parse_finite(value, column):
    if value == "":
        return None, "missing"
    try:
        number = float(value)
    except ValueError:
        return None, "invalid_numeric"
    if not math.isfinite(number):
        return None, "non_finite"
    if number < 0:
        return number, "negative"
    if column in PORT_COLUMNS and (not number.is_integer() or number > 65535):
        return number, "invalid_port"
    return number, None


def row_digest(values):
    digest = hashlib.blake2b(digest_size=16)
    for value in values:
        encoded = value.encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.digest()


class DuplicateAudit:
    """Disk-backed exact and behavior-equivalent fingerprint audit."""

    def __init__(self, directory=None):
        handle, name = tempfile.mkstemp(
            prefix="nf-unsw-v3-duplicates-", suffix=".sqlite3", dir=directory
        )
        os.close(handle)
        self.path = Path(name)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA journal_mode=OFF")
        self.connection.execute("PRAGMA synchronous=OFF")
        self.connection.execute("CREATE TABLE exact (digest BLOB PRIMARY KEY) WITHOUT ROWID")
        self.connection.execute("CREATE TABLE near (digest BLOB PRIMARY KEY) WITHOUT ROWID")
        self.exact_duplicates = 0
        self.near_duplicates = 0

    def add(self, row, columns):
        exact = row_digest(row)
        behavior = row_digest(
            value
            for column, value in zip(columns, row, strict=True)
            if column not in NON_FEATURE_COLUMNS
        )
        if (
            self.connection.execute("INSERT OR IGNORE INTO exact VALUES (?)", (exact,)).rowcount
            == 0
        ):
            self.exact_duplicates += 1
        if (
            self.connection.execute("INSERT OR IGNORE INTO near VALUES (?)", (behavior,)).rowcount
            == 0
        ):
            self.near_duplicates += 1

    def close(self):
        self.connection.commit()
        self.connection.close()
        self.path.unlink(missing_ok=True)


def validate_csv(path, columns, expected_rows, duplicate_directory=None):
    counts = Counter()
    examples = {}
    labels = Counter()
    attacks = Counter()
    min_start = None
    max_end = None
    audit = DuplicateAudit(duplicate_directory)
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.reader(stream)
            try:
                header = next(reader)
            except StopIteration as error:
                raise ValueError("dataset is empty") from error
            if header != columns:
                raise ValueError("schema or column ordering does not match the manifest contract")
            if len(set(header)) != len(header):
                raise ValueError("header contains duplicate columns")
            index = {name: position for position, name in enumerate(columns)}
            numeric_columns = [name for name in columns if name not in IP_COLUMNS + ("Attack",)]
            for line_number, row in enumerate(reader, start=2):
                counts["rows"] += 1
                if len(row) != len(columns):
                    counts["wrong_width"] += 1
                    add_example(examples, "wrong_width", line_number)
                    continue
                audit.add(row, columns)
                parsed = {}
                for column in numeric_columns:
                    number, issue = parse_finite(row[index[column]], column)
                    if issue:
                        counts[f"{issue}:{column}"] += 1
                        add_example(examples, f"{issue}:{column}", line_number)
                    parsed[column] = number
                for column in IP_COLUMNS:
                    try:
                        address = ipaddress.ip_address(row[index[column]])
                        if address.version != 4:
                            raise ValueError
                    except ValueError:
                        counts[f"invalid_ip:{column}"] += 1
                        add_example(examples, f"invalid_ip:{column}", line_number)
                label = row[index["Label"]]
                attack = row[index["Attack"]]
                labels[label] += 1
                attacks[attack] += 1
                if label not in {"0", "1"}:
                    counts["invalid_label"] += 1
                    add_example(examples, "invalid_label", line_number)
                if attack not in VALID_ATTACKS:
                    counts["invalid_attack"] += 1
                    add_example(examples, "invalid_attack", line_number)
                if (label == "0" and attack != "Benign") or (label == "1" and attack == "Benign"):
                    counts["label_attack_inconsistent"] += 1
                    add_example(examples, "label_attack_inconsistent", line_number)
                start = parsed["FLOW_START_MILLISECONDS"]
                end = parsed["FLOW_END_MILLISECONDS"]
                duration = parsed["FLOW_DURATION_MILLISECONDS"]
                if start is not None:
                    min_start = start if min_start is None else min(min_start, start)
                if end is not None:
                    max_end = end if max_end is None else max(max_end, end)
                if start is not None and end is not None and end < start:
                    counts["end_before_start"] += 1
                    add_example(examples, "end_before_start", line_number)
                if start is not None and end is not None and duration is not None:
                    # nProbe reports integer millisecond boundaries; tolerate one
                    # millisecond of rounding but flag larger inconsistencies.
                    if abs((end - start) - duration) > 1:
                        counts["duration_mismatch"] += 1
                        add_example(examples, "duration_mismatch", line_number)
            if counts["rows"] == 0:
                raise ValueError("dataset has no data rows")
    finally:
        audit.close()
    counts["exact_duplicate_rows"] = audit.exact_duplicates
    counts["near_duplicate_rows"] = audit.near_duplicates
    if counts["rows"] != expected_rows:
        counts["row_count_mismatch"] = abs(counts["rows"] - expected_rows)
    issue_counts = {key: value for key, value in sorted(counts.items()) if key != "rows" and value}
    return {
        "rows": counts["rows"],
        "expected_rows": expected_rows,
        "labels": dict(sorted(labels.items())),
        "attacks": dict(sorted(attacks.items())),
        "timestamp_range_epoch_ms": {"minimum_start": min_start, "maximum_end": max_end},
        "issue_counts": issue_counts,
        "example_line_numbers": examples,
        "duplicate_definition": {
            "exact": "All 55 ordered CSV values are identical.",
            "near": (
                "All non-identifier, non-timestamp, non-port and non-target "
                "values are identical."
            ),
        },
    }


def refuse_unsafe_report(report, protected):
    resolved = report.resolve(strict=False)
    if any(resolved == path.resolve(strict=False) for path in protected):
        raise ValueError("report path must not overwrite an input or manifest")


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(f"{path.name}.{os.getpid()}.partial")
    backup = path.with_name(f"{path.name}.{os.getpid()}.backup")
    try:
        with staged.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
        try:
            os.replace(staged, path)
        except PermissionError:
            # Some Windows filesystems reject replace-over-existing. Keep the
            # old report recoverable until the staged report owns the target.
            if not path.exists():
                raise
            os.replace(path, backup)
            try:
                os.replace(staged, path)
            except BaseException:
                os.replace(backup, path)
                raise
            backup.unlink(missing_ok=True)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    parser.add_argument("--duplicate-directory", type=Path)
    parser.add_argument("--no-byte-verification", action="store_true")
    args = parser.parse_args(argv)
    if not args.dataset.is_file() and args.dataset == DATASET_PATH:
        print(f"[validate_data] SKIPPED: {SKIPPED_MESSAGE}")
        if os.getenv("GITHUB_ACTIONS") == "true":
            print(f"::warning::{SKIPPED_MESSAGE}")
        return 0
    try:
        if not args.dataset.is_file():
            raise ValueError(f"dataset file does not exist: {args.dataset}")
        if not args.manifest.is_file():
            raise ValueError(f"manifest file does not exist: {args.manifest}")
        refuse_unsafe_report(args.report, (args.dataset, args.manifest))
        _manifest, columns, entry = load_contract(args.manifest)
        digest = None
        if not args.no_byte_verification:
            digest = verify_dataset_bytes(args.dataset, entry)
        result = validate_csv(
            args.dataset,
            columns,
            entry["expected_rows"],
            args.duplicate_directory,
        )
        status = "PASS" if not result["issue_counts"] else "FAIL"
        report = {
            "dataset": "NF-UNSW-NB15-v3",
            "status": status,
            "real_data": True,
            "source_file": args.dataset.name,
            "manifest": args.manifest.name,
            "manifest_sha256_verified": not args.no_byte_verification,
            "dataset_sha256": digest,
            **result,
        }
        write_report(args.report, report)
        print(
            f"[validate_data] {status}: rows={result['rows']} "
            f"issues={sum(result['issue_counts'].values())} report={args.report}"
        )
        return 0 if status == "PASS" else 1
    except (OSError, ValueError, KeyError, StopIteration, json.JSONDecodeError) as error:
        print(f"[validate_data] ERROR: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
