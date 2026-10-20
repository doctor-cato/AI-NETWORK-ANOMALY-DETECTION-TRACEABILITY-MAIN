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
ATTACK_CATEGORIES = (
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
)
VALID_ATTACKS = set(ATTACK_CATEGORIES)
ATTACK_BITS = {attack: 1 << index for index, attack in enumerate(ATTACK_CATEGORIES)}
FINGERPRINT_SCHEMA_VERSION = "nf-unsw-nb15-v3-fingerprint-v1"
MAX_EXAMPLES = 20
QUALITY_TOKEN_ISSUES = {
    "missing",
    "positive_infinity",
    "negative_infinity",
    "nan",
    "invalid_numeric",
}
QUALITY_RELATION_COLUMNS = (
    "FLOW_DURATION_MILLISECONDS",
    "DURATION_IN",
    "DURATION_OUT",
    "IN_PKTS",
    "OUT_PKTS",
    "IN_BYTES",
    "OUT_BYTES",
)


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
    if math.isnan(number):
        return None, "nan"
    if math.isinf(number):
        return None, "positive_infinity" if number > 0 else "negative_infinity"
    if number < 0:
        return number, "negative"
    if column in PORT_COLUMNS and (not number.is_integer() or number > 65535):
        return number, "invalid_port"
    return number, None


def numeric_state(value):
    if value is None:
        return "unavailable"
    if value == 0:
        return "zero"
    if value < 0:
        return "negative"
    return "positive"


def duration_bucket(value):
    if value is None:
        return "unavailable"
    if value < 0:
        return "negative"
    if value == 0:
        return "zero"
    if value <= 1:
        return "small_positive_le_1ms"
    return "greater_than_1ms"


class NumericQualityAudit:
    """Aggregate numeric-token findings without retaining source rows."""

    def __init__(self):
        self.affected_rows = 0
        self.multi_finding_rows = 0
        self.patterns = Counter()
        self.finding_type_counts = Counter({issue: 0 for issue in QUALITY_TOKEN_ISSUES})
        self.by_issue = {}

    def add(self, issues, parsed, label, attack, protocol):
        relevant = tuple(
            sorted(
                issue
                for issue in issues
                if issue.split(":", 1)[0] in QUALITY_TOKEN_ISSUES
            )
        )
        if not relevant:
            return
        self.affected_rows += 1
        if len(relevant) > 1:
            self.multi_finding_rows += 1
        self.patterns[" | ".join(relevant)] += 1
        for issue in relevant:
            self.finding_type_counts[issue.split(":", 1)[0]] += 1
            aggregate = self.by_issue.setdefault(
                issue,
                {
                    "labels": Counter(),
                    "attacks": Counter(),
                    "protocols": Counter(),
                    "duration_buckets": {
                        "FLOW_DURATION_MILLISECONDS": Counter(),
                        "DURATION_IN": Counter(),
                        "DURATION_OUT": Counter(),
                    },
                    "related_numeric_states": {
                        column: Counter() for column in QUALITY_RELATION_COLUMNS[3:]
                    },
                },
            )
            aggregate["labels"][label] += 1
            aggregate["attacks"][attack] += 1
            aggregate["protocols"][protocol] += 1
            for column in QUALITY_RELATION_COLUMNS[:3]:
                aggregate["duration_buckets"][column][duration_bucket(parsed[column])] += 1
            for column in QUALITY_RELATION_COLUMNS[3:]:
                aggregate["related_numeric_states"][column][numeric_state(parsed[column])] += 1

    def report(self):
        def sorted_counter(counter):
            return dict(sorted(counter.items(), key=lambda item: str(item[0])))

        findings = {}
        for issue, aggregate in sorted(self.by_issue.items()):
            findings[issue] = {
                "labels": sorted_counter(aggregate["labels"]),
                "attacks": sorted_counter(aggregate["attacks"]),
                "protocols": sorted_counter(aggregate["protocols"]),
                "duration_buckets": {
                    column: sorted_counter(counts)
                    for column, counts in aggregate["duration_buckets"].items()
                },
                "related_numeric_states": {
                    column: sorted_counter(counts)
                    for column, counts in aggregate["related_numeric_states"].items()
                },
            }
        return {
            "affected_unique_rows": self.affected_rows,
            "rows_with_one_finding": self.affected_rows - self.multi_finding_rows,
            "rows_with_multiple_findings": self.multi_finding_rows,
            "finding_type_counts": sorted_counter(self.finding_type_counts),
            "overlap_patterns": sorted_counter(self.patterns),
            "findings": findings,
            "causality_note": (
                "Aggregates describe observed associations only. They do not establish how "
                "the published feature values were computed or why a value became non-finite."
            ),
        }


def row_digest(values, namespace):
    digest = hashlib.blake2b(digest_size=16)
    digest.update(FINGERPRINT_SCHEMA_VERSION.encode("ascii"))
    digest.update(namespace.encode("ascii"))
    for value in values:
        encoded = value.encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.digest()


class DuplicateAudit:
    """Disk-backed exact, ML-equivalent and behavioral-v1 audit."""

    def __init__(self, directory=None):
        handle, name = tempfile.mkstemp(
            prefix="nf-unsw-v3-duplicates-", suffix=".sqlite3", dir=directory
        )
        os.close(handle)
        self.path = Path(name)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA journal_mode=OFF")
        self.connection.execute("PRAGMA synchronous=OFF")
        self.connection.execute(
            "CREATE TABLE exact (digest BLOB PRIMARY KEY, count INTEGER NOT NULL) WITHOUT ROWID"
        )
        self.connection.execute(
            "CREATE TABLE ml (digest BLOB PRIMARY KEY, count INTEGER NOT NULL, "
            "label_mask INTEGER NOT NULL, attack_mask INTEGER NOT NULL) WITHOUT ROWID"
        )
        self.connection.execute(
            "CREATE TABLE behavior (digest BLOB PRIMARY KEY, count INTEGER NOT NULL) WITHOUT ROWID"
        )
        self.exact_duplicates = 0
        self.ml_feature_equivalent_duplicates = 0
        self.behavioral_duplicates = 0
        self.exact_duplicate_labels = Counter()
        self.exact_duplicate_attacks = Counter()

    def add(self, row, columns):
        index = {column: position for position, column in enumerate(columns)}
        label = row[index["Label"]]
        attack = row[index["Attack"]]
        label_mask = 1 << int(label) if label in {"0", "1"} else 0
        attack_mask = ATTACK_BITS.get(attack, 0)
        exact = row_digest(row, "full-row")
        ml_feature = row_digest(
            (
                value
                for column, value in zip(columns, row, strict=True)
                if column not in NON_FEATURE_COLUMNS
            ),
            "ml-feature",
        )
        behavior = row_digest(
            (
                value
                for column, value in zip(columns, row, strict=True)
                if column not in NON_FEATURE_COLUMNS
            ),
            "behavioral-v1",
        )
        if (
            self.connection.execute(
                "INSERT OR IGNORE INTO exact VALUES (?, 1)", (exact,)
            ).rowcount
            == 0
        ):
            self.exact_duplicates += 1
            self.exact_duplicate_labels[label] += 1
            self.exact_duplicate_attacks[attack] += 1
            self.connection.execute("UPDATE exact SET count = count + 1 WHERE digest = ?", (exact,))
        if (
            self.connection.execute(
                "INSERT OR IGNORE INTO ml VALUES (?, 1, ?, ?)",
                (ml_feature, label_mask, attack_mask),
            ).rowcount
            == 0
        ):
            self.ml_feature_equivalent_duplicates += 1
            self.connection.execute(
                "UPDATE ml SET count = count + 1, label_mask = label_mask | ?, "
                "attack_mask = attack_mask | ? WHERE digest = ?",
                (label_mask, attack_mask, ml_feature),
            )
        if (
            self.connection.execute(
                "INSERT OR IGNORE INTO behavior VALUES (?, 1)", (behavior,)
            ).rowcount
            == 0
        ):
            self.behavioral_duplicates += 1
            self.connection.execute(
                "UPDATE behavior SET count = count + 1 WHERE digest = ?", (behavior,)
            )

    def report(self):
        exact_groups = self.connection.execute(
            "SELECT COUNT(*) FROM exact WHERE count > 1"
        ).fetchone()[0]
        ml_groups = 0
        label_conflict_groups = 0
        label_conflict_rows = 0
        benign_attack_conflict_groups = 0
        multiple_attack_values_groups = 0
        rows_in_multiple_attack_values_groups = 0
        multiple_malicious_categories_groups = 0
        attack_value_conflict_patterns = {}
        rare_conflicts = {
            category: {"fingerprints": 0, "rows": 0} for category in ("Analysis", "Worms")
        }
        rare_multi_attack = {
            category: {"fingerprints": 0, "rows": 0} for category in ("Analysis", "Worms")
        }
        benign_bit = ATTACK_BITS["Benign"]
        malicious_mask = sum(
            bit for category, bit in ATTACK_BITS.items() if category != "Benign"
        )
        for count, label_mask, attack_mask in self.connection.execute(
            "SELECT count, label_mask, attack_mask FROM ml"
        ):
            if count > 1:
                ml_groups += 1
            has_label_conflict = label_mask == 3
            if has_label_conflict:
                label_conflict_groups += 1
                label_conflict_rows += count
            has_benign_attack = bool(attack_mask & benign_bit) and bool(
                attack_mask & malicious_mask
            )
            if has_benign_attack:
                benign_attack_conflict_groups += 1
            if attack_mask.bit_count() > 1:
                multiple_attack_values_groups += 1
                rows_in_multiple_attack_values_groups += count
                categories = tuple(
                    category
                    for category in ATTACK_CATEGORIES
                    if attack_mask & ATTACK_BITS[category]
                )
                pattern = " | ".join(categories)
                pattern_counts = attack_value_conflict_patterns.setdefault(
                    pattern, {"fingerprints": 0, "rows": 0}
                )
                pattern_counts["fingerprints"] += 1
                pattern_counts["rows"] += count
                for category in rare_multi_attack:
                    if attack_mask & ATTACK_BITS[category]:
                        rare_multi_attack[category]["fingerprints"] += 1
                        rare_multi_attack[category]["rows"] += count
            if (attack_mask & malicious_mask).bit_count() > 1:
                multiple_malicious_categories_groups += 1
            if has_label_conflict:
                for category in rare_conflicts:
                    if attack_mask & ATTACK_BITS[category]:
                        rare_conflicts[category]["fingerprints"] += 1
                        rare_conflicts[category]["rows"] += count
        behavioral_groups = self.connection.execute(
            "SELECT COUNT(*) FROM behavior WHERE count > 1"
        ).fetchone()[0]
        return {
            "schema_version": FINGERPRINT_SCHEMA_VERSION,
            "definitions": {
                "exact_full_row": {
                    "columns": "all 55 ordered CSV columns, including targets",
                    "purpose": "byte-level parsed-row identity and exact-dedup impact audit",
                },
                "source_feature": {
                    "columns": "all 53 published NetFlow fields; targets excluded",
                    "purpose": "cross-split observation overlap even if labels differ",
                },
                "ml_feature_equivalent": {
                    "columns": "the ordered 47-feature baseline; metadata and targets excluded",
                    "purpose": "memorization risk and label-conflict audit",
                },
                "behavioral_v1": {
                    "columns": "the ordered 47-feature baseline under a separate namespace",
                    "purpose": "correlation-oriented equivalence; not an automatic dedup key",
                },
            },
            "exact": {
                "duplicate_rows": self.exact_duplicates,
                "fingerprints_with_duplicates": exact_groups,
                "duplicate_rows_by_label": dict(sorted(self.exact_duplicate_labels.items())),
                "duplicate_rows_by_attack": dict(sorted(self.exact_duplicate_attacks.items())),
            },
            "ml_feature_equivalent": {
                "duplicate_rows": self.ml_feature_equivalent_duplicates,
                "fingerprints_with_duplicates": ml_groups,
                "label_conflict_fingerprints": label_conflict_groups,
                "rows_in_label_conflict_fingerprints": label_conflict_rows,
                "benign_attack_conflict_fingerprints": benign_attack_conflict_groups,
                "multiple_attack_values_fingerprints": multiple_attack_values_groups,
                "rows_in_multiple_attack_values_fingerprints": (
                    rows_in_multiple_attack_values_groups
                ),
                "multiple_malicious_categories_fingerprints": (
                    multiple_malicious_categories_groups
                ),
                "attack_value_conflict_patterns": dict(
                    sorted(attack_value_conflict_patterns.items())
                ),
                "rare_category_label_conflicts": rare_conflicts,
                "rare_category_multi_attack_fingerprints": rare_multi_attack,
            },
            "behavioral_v1": {
                "duplicate_rows": self.behavioral_duplicates,
                "fingerprints_with_duplicates": behavioral_groups,
                "automatic_removal_permitted": False,
            },
        }

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
    quality_audit = NumericQualityAudit()
    duplicate_analysis = None
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
                row_issues = []
                for column in numeric_columns:
                    number, issue = parse_finite(row[index[column]], column)
                    if issue:
                        issue_key = f"{issue}:{column}"
                        counts[issue_key] += 1
                        row_issues.append(issue_key)
                        add_example(examples, issue_key, line_number)
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
                quality_audit.add(
                    row_issues,
                    parsed,
                    label,
                    attack,
                    row[index["PROTOCOL"]],
                )
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
            duplicate_analysis = audit.report()
    finally:
        audit.close()
    counts["exact_duplicate_rows"] = duplicate_analysis["exact"]["duplicate_rows"]
    counts["ml_feature_equivalent_duplicate_rows"] = duplicate_analysis[
        "ml_feature_equivalent"
    ]["duplicate_rows"]
    counts["behavioral_fingerprint_duplicate_rows"] = duplicate_analysis["behavioral_v1"][
        "duplicate_rows"
    ]
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
        "duplicate_analysis": {
            **duplicate_analysis,
            "hypothetical_exact_dedup_keep_first": {
                "retained_by_label": {
                    label: count
                    - duplicate_analysis["exact"]["duplicate_rows_by_label"].get(label, 0)
                    for label, count in sorted(labels.items())
                },
                "retained_by_attack": {
                    attack: count
                    - duplicate_analysis["exact"]["duplicate_rows_by_attack"].get(attack, 0)
                    for attack, count in sorted(attacks.items())
                },
                "applied": False,
            },
        },
        "numeric_quality_analysis": quality_audit.report(),
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
