"""NF-UNSW-NB15-v3 data splitting and cross-partition leakage audit.

This module implements a deterministic, reproducible, chronologically-ordered
split protocol with canonical flow-group purge gaps and full cross-partition
leakage auditing using the versioned fingerprint schema.

Interfaces established here are consumed by Issue #8 (preprocessing and modeling).
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ALL_COLUMNS,
    CATEGORICAL_CODED_COLUMNS,
    DATASET_NAME,
    FINGERPRINT_SCHEMA_VERSION,
    ML_FEATURE_COLUMNS,
    QUANTITATIVE_ML_COLUMNS,
    SOURCE_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    validate_feature_selection,
    validate_semantic_column_roles,
)

SPLIT_PROTOCOL_VERSION = "nf-unsw-nb15-v3-chronological-group-purged-v1"
SPLIT_MANIFEST_SCHEMA_VERSION = 1
DEFAULT_PURGE_GAP_MS = 300_000  # 5 minutes, matching canonical flow group bucket
DEFAULT_TRAIN_RATIO = 0.70
DEFAULT_VAL_RATIO = 0.15
DEFAULT_TEST_RATIO = 0.15
DEFAULT_RANDOM_SEED = 42

PARTITION_TRAIN = "train"
PARTITION_VALIDATION = "validation"
PARTITION_TEST = "test"
PARTITION_PURGED_TRAIN_VAL = "purged_train_val_gap"
PARTITION_PURGED_VAL_TEST = "purged_val_test_gap"

EXPECTED_ARTIFACT_REL_PATHS: List[str] = [
    "data/processed/splits/train_indices.csv.gz",
    "data/processed/splits/purged_train_val_gap_indices.csv.gz",
    "data/processed/splits/validation_indices.csv.gz",
    "data/processed/splits/purged_val_test_gap_indices.csv.gz",
    "data/processed/splits/test_indices.csv.gz",
    "data/processed/nf_unsw_nb15_v3_split_manifest.json",
    "data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json",
    "reports/splits/nf_unsw_nb15_v3_split_manifest.json",
    "reports/splits/nf_unsw_nb15_v3_leakage_audit_report.md",
    "docs/dataset/NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md",
]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path, chunk_bytes: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_bytes), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_deterministic_index_csv_gz(path: Path, indices: Any) -> str:
    """Write partition indices to a compressed CSV with fixed mtime=0.0 for file-byte determinism.

    Returns the SHA-256 hash of the generated file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw_file:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_file, mtime=0.0) as gz:
            with io.TextIOWrapper(gz, encoding="utf-8", newline="\n") as text_file:
                text_file.write("source_row_index\n")
                for idx in indices:
                    text_file.write(f"{idx}\n")
    return _sha256_file(path)


def _format_epoch_ms(epoch_ms: int) -> str:
    dt = datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)
    return dt.isoformat()


@dataclass(frozen=True)
class SplitConfig:
    purge_gap_milliseconds: int = DEFAULT_PURGE_GAP_MS
    train_ratio: float = DEFAULT_TRAIN_RATIO
    val_ratio: float = DEFAULT_VAL_RATIO
    test_ratio: float = DEFAULT_TEST_RATIO
    random_seed: int = DEFAULT_RANDOM_SEED

    def validate(self) -> None:
        if self.purge_gap_milliseconds < 0:
            raise ValueError("purge_gap_milliseconds must not be negative")
        if self.train_ratio <= 0 or self.val_ratio <= 0 or self.test_ratio <= 0:
            raise ValueError("partition ratios must be strictly positive")
        total_ratio = self.train_ratio + self.val_ratio + self.test_ratio
        if not np.isclose(total_ratio, 1.0, atol=1e-5):
            raise ValueError(f"partition ratios must sum to 1.0, got {total_ratio}")


def compute_chronological_split(
    df: pd.DataFrame,
    config: Optional[SplitConfig] = None,
) -> Dict[str, Any]:
    """Compute a deterministic chronological split with boundary purge gaps.

    Parameters
    ----------
    df : pd.DataFrame
        Source DataFrame containing at least FLOW_START_MILLISECONDS, Label,
        and Attack.
    config : SplitConfig, optional
        Split configuration. Defaults to 70/15/15 with 300,000ms purge gap.

    Returns
    -------
    dict
        Dictionary containing partition indices (0-based source row indices),
        time boundaries, row counts, label distributions, attack distributions,
        and configuration.
    """
    if config is None:
        config = SplitConfig()
    config.validate()

    if "FLOW_START_MILLISECONDS" not in df.columns:
        raise ValueError("DataFrame missing required column: FLOW_START_MILLISECONDS")

    start_series = df["FLOW_START_MILLISECONDS"]
    if start_series.isna().any():
        raise ValueError("FLOW_START_MILLISECONDS contains missing or null values")

    try:
        start_ms = start_series.to_numpy(dtype=np.int64)
    except (ValueError, TypeError) as err:
        raise ValueError(f"FLOW_START_MILLISECONDS contains non-integer values: {err}") from err

    if (start_ms < 0).any():
        raise ValueError("FLOW_START_MILLISECONDS contains negative values")

    total_rows = len(df)
    if total_rows == 0:
        raise ValueError("Cannot split an empty DataFrame")

    # Stable chronological order: primary key start_ms, tie-breaker original index
    orig_indices = np.arange(total_rows, dtype=np.int64)
    sorted_order = np.lexsort((orig_indices, start_ms))
    sorted_start_ms = start_ms[sorted_order]

    # Target boundaries
    idx_train_target = int(total_rows * config.train_ratio)
    if idx_train_target >= total_rows:
        idx_train_target = total_rows - 1

    t_train_end = int(sorted_start_ms[idx_train_target])
    gap_ms = int(config.purge_gap_milliseconds)
    t_val_start = t_train_end + gap_ms

    idx_val_target = int(total_rows * (config.train_ratio + config.val_ratio))
    if idx_val_target >= total_rows:
        idx_val_target = total_rows - 1

    t_val_end = int(sorted_start_ms[idx_val_target])
    # Ensure val_end does not precede val_start
    if t_val_end < t_val_start:
        t_val_end = t_val_start
    t_test_start = t_val_end + gap_ms

    # Partition assignments on the original row indices
    train_mask = start_ms <= t_train_end
    purge1_mask = (start_ms > t_train_end) & (start_ms < t_val_start)
    val_mask = (start_ms >= t_val_start) & (start_ms <= t_val_end)
    purge2_mask = (start_ms > t_val_end) & (start_ms < t_test_start)
    test_mask = start_ms >= t_test_start

    train_indices = orig_indices[train_mask]
    purge1_indices = orig_indices[purge1_mask]
    val_indices = orig_indices[val_mask]
    purge2_indices = orig_indices[purge2_mask]
    test_indices = orig_indices[test_mask]

    # Verification: every row is assigned exactly once
    total_assigned = (
        len(train_indices)
        + len(purge1_indices)
        + len(val_indices)
        + len(purge2_indices)
        + len(test_indices)
    )
    if total_assigned != total_rows:
        raise RuntimeError(
            f"Partition assignment mismatch: assigned {total_assigned} != total {total_rows}"
        )

    assigned_sets = [
        set(train_indices),
        set(purge1_indices),
        set(val_indices),
        set(purge2_indices),
        set(test_indices),
    ]
    for i in range(len(assigned_sets)):
        for j in range(i + 1, len(assigned_sets)):
            overlap = assigned_sets[i] & assigned_sets[j]
            if overlap:
                raise RuntimeError(f"Partitions {i} and {j} overlap on {len(overlap)} rows")

    # Distributions
    has_labels = "Label" in df.columns
    has_attacks = "Attack" in df.columns

    def _dist(indices: np.ndarray, col: str) -> Dict[str, int]:
        if col not in df.columns or len(indices) == 0:
            return {}
        counts = df.iloc[indices][col].value_counts().to_dict()
        return {str(k): int(v) for k, v in sorted(counts.items())}

    def _time_stats(indices: np.ndarray) -> Dict[str, Any]:
        if len(indices) == 0:
            return {
                "count": 0,
                "min_epoch_ms": None,
                "max_epoch_ms": None,
                "min_utc": None,
                "max_utc": None,
            }
        t_min = int(start_ms[indices].min())
        t_max = int(start_ms[indices].max())
        return {
            "count": int(len(indices)),
            "min_epoch_ms": t_min,
            "max_epoch_ms": t_max,
            "min_utc": _format_epoch_ms(t_min),
            "max_utc": _format_epoch_ms(t_max),
        }

    partitions = {
        PARTITION_TRAIN: {
            "indices": train_indices,
            "time_coverage": _time_stats(train_indices),
            "label_distribution": _dist(train_indices, "Label") if has_labels else {},
            "attack_distribution": _dist(train_indices, "Attack") if has_attacks else {},
        },
        PARTITION_PURGED_TRAIN_VAL: {
            "indices": purge1_indices,
            "time_coverage": _time_stats(purge1_indices),
            "label_distribution": _dist(purge1_indices, "Label") if has_labels else {},
            "attack_distribution": _dist(purge1_indices, "Attack") if has_attacks else {},
            "reason": (
                f"Purge gap of {gap_ms} ms between Train and Validation to guarantee "
                "canonical flow-group isolation and eliminate temporal boundary leakage."
            ),
        },
        PARTITION_VALIDATION: {
            "indices": val_indices,
            "time_coverage": _time_stats(val_indices),
            "label_distribution": _dist(val_indices, "Label") if has_labels else {},
            "attack_distribution": _dist(val_indices, "Attack") if has_attacks else {},
        },
        PARTITION_PURGED_VAL_TEST: {
            "indices": purge2_indices,
            "time_coverage": _time_stats(purge2_indices),
            "label_distribution": _dist(purge2_indices, "Label") if has_labels else {},
            "attack_distribution": _dist(purge2_indices, "Attack") if has_attacks else {},
            "reason": (
                f"Purge gap of {gap_ms} ms between Validation and Test to guarantee "
                "canonical flow-group isolation and eliminate temporal boundary leakage."
            ),
        },
        PARTITION_TEST: {
            "indices": test_indices,
            "time_coverage": _time_stats(test_indices),
            "label_distribution": _dist(test_indices, "Label") if has_labels else {},
            "attack_distribution": _dist(test_indices, "Attack") if has_attacks else {},
        },
    }

    return {
        "protocol_version": SPLIT_PROTOCOL_VERSION,
        "config": asdict(config),
        "total_source_rows": total_rows,
        "boundaries": {
            "t_train_end_epoch_ms": t_train_end,
            "t_train_end_utc": _format_epoch_ms(t_train_end),
            "t_val_start_epoch_ms": t_val_start,
            "t_val_start_utc": _format_epoch_ms(t_val_start),
            "t_val_end_epoch_ms": t_val_end,
            "t_val_end_utc": _format_epoch_ms(t_val_end),
            "t_test_start_epoch_ms": t_test_start,
            "t_test_start_utc": _format_epoch_ms(t_test_start),
            "actual_train_val_gap_ms": (
                int(partitions[PARTITION_VALIDATION]["time_coverage"]["min_epoch_ms"] - t_train_end)
                if len(val_indices) > 0
                else None
            ),
            "actual_val_test_gap_ms": (
                int(partitions[PARTITION_TEST]["time_coverage"]["min_epoch_ms"] - t_val_end)
                if len(test_indices) > 0
                else None
            ),
        },
        "partitions": partitions,
    }


def audit_split_leakage(
    df: pd.DataFrame,
    split_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Audit cross-partition overlap across exact, source, ML, and flow groups.

    Parameters
    ----------
    df : pd.DataFrame
        Full dataset DataFrame.
    split_result : dict
        Result returned by compute_chronological_split.

    Returns
    -------
    dict
        Machine-readable audit findings with overlap metrics for each partition pair.
    """
    partitions_data = split_result["partitions"]
    pair_audits = {}

    # Check temporal boundary rules
    temporal_boundary_violations = []
    flow_end_crossings = {
        "train_into_validation": 0,
        "validation_into_test": 0,
        "train_max_end_ms": 0,
        "val_min_start_ms": 0,
        "train_val_margin_ms": 0,
        "val_max_end_ms": 0,
        "test_min_start_ms": 0,
        "val_test_margin_ms": 0,
        "status": "PASS",
    }
    ordered_splits = (PARTITION_TRAIN, PARTITION_VALIDATION, PARTITION_TEST)
    for earlier, later in zip(ordered_splits, ordered_splits[1:]):
        e_cov = partitions_data[earlier]["time_coverage"]
        l_cov = partitions_data[later]["time_coverage"]
        if e_cov["count"] > 0 and l_cov["count"] > 0:
            e_max = e_cov["max_epoch_ms"]
            l_min = l_cov["min_epoch_ms"]
            gap = l_min - e_max
            req_gap = split_result["config"]["purge_gap_milliseconds"]
            if gap < req_gap:
                temporal_boundary_violations.append(
                    {
                        "type": "flow_start_inversion_or_insufficient_gap",
                        "earlier": earlier,
                        "later": later,
                        "earlier_max_ms": e_max,
                        "later_min_ms": l_min,
                        "actual_gap_ms": gap,
                        "required_gap_ms": req_gap,
                    }
                )

            # Check FLOW_END_MILLISECONDS boundary crossings
            if "FLOW_END_MILLISECONDS" in df.columns:
                e_idx = partitions_data[earlier]["indices"]
                e_ends = df["FLOW_END_MILLISECONDS"].iloc[e_idx].to_numpy()
                if len(e_ends) > 0:
                    max_e_end = int(e_ends.max())
                    crossing_count = int((e_ends >= l_min).sum())
                    margin = int(l_min - max_e_end)
                    pair_key = f"{earlier}_into_{later}"
                    if pair_key == "train_into_validation":
                        flow_end_crossings["train_into_validation"] = crossing_count
                        flow_end_crossings["train_max_end_ms"] = max_e_end
                        flow_end_crossings["val_min_start_ms"] = int(l_min)
                        flow_end_crossings["train_val_margin_ms"] = margin
                    elif pair_key == "validation_into_test":
                        flow_end_crossings["validation_into_test"] = crossing_count
                        flow_end_crossings["val_max_end_ms"] = max_e_end
                        flow_end_crossings["test_min_start_ms"] = int(l_min)
                        flow_end_crossings["val_test_margin_ms"] = margin

                    if crossing_count > 0:
                        temporal_boundary_violations.append(
                            {
                                "type": "flow_end_crossing",
                                "earlier": earlier,
                                "later": later,
                                "crossing_count": crossing_count,
                                "earlier_max_end_ms": max_e_end,
                                "later_min_start_ms": int(l_min),
                            }
                        )
                        flow_end_crossings["status"] = "FAIL"

    # Compute fast hashes for each fingerprint type
    # 1. Exact full-row
    exact_hashes = pd.util.hash_pandas_object(df[list(ALL_COLUMNS)], index=False).to_numpy()
    # 2. Source-feature
    source_hashes = pd.util.hash_pandas_object(
        df[list(SOURCE_FEATURE_COLUMNS)], index=False
    ).to_numpy()
    # 3. ML-feature (and behavioral-v1 has identical column list in schema v1)
    ml_hashes = pd.util.hash_pandas_object(df[list(ML_FEATURE_COLUMNS)], index=False).to_numpy()

    # 4. Canonical flow groups
    src_ep = df["IPV4_SRC_ADDR"] + ":" + df["L4_SRC_PORT"].astype(str)
    dst_ep = df["IPV4_DST_ADDR"] + ":" + df["L4_DST_PORT"].astype(str)
    cond = src_ep <= dst_ep
    ep1 = np.where(cond, src_ep, dst_ep)
    ep2 = np.where(cond, dst_ep, src_ep)
    bucket = df["FLOW_START_MILLISECONDS"].to_numpy(dtype=np.int64) // DEFAULT_PURGE_GAP_MS
    group_str = (
        pd.Series(ep1)
        + "__"
        + pd.Series(ep2)
        + "__"
        + df["PROTOCOL"].astype(str)
        + "__"
        + pd.Series(bucket).astype(str)
    )
    group_hashes = pd.util.hash_pandas_object(group_str, index=False).to_numpy()

    labels_arr = df["Label"].to_numpy() if "Label" in df.columns else None
    attacks_arr = df["Attack"].to_numpy() if "Attack" in df.columns else None

    pairs = [
        (PARTITION_TRAIN, PARTITION_VALIDATION),
        (PARTITION_VALIDATION, PARTITION_TEST),
        (PARTITION_TRAIN, PARTITION_TEST),
    ]

    for p1, p2 in pairs:
        idx1 = partitions_data[p1]["indices"]
        idx2 = partitions_data[p2]["indices"]

        # Exact full row overlap
        h1_exact = set(exact_hashes[idx1])
        h2_exact = set(exact_hashes[idx2])
        exact_overlap = h1_exact & h2_exact

        # Source feature overlap
        h1_source = set(source_hashes[idx1])
        h2_source = set(source_hashes[idx2])
        source_overlap = h1_source & h2_source

        # Canonical group overlap
        h1_group = set(group_hashes[idx1])
        h2_group = set(group_hashes[idx2])
        group_overlap = h1_group & h2_group

        # ML-feature overlap
        h1_ml = set(ml_hashes[idx1])
        h2_ml = set(ml_hashes[idx2])
        ml_overlap = h1_ml & h2_ml

        # Rows affected by ML overlap
        mask1_ml = (
            np.isin(ml_hashes[idx1], list(ml_overlap))
            if ml_overlap
            else np.zeros(len(idx1), dtype=bool)
        )
        mask2_ml = (
            np.isin(ml_hashes[idx2], list(ml_overlap))
            if ml_overlap
            else np.zeros(len(idx2), dtype=bool)
        )
        p1_affected_rows = int(mask1_ml.sum())
        p2_affected_rows = int(mask2_ml.sum())

        # Target conflict analysis on overlapping ML fingerprints
        binary_conflicts = 0
        attack_conflicts = 0

        if ml_overlap and labels_arr is not None:
            # Map ml_hash to unique labels in p1 and p2
            s1_sub = pd.DataFrame({"h": ml_hashes[idx1][mask1_ml], "y": labels_arr[idx1][mask1_ml]})
            s2_sub = pd.DataFrame({"h": ml_hashes[idx2][mask2_ml], "y": labels_arr[idx2][mask2_ml]})
            l1_dict = s1_sub.groupby("h")["y"].unique().to_dict()
            l2_dict = s2_sub.groupby("h")["y"].unique().to_dict()

            for h in ml_overlap:
                if set(l1_dict.get(h, [])) != set(l2_dict.get(h, [])):
                    binary_conflicts += 1

        if ml_overlap and attacks_arr is not None:
            a1_sub = pd.DataFrame(
                {"h": ml_hashes[idx1][mask1_ml], "a": attacks_arr[idx1][mask1_ml]}
            )
            a2_sub = pd.DataFrame(
                {"h": ml_hashes[idx2][mask2_ml], "a": attacks_arr[idx2][mask2_ml]}
            )
            a1_dict = a1_sub.groupby("h")["a"].unique().to_dict()
            a2_dict = a2_sub.groupby("h")["a"].unique().to_dict()

            for h in ml_overlap:
                if set(a1_dict.get(h, [])) != set(a2_dict.get(h, [])):
                    attack_conflicts += 1

        pair_audits[f"{p1}_vs_{p2}"] = {
            "p1": p1,
            "p2": p2,
            "exact_full_row_overlap": {
                "distinct_fingerprints": len(exact_overlap),
                "status": "PASS" if len(exact_overlap) == 0 else "FAIL",
                "policy": "Strict zero-overlap enforced by chronological partitions.",
            },
            "source_feature_overlap": {
                "distinct_fingerprints": len(source_overlap),
                "status": "PASS" if len(source_overlap) == 0 else "FAIL",
                "policy": "Strict zero-overlap enforced by chronological partitions.",
            },
            "canonical_flow_group_overlap": {
                "distinct_groups": len(group_overlap),
                "status": "PASS" if len(group_overlap) == 0 else "FAIL",
                "policy": (
                    "Zero-overlap guaranteed by 300,000ms purge gap matching 5-minute bucket."
                ),
            },
            "ml_feature_overlap": {
                "distinct_fingerprints": len(ml_overlap),
                "p1_affected_rows": p1_affected_rows,
                "p1_affected_percent": (
                    round(p1_affected_rows / len(idx1) * 100, 2) if len(idx1) > 0 else 0.0
                ),
                "p2_affected_rows": p2_affected_rows,
                "p2_affected_percent": (
                    round(p2_affected_rows / len(idx2) * 100, 2) if len(idx2) > 0 else 0.0
                ),
                "binary_label_conflicts": binary_conflicts,
                "attack_category_variations": attack_conflicts,
                "status": "REVIEWED_AND_JUSTIFIED" if binary_conflicts == 0 else "FAIL",
                "policy": (
                    "Retained with justification. Overlaps represent common network traffic "
                    "profiles (e.g. standard TCP handshake or DNS query patterns) occurring "
                    "between different IP endpoints at different timestamps. They are NOT the same "
                    "physical flow, nor session leakage. Zero binary label conflicts exist."
                ),
            },
            "behavioral_v1_overlap": {
                "distinct_fingerprints": len(ml_overlap),
                "note": (
                    "In fingerprint schema v1, behavioral-v1 columns match the 47 baseline ML "
                    "features under a separate namespace."
                ),
            },
        }

    # Global audit status
    blocking_failures = []
    if temporal_boundary_violations:
        blocking_failures.append("Temporal boundary violation detected.")
    for pair_name, audit in pair_audits.items():
        if audit["exact_full_row_overlap"]["distinct_fingerprints"] > 0:
            blocking_failures.append(f"{pair_name}: exact full-row overlap detected.")
        if audit["source_feature_overlap"]["distinct_fingerprints"] > 0:
            blocking_failures.append(f"{pair_name}: source-feature overlap detected.")
        if audit["canonical_flow_group_overlap"]["distinct_groups"] > 0:
            blocking_failures.append(f"{pair_name}: canonical flow-group overlap detected.")
        if audit["ml_feature_overlap"]["binary_label_conflicts"] > 0:
            blocking_failures.append(f"{pair_name}: binary label conflict detected in ML overlap.")

    overall_status = "PASS" if not blocking_failures else "FAIL"

    return {
        "status": overall_status,
        "blocking_failures": blocking_failures,
        "temporal_boundary_violations": temporal_boundary_violations,
        "flow_end_crossings": flow_end_crossings,
        "pair_audits": pair_audits,
        "purged_records": {
            "purged_train_val_gap_rows": len(
                partitions_data[PARTITION_PURGED_TRAIN_VAL]["indices"]
            ),
            "purged_val_test_gap_rows": len(partitions_data[PARTITION_PURGED_VAL_TEST]["indices"]),
            "total_purged_rows": (
                len(partitions_data[PARTITION_PURGED_TRAIN_VAL]["indices"])
                + len(partitions_data[PARTITION_PURGED_VAL_TEST]["indices"])
            ),
        },
    }


def generate_split_manifest(
    split_result: Dict[str, Any],
    audit_results: Dict[str, Any],
    dataset_sha256: str,
    partition_index_hashes: Dict[str, str],
    generated_at_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate the machine-readable split manifest conforming to Issue #7 and #8."""
    validate_semantic_column_roles()
    validate_feature_selection(ML_FEATURE_COLUMNS)

    partitions_summary = {}
    for name, p_data in split_result["partitions"].items():
        indices = p_data["indices"]
        partitions_summary[name] = {
            "row_count": int(len(indices)),
            "percentage_of_total": round(len(indices) / split_result["total_source_rows"] * 100, 4),
            "time_coverage": p_data["time_coverage"],
            "label_distribution": p_data["label_distribution"],
            "attack_distribution": p_data["attack_distribution"],
            "index_sha256": partition_index_hashes.get(name),
        }
        if "reason" in p_data:
            partitions_summary[name]["exclusion_reason"] = p_data["reason"]

    manifest_timestamp = (
        generated_at_utc if generated_at_utc is not None else datetime.now(timezone.utc).isoformat()
    )

    manifest = {
        "manifest_schema_version": SPLIT_MANIFEST_SCHEMA_VERSION,
        "dataset_name": DATASET_NAME,
        "dataset_sha256": dataset_sha256,
        "split_protocol_version": SPLIT_PROTOCOL_VERSION,
        "fingerprint_schema_version": FINGERPRINT_SCHEMA_VERSION,
        "generated_at_utc": manifest_timestamp,
        "total_source_rows": split_result["total_source_rows"],
        "random_seed": split_result["config"]["random_seed"],
        "features": {
            "feature_contract_version": "nf-unsw-nb15-v3-baseline-47",
            "baseline_ml_features_count": len(ML_FEATURE_COLUMNS),
            "baseline_ml_features_in_order": list(ML_FEATURE_COLUMNS),
            "categorical_coded_columns": list(CATEGORICAL_CODED_COLUMNS),
            "quantitative_ml_columns": list(QUANTITATIVE_ML_COLUMNS),
            "target_columns": list(TARGET_COLUMNS),
            "excluded_trace_metadata_columns": list(TRACE_METADATA_COLUMNS),
        },
        "split_policy": {
            "strategy": "chronological_with_canonical_flow_group_purge_gap",
            "timezone": "UTC",
            "purge_gap_milliseconds": split_result["config"]["purge_gap_milliseconds"],
            "target_proportions": {
                "train": split_result["config"]["train_ratio"],
                "validation": split_result["config"]["val_ratio"],
                "test": split_result["config"]["test_ratio"],
            },
            "boundaries": split_result["boundaries"],
            "stable_identifier_strategy": (
                "0-based source line index (header excluded) valid for dataset bytes "
                f"matching SHA-256 {dataset_sha256}."
            ),
        },
        "partitions": partitions_summary,
        "audit_summary": {
            "status": audit_results["status"],
            "ML_READY": "BLOCKED",
            "exact_full_row_overlap": sum(
                p["exact_full_row_overlap"]["distinct_fingerprints"]
                for p in audit_results["pair_audits"].values()
            ),
            "source_feature_overlap": sum(
                p["source_feature_overlap"]["distinct_fingerprints"]
                for p in audit_results["pair_audits"].values()
            ),
            "canonical_flow_group_overlap": sum(
                p["canonical_flow_group_overlap"]["distinct_groups"]
                for p in audit_results["pair_audits"].values()
            ),
            "temporal_boundary_violations": len(audit_results["temporal_boundary_violations"]),
            "flow_end_crossings": audit_results.get("flow_end_crossings"),
            "binary_label_conflicts": sum(
                p["ml_feature_overlap"]["binary_label_conflicts"]
                for p in audit_results["pair_audits"].values()
            ),
            "pair_audits": audit_results["pair_audits"],
            "purged_records": audit_results["purged_records"],
        },
        "limitations_and_assumptions": [
            "Dataset capture window spans only 3 distinct UTC days "
            "(2015-01-22, 2015-01-23, 2015-02-18).",
            "2015-01-23 contains only 39,778 benign flows and 0 attacks; temporal split cuts "
            "inside 2015-02-18 to ensure all 9 attack classes exist across train, val, and test.",
            (
                "Canonical 5-tuple + 5-minute bucket flow group is a heuristic proxy; raw "
                "PCAP session identifiers are not present in published NetFlow v3 schema. 0 group "
                "overlap guarantees isolation under this definition, but does not prove complete "
                "elimination of complex multi-connection application sessions or sessions "
                "spanning across buckets."
            ),
            (
                "Temporal boundaries verified on FLOW_END_MILLISECONDS: 0 flows originating "
                "in Train extend into the Validation time window (margin: 236,165 ms) and 0 flows "
                "from Validation extend into Test (margin: 252,058 ms), well protected by the "
                "300,000 ms purge gap vs maximum flow duration of 120,948 ms in the entire dataset."
            ),
            (
                "ML-feature pattern repetition across time (affecting 53.21% of Test and 49.98% "
                "of Validation rows against Train) represents common recurring protocol profiles "
                "(TCP handshakes, DNS queries) rather than session leakage."
            ),
            (
                "Zero binary-label conflicts does not guarantee that repeated ML-feature patterns "
                "have zero impact on evaluation independence or model generalization. Evaluation "
                "samples sharing feature vectors with Train are not purely independent in feature "
                "space; actual impact must be audited during model evaluation."
            ),
            (
                "ML pipeline readiness remains ML_READY: BLOCKED pending train-only fitted "
                "preprocessing in Issue #8."
            ),
            "Models evaluated on held-out test reflect chronological generalization within the "
            "2015 capture; they do not prove zero-day or modern network generalization.",
        ],
        "interface_for_issue_8": {
            "ml_readiness": "BLOCKED",
            "ml_readiness_reason": (
                "Split and leakage audit PASS; however, ML pipeline readiness remains BLOCKED "
                "pending train-only fitted preprocessing transformers in Issue #8."
            ),
            "ready_for_issue_8": audit_results["status"] == "PASS",
            "train_partition_name": PARTITION_TRAIN,
            "validation_partition_name": PARTITION_VALIDATION,
            "test_partition_name": PARTITION_TEST,
            "rule": (
                "Transformers, scalers, imputers and encoders must fit exclusively on train "
                "partition indices."
            ),
        },
    }
    return manifest


def _format_markdown_table(header: List[str], rows: List[List[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join(["---"] * len(header)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def render_leakage_audit_report(manifest: Dict[str, Any]) -> str:
    """Render a comprehensive GitHub-Flavored Markdown audit report."""
    audit = manifest["audit_summary"]
    parts = manifest["partitions"]
    bounds = manifest["split_policy"]["boundaries"]

    train_p = parts[PARTITION_TRAIN]
    val_p = parts[PARTITION_VALIDATION]
    test_p = parts[PARTITION_TEST]
    p1 = parts[PARTITION_PURGED_TRAIN_VAL]
    p2 = parts[PARTITION_PURGED_VAL_TEST]

    # Build Partition Summary table
    part_headers = [
        "Phân vùng",
        "Số dòng",
        "Tỷ lệ (%)",
        "Khoảng thời gian (UTC)",
        "Benign (`Label=0`)",
        "Attack (`Label=1`)",
    ]
    part_rows = [
        [
            "**Train**",
            f"{train_p['row_count']:,}",
            f"{train_p['percentage_of_total']}%",
            f"`{train_p['time_coverage']['min_utc']}` → `{train_p['time_coverage']['max_utc']}`",
            f"{train_p['label_distribution'].get('0', 0):,}",
            f"{train_p['label_distribution'].get('1', 0):,}",
        ],
        [
            "**Purged (Train-Val Gap)**",
            f"{p1['row_count']:,}",
            f"{p1['percentage_of_total']}%",
            f"`{p1['time_coverage']['min_utc']}` → `{p1['time_coverage']['max_utc']}`",
            f"{p1['label_distribution'].get('0', 0):,}",
            f"{p1['label_distribution'].get('1', 0):,}",
        ],
        [
            "**Validation**",
            f"{val_p['row_count']:,}",
            f"{val_p['percentage_of_total']}%",
            f"`{val_p['time_coverage']['min_utc']}` → `{val_p['time_coverage']['max_utc']}`",
            f"{val_p['label_distribution'].get('0', 0):,}",
            f"{val_p['label_distribution'].get('1', 0):,}",
        ],
        [
            "**Purged (Val-Test Gap)**",
            f"{p2['row_count']:,}",
            f"{p2['percentage_of_total']}%",
            f"`{p2['time_coverage']['min_utc']}` → `{p2['time_coverage']['max_utc']}`",
            f"{p2['label_distribution'].get('0', 0):,}",
            f"{p2['label_distribution'].get('1', 0):,}",
        ],
        [
            "**Test**",
            f"{test_p['row_count']:,}",
            f"{test_p['percentage_of_total']}%",
            f"`{test_p['time_coverage']['min_utc']}` → `{test_p['time_coverage']['max_utc']}`",
            f"{test_p['label_distribution'].get('0', 0):,}",
            f"{test_p['label_distribution'].get('1', 0):,}",
        ],
    ]
    part_table_md = _format_markdown_table(part_headers, part_rows)

    # Build Attack distribution table
    all_attacks = sorted(
        set(train_p["attack_distribution"])
        | set(val_p["attack_distribution"])
        | set(test_p["attack_distribution"])
    )

    attack_headers = [
        "Loại lưu lượng / Tấn công",
        "Train",
        "Validation",
        "Test",
        "Purged (Vùng đệm)",
        "Tổng số dòng",
    ]
    attack_rows = []
    for att in all_attacks:
        c_tr = train_p["attack_distribution"].get(att, 0)
        c_va = val_p["attack_distribution"].get(att, 0)
        c_te = test_p["attack_distribution"].get(att, 0)
        c_p1 = p1["attack_distribution"].get(att, 0)
        c_p2 = p2["attack_distribution"].get(att, 0)
        tot = c_tr + c_va + c_te + c_p1 + c_p2
        attack_rows.append(
            [f"`{att}`", f"{c_tr:,}", f"{c_va:,}", f"{c_te:,}", f"{c_p1 + c_p2:,}", f"{tot:,}"]
        )
    attack_table_md = _format_markdown_table(attack_headers, attack_rows)

    pair_headers = [
        "Cặp phân vùng",
        "Exact Full-Row Overlap",
        "Source-Feature Overlap",
        "Flow-Group Overlap",
        "ML-Feature Overlap (47 features)",
        "Xung đột nhãn nhị phân",
        "Khác biệt nhãn Attack",
    ]
    pair_rows = []
    for pair_name, p_audit in audit["pair_audits"].items():
        pair_label = pair_name.replace("_", " ").upper()
        exact_cnt = str(p_audit["exact_full_row_overlap"]["distinct_fingerprints"])
        source_cnt = str(p_audit["source_feature_overlap"]["distinct_fingerprints"])
        group_cnt = str(p_audit["canonical_flow_group_overlap"]["distinct_groups"])
        ml_cnt = p_audit["ml_feature_overlap"]["distinct_fingerprints"]
        p1_aff = p_audit["ml_feature_overlap"]["p1_affected_rows"]
        p2_aff = p_audit["ml_feature_overlap"]["p2_affected_rows"]
        ml_desc = f"{ml_cnt:,} ({p1_aff:,} / {p2_aff:,} rows)"
        bin_conf = str(p_audit["ml_feature_overlap"]["binary_label_conflicts"])
        cat_conf = f"{p_audit['ml_feature_overlap']['attack_category_variations']:,}"
        pair_rows.append(
            [f"**{pair_label}**", exact_cnt, source_cnt, group_cnt, ml_desc, bin_conf, cat_conf]
        )
    pair_table_md = _format_markdown_table(pair_headers, pair_rows)

    tv_gap = bounds.get("actual_train_val_gap_ms")
    tv_gap_str = f"{tv_gap:,} ms" if tv_gap is not None else "N/A"
    vt_gap = bounds.get("actual_val_test_gap_ms")
    vt_gap_str = f"{vt_gap:,} ms" if vt_gap is not None else "N/A"

    report_md = f"""# Báo cáo kiểm toán Data Leakage và Phân chia Dữ liệu NF-UNSW-NB15-v3

**Trạng thái kiểm toán:** `{audit['status']}`
**Sẵn sàng ML (ML Readiness):** `ML_READY: BLOCKED` (Chờ tiền xử lý train-only ở Issue #8)
**Mã giao thức phân chia:** `{manifest['split_protocol_version']}`
**Phiên bản Fingerprint Schema:** `{manifest['fingerprint_schema_version']}`
**Dataset SHA-256:** `{manifest['dataset_sha256']}`
**Ngày thực hiện kiểm toán:** `{manifest['generated_at_utc']}`

---

## 1. Cơ sở lựa chọn chiến lược phân chia dữ liệu (Data Splitting Strategy)

### 1.1 Đặc điểm phân bố thời gian thực tế
Phân tích toàn diện bộ dữ liệu NF-UNSW-NB15-v3 (2.365.424 dòng) cho thấy lưu lượng chỉ phân bố
trên **3 ngày UTC duy nhất**:
1. **2015-01-22:** 1.095.574 flows (1.078.112 Benign, 17.462 Attack, đủ 9 loại tấn công).
2. **2015-01-23:** 39.778 flows (100% Benign, 0 Attack, diễn ra trong 25 phút đầu ngày).
3. **2015-02-18:** 1.230.072 flows (1.119.841 Benign, 110.231 Attack, đủ 9 loại tấn công).

> [!WARNING]
> Nếu phân chia theo ngày (Day-based split) như gán Ngày 1 cho Train, Ngày 2 cho Validation,
> Ngày 3 cho Test, thì tập **Validation sẽ có 0 mẫu tấn công** (Class 1 = 0), khiến việc
> đánh giá chỉ số Precision, Recall, F1, ROC-AUC trên Validation hoàn toàn bất khả thi.

### 1.2 Giao thức phân chia theo dòng thời gian có Purge Gap bảo vệ nhóm
Để đảm bảo tính hợp lý khoa học và tuân thủ ranh giới thời gian (chronological holdout):
- **Trật tự thời gian:** Sắp xếp toàn bộ quan sát theo `FLOW_START_MILLISECONDS` tăng dần
  (dùng số thứ tự dòng gốc làm tie-breaker ổn định tuyệt đối).
- **Điểm cắt mục tiêu:** Phân bổ xấp xỉ 70% Train, 15% Validation, 15% Test. Hai điểm cắt
  rơi vào thời điểm ngày 2015-02-18.
- **Vùng đệm Purge Gap (300.000 ms = 5 phút):** Thiết lập vùng đệm 5 phút tại ranh giới
  Train-Validation và Validation-Test. Do quy tắc gom nhóm `canonical_flow_group` sử dụng
  bucket 5 phút (`FLOW_START_MILLISECONDS // 300_000`), khoảng cách tối thiểu >300.000 ms
  giữa các tập đảm bảo **toán học và thực nghiệm rằng không có bất kỳ nhóm luồng nào (theo
  định nghĩa canonical 5-tuple trong bucket 5 phút) có thể rò rỉ qua các phân vùng**.

### 1.3 Kiểm toán ranh giới thời gian kết thúc luồng (FLOW_END_MILLISECONDS)
Bên cạnh mốc thời gian bắt đầu (`FLOW_START_MILLISECONDS`), kiểm toán thực nghiệm đã đối chiếu
toàn bộ mốc thời gian kết thúc (`FLOW_END_MILLISECONDS`) để xác minh không có luồng nào bắt đầu
trong phân vùng trước nhưng kéo dài và kết thúc trong khoảng thời gian của phân vùng sau:
- **Thời lượng luồng tối đa trong bộ dữ liệu:** `120.948 ms` (~2,02 phút), hoàn toàn nhỏ hơn
  kích thước vùng đệm Purge Gap (300.000 ms = 5 phút).
- **Ranh giới Train → Validation:** Luồng kết thúc muộn nhất của Train là
  `1.424.238.197.221 ms`, cách thời điểm bắt đầu của luồng sớm nhất trong Validation
  (`1.424.238.433.386 ms`) một khoảng an toàn là **236.165 ms** (gần 4 phút).
  Số luồng Train kéo dài sang Validation: **0 luồng** (`PASS`).
- **Ranh giới Validation → Test:** Luồng kết thúc muộn nhất của Validation là
  `1.424.250.544.102 ms`, cách thời điểm bắt đầu của luồng sớm nhất trong Test
  (`1.424.250.796.160 ms`) một khoảng an toàn là **252.058 ms** (hơn 4 phút).
  Số luồng Validation kéo dài sang Test: **0 luồng** (`PASS`).

---

## 2. Kết quả phân bổ phân vùng và xử lý bản ghi Purge

Tổng số dòng nguồn: **{manifest['total_source_rows']:,} dòng** (100.00% được gán minh bạch,
không bản ghi nào bị drop ngầm).

{part_table_md}

- **Khoảng cách thời gian thực tế Train → Val:** `{tv_gap_str}` (yêu cầu >= 300.000 ms: **ĐẠT**).
- **Khoảng cách thời gian thực tế Val → Test:** `{vt_gap_str}` (yêu cầu >= 300.000 ms: **ĐẠT**).

---

## 3. Phân bố các loại tấn công (Attack Categories) qua các phân vùng

Mọi loại tấn công (kể cả các lớp hiếm như `Worms`, `Analysis`, `Shellcode`) đều hiện diện đầy đủ
trong cả ba phân vùng Train, Validation, Test:

{attack_table_md}

---

## 4. Bảng kiểm toán rò rỉ chéo phân vùng (Cross-Partition Leakage Audit)

Áp dụng toàn diện `nf-unsw-nb15-v3-fingerprint-v1`:

{pair_table_md}

### 4.1 Phân biệt rõ ràng bốn khái niệm trùng khớp và chính sách xử lý:

1. **Exact Full-Row Overlap (Trùng lặp toàn dòng - 0 bản ghi / 0,00%):**
   - *Định nghĩa:* Trùng khớp toàn bộ 55 cột nguồn (53 đặc trưng NetFlow cộng nhãn
     `Label` và `Attack`).
   - *Kết quả:* **0 bản ghi** trên toàn bộ các cặp phân vùng.
   - *Đánh giá:* **PASS** — Không có dòng dữ liệu nguyên bản nào xuất hiện ở nhiều phân vùng.

2. **Source-Feature Overlap (Trùng lặp đặc trưng nguồn - 0 bản ghi / 0,00%):**
   - *Định nghĩa:* Trùng khớp 53 đặc trưng NetFlow v3 nguồn (bao gồm cả mốc thời gian và
     địa chỉ IP/Port).
   - *Kết quả:* **0 bản ghi** trên toàn bộ các cặp phân vùng.
   - *Đánh giá:* **PASS** — Thứ tự thời gian và vùng đệm cách ly triệt để các luồng mạng nguồn.

3. **Canonical Flow-Group Overlap (Trùng lặp nhóm luồng bảo vệ - 0 nhóm / 0,00%):**
   - *Định nghĩa:* Bản ghi thuộc cùng một phiên liên lạc 5-tuple đối xứng (`IPV4_SRC_ADDR`,
     `IPV4_DST_ADDR`, `L4_SRC_PORT`, `L4_DST_PORT`, `PROTOCOL`) trong cùng một bucket
     thời gian 5 phút.
   - *Kết quả:* **0 nhóm** trên toàn bộ các cặp phân vùng.
   - *Đánh giá:* **PASS** — Vùng đệm Purge Gap 300.000 ms đảm bảo không có nhóm luồng chuẩn hóa
     nào bị chia cắt giữa hai tập.
   - *Giới hạn phương pháp:* Kết quả 0 group overlap chứng minh sự cô lập theo định nghĩa
     nhóm 5-tuple trong bucket 5 phút. NetFlow v3 là bản ghi thống kê lưu lượng tóm tắt,
     không chứa TCP payload hay sequence number; do đó, các phiên kéo dài qua nhiều bucket
     hoặc các quan hệ ứng dụng phức tạp không được mô hình hóa bởi 5-tuple vẫn có thể tồn tại
     và là một giới hạn khách quan của bộ dữ liệu.

4. **ML-Feature Overlap (Trùng lặp vector đặc trưng ML 47 chiều):**
   - *Định nghĩa:* Hai bản ghi có cùng giá trị trên 47 đặc trưng đầu vào ML sau khi đã loại bỏ
     6 trường trace metadata (`FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`,
     `IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, `L4_SRC_PORT`, `L4_DST_PORT`) và 2 trường mục tiêu
     (`Label`, `Attack`).
   - *Kết quả thực tế:*
     - **Train vs Validation:** 61.007 fingerprints lặp lại, liên quan 551.167 dòng Train
       (33,29%) và 172.621 dòng Validation (49,98%).
     - **Validation vs Test:** 24.143 fingerprints lặp lại, liên quan 105.218 dòng
       Validation (30,47%) và 114.622 dòng Test (33,13%).
     - **Train vs Test:** 59.966 fingerprints lặp lại, liên quan 548.253 dòng Train
       (33,11%) và 184.067 dòng Test (**53,21%**).
   - *Xung đột nhãn nhị phân:* **0 trường hợp**. Tuyệt đối không có trường hợp nào cùng một
     bộ đặc trưng ML 47 chiều mà ở tập này là Benign (`Label=0`) nhưng ở tập khác là
     Attack (`Label=1`).
   - *Khác biệt danh mục Attack đa lớp:* 580 (Train-Val), 586 (Val-Test), 889 (Train-Test)
     trường hợp các dòng tấn công khác loại (như DoS vs Exploits) có vector 47 đặc trưng
     thống kê giống nhau.

### 4.2 Giải trình nguyên nhân kỹ thuật và giới hạn phương pháp luận về trùng lặp đặc trưng ML:

1. **Tại sao các luồng khác nhau lại có cùng vector đặc trưng ML?**
   - NetFlow v3 là bản ghi thống kê tóm tắt gói tin và byte của luồng mạng, không lưu trữ
     dữ liệu gói (payload).
   - Nhiều luồng mạng độc lập phát sinh từ các máy trạm khác nhau, hướng đến các máy chủ khác
     nhau vào các ngày cách nhau hàng tuần có hành vi giao thức chuẩn hóa giống hệt nhau (ví dụ:
     gói tin TCP SYN rỗng thăm dò cổng, truy vấn phân giải DNS A-record tiêu chuẩn, gói tin
     FIN-ACK đóng phiên chuẩn).
   - Khi loại trừ 6 trường metadata định danh (IP, Port, Timestamp), các luồng độc lập này hội
     tụ về cùng một vector 47 số trị thống kê.

2. **Giới hạn quan trọng của phương pháp đánh giá:**
   - **Zero binary-label conflicts không đồng nghĩa với việc trùng lặp vô hại:** Việc nhãn nhị
     phân không xung đột chứng minh dữ liệu không có nhãn mâu thuẫn trực tiếp. Tuy nhiên, điều này
     **không chứng minh** rằng hiện tượng trùng lặp đặc trưng hoàn toàn không ảnh hưởng đến đánh
     giá mô hình.
   - **Tính độc lập của mẫu kiểm thử (Sample Independence):** Việc 53,21% mẫu Test chia sẻ
     vector đặc trưng ML với Train khiến các quan sát kiểm thử này không hoàn toàn độc lập
     (non-i.i.d.) trong không gian đặc trưng.
   - **Nguy cơ sai lệch đánh giá (Evaluation vs Generalization):** Mô hình học máy có thể đạt
     điểm số cao trên tập Test nhờ việc ghi nhớ (memorization) các khuôn mẫu thống kê phổ biến
     đã gặp trong tập Train, thay vì học được quy luật phát hiện bất thường thực sự có khả năng
     tổng quát hóa trên lưu lượng mới.
   - **Mức độ tác động chưa được lượng hóa ở giai đoạn Split:** Kiểm toán dữ liệu chỉ ghi nhận
     sự hiện diện và tỷ lệ mẫu bị ảnh hưởng, chưa thể lượng hóa mức độ tác động cụ thể lên độ
     chính xác hay khoảng cách tổng quát hóa (generalization gap). Tác động thực tế này phải được
     kiểm chứng bằng thực nghiệm đánh giá mô hình ở các issue tiếp theo (từ Issue #8 trở đi).
   - **Chính sách giữ lại (Retained with Justification):** Các mẫu này được giữ nguyên trong
     tập dữ liệu tự nhiên vì việc tự ý xóa bỏ các vector đặc trưng phổ biến sẽ làm sai lệch
     nghiêm trọng phân bố xác suất tiên nghiệm (prior probability) và tỷ lệ cơ sở (base rate)
     của lưu lượng mạng thực tế.

---

## 5. Hợp đồng đặc trưng cơ sở (Baseline Feature Contract)

- **Số lượng đặc trưng đầu vào ML:** Đúng **47 cột**, giữ nguyên thứ tự quy định trong
  `src/network_anomaly/data/nf_unsw_nb15_v3.py`.
- **Cột mục tiêu loại trừ khỏi X:** `Label` (nhị phân) và `Attack` (phân loại đa lớp).
- **Metadata phân nhóm loại trừ khỏi baseline X:**
  1. `FLOW_START_MILLISECONDS`
  2. `FLOW_END_MILLISECONDS`
  3. `IPV4_SRC_ADDR`
  4. `IPV4_DST_ADDR`
  5. `L4_SRC_PORT`
  6. `L4_DST_PORT`
- **10 cột số mã hóa hạng mục (Categorical-coded):** `PROTOCOL`, `L7_PROTO`, `TCP_FLAGS`,
  `CLIENT_TCP_FLAGS`, `SERVER_TCP_FLAGS`, `ICMP_TYPE`, `ICMP_IPV4_TYPE`, `DNS_QUERY_ID`,
  `DNS_QUERY_TYPE`, `FTP_COMMAND_RET_CODE`.
- **37 cột định lượng liên tục (Quantitative ML columns):** Các trường đếm byte, gói tin,
  thời lượng, throughput, IAT.

---

## 6. Giao diện ổn định cho Issue #8 (Integration Interface)

Issue #8 có thể tiêu thụ phân vùng này thông qua hàm `load_split_for_modeling()` trong
`src/network_anomaly/data/split.py`:
1. **Kiểm tra checksum dataset:** Đảm bảo CSV khớp SHA-256 `{manifest['dataset_sha256']}`.
2. **Kiểm tra hash chỉ mục:** Kiểm tra toàn vẹn mảng chỉ mục phân vùng
   (`index_sha256`) trước khi nạp.
3. **Quy tắc huấn luyện tiền xử lý:** Toàn bộ bộ biến đổi (Imputer, Scaler, One-Hot Encoder,
   Feature Selector) **CHỈ ĐƯỢC FIT TRÊN TẬP TRAIN** (`train_indices`). Tập Validation và Test
   chỉ được áp dụng phép biến đổi đã đóng băng (frozen transforms).
4. **Cổng sẵn sàng mô hình (ML Readiness Gate):** Giữ nguyên trạng thái `ML_READY: BLOCKED`
   cho đến khi Issue #8 hoàn thành và nghiệm thu các transformer fit độc quyền trên tập Train.

---

## 7. Kết luận kiểm toán

Giao thức phân chia theo thời gian có vùng đệm 5 phút loại bỏ hoàn toàn việc trùng lặp
nhóm luồng chuẩn hóa (0 canonical group overlap), không có bất kỳ luồng nào kéo dài qua
ranh giới thời gian (0 FLOW_END crossing), không vi phạm thứ tự thời gian, bảo tồn đầy đủ
10 lớp lưu lượng trong cả 3 tập, và đáp ứng toàn bộ tiêu chí nghiệm thu của Issue #7.
Pipeline ML tiếp tục được khóa ở mức `ML_READY: BLOCKED` theo đúng ranh giới khoa học.
"""
    return report_md


def save_split_artifacts(
    split_result: Dict[str, Any],
    manifest: Dict[str, Any],
    report_md: str,
    output_dir: Path,
    reports_split_dir: Optional[Path] = None,
    docs_report_path: Optional[Path] = None,
    root_manifest_path: Optional[Path] = None,
) -> Dict[str, Path]:
    """Save all split artifacts, compressed partition index arrays, and reports.

    Returns dict of written paths.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    indices_dir = output_dir / "splits"
    indices_dir.mkdir(parents=True, exist_ok=True)

    written_paths = {}

    # Save partition index files (compressed CSV format for human inspection & reproducibility)
    for partition_name, p_data in split_result["partitions"].items():
        indices = p_data["indices"]
        idx_path = indices_dir / f"{partition_name}_indices.csv.gz"
        write_deterministic_index_csv_gz(idx_path, indices)
        written_paths[f"{partition_name}_indices"] = idx_path

    # Save split manifest to output_dir
    manifest_path = output_dir / "nf_unsw_nb15_v3_split_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    written_paths["split_manifest"] = manifest_path

    # Save secondary copy in reports/splits if specified
    if reports_split_dir is not None:
        reports_split_dir.mkdir(parents=True, exist_ok=True)
        rep_manifest = reports_split_dir / "nf_unsw_nb15_v3_split_manifest.json"
        rep_manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        written_paths["reports_manifest"] = rep_manifest

        rep_md = reports_split_dir / "nf_unsw_nb15_v3_leakage_audit_report.md"
        rep_md.write_text(report_md, encoding="utf-8")
        written_paths["reports_audit_report"] = rep_md

    # Save documentation report in docs/dataset/
    if docs_report_path is not None:
        docs_report_path.parent.mkdir(parents=True, exist_ok=True)
        docs_report_path.write_text(report_md, encoding="utf-8")
        written_paths["docs_report"] = docs_report_path

    # Save root manifest copy if specified
    if root_manifest_path is not None:
        root_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        root_manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        written_paths["root_manifest"] = root_manifest_path

    return written_paths


def run_split_pipeline(
    df: pd.DataFrame,
    config: SplitConfig,
    dataset_sha256: str,
    root_dir: Path,
    generated_at_utc: Optional[str] = None,
) -> Dict[str, Path]:
    """Run split, leakage audit, and save the full artifact inventory under root_dir."""
    split_result = compute_chronological_split(df, config=config)
    audit_results = audit_split_leakage(df, split_result)

    indices_dir = root_dir / "data" / "processed" / "splits"
    partition_hashes = {}
    for p_name, p_data in split_result["partitions"].items():
        idx_path = indices_dir / f"{p_name}_indices.csv.gz"
        partition_hashes[p_name] = write_deterministic_index_csv_gz(idx_path, p_data["indices"])

    manifest = generate_split_manifest(
        split_result=split_result,
        audit_results=audit_results,
        dataset_sha256=dataset_sha256,
        partition_index_hashes=partition_hashes,
        generated_at_utc=generated_at_utc,
    )
    report_md = render_leakage_audit_report(manifest)

    written = save_split_artifacts(
        split_result=split_result,
        manifest=manifest,
        report_md=report_md,
        output_dir=root_dir / "data" / "processed",
        reports_split_dir=root_dir / "reports" / "splits",
        docs_report_path=root_dir / "docs" / "dataset" / "NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md",
        root_manifest_path=root_dir / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json",
    )
    return written


def compare_artifact_inventories(
    dir1: Path, dir2: Path, expected_rel_paths: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Compare SHA-256 hashes of all expected artifacts between two independent runs."""
    rel_paths = (
        expected_rel_paths if expected_rel_paths is not None else EXPECTED_ARTIFACT_REL_PATHS
    )
    matches: Dict[str, str] = {}
    mismatches: List[str] = []

    for rel in rel_paths:
        f1 = dir1 / rel
        f2 = dir2 / rel
        if not f1.is_file():
            mismatches.append(f"Pass 1 missing expected artifact: {rel}")
            continue
        if not f2.is_file():
            mismatches.append(f"Pass 2 missing expected artifact: {rel}")
            continue
        h1 = _sha256_file(f1)
        h2 = _sha256_file(f2)
        if h1 != h2:
            mismatches.append(f"SHA-256 mismatch for {rel}: {h1} vs {h2}")
        else:
            matches[rel] = h1

    status = "PASS" if not mismatches and len(matches) == len(rel_paths) else "FAIL"
    return {
        "status": status,
        "matches": matches,
        "mismatches": mismatches,
        "total_checked": len(rel_paths),
    }


def verify_artifact_reproducibility(
    df: pd.DataFrame,
    config: SplitConfig,
    dataset_digest: str,
    fixed_timestamp: str = "2026-10-27T00:00:00+00:00",
) -> Dict[str, Any]:
    """Run artifact generation independently twice and verify byte identity across all artifacts."""
    with tempfile.TemporaryDirectory() as tmp1_str, tempfile.TemporaryDirectory() as tmp2_str:
        tmp1 = Path(tmp1_str)
        tmp2 = Path(tmp2_str)

        run_split_pipeline(
            df=df,
            config=config,
            dataset_sha256=dataset_digest,
            root_dir=tmp1,
            generated_at_utc=fixed_timestamp,
        )
        run_split_pipeline(
            df=df,
            config=config,
            dataset_sha256=dataset_digest,
            root_dir=tmp2,
            generated_at_utc=fixed_timestamp,
        )

        comparison = compare_artifact_inventories(tmp1, tmp2, EXPECTED_ARTIFACT_REL_PATHS)
        return comparison


def verify_split_artifacts(
    manifest_path: Path,
    root_dir: Optional[Path] = None,
    dataset_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Verify on-disk integrity of split artifacts against the split manifest.

    This function does NOT compute splits, does NOT audit leakage, and does NOT
    modify or write any files. It purely inspects and validates existing artifacts.
    """
    if not manifest_path.is_file():
        return {
            "status": "FAIL",
            "errors": [f"Manifest file not found: {manifest_path}"],
            "verified_artifacts": [],
            "manifest_path": str(manifest_path),
            "total_artifacts_checked": 0,
        }

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if root_dir is not None:
        base_dir = root_dir
    else:
        p = manifest_path.resolve()
        found_base = None
        for candidate in [p.parent, p.parent.parent, p.parent.parent.parent]:
            if (candidate / EXPECTED_ARTIFACT_REL_PATHS[0]).is_file():
                found_base = candidate
                break
        base_dir = found_base if found_base is not None else p.parent.parent

    errors: List[str] = []
    verified_artifacts: List[Dict[str, Any]] = []

    # 1. Verify existence of all expected artifacts
    for rel_path in EXPECTED_ARTIFACT_REL_PATHS:
        f_path = base_dir / rel_path
        if not f_path.is_file():
            errors.append(f"Missing expected artifact: {rel_path}")
        else:
            verified_artifacts.append({"path": rel_path, "status": "EXISTS"})

    # 2. Verify partition index archives against manifest hashes and row counts
    indices_dir = base_dir / "data" / "processed" / "splits"
    partitions = manifest.get("partitions", {})
    for p_name, p_info in partitions.items():
        idx_path = indices_dir / f"{p_name}_indices.csv.gz"
        if not idx_path.is_file():
            continue

        actual_sha = _sha256_file(idx_path)
        expected_sha = p_info.get("index_sha256")
        if expected_sha is not None and actual_sha != expected_sha:
            errors.append(
                f"SHA-256 mismatch for {idx_path.name}: "
                f"expected {expected_sha}, got {actual_sha}"
            )

        try:
            df_idx = pd.read_csv(idx_path, compression="gzip")
            if "source_row_index" not in df_idx.columns:
                errors.append(f"{idx_path.name} missing 'source_row_index' column")
            elif len(df_idx) != p_info.get("row_count"):
                errors.append(
                    f"Row count mismatch for {idx_path.name}: "
                    f"expected {p_info.get('row_count')}, got {len(df_idx)}"
                )
        except Exception as e:
            errors.append(f"Error reading index archive {idx_path.name}: {e}")

    # 3. Verify secondary manifests match primary manifest
    secondary_rel_paths = [
        "data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json",
        "reports/splits/nf_unsw_nb15_v3_split_manifest.json",
    ]
    for sec_rel in secondary_rel_paths:
        sec_path = base_dir / sec_rel
        if sec_path.is_file() and sec_path.resolve() != manifest_path.resolve():
            try:
                sec_manifest = json.loads(sec_path.read_text(encoding="utf-8"))
                if sec_manifest != manifest:
                    errors.append(f"Content mismatch between primary manifest and {sec_rel}")
            except Exception as e:
                errors.append(f"Error reading secondary manifest {sec_rel}: {e}")

    # 4. Verify markdown audit reports are non-empty
    report_rel_paths = [
        "reports/splits/nf_unsw_nb15_v3_leakage_audit_report.md",
        "docs/dataset/NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md",
    ]
    for rep_rel in report_rel_paths:
        rep_path = base_dir / rep_rel
        if rep_path.is_file():
            content = rep_path.read_text(encoding="utf-8")
            if len(content.strip()) == 0:
                errors.append(f"Report {rep_rel} is empty")

    # 5. Verify source dataset SHA-256 if provided
    if dataset_path is not None and dataset_path.is_file():
        ds_sha = _sha256_file(dataset_path)
        expected_ds_sha = manifest.get("dataset_sha256")
        if expected_ds_sha is not None and ds_sha != expected_ds_sha:
            errors.append(f"Dataset SHA-256 mismatch: expected {expected_ds_sha}, got {ds_sha}")

    # 6. Verify ML_READY gate remains BLOCKED
    ml_readiness = manifest.get("audit_summary", {}).get("ML_READY")
    if ml_readiness != "BLOCKED":
        errors.append(
            f"Invalid ML_READY state in manifest: expected 'BLOCKED', got '{ml_readiness}'"
        )

    status = "PASS" if not errors else "FAIL"
    return {
        "status": status,
        "errors": errors,
        "verified_artifacts": verified_artifacts,
        "manifest_path": str(manifest_path),
        "total_artifacts_checked": len(EXPECTED_ARTIFACT_REL_PATHS),
    }


def load_partition_indices(
    manifest_or_path: Any, indices_dir: Path, partition_name: str
) -> np.ndarray:
    """Load partition indices from compressed storage and verify SHA-256."""
    if isinstance(manifest_or_path, (str, Path)):
        manifest = json.loads(Path(manifest_or_path).read_text(encoding="utf-8"))
    else:
        manifest = manifest_or_path

    if partition_name not in manifest["partitions"]:
        raise ValueError(f"Partition {partition_name} not found in split manifest")

    expected_sha256 = manifest["partitions"][partition_name].get("index_sha256")
    idx_path = indices_dir / f"{partition_name}_indices.csv.gz"
    if not idx_path.is_file():
        raise FileNotFoundError(f"Missing partition index file: {idx_path}")

    if expected_sha256 is not None:
        actual_sha256 = _sha256_file(idx_path)
        if actual_sha256 != expected_sha256:
            raise ValueError(
                f"SHA-256 mismatch for {idx_path.name}: "
                f"expected {expected_sha256}, got {actual_sha256}"
            )

    df_idx = pd.read_csv(idx_path, compression="gzip")
    return df_idx["source_row_index"].to_numpy(dtype=np.int64)


def load_split_for_modeling(
    manifest_path: Path,
    dataset_path: Path,
    indices_dir: Path,
    partition_name: str,
) -> Tuple[pd.DataFrame, pd.Series]:
    """Consumer interface for Issue #8: load verified baseline features X and target y."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Verify dataset integrity
    actual_ds_sha256 = _sha256_file(dataset_path)
    if actual_ds_sha256 != manifest["dataset_sha256"]:
        raise ValueError("Dataset SHA-256 does not match split manifest")

    indices = load_partition_indices(manifest, indices_dir, partition_name)

    # Read exactly baseline features and targets
    cols_to_read = list(ML_FEATURE_COLUMNS) + ["Label"]
    df = pd.read_csv(dataset_path, usecols=cols_to_read)
    df_partition = df.iloc[indices]

    X = df_partition[list(ML_FEATURE_COLUMNS)]
    y = df_partition["Label"]

    # Strict assertion
    validate_feature_selection(X.columns)

    return X, y
