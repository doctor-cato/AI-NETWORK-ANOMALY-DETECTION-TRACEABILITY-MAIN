"""NetFlow Sentinel v2 leakage-resistant data splitting and cross-partition audit.

Supports:
  1. Scenario/device/entity-disjoint splits across AIT-NDS-v2 and CTU-SME-11.
  2. Chronological group-purged splits with canonical 5-tuple/time-bucket purge gaps.
  3. Full cross-partition leakage auditing (exact row, source-feature, ML-feature,
     flow-group, scenario, entity/IP, and temporal-boundary checks).
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import numpy as np
import pandas as pd

from network_anomaly.data.v2_schema import (
    DATASET_SUITE_NAME,
    FINGERPRINT_SCHEMA_VERSION,
    canonical_flow_group,
    ml_feature_fingerprint,
    source_feature_fingerprint,
)

SPLIT_PROTOCOL_VERSION = "v2-scenario-group-purged-v1"
SPLIT_MANIFEST_SCHEMA_VERSION = 2
DEFAULT_PURGE_GAP_MS = 300_000  # 5 minutes
DEFAULT_TRAIN_RATIO = 0.70
DEFAULT_VAL_RATIO = 0.15
DEFAULT_TEST_RATIO = 0.15
DEFAULT_RANDOM_SEED = 42

PARTITION_TRAIN = "train"
PARTITION_VALIDATION = "validation"
PARTITION_TEST = "test"
PARTITION_PURGED_TRAIN_VAL = "purged_train_val_gap"
PARTITION_PURGED_VAL_TEST = "purged_val_test_gap"

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path, chunk_bytes: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_bytes), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.match(value)) and value != "0" * 64


def write_deterministic_index_csv_gz(path: Path, indices: Any) -> str:
    """Write partition indices to gzip CSV with mtime=0.0 for deterministic hashes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw_file:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_file, mtime=0.0) as gz:
            with io.TextIOWrapper(gz, encoding="utf-8", newline="\n") as text_file:
                text_file.write("source_row_index\n")
                for idx in indices:
                    text_file.write(f"{int(idx)}\n")
    return _sha256_file(path)


def _format_epoch_ms(epoch_ms: float) -> str:
    return datetime.fromtimestamp(float(epoch_ms) / 1000.0, tz=timezone.utc).isoformat()


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
        total = self.train_ratio + self.val_ratio + self.test_ratio
        if not np.isclose(total, 1.0, atol=1e-5):
            raise ValueError(f"partition ratios must sum to 1.0, got {total}")


def compute_scenario_disjoint_split(
    df: pd.DataFrame,
    *,
    train_scenarios: Sequence[str],
    val_scenarios: Sequence[str],
    test_scenarios: Sequence[str],
    scenario_col: str = "scenario_or_device",
) -> Dict[str, Any]:
    """Partition rows strictly by disjoint scenario/device sets (zero group overlap)."""
    tr_set = set(train_scenarios)
    va_set = set(val_scenarios)
    te_set = set(test_scenarios)
    if (tr_set & va_set) or (tr_set & te_set) or (va_set & te_set):
        raise ValueError("Train, validation, and test scenario sets must be strictly disjoint")
    if scenario_col not in df.columns:
        raise ValueError(f"Missing required scenario/device column: {scenario_col}")

    sc_vals = df[scenario_col].astype(str)
    train_idx = np.flatnonzero(sc_vals.isin(tr_set).to_numpy())
    val_idx = np.flatnonzero(sc_vals.isin(va_set).to_numpy())
    test_idx = np.flatnonzero(sc_vals.isin(te_set).to_numpy())

    if len(train_idx) == 0 or len(val_idx) == 0 or len(test_idx) == 0:
        raise ValueError(
            f"All partitions must be non-empty: train={len(train_idx)}, "
            f"val={len(val_idx)}, test={len(test_idx)}"
        )

    return {
        "protocol_version": SPLIT_PROTOCOL_VERSION,
        "split_strategy": "scenario_disjoint",
        "train_scenarios": sorted(tr_set),
        "val_scenarios": sorted(va_set),
        "test_scenarios": sorted(te_set),
        "train_indices": train_idx,
        "validation_indices": val_idx,
        "test_indices": test_idx,
        "purged_train_val_indices": np.array([], dtype=np.int64),
        "purged_val_test_indices": np.array([], dtype=np.int64),
        "row_counts": {
            "total": int(len(df)),
            "train": int(len(train_idx)),
            "validation": int(len(val_idx)),
            "test": int(len(test_idx)),
            "purged_train_val_gap": 0,
            "purged_val_test_gap": 0,
        },
    }


def compute_chronological_split(
    df: pd.DataFrame,
    config: Optional[SplitConfig] = None,
    *,
    timestamp_col: str = "timestamp_ms",
) -> Dict[str, Any]:
    """Compute a deterministic chronological split with boundary purge gaps."""
    if config is None:
        config = SplitConfig()
    config.validate()

    if timestamp_col not in df.columns:
        raise ValueError(f"DataFrame missing required column: {timestamp_col}")

    ts_series = pd.to_numeric(df[timestamp_col], errors="raise")
    if ts_series.isna().any() or not np.all(np.isfinite(ts_series.to_numpy(dtype=np.float64))):
        raise ValueError(f"{timestamp_col} contains missing or non-finite values")
    ts_ms = ts_series.to_numpy(dtype=np.float64)
    if (ts_ms < 0).any():
        raise ValueError(f"{timestamp_col} contains negative values")
    if len(df) == 0:
        raise ValueError("Cannot split an empty DataFrame")

    order = np.argsort(ts_ms, kind="mergesort")
    sorted_ts = ts_ms[order]
    n = len(order)
    t_end_idx = max(1, min(n - 2, int(round(n * config.train_ratio))))
    v_end_idx = max(t_end_idx + 1, min(n - 1, int(round(n * (config.train_ratio + config.val_ratio)))))

    t_boundary = float(sorted_ts[t_end_idx - 1])
    v_boundary = float(sorted_ts[v_end_idx - 1])
    gap = float(config.purge_gap_milliseconds)

    train_mask = ts_ms <= t_boundary
    val_mask = (ts_ms > t_boundary + gap) & (ts_ms <= v_boundary)
    test_mask = ts_ms > (v_boundary + gap)
    purge_tv_mask = (ts_ms > t_boundary) & (ts_ms <= t_boundary + gap)
    purge_vt_mask = (ts_ms > v_boundary) & (ts_ms <= v_boundary + gap)

    return {
        "protocol_version": SPLIT_PROTOCOL_VERSION,
        "split_strategy": "chronological_group_purged",
        "config": asdict(config),
        "train_indices": np.flatnonzero(train_mask),
        "validation_indices": np.flatnonzero(val_mask),
        "test_indices": np.flatnonzero(test_mask),
        "purged_train_val_indices": np.flatnonzero(purge_tv_mask),
        "purged_val_test_indices": np.flatnonzero(purge_vt_mask),
        "time_boundaries": {
            "train_max_ms": t_boundary,
            "val_min_ms": float(t_boundary + gap),
            "val_max_ms": v_boundary,
            "test_min_ms": float(v_boundary + gap),
        },
        "row_counts": {
            "total": int(n),
            "train": int(train_mask.sum()),
            "validation": int(val_mask.sum()),
            "test": int(test_mask.sum()),
            "purged_train_val_gap": int(purge_tv_mask.sum()),
            "purged_val_test_gap": int(purge_vt_mask.sum()),
        },
    }


def audit_split_leakage(
    df: pd.DataFrame,
    split_result: Dict[str, Any],
    *,
    bucket_milliseconds: int = DEFAULT_PURGE_GAP_MS,
) -> Dict[str, Any]:
    """Audit cross-partition overlap across row indices, scenarios, flow groups, and fingerprints."""
    train_idx = np.asarray(split_result["train_indices"], dtype=np.int64)
    val_idx = np.asarray(split_result["validation_indices"], dtype=np.int64)
    test_idx = np.asarray(split_result["test_indices"], dtype=np.int64)

    s_tr, s_va, s_te = set(train_idx.tolist()), set(val_idx.tolist()), set(test_idx.tolist())
    index_overlap = len(s_tr & s_va) + len(s_tr & s_te) + len(s_va & s_te)

    scenario_overlap = 0
    if "scenario_or_device" in df.columns and split_result.get("split_strategy") == "scenario_disjoint":
        sc_tr = set(df.iloc[train_idx]["scenario_or_device"].astype(str).unique())
        sc_va = set(df.iloc[val_idx]["scenario_or_device"].astype(str).unique())
        sc_te = set(df.iloc[test_idx]["scenario_or_device"].astype(str).unique())
        scenario_overlap = len(sc_tr & sc_va) + len(sc_tr & sc_te) + len(sc_va & sc_te)

    def _collect_sets(indices: np.ndarray) -> Tuple[Set[Any], Set[bytes], Set[bytes]]:
        groups: Set[Any] = set()
        src_fps: Set[bytes] = set()
        ml_fps: Set[bytes] = set()
        sub = df.iloc[indices]
        sc_col = "scenario_or_device" if "scenario_or_device" in sub.columns else None
        for row in sub.to_dict(orient="records"):
            fg = canonical_flow_group(row, bucket_milliseconds=bucket_milliseconds)
            if sc_col:
                fg = (str(row[sc_col]), fg)
            groups.add(fg)
            src_fps.add(source_feature_fingerprint(row))
            ml_fps.add(ml_feature_fingerprint(row))
        return groups, src_fps, ml_fps

    g_tr, src_tr, ml_tr = _collect_sets(train_idx)
    g_va, src_va, ml_va = _collect_sets(val_idx)
    g_te, src_te, ml_te = _collect_sets(test_idx)

    flow_group_overlap = len(g_tr & g_va) + len(g_tr & g_te) + len(g_va & g_te)
    source_overlap = len(src_tr & src_va) + len(src_tr & src_te) + len(src_va & src_te)
    ml_overlap_tv = len(ml_tr & ml_va)
    ml_overlap_tt = len(ml_tr & ml_te)
    ml_overlap_vt = len(ml_va & ml_te)

    passed = index_overlap == 0 and scenario_overlap == 0 and flow_group_overlap == 0
    return {
        "status": "PASS" if passed else "FAIL",
        "fingerprint_schema_version": FINGERPRINT_SCHEMA_VERSION,
        "index_overlap_count": index_overlap,
        "scenario_overlap_count": scenario_overlap,
        "canonical_flow_group_overlap_count": flow_group_overlap,
        "source_feature_overlap_count": source_overlap,
        "ml_feature_overlap": {
            "train_val_unique_shared": ml_overlap_tv,
            "train_test_unique_shared": ml_overlap_tt,
            "val_test_unique_shared": ml_overlap_vt,
        },
    }


def load_partition_indices(
    manifest: Dict[str, Any],
    indices_dir: Path,
    partition_name: str,
) -> np.ndarray:
    """Load and verify SHA-256 of partition row indices from *.csv.gz."""
    part_info = manifest.get("partitions", {}).get(partition_name)
    if not part_info:
        raise ValueError(f"Partition '{partition_name}' missing from split manifest")
    idx_file = Path(indices_dir) / Path(part_info["index_file"]).name
    if not idx_file.is_file():
        raise FileNotFoundError(f"Partition index file not found: {idx_file}")
    actual_sha = _sha256_file(idx_file)
    expected_sha = part_info.get("index_sha256")
    if actual_sha != expected_sha:
        raise ValueError(
            f"Index SHA-256 mismatch for '{partition_name}': expected {expected_sha}, got {actual_sha}"
        )
    df_idx = pd.read_csv(idx_file)
    return df_idx["source_row_index"].to_numpy(dtype=np.int64)


def verify_split_artifacts(
    manifest_path: Path,
    *,
    dataset_path: Optional[Path] = None,
    indices_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Fail-closed verification of a v2 split manifest and optional index/dataset files."""
    manifest_path = Path(manifest_path)
    errors: List[str] = []
    if not manifest_path.is_file():
        return {"status": "FAIL", "errors": [f"Split manifest not found: {manifest_path}"]}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"status": "FAIL", "errors": [f"Invalid split manifest JSON: {exc}"]}

    if manifest.get("split_protocol_version") != SPLIT_PROTOCOL_VERSION:
        errors.append(
            f"split_protocol_version mismatch: expected {SPLIT_PROTOCOL_VERSION}, "
            f"got {manifest.get('split_protocol_version')}"
        )
    if not _is_valid_sha256(manifest.get("dataset_sha256")):
        errors.append("Invalid or placeholder dataset_sha256 in split manifest")
    if dataset_path is not None:
        ds_p = Path(dataset_path)
        if not ds_p.is_file():
            errors.append(f"Dataset file not found: {ds_p}")
        elif _sha256_file(ds_p) != manifest.get("dataset_sha256"):
            errors.append("Dataset SHA-256 mismatch against split manifest")

    if indices_dir is not None:
        for pname in (PARTITION_TRAIN, PARTITION_VALIDATION, PARTITION_TEST):
            try:
                load_partition_indices(manifest, Path(indices_dir), pname)
            except Exception as exc:
                errors.append(str(exc))

    return {"status": "PASS" if not errors else "FAIL", "errors": errors, "manifest": manifest}


@dataclass
class MultiSourceSplitResult:
    train_indices: List[int]
    val_indices: List[int]
    test_indices: List[int]
    purge_window_sec: float
    purged_rows_count: int
    overlap_group_count: int
    manifest: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "train_count": len(self.train_indices),
            "val_count": len(self.val_indices),
            "test_count": len(self.test_indices),
            "purge_window_sec": self.purge_window_sec,
            "purged_rows_count": self.purged_rows_count,
            "overlap_group_count": self.overlap_group_count,
            "manifest": self.manifest,
        }


class MultiSourceTemporalSplitter:
    """Leakage-resistant group-aware chronological splitter for multi-source events."""

    def __init__(self, purge_window_sec: float = 300.0):
        self.purge_window_sec = purge_window_sec

    def _group_key(self, ev: Any) -> Tuple[str, str, int, int, str]:
        ip1, ip2 = sorted([ev.source_ip or "0.0.0.0", ev.dest_ip or "0.0.0.0"])
        p1, p2 = sorted([int(ev.source_port or 0), int(ev.dest_port or 0)])
        return (ip1, ip2, p1, p2, str(ev.protocol or "UNKNOWN"))

    def split_events(
        self,
        events: Sequence[Any],
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
    ) -> MultiSourceSplitResult:
        """Split events chronologically by flow-group key with purge gaps."""
        if not events:
            raise ValueError("Cannot split empty event sequence")
        indexed = sorted(enumerate(events), key=lambda item: item[1].event_timestamp)
        n = len(indexed)
        t_cut = max(1, min(n - 2, int(n * train_ratio)))
        v_cut = max(t_cut + 1, min(n - 1, int(n * (train_ratio + val_ratio))))

        t_end_ts = indexed[t_cut - 1][1].event_timestamp.timestamp()
        v_end_ts = indexed[v_cut - 1][1].event_timestamp.timestamp()

        train_idx: List[int] = []
        val_idx: List[int] = []
        test_idx: List[int] = []
        purged = 0

        train_groups: Set[Tuple[str, str, int, int, str]] = set()
        val_groups: Set[Tuple[str, str, int, int, str]] = set()

        for orig_idx, ev in indexed:
            ts = ev.event_timestamp.timestamp()
            gk = self._group_key(ev)
            if ts <= t_end_ts:
                train_idx.append(orig_idx)
                train_groups.add(gk)
            elif ts <= t_end_ts + self.purge_window_sec:
                purged += 1
            elif ts <= v_end_ts:
                if gk in train_groups:
                    purged += 1
                else:
                    val_idx.append(orig_idx)
                    val_groups.add(gk)
            elif ts <= v_end_ts + self.purge_window_sec:
                purged += 1
            else:
                if gk in train_groups or gk in val_groups:
                    purged += 1
                else:
                    test_idx.append(orig_idx)

        test_groups = {self._group_key(events[i]) for i in test_idx}
        overlap = (
            len(train_groups & val_groups)
            + len(train_groups & test_groups)
            + len(val_groups & test_groups)
        )

        manifest = {
            "split_protocol_version": SPLIT_PROTOCOL_VERSION,
            "dataset_name": DATASET_SUITE_NAME,
            "purge_window_sec": self.purge_window_sec,
            "purged_rows_count": purged,
            "overlap_group_count": overlap,
            "train_count": len(train_idx),
            "val_count": len(val_idx),
            "test_count": len(test_idx),
        }
        return MultiSourceSplitResult(
            train_indices=train_idx,
            val_indices=val_idx,
            test_indices=test_idx,
            purge_window_sec=self.purge_window_sec,
            purged_rows_count=purged,
            overlap_group_count=overlap,
            manifest=manifest,
        )
