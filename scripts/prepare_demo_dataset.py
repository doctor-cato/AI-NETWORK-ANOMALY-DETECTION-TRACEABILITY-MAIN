#!/usr/bin/env python3
"""Prepare a canonical, Validation-only demo CSV dataset and verify artifact readiness.

Reuses canonical NF-UNSW-NB15-v3 split verification and partition_indices helpers
from scripts/fetch_external_dataset.py and network_anomaly.data.split without
introducing a parallel split or sampling pipeline.

Outputs (written to data/demo/ by default, gitignored):
- demo_flows.csv: row_id (= source_row_index), 6 TRACE_METADATA_COLUMNS, 47 ML_FEATURE_COLUMNS
  (strictly NO Label or Attack columns).
- demo_labels.csv: row_id, Label, Attack (ground truth kept strictly separate for UI evaluation).
- demo_manifest.json: provenance, SHA-256 digests, overlap checks, scientific disclaimer,
  and verified artifact readiness status for Preprocessor + 4 model families.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_SOURCE = PROJECT_ROOT / "src"
_LOCAL_SCRIPTS = PROJECT_ROOT / "scripts"
if str(_LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(_LOCAL_SOURCE))
if str(_LOCAL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_LOCAL_SCRIPTS))

from fetch_external_dataset import (  # noqa: E402
    _compute_indices_sha256,
    _load_split_manifest_sha256,
    _load_verified_partition_indices,
    _verify_unsw_row_indices_membership,
)

from network_anomaly.config import ARTIFACTS  # noqa: E402
from network_anomaly.data.nf_unsw_nb15_v3 import (  # noqa: E402
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.inference.predict import (  # noqa: E402
    _sha256_file,
    load_verified_model,
    load_verified_preprocessor,
)

DEFAULT_SOURCE_CSV = (
    PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
)
DEFAULT_SPLIT_MANIFEST = PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json"
DEFAULT_INDICES_DIR = PROJECT_ROOT / "data" / "processed" / "splits"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "demo"

MIN_DEMO_ROWS = 100
MAX_DEMO_ROWS = 300
DEFAULT_DEMO_ROWS = 200
DEFAULT_RANDOM_SEED = 42


def _display_path(path: Path) -> str:
    """Return workspace-relative POSIX path when under PROJECT_ROOT."""
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def inspect_artifact_readiness(
    artifacts_dir: Optional[Path] = None,
    reports_dir: Optional[Path] = None,
    split_manifest_path: Optional[Path] = DEFAULT_SPLIT_MANIFEST,
) -> Dict[str, Any]:
    """Check preprocessor and 4 retained model artifacts fail-closed without dummy fallbacks."""
    art_root = Path(artifacts_dir) if artifacts_dir is not None else ARTIFACTS
    rep_root = Path(reports_dir) if reports_dir is not None else (PROJECT_ROOT / "reports")
    split_man = Path(split_manifest_path) if split_manifest_path is not None else None

    prep_path = art_root / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    prep_manifest = rep_root / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    prep_sha: Optional[str] = None
    prep_info: Dict[str, Any]
    try:
        _, prep_meta = load_verified_preprocessor(
            artifact_path=prep_path,
            manifest_path=prep_manifest,
            split_manifest_path=split_man,
        )
        prep_sha = prep_meta.get("artifact_sha256")
        prep_info = {
            "ready": True,
            "status": "READY",
            "artifact_path": _display_path(prep_path),
            "manifest_path": _display_path(prep_manifest),
            "artifact_sha256": prep_sha,
            "reason": None,
        }
    except Exception as exc:
        prep_info = {
            "ready": False,
            "status": "BLOCKED / NOT READY",
            "artifact_path": _display_path(prep_path),
            "manifest_path": _display_path(prep_manifest),
            "artifact_sha256": None,
            "reason": str(exc),
        }

    xgb_baseline = art_root / "models" / "xgboost" / "xgboost_baseline.joblib"
    xgb_path = (
        xgb_baseline
        if xgb_baseline.is_file()
        else art_root / "models" / "xgboost" / "xgboost.joblib"
    )
    xgb_sidecar = xgb_path.parent / "xgboost_manifest.json"
    xgb_report = rep_root / "models" / "xgboost_manifest.json"
    xgb_manifest = xgb_sidecar if xgb_sidecar.is_file() else xgb_report

    ae_path = art_root / "models" / "autoencoder" / "autoencoder_model.joblib"
    ae_sidecar = art_root / "models" / "autoencoder" / "autoencoder_manifest.json"
    ae_report = rep_root / "models" / "autoencoder_manifest.json"
    ae_manifest = ae_sidecar if ae_sidecar.is_file() else ae_report

    candidates: Dict[str, Tuple[Path, Path]] = {
        "random_forest": (
            art_root / "models" / "random_forest" / "random_forest_baseline.joblib",
            rep_root / "models" / "random_forest_manifest.json",
        ),
        "xgboost": (xgb_path, xgb_manifest),
        "isolation_forest": (
            art_root / "models" / "isolation_forest" / "isolation_forest.joblib",
            rep_root / "models" / "isolation_forest_manifest.json",
        ),
        "autoencoder": (ae_path, ae_manifest),
    }

    models_status: Dict[str, Dict[str, Any]] = {}
    ready_models: List[str] = []
    for model_key, (model_path, manifest_path) in candidates.items():
        if not prep_info["ready"]:
            models_status[model_key] = {
                "ready": False,
                "status": "BLOCKED / NOT READY",
                "model_path": _display_path(model_path),
                "manifest_path": _display_path(manifest_path),
                "model_artifact_sha256": None,
                "reason": "Preprocessor artifact is not verified/ready",
            }
            continue
        try:
            _, model_meta = load_verified_model(
                model_artifact_path=model_path,
                manifest_path=manifest_path,
                expected_preprocessor_sha256=prep_sha,
            )
            ready_models.append(model_key)
            models_status[model_key] = {
                "ready": True,
                "status": "READY",
                "model_path": _display_path(model_path),
                "manifest_path": _display_path(manifest_path),
                "model_artifact_sha256": model_meta.get("model_artifact_sha256"),
                "model_type": model_meta.get("model_type"),
                "run_id": model_meta.get("run_id"),
                "reason": None,
            }
        except Exception as exc:
            models_status[model_key] = {
                "ready": False,
                "status": "BLOCKED / NOT READY",
                "model_path": _display_path(model_path),
                "manifest_path": _display_path(manifest_path),
                "model_artifact_sha256": None,
                "reason": str(exc),
            }

    overall_status = (
        "READY" if (prep_info["ready"] and len(ready_models) > 0) else "BLOCKED / NOT READY"
    )
    return {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "overall_status": overall_status,
        "ready_models": ready_models,
        "preprocessor": prep_info,
        "models": models_status,
    }


def _stream_validation_candidates(
    source_csv_path: Path,
    validation_indices: np.ndarray,
    chunk_size: int = 100_000,
) -> pd.DataFrame:
    """Stream canonical CSV and keep only Validation partition rows with source row identity."""
    required_cols = list(TRACE_METADATA_COLUMNS) + list(ML_FEATURE_COLUMNS) + list(TARGET_COLUMNS)
    header_cols = pd.read_csv(source_csv_path, nrows=0).columns.tolist()
    missing_cols = [c for c in required_cols if c not in header_cols]
    if missing_cols:
        raise ValueError(f"Canonical source CSV missing required columns: {missing_cols}")

    sorted_val = np.sort(validation_indices.astype(np.int64))
    max_val_idx = int(sorted_val[-1])
    val_mask = np.zeros(max_val_idx + 1, dtype=bool)
    val_mask[sorted_val] = True

    chunks: List[pd.DataFrame] = []
    current_row = 0
    with pd.read_csv(
        source_csv_path,
        usecols=required_cols,
        chunksize=chunk_size,
        low_memory=False,
    ) as reader:
        for chunk in reader:
            if current_row > max_val_idx:
                break
            n_rows = len(chunk)
            valid_len = min(n_rows, max_val_idx + 1 - current_row)
            local_mask = val_mask[current_row : current_row + valid_len]
            if np.any(local_mask):
                sub = chunk.iloc[:valid_len].loc[local_mask].copy()
                row_positions = current_row + np.nonzero(local_mask)[0]
                sub.insert(0, "row_id", row_positions.astype(np.int64))
                chunks.append(sub)
            current_row += n_rows

    if current_row <= max_val_idx:
        raise ValueError(
            f"Canonical source CSV ended prematurely at row {current_row} before max "
            f"Validation index {max_val_idx}"
        )

    combined = pd.concat(chunks, ignore_index=True) if chunks else pd.DataFrame()
    if len(combined) != int(sorted_val.size):
        raise ValueError(
            f"Validation row count mismatch: expected {sorted_val.size}, loaded {len(combined)}"
        )
    return combined


def prepare_demo_dataset(
    source_csv_path: Path = DEFAULT_SOURCE_CSV,
    split_manifest_path: Path = DEFAULT_SPLIT_MANIFEST,
    indices_dir: Path = DEFAULT_INDICES_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    sample_rows: int = DEFAULT_DEMO_ROWS,
    random_seed: int = DEFAULT_RANDOM_SEED,
    artifacts_dir: Optional[Path] = None,
    reports_dir: Optional[Path] = None,
    chunk_size: int = 100_000,
) -> Dict[str, Any]:
    """Extract a class-balanced Validation-only demo dataset and export provenance manifest."""
    if (
        isinstance(sample_rows, bool)
        or not isinstance(sample_rows, int)
        or sample_rows < MIN_DEMO_ROWS
        or sample_rows > MAX_DEMO_ROWS
    ):
        raise ValueError(
            f"sample_rows must be an integer in [{MIN_DEMO_ROWS}, {MAX_DEMO_ROWS}], got {sample_rows!r}"
        )
    if isinstance(random_seed, bool) or not isinstance(random_seed, int):
        raise ValueError(f"random_seed must be an integer, got {random_seed!r}")

    source_csv = Path(source_csv_path)
    split_manifest = Path(split_manifest_path)
    idx_dir = Path(indices_dir)
    out_dir = Path(output_dir)

    if not source_csv.is_file():
        raise FileNotFoundError(f"Canonical NF-UNSW-NB15-v3 CSV not found: {source_csv}")
    if not split_manifest.is_file():
        raise FileNotFoundError(f"Canonical split manifest not found: {split_manifest}")

    # 1. Fail-closed verification of raw CSV SHA-256 and canonical split indices
    expected_dataset_sha = _load_split_manifest_sha256(split_manifest)
    actual_dataset_sha = _sha256_file(source_csv)
    if actual_dataset_sha.lower() != expected_dataset_sha.lower():
        raise ValueError(
            f"Source CSV SHA-256 mismatch: expected {expected_dataset_sha}, got {actual_dataset_sha}"
        )

    split_data = json.loads(split_manifest.read_text(encoding="utf-8"))
    split_manifest_sha = _sha256_file(split_manifest)
    train_indices = _load_verified_partition_indices(split_data, split_manifest, idx_dir, "train")
    val_indices = _load_verified_partition_indices(
        split_data, split_manifest, idx_dir, "validation"
    )
    test_indices = _load_verified_partition_indices(split_data, split_manifest, idx_dir, "test")
    assert train_indices is not None and val_indices is not None and test_indices is not None

    if np.intersect1d(train_indices, val_indices).size > 0:
        raise ValueError("Canonical Train and Validation split indices overlap")
    if np.intersect1d(train_indices, test_indices).size > 0:
        raise ValueError("Canonical Train and Test split indices overlap")
    if np.intersect1d(val_indices, test_indices).size > 0:
        raise ValueError("Canonical Validation and Test split indices overlap")

    # 2. Stream ONLY Validation rows (stopping strictly before Held-out Test boundary)
    val_df = _stream_validation_candidates(
        source_csv, validation_indices=val_indices, chunk_size=chunk_size
    )

    # 3. Deterministic class-balanced sampling inside verified Validation pool
    benign_pool = val_df.loc[val_df["Label"] == 0, "row_id"].to_numpy(dtype=np.int64)
    attack_pool = val_df.loc[val_df["Label"] == 1, "row_id"].to_numpy(dtype=np.int64)
    n_benign = sample_rows // 2
    n_attack = sample_rows - n_benign
    if benign_pool.size < n_benign:
        raise ValueError(
            f"Validation partition has only {benign_pool.size} Benign rows; need {n_benign}"
        )
    if attack_pool.size < n_attack:
        raise ValueError(
            f"Validation partition has only {attack_pool.size} Attack rows; need {n_attack}"
        )

    rng = np.random.default_rng(random_seed)
    chosen_benign = rng.choice(benign_pool, size=n_benign, replace=False)
    chosen_attack = rng.choice(attack_pool, size=n_attack, replace=False)
    selected_indices = np.sort(np.concatenate([chosen_benign, chosen_attack])).astype(np.int64)

    # 4. Re-verify partition membership and zero Train/Test overlap via PR #47 canonical verifier
    _verify_unsw_row_indices_membership(
        selected_indices, split_manifest, idx_dir, partition="validation"
    )
    train_overlap = int(np.intersect1d(selected_indices, train_indices).size)
    test_overlap = int(np.intersect1d(selected_indices, test_indices).size)
    if train_overlap != 0 or test_overlap != 0:
        raise RuntimeError(
            f"Leakage detected in demo sample: train_overlap={train_overlap}, test_overlap={test_overlap}"
        )

    selected_df = val_df[val_df["row_id"].isin(set(selected_indices.tolist()))].sort_values(
        "row_id", kind="mergesort"
    )
    if len(selected_df) != sample_rows:
        raise RuntimeError(
            f"Selected demo row count mismatch: expected {sample_rows}, got {len(selected_df)}"
        )

    # 5. Strictly separate demo_flows.csv (NO Label/Attack) and demo_labels.csv
    flow_columns = ["row_id", *TRACE_METADATA_COLUMNS, *ML_FEATURE_COLUMNS]
    flows_df = selected_df[flow_columns].copy()
    if any(t in flows_df.columns for t in TARGET_COLUMNS):
        raise RuntimeError("Target columns leaked into demo_flows.csv")

    labels_df = selected_df[["row_id", *TARGET_COLUMNS]].copy()

    out_dir.mkdir(parents=True, exist_ok=True)
    flows_path = out_dir / "demo_flows.csv"
    labels_path = out_dir / "demo_labels.csv"
    manifest_path = out_dir / "demo_manifest.json"

    flows_df.to_csv(flows_path, index=False, lineterminator="\n")
    labels_df.to_csv(labels_path, index=False, lineterminator="\n")

    flows_sha = _sha256_file(flows_path)
    labels_sha = _sha256_file(labels_path)
    indices_sha = _compute_indices_sha256(selected_indices)

    label_counts = {str(int(k)): int(v) for k, v in labels_df["Label"].value_counts().items()}
    attack_counts = {str(k): int(v) for k, v in labels_df["Attack"].value_counts().items()}

    artifact_readiness = inspect_artifact_readiness(
        artifacts_dir=artifacts_dir,
        reports_dir=reports_dir,
        split_manifest_path=split_manifest,
    )

    partitions_meta = split_data.get("partitions", {})
    manifest_payload: Dict[str, Any] = {
        "schema_version": "1.0",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_name": "NF-UNSW-NB15-v3",
        "source_csv_path": _display_path(source_csv),
        "source_dataset_sha256": actual_dataset_sha,
        "split_manifest_path": _display_path(split_manifest),
        "split_manifest_sha256": split_manifest_sha,
        "partition_indices_sha256": {
            "train": partitions_meta.get("train", {}).get("index_sha256"),
            "validation": partitions_meta.get("validation", {}).get("index_sha256"),
            "test": partitions_meta.get("test", {}).get("index_sha256"),
        },
        "sampling": {
            "partition": "validation",
            "sampling_method": "deterministic_validation_class_balanced",
            "sample_rows": int(sample_rows),
            "random_seed": int(random_seed),
            "row_id_definition": "0-based CSV data row index (source_row_index) in NF-UNSW-NB15-v3.csv",
            "train_overlap_count": train_overlap,
            "test_overlap_count": test_overlap,
            "selected_indices_sha256": indices_sha,
            "source_row_indices": [int(x) for x in selected_indices.tolist()],
            "class_distribution": {
                "label_counts": label_counts,
                "attack_counts": attack_counts,
            },
        },
        "outputs": {
            "demo_flows_csv": {
                "path": _display_path(flows_path),
                "sha256": flows_sha,
                "row_count": int(len(flows_df)),
                "columns": flow_columns,
                "ml_feature_count": len(ML_FEATURE_COLUMNS),
                "trace_metadata_columns": list(TRACE_METADATA_COLUMNS),
                "target_columns_present": [],
            },
            "demo_labels_csv": {
                "path": _display_path(labels_path),
                "sha256": labels_sha,
                "row_count": int(len(labels_df)),
                "columns": ["row_id", *TARGET_COLUMNS],
            },
        },
        "scientific_validity_notice": (
            "Synthetic class-balanced demo subset (~50% Benign / ~50% Attack) extracted strictly "
            "from the verified Validation partition for offline interactive UI demonstration. "
            "It does NOT reflect real-world deployment prevalence, must NEVER be used for model "
            "training or hyperparameter tuning, and keeps the Held-out Test partition strictly locked "
            "(test_overlap_count == 0)."
        ),
        "artifact_readiness": artifact_readiness,
    }
    manifest_path.write_text(
        json.dumps(manifest_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return {
        "flows_path": flows_path,
        "labels_path": labels_path,
        "manifest_path": manifest_path,
        "manifest": manifest_payload,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser for prepare_demo_dataset.py."""
    parser = argparse.ArgumentParser(
        description="Prepare verified Validation-only demo CSV files and check model readiness.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source-csv",
        type=Path,
        default=DEFAULT_SOURCE_CSV,
        help="Path to canonical NF-UNSW-NB15-v3.csv",
    )
    parser.add_argument(
        "--split-manifest",
        type=Path,
        default=DEFAULT_SPLIT_MANIFEST,
        help="Path to NF_UNSW_NB15_V3_SPLIT_MANIFEST.json",
    )
    parser.add_argument(
        "--indices-dir",
        type=Path,
        default=DEFAULT_INDICES_DIR,
        help="Directory containing train/validation/test index .csv.gz files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Output directory for demo_flows.csv, demo_labels.csv, demo_manifest.json",
    )
    parser.add_argument(
        "--sample-rows",
        type=int,
        default=DEFAULT_DEMO_ROWS,
        help=f"Number of Validation rows to extract [{MIN_DEMO_ROWS}..{MAX_DEMO_ROWS}]",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_RANDOM_SEED,
        help="Deterministic RNG seed for class-balanced Validation sampling",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Inspect preprocessor/model readiness only without generating demo CSV files",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.check_only:
        readiness = inspect_artifact_readiness(split_manifest_path=args.split_manifest)
        print(json.dumps(readiness, indent=2))
        return 0 if readiness["overall_status"] == "READY" else 1

    try:
        result = prepare_demo_dataset(
            source_csv_path=args.source_csv,
            split_manifest_path=args.split_manifest,
            indices_dir=args.indices_dir,
            output_dir=args.output_dir,
            sample_rows=args.sample_rows,
            random_seed=args.seed,
        )
    except Exception as exc:
        sys.stderr.write(f"[DEMO PREP BLOCKED] {exc}\n")
        return 1

    man = result["manifest"]
    readiness = man["artifact_readiness"]
    print(
        f"[DEMO PREP] SUCCESS: wrote {man['sampling']['sample_rows']} Validation rows to {args.output_dir}"
    )
    print(f"  demo_flows.csv   SHA-256: {man['outputs']['demo_flows_csv']['sha256']}")
    print(f"  demo_labels.csv  SHA-256: {man['outputs']['demo_labels_csv']['sha256']}")
    print(
        f"  Train/Test overlap      : {man['sampling']['train_overlap_count']}/{man['sampling']['test_overlap_count']}"
    )
    print(
        f"  Overall artifact status : {readiness['overall_status']} (ready models: {readiness['ready_models']})"
    )
    for model_key, status in readiness["models"].items():
        print(f"    - {model_key:17s}: {status['status']}")
    return 0 if readiness["overall_status"] == "READY" else 1


if __name__ == "__main__":
    sys.exit(main())
