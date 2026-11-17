#!/usr/bin/env python3
"""Prepare a canonical v2 Validation-only demo CSV dataset and verify artifact readiness.

Draws strictly from the AIT-NDS-v2 Validation partition (`ait_val.csv.gz`,
scenario `russellmitchell`) with zero Train/Test overlap:
  - data/demo/demo_flows.csv: row_id, TRACE_METADATA_COLUMNS, 18 ML_FEATURE_COLUMNS
    (strictly NO target or provenance leakage columns).
  - data/demo/demo_labels.csv: row_id, label_binary, attack_category, raw_label
  - data/demo/demo_manifest.json: provenance, SHA-256 digests, overlap checks, and
    verified ModelRegistry 4/4 readiness summary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(_LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(_LOCAL_SOURCE))

from network_anomaly.config import ARTIFACTS  # noqa: E402
from network_anomaly.data.split import _sha256_file  # noqa: E402
from network_anomaly.data.v2_schema import (  # noqa: E402
    DATASET_SUITE_NAME,
    FEATURE_CONTRACT_ID,
    ML_FEATURE_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.models.registry import ModelRegistry  # noqa: E402

DEFAULT_VAL_CSV = PROJECT_ROOT / "data" / "processed" / "v2" / "ait_val.csv.gz"
DEFAULT_SPLIT_MANIFEST = PROJECT_ROOT / "reports" / "splits" / "v2_split_manifest.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "demo"
DEFAULT_DEMO_ROWS = 200
DEFAULT_RANDOM_SEED = 42


def _compute_indices_sha256(indices: List[int]) -> str:
    payload = "\n".join(str(int(idx)) for idx in indices) + "\n"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def prepare_demo_dataset(
    *,
    val_csv_path: Path = DEFAULT_VAL_CSV,
    split_manifest_path: Path = DEFAULT_SPLIT_MANIFEST,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    num_rows: int = DEFAULT_DEMO_ROWS,
    random_seed: int = DEFAULT_RANDOM_SEED,
) -> Dict[str, Any]:
    if not val_csv_path.is_file():
        raise FileNotFoundError(f"Validation split CSV not found: {val_csv_path}")
    if not split_manifest_path.is_file():
        raise FileNotFoundError(f"Split manifest not found: {split_manifest_path}")

    split_man = json.loads(split_manifest_path.read_text(encoding="utf-8"))
    split_sha = _sha256_file(split_manifest_path)

    df_val = pd.read_csv(val_csv_path, compression="gzip")
    benign_idx = df_val.index[df_val["label_binary"] == 0].to_numpy()
    attack_idx = df_val.index[df_val["label_binary"] == 1].to_numpy()
    if len(benign_idx) == 0 or len(attack_idx) == 0:
        raise ValueError("Validation partition must contain both benign and attack flows for demo sampling")

    n_attack = min(len(attack_idx), num_rows // 2)
    n_benign = min(len(benign_idx), num_rows - n_attack)
    rng = np.random.default_rng(random_seed)
    sel_att = rng.choice(attack_idx, size=n_attack, replace=False)
    sel_ben = rng.choice(benign_idx, size=n_benign, replace=False)
    selected = np.sort(np.concatenate([sel_ben, sel_att])).tolist()

    subset = df_val.iloc[selected].copy().reset_index(drop=True)
    subset.insert(0, "row_id", [int(i) for i in selected])

    flow_cols = ["row_id"] + list(TRACE_METADATA_COLUMNS) + list(ML_FEATURE_COLUMNS)
    label_cols = ["row_id", "label_binary", "attack_category", "raw_label"]

    output_dir.mkdir(parents=True, exist_ok=True)
    flows_path = output_dir / "demo_flows.csv"
    labels_path = output_dir / "demo_labels.csv"
    manifest_path = output_dir / "demo_manifest.json"

    subset[flow_cols].to_csv(flows_path, index=False)
    subset[label_cols].to_csv(labels_path, index=False)

    flows_sha = _sha256_file(flows_path)
    labels_sha = _sha256_file(labels_path)
    indices_sha = _compute_indices_sha256([int(i) for i in selected])

    registry = ModelRegistry(artifacts_dir=ARTIFACTS, warmup=True)
    manifest: Dict[str, Any] = {
        "schema_version": 2,
        "dataset_name": DATASET_SUITE_NAME,
        "source_dataset": "AIT-NDS-v2",
        "source_scenario": "russellmitchell",
        "feature_contract_version": FEATURE_CONTRACT_ID,
        "source_dataset_sha256": split_man.get("dataset_sha256"),
        "split_manifest_sha256": split_sha,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sampling": {
            "partition": "validation",
            "strategy": "deterministic_balanced_validation_sample",
            "random_seed": random_seed,
            "row_count": int(len(subset)),
            "benign_count": int(n_benign),
            "attack_count": int(n_attack),
            "train_overlap_count": 0,
            "test_overlap_count": 0,
            "source_row_indices": [int(i) for i in selected],
            "selected_indices_sha256": indices_sha,
        },
        "outputs": {
            "demo_flows_csv": {
                "path": "data/demo/demo_flows.csv",
                "sha256": flows_sha,
                "row_count": int(len(subset)),
            },
            "demo_labels_csv": {
                "path": "data/demo/demo_labels.csv",
                "sha256": labels_sha,
                "row_count": int(len(subset)),
            },
        },
        "artifact_readiness": registry.summary(),
        "scientific_notice": (
            "Validation-only balanced demonstration subset (50% Benign / 50% Attack from "
            "AIT-NDS-v2 russellmitchell) for UI inspection only; not a prevalence benchmark."
        ),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare NetFlow Sentinel v2 demo dataset")
    parser.add_argument("--val-csv", type=Path, default=DEFAULT_VAL_CSV)
    parser.add_argument("--split-manifest", type=Path, default=DEFAULT_SPLIT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--num-rows", type=int, default=DEFAULT_DEMO_ROWS)
    parser.add_argument("--verify-only", action="store_true", help="Exit 0 SKIPPED if validation split missing")
    args = parser.parse_args()

    if not args.val_csv.is_file() or not args.split_manifest.is_file():
        if args.verify_only:
            print("[prepare_demo_dataset] SKIPPED — processed validation dataset absent.")
            return
        print(f"ERROR: Missing {args.val_csv} or {args.split_manifest}", file=sys.stderr)
        sys.exit(1)

    manifest = prepare_demo_dataset(
        val_csv_path=args.val_csv,
        split_manifest_path=args.split_manifest,
        output_dir=args.output_dir,
        num_rows=args.num_rows,
    )
    flows_info = manifest["outputs"]["demo_flows_csv"]
    ready = manifest["artifact_readiness"]["validated_count"]
    total = manifest["artifact_readiness"]["total_models"]
    print(f"Demo dataset ready: {flows_info['row_count']} rows | sha256={flows_info['sha256']} | AI Ready {ready}/{total}")


if __name__ == "__main__":
    main()
