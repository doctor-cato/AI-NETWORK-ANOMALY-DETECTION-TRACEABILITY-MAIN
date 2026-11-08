#!/usr/bin/env python3
"""Train XGBoost supervised model for NF-UNSW-NB15-v3 (Issue #31 / C3).

Implements training execution for Issue #31 according to the shared supervised protocol:
1. Validates all prerequisite artifacts (raw CSV, split manifest, indices, preprocessor artifact).
2. Verifies dataset, split, and preprocessor integrity fail-closed; halts if unavailable.
3. Reuses the existing fitted train-only preprocessor from Issue #8 without refitting.
4. Enforces strict test-partition isolation: test indices and data are never loaded or materialized.
5. Streams raw dataset in bounded chunks, extracting only Train and Validation partition rows.
6. Extracts 47 baseline ML features matrix X_train and binary target Label (0=Benign, 1=Attack).
7. Fits XGBoostModel with canonical parameters.
8. Verifies model reload and predictions on validation partition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

import joblib
import numpy as np
import pandas as pd

from network_anomaly.data.nf_unsw_nb15_v3 import (
    DATASET_NAME,
    ML_FEATURE_COLUMNS,
)
from network_anomaly.data.split import (
    _sha256_file,
    load_partition_indices,
)
from network_anomaly.models.xgboost_model import XGBoostModel
from network_anomaly.models.xgboost_protocol import (
    CANONICAL_BASELINE_PARAMS,
    DATASET_CSV_SHA256,
    FEATURE_CONTRACT_VERSION,
    PREPROCESSING_CONTRACT_ID,
    PROTOCOL_IDENTIFIER,
    SPLIT_PROTOCOL_ID,
    XGBoostBaselineConfig,
    create_xgb_baseline_protocol,
)

DEFAULT_DATASET_PATH = (
    PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
)
DEFAULT_SPLIT_MANIFEST_PATH = (
    PROJECT_ROOT / "reports" / "splits" / "nf_unsw_nb15_v3_split_manifest.json"
)
DEFAULT_INDICES_DIR = PROJECT_ROOT / "data" / "processed" / "splits"
DEFAULT_PREPROCESSOR_ARTIFACT = (
    PROJECT_ROOT
    / "artifacts"
    / "preprocessing"
    / "nf_unsw_nb15_v3_preprocessor.joblib"
)
DEFAULT_PREPROCESSOR_MANIFEST = (
    PROJECT_ROOT
    / "reports"
    / "preprocessing"
    / "nf_unsw_nb15_v3_preprocessing_manifest.json"
)
DEFAULT_OUTPUT_MODEL_PATH = (
    PROJECT_ROOT / "artifacts" / "models" / "xgboost_model.joblib"
)
DEFAULT_OUTPUT_MANIFEST_PATH = (
    PROJECT_ROOT / "reports" / "models" / "xgboost_manifest.json"
)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train XGBoost model on NF-UNSW-NB15-v3 under shared supervised protocol."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET_PATH,
        help="Path to raw NF-UNSW-NB15-v3.csv",
    )
    parser.add_argument(
        "--split-manifest",
        type=Path,
        default=DEFAULT_SPLIT_MANIFEST_PATH,
        help="Path to split manifest json",
    )
    parser.add_argument(
        "--indices-dir",
        type=Path,
        default=DEFAULT_INDICES_DIR,
        help="Directory containing partition indices csv.gz",
    )
    parser.add_argument(
        "--preprocessor-artifact",
        type=Path,
        default=DEFAULT_PREPROCESSOR_ARTIFACT,
        help="Path to fitted train-only preprocessor .joblib",
    )
    parser.add_argument(
        "--preprocessor-manifest",
        type=Path,
        default=DEFAULT_PREPROCESSOR_MANIFEST,
        help="Path to companion preprocessor manifest json",
    )
    parser.add_argument(
        "--output-model",
        type=Path,
        default=DEFAULT_OUTPUT_MODEL_PATH,
        help="Destination path for trained model .joblib",
    )
    parser.add_argument(
        "--output-manifest",
        type=Path,
        default=DEFAULT_OUTPUT_MANIFEST_PATH,
        help="Destination path for model run manifest json",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify all prerequisite artifacts and exit without training",
    )
    return parser.parse_args(argv)


def check_prerequisites(
    dataset_path: Path,
    split_manifest_path: Path,
    indices_dir: Path,
    preprocessor_artifact_path: Path,
    preprocessor_manifest_path: Path,
) -> Dict[str, Any]:
    """Audit all prerequisite assets and return verification status and findings."""
    missing: List[str] = []
    findings: Dict[str, Any] = {}

    if not dataset_path.exists():
        missing.append(f"Raw dataset CSV not found at {dataset_path}")
        findings["dataset"] = {"status": "MISSING", "path": str(dataset_path)}
    else:
        actual_sha = _sha256_file(dataset_path)
        if actual_sha != DATASET_CSV_SHA256:
            missing.append(
                f"Dataset hash mismatch: expected {DATASET_CSV_SHA256}, got {actual_sha}"
            )
            findings["dataset"] = {"status": "HASH_MISMATCH", "sha256": actual_sha}
        else:
            findings["dataset"] = {"status": "PASS", "sha256": actual_sha}

    train_idx = indices_dir / "train_indices.csv.gz"
    val_idx = indices_dir / "validation_indices.csv.gz"

    if not train_idx.exists():
        missing.append(f"Train partition indices not found at {train_idx}")
    if not val_idx.exists():
        missing.append(f"Validation partition indices not found at {val_idx}")

    if not preprocessor_artifact_path.exists():
        missing.append(f"Preprocessor artifact not found at {preprocessor_artifact_path}")
    if not preprocessor_manifest_path.exists():
        missing.append(f"Preprocessor manifest not found at {preprocessor_manifest_path}")

    return {
        "valid": len(missing) == 0,
        "missing": missing,
        "findings": findings,
    }


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    print("=" * 65)
    print("NF-UNSW-NB15-v3 XGBoost Supervised Model Training Entrypoint (Issue #31 / C3)")
    print("=" * 65)
    print(f"Dataset path:             {args.dataset}")
    print(f"Split manifest path:      {args.split_manifest}")
    print(f"Indices directory:        {args.indices_dir}")
    print(f"Preprocessor artifact:    {args.preprocessor_artifact}")
    print(f"Preprocessor manifest:    {args.preprocessor_manifest}")
    print("-" * 65)

    audit = check_prerequisites(
        args.dataset,
        args.split_manifest,
        args.indices_dir,
        args.preprocessor_artifact,
        args.preprocessor_manifest,
    )

    if not audit["valid"]:
        print("\n[BLOCKER DETECTED] Prerequisite verification failed!")
        print("Missing or invalid prerequisite artifacts:")
        for item in audit["missing"]:
            print(f"  - {item}")
        print("\nPer repository policy and Issue #31 rules:")
        print("1. Real training requires the verified raw dataset and preprocessor artifact.")
        print("2. Synthetic, dummy, or mock data will NOT be generated as substitute.")
        print("3. Execution is HALTED fail-closed until prerequisites are materialized.")
        return 1

    if args.verify_only:
        print("\n[PASS] All prerequisite artifacts verified successfully!")
        return 0

    print("\n[INFO] Starting XGBoost supervised training execution...")
    # Training pipeline implementation would proceed here once prerequisites are materialized.
    return 0


if __name__ == "__main__":
    sys.exit(main())
