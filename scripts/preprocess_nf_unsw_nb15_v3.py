#!/usr/bin/env python3
"""Run train-only preprocessing pipeline for NF-UNSW-NB15-v3.

This script executes Issue #8:
1. Verifies official split manifest and partition index integrity.
2. Extracts the 47 baseline ML features matrix X, Label, and Attack.
3. Fits the preprocessor strictly on Train (imputing missing, NaN, and positive/negative infinity).
4. Transforms Train, Validation, and Test partitions with frozen state.
5. Verifies finite output matrices, strict 47-feature contracts, and zero target leakage.
6. Saves the fitted preprocessor artifact and companion provenance manifest.
7. Supports --verify-only and --check-reproducibility flags.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

import numpy as np  # noqa: E402

from network_anomaly.data.nf_unsw_nb15_v3 import (  # noqa: E402
    ML_FEATURE_COLUMNS,
)
from network_anomaly.preprocessing.pipeline import (  # noqa: E402
    EXPECTED_DATASET_SHA256,
    load_and_preprocess_split,
    verify_preprocessing_artifact,
)

DEFAULT_DATASET = PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "processed" / "nf_unsw_nb15_v3_split_manifest.json"
DEFAULT_INDICES_DIR = PROJECT_ROOT / "data" / "processed" / "splits"
DEFAULT_OUTPUT_ARTIFACT = (
    PROJECT_ROOT / "artifacts" / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
)
DEFAULT_OUTPUT_MANIFEST = (
    PROJECT_ROOT / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
)


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fit train-only preprocessor and transform NF-UNSW-NB15-v3 partitions."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help="Path to raw NF-UNSW-NB15-v3.csv",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="Path to split manifest json",
    )
    parser.add_argument(
        "--indices-dir",
        type=Path,
        default=DEFAULT_INDICES_DIR,
        help="Directory containing partition index files",
    )
    parser.add_argument(
        "--output-artifact",
        type=Path,
        default=DEFAULT_OUTPUT_ARTIFACT,
        help="Path for fitted preprocessor artifact .joblib",
    )
    parser.add_argument(
        "--output-manifest",
        type=Path,
        default=DEFAULT_OUTPUT_MANIFEST,
        help="Path for companion preprocessing manifest .json",
    )
    parser.add_argument(
        "--scaler",
        type=str,
        default="none",
        choices=["none", "robust", "standard", "minmax"],
        help="Scaler for quantitative columns (default: none)",
    )
    parser.add_argument(
        "--add-missing-indicators",
        action="store_true",
        help="Add binary indicator columns for missingness learned strictly on Train",
    )
    parser.add_argument(
        "--handle-unknown-categories",
        type=str,
        default="passthrough",
        choices=["passthrough", "sentinel", "error"],
        help="Strategy for unseen discrete categories in Validation/Test (default: passthrough)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify existing preprocessing artifact without refitting",
    )
    parser.add_argument(
        "--check-reproducibility",
        action="store_true",
        help="Run fit independently twice and verify exact identity of output and parameters",
    )
    return parser.parse_args(argv)


def run_reproducibility_check(
    dataset_path: Path,
    manifest_path: Path,
    indices_dir: Path,
    scaler_type: str,
    add_missing_indicators: bool = False,
    handle_unknown_categories: str = "passthrough",
) -> None:
    """Verify that two independent fit runs produce identical parameters and transformations."""
    print("[preprocess] ========================================================")
    print("[preprocess] Running independent dual-pass preprocessor reproducibility check...")
    print("[preprocess] ========================================================")

    with tempfile.TemporaryDirectory() as tmp1_str, tempfile.TemporaryDirectory() as tmp2_str:
        tmp1 = Path(tmp1_str)
        tmp2 = Path(tmp2_str)

        art1 = tmp1 / "preprocessor.joblib"
        man1 = tmp1 / "manifest.json"
        art2 = tmp2 / "preprocessor.joblib"
        man2 = tmp2 / "manifest.json"

        print("[preprocess] Pass 1: fitting preprocessor...")
        t_data1, v_data1, te_data1, prep1, _ = load_and_preprocess_split(
            manifest_path=manifest_path,
            dataset_path=dataset_path,
            indices_dir=indices_dir,
            scaler_type=scaler_type,
            add_missing_indicators=add_missing_indicators,
            handle_unknown_categories=handle_unknown_categories,
            save_artifact_path=art1,
            save_manifest_path=man1,
        )

        print("[preprocess] Pass 2: fitting preprocessor independently...")
        t_data2, v_data2, te_data2, prep2, _ = load_and_preprocess_split(
            manifest_path=manifest_path,
            dataset_path=dataset_path,
            indices_dir=indices_dir,
            scaler_type=scaler_type,
            add_missing_indicators=add_missing_indicators,
            handle_unknown_categories=handle_unknown_categories,
            save_artifact_path=art2,
            save_manifest_path=man2,
        )

        # Check parameter identity
        assert (
            prep1.imputed_values_ == prep2.imputed_values_
        ), "Imputed values mismatch between runs"
        assert prep1.scaler_params_ == prep2.scaler_params_, "Scaler params mismatch between runs"
        assert (
            prep1.category_vocabularies_ == prep2.category_vocabularies_
        ), "Vocabularies mismatch between runs"
        assert (
            prep1.constant_features_ == prep2.constant_features_
        ), "Constant features mismatch between runs"
        assert (
            prep1.indicator_features_ == prep2.indicator_features_
        ), "Indicator features mismatch between runs"

        # Check numeric output identity
        np.testing.assert_array_equal(t_data1[0].to_numpy(), t_data2[0].to_numpy())
        np.testing.assert_array_equal(v_data1[0].to_numpy(), v_data2[0].to_numpy())
        np.testing.assert_array_equal(te_data1[0].to_numpy(), te_data2[0].to_numpy())

        print(
            "[preprocess] PASS: preprocessor reproducibility verified "
            "(100% parameter and output identity)"
        )


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)

    # 1. Verify-only mode (strictly fail-closed: companion manifest, split manifest,
    # artifact, and raw dataset are mandatory)
    if args.verify_only:
        print(f"[preprocess] Verifying existing preprocessor artifact: {args.output_artifact}...")
        missing_files = []
        if not args.dataset.is_file():
            missing_files.append(f"raw dataset ({args.dataset})")
        if not args.manifest.is_file():
            missing_files.append(f"split manifest ({args.manifest})")
        if not args.output_artifact.is_file():
            missing_files.append(f"preprocessor artifact ({args.output_artifact})")
        if not args.output_manifest.is_file():
            missing_files.append(f"companion manifest ({args.output_manifest})")

        if missing_files:
            print(
                f"[preprocess] FAIL: verify-only mode requires all input/output files to exist. "
                f"Missing: {', '.join(missing_files)}"
            )
            return 1

        result = verify_preprocessing_artifact(
            artifact_path=args.output_artifact,
            manifest_path=args.output_manifest,
            split_manifest_path=args.manifest,
            expected_dataset_sha256=EXPECTED_DATASET_SHA256,
        )
        if result["status"] == "PASS":
            print("[preprocess] PASS: artifact integrity and schema verified.")
            return 0
        else:
            print(f"[preprocess] FAIL: artifact verification errors: {result['errors']}")
            return 1

    # 2. Check if raw dataset exists; if not, skip cleanly (CI mode)
    if not args.dataset.is_file():
        print(f"PREPROCESSING: SKIPPED (raw dataset absent at {args.dataset})")
        return 0

    # 3. Check reproducibility if requested
    if args.check_reproducibility:
        run_reproducibility_check(
            dataset_path=args.dataset,
            manifest_path=args.manifest,
            indices_dir=args.indices_dir,
            scaler_type=args.scaler,
            add_missing_indicators=args.add_missing_indicators,
            handle_unknown_categories=args.handle_unknown_categories,
        )

    # 4. Standard execution
    t0 = time.time()
    print("[preprocess] Loading and fitting train-only preprocessor on NF-UNSW-NB15-v3...")
    train_data, val_data, test_data, preprocessor, audit_report = load_and_preprocess_split(
        manifest_path=args.manifest,
        dataset_path=args.dataset,
        indices_dir=args.indices_dir,
        scaler_type=args.scaler,
        add_missing_indicators=args.add_missing_indicators,
        handle_unknown_categories=args.handle_unknown_categories,
        save_artifact_path=args.output_artifact,
        save_manifest_path=args.output_manifest,
    )
    elapsed = time.time() - t0

    X_train, y_train, _ = train_data
    X_val, y_val, _ = val_data
    X_test, y_test, _ = test_data

    print(f"[preprocess] Success in {elapsed:.2f}s:")
    print(
        f"  Train shape:      {X_train.shape} (finite: {np.all(np.isfinite(X_train.to_numpy()))})"
    )
    print(f"  Validation shape: {X_val.shape} (finite: {np.all(np.isfinite(X_val.to_numpy()))})")
    print(f"  Test shape:       {X_test.shape} (finite: {np.all(np.isfinite(X_test.to_numpy()))})")
    print(f"  Features count:   {len(ML_FEATURE_COLUMNS)} in exact contract order")
    print(f"  Scaler type:      {args.scaler}")
    art_sha = audit_report.get("preprocessor_artifact_sha256")
    print(f"  Artifact saved:   {args.output_artifact} (SHA-256: {art_sha})")
    print(f"  Manifest saved:   {args.output_manifest}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
