#!/usr/bin/env python3
"""Run deterministic data splitting and cross-partition leakage audit for NF-UNSW-NB15-v3.

This script executes GitHub Issue #7:
1. Verifies source dataset bytes against NF_UNSW_NB15_V3_MANIFEST.json.
2. Computes the chronological train/val/test split with canonical flow-group purge gaps.
3. Audits cross-partition leakage for all pairs (train-val, val-test, train-test).
4. Produces:
   - data/processed/nf_unsw_nb15_v3_split_manifest.json
   - data/processed/splits/*.csv.gz
   - reports/splits/nf_unsw_nb15_v3_split_manifest.json
   - reports/splits/nf_unsw_nb15_v3_leakage_audit_report.md
   - docs/dataset/NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md
5. Verifies split reproducibility.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

import pandas as pd  # noqa: E402

from network_anomaly.data.split import (  # noqa: E402
    DEFAULT_PURGE_GAP_MS,
    DEFAULT_RANDOM_SEED,
    DEFAULT_TEST_RATIO,
    DEFAULT_TRAIN_RATIO,
    DEFAULT_VAL_RATIO,
    EXPECTED_ARTIFACT_REL_PATHS,
    SplitConfig,
    _sha256_file,
    audit_split_leakage,
    compare_artifact_inventories,
    compute_chronological_split,
    generate_split_manifest,
    render_leakage_audit_report,
    run_split_pipeline,
    save_split_artifacts,
    verify_split_artifacts,
    write_deterministic_index_csv_gz,
)

DEFAULT_DATASET = PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv"
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_MANIFEST.json"
DEFAULT_PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
DEFAULT_REPORTS_SPLIT_DIR = PROJECT_ROOT / "reports" / "splits"
DEFAULT_DOCS_REPORT = PROJECT_ROOT / "docs" / "dataset" / "NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md"
DEFAULT_ROOT_MANIFEST = PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json"

EXPECTED_DATASET_SHA256 = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Split NF-UNSW-NB15-v3 and perform comprehensive leakage audit."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEFAULT_DATASET,
        help="Path to NF-UNSW-NB15-v3.csv",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_PROCESSED_DIR,
        help="Output directory for processed split artifacts",
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=DEFAULT_REPORTS_SPLIT_DIR,
        help="Output directory for reports/splits",
    )
    parser.add_argument(
        "--docs-report",
        type=Path,
        default=DEFAULT_DOCS_REPORT,
        help="Output path for docs/dataset/NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md",
    )
    parser.add_argument(
        "--root-manifest",
        type=Path,
        default=DEFAULT_ROOT_MANIFEST,
        help="Output path for root data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json",
    )
    parser.add_argument(
        "--purge-gap-ms",
        type=int,
        default=DEFAULT_PURGE_GAP_MS,
        help="Purge gap in milliseconds (default: 300000 ms = 5 minutes)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify existing split manifest and indices against dataset without recomputing",
    )
    parser.add_argument(
        "--check-reproducibility",
        action="store_true",
        help="Run split algorithm twice and verify exact identity of output",
    )
    return parser.parse_args()


def verify_source_dataset(dataset_path: Path) -> str:
    if not dataset_path.is_file():
        print(f"[split_and_audit] ERROR: dataset file not found: {dataset_path}")
        print("Run 'python scripts/fetch_nf_unsw_nb15_v3.py' first.")
        sys.exit(2)

    print(f"[split_and_audit] Verifying SHA-256 for {dataset_path.name}...")
    digest = _sha256_file(dataset_path)
    if digest != EXPECTED_DATASET_SHA256:
        print("[split_and_audit] ERROR: dataset SHA-256 mismatch!")
        print(f"  Expected: {EXPECTED_DATASET_SHA256}")
        print(f"  Got:      {digest}")
        sys.exit(2)
    print(f"[split_and_audit] PASS: dataset SHA-256 verified ({digest})")
    return digest


def verify_artifact_reproducibility(
    df: pd.DataFrame, config: SplitConfig, dataset_digest: str
) -> None:
    """Run artifact generation independently twice and verify byte identity across all artifacts."""
    print("[split_and_audit] ========================================================")
    print("[split_and_audit] Running independent dual-pass artifact reproducibility check...")
    print("[split_and_audit] ========================================================")

    fixed_timestamp = "2026-10-27T00:00:00+00:00"

    with tempfile.TemporaryDirectory() as tmp1_str, tempfile.TemporaryDirectory() as tmp2_str:
        tmp1 = Path(tmp1_str)
        tmp2 = Path(tmp2_str)

        print("[split_and_audit] Reproducibility Pass 1: generating full artifact inventory...")
        run_split_pipeline(
            df=df,
            config=config,
            dataset_sha256=dataset_digest,
            root_dir=tmp1,
            generated_at_utc=fixed_timestamp,
        )

        print("[split_and_audit] Reproducibility Pass 2: generating full artifact inventory...")
        run_split_pipeline(
            df=df,
            config=config,
            dataset_sha256=dataset_digest,
            root_dir=tmp2,
            generated_at_utc=fixed_timestamp,
        )

        print(
            "[split_and_audit] Comparing all generated artifacts on disk between Pass 1 and Pass 2:"
        )
        comp = compare_artifact_inventories(tmp1, tmp2, EXPECTED_ARTIFACT_REL_PATHS)

        for rel_file, sha in comp["matches"].items():
            print(f"  * {rel_file:<58}: SHA-256 MATCH ({sha})")

        if comp["mismatches"]:
            print("[split_and_audit] ERROR: Artifact reproducibility check FAILED!")
            for m in comp["mismatches"]:
                print(f"  - {m}")
            sys.exit(2)

        print(
            f"[split_and_audit] PASS: Byte-for-byte file reproducibility verified across all "
            f"{comp['total_checked']} artifacts."
        )


def main() -> None:
    args = parse_args()
    print("=" * 70)
    print("NF-UNSW-NB15-v3 Data Splitting and Cross-Partition Leakage Audit")
    print("=" * 70)

    # In --verify-only mode: validate existing on-disk artifacts without re-splitting or writing
    if args.verify_only:
        print("[split_and_audit] Running in --verify-only mode (validating existing artifacts)...")
        manifest_path = (
            args.root_manifest
            if args.root_manifest.is_file()
            else (args.output_dir / "nf_unsw_nb15_v3_split_manifest.json")
        )
        dataset_path = args.dataset if (args.dataset and args.dataset.is_file()) else None

        result = verify_split_artifacts(
            manifest_path=manifest_path,
            root_dir=PROJECT_ROOT,
            dataset_path=dataset_path,
        )

        for art in result["verified_artifacts"]:
            print(f"  * {art['path']:<58}: EXISTS")

        if result["status"] != "PASS":
            print("[split_and_audit] ERROR: Artifact verification FAILED with errors:")
            for err in result["errors"]:
                print(f"  - {err}")
            sys.exit(2)

        print("=" * 70)
        print(
            f"[split_and_audit] PASS: All {result['total_artifacts_checked']} split artifacts "
            "successfully verified on disk."
        )
        print(f"[split_and_audit] Manifest: {manifest_path}")
        print("=" * 70)
        sys.exit(0)

    dataset_digest = verify_source_dataset(args.dataset)

    config = SplitConfig(
        purge_gap_milliseconds=args.purge_gap_ms,
        train_ratio=DEFAULT_TRAIN_RATIO,
        val_ratio=DEFAULT_VAL_RATIO,
        test_ratio=DEFAULT_TEST_RATIO,
        random_seed=DEFAULT_RANDOM_SEED,
    )

    t0 = time.time()
    print(f"[split_and_audit] Loading full CSV from {args.dataset}...")
    df = pd.read_csv(args.dataset)
    load_time = time.time() - t0
    print(f"[split_and_audit] Loaded {len(df):,} rows in {load_time:.2f} seconds.")

    # If check-reproducibility requested, run independent dual-pass check on disk files
    if args.check_reproducibility:
        verify_artifact_reproducibility(df, config=config, dataset_digest=dataset_digest)

    print(
        "[split_and_audit] Computing chronological split "
        f"(purge gap: {config.purge_gap_milliseconds} ms)..."
    )
    t1 = time.time()
    split_result = compute_chronological_split(df, config=config)
    split_time = time.time() - t1
    print(f"[split_and_audit] Split completed in {split_time:.2f} seconds.")

    parts = split_result["partitions"]
    for name, p_info in parts.items():
        n_rows = len(p_info["indices"])
        pct = n_rows / split_result["total_source_rows"] * 100
        print(f"  * {name:<22}: {n_rows:>9,} rows ({pct:6.2f}%)")

    print("[split_and_audit] Performing cross-partition leakage audit...")
    t2 = time.time()
    audit_results = audit_split_leakage(df, split_result)
    audit_time = time.time() - t2
    print(
        f"[split_and_audit] Audit completed in {audit_time:.2f}s. "
        f"Status: {audit_results['status']}"
    )

    for pair_name, p_audit in audit_results["pair_audits"].items():
        exact = p_audit["exact_full_row_overlap"]["distinct_fingerprints"]
        source = p_audit["source_feature_overlap"]["distinct_fingerprints"]
        group = p_audit["canonical_flow_group_overlap"]["distinct_groups"]
        ml_cnt = p_audit["ml_feature_overlap"]["distinct_fingerprints"]
        bin_conf = p_audit["ml_feature_overlap"]["binary_label_conflicts"]
        cat_conf = p_audit["ml_feature_overlap"]["attack_category_variations"]
        print(
            f"  Pair {pair_name:<20}: exact={exact}, source={source}, group={group}, "
            f"ml_overlap={ml_cnt:,}, binary_conflicts={bin_conf}, cat_conflicts={cat_conf:,}"
        )

    # Compute index hashes for the manifest using deterministic gzip writing
    print("[split_and_audit] Writing partition index files and computing SHA-256 hashes...")
    indices_dir = args.output_dir / "splits"
    indices_dir.mkdir(parents=True, exist_ok=True)
    partition_hashes = {}

    for p_name, p_data in parts.items():
        idx_path = indices_dir / f"{p_name}_indices.csv.gz"
        partition_hashes[p_name] = write_deterministic_index_csv_gz(idx_path, p_data["indices"])
        print(f"  * {idx_path.name}: sha256={partition_hashes[p_name]}")

    print("[split_and_audit] Generating split manifest and reports...")
    manifest = generate_split_manifest(
        split_result=split_result,
        audit_results=audit_results,
        dataset_sha256=dataset_digest,
        partition_index_hashes=partition_hashes,
    )
    report_md = render_leakage_audit_report(manifest)

    written = save_split_artifacts(
        split_result=split_result,
        manifest=manifest,
        report_md=report_md,
        output_dir=args.output_dir,
        reports_split_dir=args.reports_dir,
        docs_report_path=args.docs_report,
        root_manifest_path=args.root_manifest,
    )

    print("[split_and_audit] Artifacts written:")
    for key, path in written.items():
        print(f"  * {key:<20}: {path}")

    print("=" * 70)
    print(f"Audit Status: {audit_results['status']}")
    print(
        "[split_and_audit] ML_READY: BLOCKED (pending train-only fitted preprocessing in Issue #8)"
    )
    print("=" * 70)
    if audit_results["status"] != "PASS":
        print(f"[split_and_audit] Blocking failures: {audit_results['blocking_failures']}")
        sys.exit(2)


if __name__ == "__main__":
    main()
