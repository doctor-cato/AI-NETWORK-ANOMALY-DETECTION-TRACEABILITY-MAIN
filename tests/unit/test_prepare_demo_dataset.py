"""Unit tests for scripts/prepare_demo_dataset.py (Phase 4 demo CSV contract)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS_DIR = _PROJECT_ROOT / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from prepare_demo_dataset import (  # noqa: E402
    inspect_artifact_readiness,
    prepare_demo_dataset,
)

from network_anomaly.data.nf_unsw_nb15_v3 import (  # noqa: E402
    ALL_COLUMNS,
    CATEGORICAL_CODED_COLUMNS,
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.inference.predict import InferencePipeline, _sha256_file  # noqa: E402
from network_anomaly.preprocessing import (  # noqa: E402
    FEATURE_CONTRACT_VERSION,
    PreprocessingConfig,
    TrainOnlyPreprocessor,
)
from network_anomaly.preprocessing.pipeline import EXPECTED_DATASET_SHA256  # noqa: E402


def _build_synthetic_canonical_fixture(
    root: Path,
) -> Tuple[Path, Path, Path, str]:
    """Create synthetic UNSW CSV (300 rows) + canonical split manifest & index files."""
    rng = np.random.default_rng(123)
    n_rows = 300
    data: Dict[str, Any] = {}
    for col in ALL_COLUMNS:
        if col == "FLOW_START_MILLISECONDS":
            data[col] = 1_700_000_000_000 + np.arange(n_rows) * 10
        elif col == "FLOW_END_MILLISECONDS":
            data[col] = 1_700_000_000_005 + np.arange(n_rows) * 10
        elif col == "IPV4_SRC_ADDR":
            data[col] = [f"10.0.0.{(i % 20) + 1}" for i in range(n_rows)]
        elif col == "IPV4_DST_ADDR":
            data[col] = [f"172.16.0.{(i % 10) + 1}" for i in range(n_rows)]
        elif col in {"L4_SRC_PORT", "L4_DST_PORT"}:
            data[col] = 1024 + np.arange(n_rows)
        elif col in CATEGORICAL_CODED_COLUMNS:
            data[col] = rng.integers(0, 8, size=n_rows)
        elif col == "Label":
            labels = np.array([i % 2 for i in range(n_rows)], dtype=np.int64)
            data[col] = labels
        elif col == "Attack":
            data[col] = ["AttackA" if i % 2 == 1 else "Benign" for i in range(n_rows)]
        else:
            data[col] = np.round(rng.normal(50.0, 10.0, size=n_rows), 4)

    df = pd.DataFrame(data, columns=list(ALL_COLUMNS))
    csv_path = root / "NF-UNSW-NB15-v3.csv"
    df.to_csv(csv_path, index=False, lineterminator="\n")
    dataset_sha = _sha256_file(csv_path)

    indices_dir = root / "splits"
    indices_dir.mkdir(parents=True, exist_ok=True)
    part_ranges = {
        "train": np.arange(0, 120, dtype=np.int64),
        "validation": np.arange(120, 250, dtype=np.int64),
        "test": np.arange(250, 300, dtype=np.int64),
    }
    partitions_meta: Dict[str, Any] = {}
    for name, idx_arr in part_ranges.items():
        idx_file = indices_dir / f"{name}_indices.csv.gz"
        pd.DataFrame({"source_row_index": idx_arr}).to_csv(
            idx_file, index=False, compression="gzip", lineterminator="\n"
        )
        partitions_meta[name] = {
            "index_file": idx_file.name,
            "index_sha256": _sha256_file(idx_file),
            "row_count": int(idx_arr.size),
        }

    split_manifest_path = root / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json"
    split_manifest_path.write_text(
        json.dumps(
            {
                "dataset_name": "NF-UNSW-NB15-v3",
                "dataset_sha256": dataset_sha,
                "total_source_rows": n_rows,
                "partitions": partitions_meta,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return csv_path, split_manifest_path, indices_dir, dataset_sha


def _build_verified_rf_tree(root: Path, split_manifest_sha: str) -> Tuple[Path, Path]:
    """Create verified TrainOnlyPreprocessor + RandomForest artifact tree in tmp root."""
    art_dir = root / "artifacts"
    rep_dir = root / "reports"
    prep_path = art_dir / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
    prep_manifest = rep_dir / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
    rf_path = art_dir / "models" / "random_forest" / "random_forest_baseline.joblib"
    rf_manifest = rep_dir / "models" / "random_forest_manifest.json"

    rng = np.random.default_rng(42)
    train_df = pd.DataFrame(
        {
            col: (
                rng.integers(0, 8, size=20)
                if col in CATEGORICAL_CODED_COLUMNS
                else rng.normal(50.0, 10.0, size=20)
            )
            for col in ML_FEATURE_COLUMNS
        }
    )
    prep = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="none"),
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256=split_manifest_sha,
    )
    prep.fit(train_df)
    prep_sha = prep.save(prep_path, prep_manifest)

    rf_path.parent.mkdir(parents=True, exist_ok=True)
    rf_manifest.parent.mkdir(parents=True, exist_ok=True)
    rf = RandomForestClassifier(n_estimators=5, random_state=42)
    rf.fit(prep.transform(train_df), np.arange(20) % 2)
    joblib.dump(rf, rf_path)
    rf_manifest.write_text(
        json.dumps(
            {
                "run_id": "test-demo-rf-run",
                "model_type": "RandomForestClassifier",
                "model_artifact_sha256": _sha256_file(rf_path),
                "preprocessor_artifact_sha256": prep_sha,
                "feature_contract_version": FEATURE_CONTRACT_VERSION,
                "class_mapping": {"0": "Benign", "1": "Attack"},
            }
        ),
        encoding="utf-8",
    )
    return art_dir, rep_dir


def test_prepare_demo_dataset_validation_only_and_inference_parity(tmp_path: Path):
    """Demo export uses Validation only, excludes targets from flows, and preserves row_id."""
    csv_path, split_man, idx_dir, _ = _build_synthetic_canonical_fixture(tmp_path)
    split_man_sha = _sha256_file(split_man)
    art_dir, rep_dir = _build_verified_rf_tree(tmp_path, split_man_sha)

    out1 = tmp_path / "demo_run_1"
    res1 = prepare_demo_dataset(
        source_csv_path=csv_path,
        split_manifest_path=split_man,
        indices_dir=idx_dir,
        output_dir=out1,
        sample_rows=100,
        random_seed=42,
        artifacts_dir=art_dir,
        reports_dir=rep_dir,
        chunk_size=64,
    )

    flows_df = pd.read_csv(res1["flows_path"])
    labels_df = pd.read_csv(res1["labels_path"])
    manifest = res1["manifest"]

    # Strict schema contract
    assert list(flows_df.columns) == ["row_id", *TRACE_METADATA_COLUMNS, *ML_FEATURE_COLUMNS]
    for target_col in TARGET_COLUMNS:
        assert target_col not in flows_df.columns
    assert list(labels_df.columns) == ["row_id", "Label", "Attack"]
    assert flows_df["row_id"].tolist() == labels_df["row_id"].tolist()
    assert len(flows_df) == 100
    assert (labels_df["Label"] == 0).sum() == 50
    assert (labels_df["Label"] == 1).sum() == 50

    # Strict Validation-only & zero Train/Test overlap
    assert all(120 <= rid < 250 for rid in flows_df["row_id"].tolist())
    assert manifest["sampling"]["partition"] == "validation"
    assert manifest["sampling"]["train_overlap_count"] == 0
    assert manifest["sampling"]["test_overlap_count"] == 0
    assert "does NOT reflect" in manifest["scientific_validity_notice"]

    # Artifact readiness (standalone canonical check without synthetic CSV hash override)
    # flags RF READY and absent models BLOCKED / NOT READY
    readiness = inspect_artifact_readiness(
        artifacts_dir=art_dir,
        reports_dir=rep_dir,
        split_manifest_path=None,
    )
    assert readiness["overall_status"] == "READY"
    assert readiness["ready_models"] == ["random_forest"]
    assert readiness["models"]["random_forest"]["status"] == "READY"
    for absent in ("xgboost", "isolation_forest", "autoencoder"):
        assert readiness["models"][absent]["status"] == "BLOCKED / NOT READY"
        assert readiness["models"][absent]["ready"] is False

    # Verified InferencePipeline consumes demo_flows.csv and preserves row_id 1-to-1
    pipe = InferencePipeline.from_artifacts(
        model_artifact_path=art_dir / "models" / "random_forest" / "random_forest_baseline.joblib",
        preprocessor_artifact_path=art_dir
        / "preprocessing"
        / "nf_unsw_nb15_v3_preprocessor.joblib",
        model_manifest_path=rep_dir / "models" / "random_forest_manifest.json",
        preprocessor_manifest_path=rep_dir
        / "preprocessing"
        / "nf_unsw_nb15_v3_preprocessing_manifest.json",
    )
    preds_df = pipe.predict(flows_df)
    assert preds_df["row_id"].tolist() == labels_df["row_id"].tolist()

    # Deterministic repeatability check
    out2 = tmp_path / "demo_run_2"
    res2 = prepare_demo_dataset(
        source_csv_path=csv_path,
        split_manifest_path=split_man,
        indices_dir=idx_dir,
        output_dir=out2,
        sample_rows=100,
        random_seed=42,
        artifacts_dir=art_dir,
        reports_dir=rep_dir,
        chunk_size=64,
    )
    assert (
        res1["manifest"]["outputs"]["demo_flows_csv"]["sha256"]
        == res2["manifest"]["outputs"]["demo_flows_csv"]["sha256"]
    )
    assert (
        res1["manifest"]["outputs"]["demo_labels_csv"]["sha256"]
        == res2["manifest"]["outputs"]["demo_labels_csv"]["sha256"]
    )


def test_prepare_demo_dataset_rejects_invalid_bounds_tampered_csv_and_overlap(tmp_path: Path):
    """Fail-closed checks enforce [100..300] bounds, dataset SHA-256, and zero split overlap."""
    csv_path, split_man, idx_dir, _ = _build_synthetic_canonical_fixture(tmp_path)

    for bad_rows in (50, 350, True):
        with pytest.raises(ValueError, match=r"100.*300"):
            prepare_demo_dataset(
                source_csv_path=csv_path,
                split_manifest_path=split_man,
                indices_dir=idx_dir,
                output_dir=tmp_path / "out_bad_rows",
                sample_rows=bad_rows,  # type: ignore[arg-type]
            )

    # Corrupt validation index file with a Train index and matching manifest hash
    contaminated_val = idx_dir / "validation_indices.csv.gz"
    pd.DataFrame({"source_row_index": np.arange(115, 250, dtype=np.int64)}).to_csv(
        contaminated_val, index=False, compression="gzip", lineterminator="\n"
    )
    man_data = json.loads(split_man.read_text(encoding="utf-8"))
    man_data["partitions"]["validation"]["index_sha256"] = _sha256_file(contaminated_val)
    man_data["partitions"]["validation"]["row_count"] = 135
    split_man.write_text(json.dumps(man_data), encoding="utf-8")

    with pytest.raises(ValueError, match="overlap"):
        prepare_demo_dataset(
            source_csv_path=csv_path,
            split_manifest_path=split_man,
            indices_dir=idx_dir,
            output_dir=tmp_path / "out_overlap",
            sample_rows=100,
        )

    # Tamper source CSV bytes -> fail-closed SHA-256 mismatch
    csv_path.write_text(csv_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        prepare_demo_dataset(
            source_csv_path=csv_path,
            split_manifest_path=split_man,
            indices_dir=idx_dir,
            output_dir=tmp_path / "out_tamper",
            sample_rows=100,
        )


def test_inspect_artifact_readiness_blocks_missing_artifacts_without_faking(tmp_path: Path):
    """Missing artifacts must report BLOCKED / NOT READY and never synthesize dummy .joblib files."""
    empty_art = tmp_path / "missing_artifacts"
    empty_rep = tmp_path / "missing_reports"
    readiness = inspect_artifact_readiness(
        artifacts_dir=empty_art,
        reports_dir=empty_rep,
        split_manifest_path=tmp_path / "missing_split.json",
    )
    assert readiness["overall_status"] == "BLOCKED / NOT READY"
    assert readiness["ready_models"] == []
    assert readiness["preprocessor"]["status"] == "BLOCKED / NOT READY"
    for model_key in ("random_forest", "xgboost", "isolation_forest", "autoencoder"):
        assert readiness["models"][model_key]["status"] == "BLOCKED / NOT READY"
    assert not empty_art.exists()
