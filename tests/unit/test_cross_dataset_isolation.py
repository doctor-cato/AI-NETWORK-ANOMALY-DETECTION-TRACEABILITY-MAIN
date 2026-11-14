"""Regression tests for cross-dataset isolation, anti-leakage, and Test Lock (Issue #57, #58)."""

from __future__ import annotations

import gzip
import hashlib
import importlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

import scripts.run_cross_dataset_experiments as cross_exp
from network_anomaly.data.nf_unsw_nb15_v3 import CATEGORICAL_CODED_COLUMNS, ML_FEATURE_COLUMNS
from network_anomaly.inference.predict import _sha256_file
from network_anomaly.models.robust_experiment import (
    FEATURES_E1,
    compute_fingerprint_disjoint_split,
)
from network_anomaly.preprocessing import (
    FEATURE_CONTRACT_VERSION,
    PreprocessingConfig,
    TrainOnlyPreprocessor,
)
from network_anomaly.preprocessing.pipeline import EXPECTED_DATASET_SHA256
from scripts.fetch_external_dataset import (
    DATASET_CONFIGS,
    UNSW_CANONICAL_TRAIN_END,
    UNSW_TEST_LOCK_START,
    UNSW_VALIDATION_START,
    validate_slice_sampling_parameters,
    verify_unsw_sample_binding,
    verify_unsw_validation_membership,
)
from scripts.run_cross_dataset_experiments import (
    DEFAULT_SPLIT_MANIFEST,
    DEFAULT_TON_CSV,
    run_all_cross_dataset_experiments,
    verify_split_manifest_and_test_lock,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_ton_sample_name_matches_fetcher():
    assert DEFAULT_TON_CSV.name == DATASET_CONFIGS["NF-ToN-IoT-v3"]["sample_name"]


def test_unsw_sample_requires_verified_validation_membership(tmp_path: Path):
    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    source_csv = tmp_path / "NF-UNSW-NB15-v3.csv"
    source_rows = ["Label", "0", "1", "0", "1", "0", "0", "1", "0", "1"]
    source_csv.write_text("\n".join(source_rows) + "\n", encoding="utf-8")
    dataset_sha256 = hashlib.sha256(source_csv.read_bytes()).hexdigest()

    partitions = {}
    for name, rows in (("train", [0, 1, 2]), ("validation", [5, 6, 7])):
        path = indices_dir / f"{name}_indices.csv.gz"
        pd.DataFrame({"source_row_index": rows}).to_csv(path, index=False, compression="gzip")
        partitions[name] = {"index_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    split_manifest = tmp_path / "split.json"
    partitions["validation"]["row_count"] = 3
    partitions["test"] = {"row_count": 1}
    split_manifest.write_text(
        json.dumps({"dataset_sha256": dataset_sha256, "partitions": partitions}),
        encoding="utf-8",
    )

    verify_unsw_validation_membership(5, 2, split_manifest, indices_dir)
    with pytest.raises(ValueError, match="overlaps verified Train"):
        verify_unsw_validation_membership(1, 2, split_manifest, indices_dir)
    with pytest.raises(ValueError, match="outside verified Validation"):
        verify_unsw_validation_membership(6, 3, split_manifest, indices_dir)

    sample = tmp_path / "validation.csv"
    sample.write_text("Label\n0\n1\n", encoding="utf-8")
    companion = sample.with_name(f"{sample.name}.manifest.json")
    companion.write_text(
        json.dumps(
            {
                "dataset_identity": {"dataset_name": "NF-UNSW-NB15-v3"},
                "content_checksum": {
                    "partition": "validation",
                    "slice_type": "slice",
                    "sample_sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
                    "source_dataset_sha256": dataset_sha256,
                    "skip_rows_offset": 5,
                    "sample_rows_extracted": 2,
                },
            }
        ),
        encoding="utf-8",
    )
    assert verify_unsw_sample_binding(sample, split_manifest, indices_dir) == 2
    with pytest.raises(ValueError, match="row count differs"):
        verify_unsw_sample_binding(sample, split_manifest, indices_dir, expected_count=3)

    benchmark = tmp_path / "benchmark.csv"
    benchmark.write_text("Label\n0\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="Dedicated UNSW Train sample"):
        run_all_cross_dataset_experiments(
            sample,
            benchmark,
            tmp_path / "report.md",
            tmp_path / "summary.json",
            split_manifest_path=split_manifest,
            indices_dir=indices_dir,
        )

    train_sample = tmp_path / "train.csv"
    train_sample.write_text("Label\n0\n1\n", encoding="utf-8")
    contaminated = json.loads(companion.read_text(encoding="utf-8"))
    contaminated["content_checksum"]["skip_rows_offset"] = 1
    companion.write_text(json.dumps(contaminated), encoding="utf-8")
    with pytest.raises(ValueError, match="overlaps verified Train"):
        run_all_cross_dataset_experiments(
            sample,
            benchmark,
            tmp_path / "report.md",
            tmp_path / "summary.json",
            unsw_train_csv=train_sample,
            split_manifest_path=split_manifest,
            indices_dir=indices_dir,
        )
    assert not (tmp_path / "summary.json").exists()

    contaminated["content_checksum"]["skip_rows_offset"] = 5
    companion.write_text(json.dumps(contaminated), encoding="utf-8")
    sample.write_text("Label\n1\n1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_unsw_sample_binding(sample, split_manifest, indices_dir)


def test_unsw_sample_binding_rejects_missing_or_tampered_source(tmp_path: Path):
    """F3 regression: reject samples lacking canonical source verification or mismatched rows."""
    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    source_csv = tmp_path / "NF-UNSW-NB15-v3.csv"
    source_rows = ["Label", "0", "1", "0", "1", "0", "0", "1", "0", "1"]
    source_csv.write_text("\n".join(source_rows) + "\n", encoding="utf-8")
    dataset_sha256 = hashlib.sha256(source_csv.read_bytes()).hexdigest()

    partitions = {}
    for name, rows in (("train", [0, 1, 2]), ("validation", [5, 6, 7])):
        path = indices_dir / f"{name}_indices.csv.gz"
        pd.DataFrame({"source_row_index": rows}).to_csv(path, index=False, compression="gzip")
        partitions[name] = {
            "row_count": len(rows),
            "index_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    partitions["test"] = {"row_count": 1}
    split_manifest = tmp_path / "split.json"
    split_manifest.write_text(
        json.dumps({"dataset_sha256": dataset_sha256, "partitions": partitions}),
        encoding="utf-8",
    )

    sample = tmp_path / "arbitrary_slice.csv"
    # Rows at source offset 5..6 are 0, 1; forge arbitrary 1, 1 with matching sample_sha256!
    sample.write_text("Label\n1\n1\n", encoding="utf-8")
    companion = sample.with_name(f"{sample.name}.manifest.json")
    base_manifest = {
        "dataset_identity": {"dataset_name": "NF-UNSW-NB15-v3"},
        "content_checksum": {
            "partition": "validation",
            "slice_type": "slice",
            "sample_sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
            "source_dataset_sha256": dataset_sha256,
            "skip_rows_offset": 5,
            "sample_rows_extracted": 2,
        },
    }
    companion.write_text(json.dumps(base_manifest), encoding="utf-8")

    # 1. Tampered slice content at valid offset must be rejected against canonical source CSV
    with pytest.raises(ValueError, match="content mismatch vs canonical UNSW source CSV"):
        verify_unsw_sample_binding(sample, split_manifest, indices_dir)

    # Restore exact slice rows
    sample.write_text("Label\n0\n1\n", encoding="utf-8")
    base_manifest["content_checksum"]["sample_sha256"] = hashlib.sha256(
        sample.read_bytes()
    ).hexdigest()
    companion.write_text(json.dumps(base_manifest), encoding="utf-8")
    assert verify_unsw_sample_binding(sample, split_manifest, indices_dir) == 2

    # 2. Missing source_dataset_sha256 must fail closed
    no_src_sha = json.loads(json.dumps(base_manifest))
    no_src_sha["content_checksum"].pop("source_dataset_sha256")
    companion.write_text(json.dumps(no_src_sha), encoding="utf-8")
    with pytest.raises(ValueError, match="source_dataset_sha256"):
        verify_unsw_sample_binding(sample, split_manifest, indices_dir)

    # 3. Boolean offset/count must be rejected
    bool_man = json.loads(json.dumps(base_manifest))
    bool_man["content_checksum"]["skip_rows_offset"] = True
    companion.write_text(json.dumps(bool_man), encoding="utf-8")
    with pytest.raises(ValueError, match="integer source row indices"):
        verify_unsw_sample_binding(sample, split_manifest, indices_dir)
    companion.write_text(json.dumps(base_manifest), encoding="utf-8")

    # 4. Modified source CSV SHA-256 must fail closed
    source_csv.write_text("\n".join(source_rows + ["0"]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source CSV SHA-256 does not match"):
        verify_unsw_sample_binding(sample, split_manifest, indices_dir)

    # 5. Absent canonical source CSV must fail closed with FileNotFoundError
    source_csv.unlink()
    with pytest.raises(FileNotFoundError, match="source CSV"):
        verify_unsw_sample_binding(sample, split_manifest, indices_dir)


def test_main_components_zero_regression():
    """Verify that current main components (XGBoost, Isolation Forest) remain intact."""
    # 1. XGBoost model and protocol
    xgb_model_path = PROJECT_ROOT / "src" / "network_anomaly" / "models" / "xgboost_model.py"
    xgb_proto_path = PROJECT_ROOT / "src" / "network_anomaly" / "models" / "xgboost_protocol.py"
    xgb_train_path = PROJECT_ROOT / "scripts" / "train_xgboost.py"

    assert xgb_model_path.exists(), "xgboost_model.py must be preserved on main"
    assert xgb_proto_path.exists(), "xgboost_protocol.py must be preserved on main"
    assert xgb_train_path.exists(), "train_xgboost.py must be preserved on main"

    xgb_mod = importlib.import_module("network_anomaly.models.xgboost_model")
    assert hasattr(xgb_mod, "XGBoostModel"), "XGBoostModel class must be intact"

    # 2. Isolation Forest model
    if_path = PROJECT_ROOT / "src" / "network_anomaly" / "models" / "isolation_forest.py"
    assert if_path.exists(), "isolation_forest.py must be preserved on main"

    # Verify isolation_forest.py is the full implementation, not the 12-line PR #47 stub
    line_count = len(if_path.read_text(encoding="utf-8").splitlines())
    assert (
        line_count >= 50
    ), f"isolation_forest.py must not be overwritten by stub ({line_count} lines)"

    if_mod = importlib.import_module("network_anomaly.models.isolation_forest")
    assert hasattr(if_mod, "anomaly_scores"), "anomaly_scores function must be intact"


def test_fetch_external_dataset_anti_leakage_guardrail():
    """First-50k slice on NF-UNSW-NB15-v3 (rows 0-50k) is strictly rejected as train-set leakage."""
    # Attempting to slice row 0 (start of training partition)
    with pytest.raises(ValueError) as excinfo:
        validate_slice_sampling_parameters("NF-UNSW-NB15-v3", skip_rows=0, sample_rows=50000)
    assert "chronological integrity violation" in str(excinfo.value).lower()
    assert f"{UNSW_CANONICAL_TRAIN_END:,}" in str(excinfo.value) or str(
        UNSW_CANONICAL_TRAIN_END
    ) in str(excinfo.value)

    # Attempting to slice inside training partition (< 1,665,240)
    with pytest.raises(ValueError) as excinfo_mid:
        validate_slice_sampling_parameters("NF-UNSW-NB15-v3", skip_rows=100000, sample_rows=10000)
    assert "chronological integrity violation" in str(excinfo_mid.value).lower()

    # Slicing at official validation start (>= 1,665,240) is permitted
    val_skip = validate_slice_sampling_parameters(
        "NF-UNSW-NB15-v3", skip_rows=UNSW_VALIDATION_START, sample_rows=50000
    )
    assert val_skip == UNSW_VALIDATION_START


def test_fetch_external_dataset_test_lock_guardrail():
    """Held-out Test split (rows >= 2,019,471) is strictly BLOCKED under Test Lock."""
    with pytest.raises(PermissionError) as excinfo:
        validate_slice_sampling_parameters(
            "NF-UNSW-NB15-v3", skip_rows=UNSW_TEST_LOCK_START, sample_rows=10000
        )
    assert "test lock enforced" in str(excinfo.value).lower()
    assert "blocked" in str(excinfo.value).lower()
    with pytest.raises(ValueError, match="crosses the purge gap"):
        validate_slice_sampling_parameters(
            "NF-UNSW-NB15-v3", skip_rows=UNSW_TEST_LOCK_START - 2, sample_rows=10
        )


def test_split_manifest_verification_and_test_lock():
    """Official split manifest must define validation, test lock, and 300s purge gap."""
    audit = verify_split_manifest_and_test_lock(DEFAULT_SPLIT_MANIFEST)
    assert audit["status"] == "VERIFIED"
    assert audit["validation_rows"] == 345371
    exp_val_sha = "a3e4470c2731870deaf57ce9a865e2491107d8e7f72383cdd0f99de0dd485cd4"
    assert audit["validation_index_sha256"] == exp_val_sha
    assert "BLOCKED" in audit["test_lock_status"]
    assert audit["purge_gap_milliseconds"] == 300000


def test_fingerprint_disjointness_in_cross_dataset_partitioning():
    """Partitioning must ensure 0 5-tuple flow overlap between train and test subsets."""
    # Synthetic dataset with repeated 5-tuples simulating multi-packet flows
    df = pd.DataFrame(
        {
            "IPV4_SRC_ADDR": ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.2", "10.0.0.3"],
            "L4_SRC_PORT": [1000, 1000, 2000, 2000, 3000],
            "IPV4_DST_ADDR": ["10.0.0.5", "10.0.0.5", "10.0.0.6", "10.0.0.6", "10.0.0.7"],
            "L4_DST_PORT": [80, 80, 443, 443, 8080],
            "PROTOCOL": [6, 6, 6, 6, 17],
            "Label": [0, 0, 1, 1, 0],
            "Attack": ["Benign", "Benign", "DoS", "DoS", "Benign"],
        }
    )
    for col in FEATURES_E1:
        if col not in df.columns:
            df[col] = 1.0

    df_train, df_test, audit = compute_fingerprint_disjoint_split(
        df, train_size=0.40, random_state=42, feature_cols=FEATURES_E1
    )
    assert audit["overlap_5tuple_fingerprints"] == 0
    assert audit["fingerprint_disjoint_verified"] is True
    assert len(df_train) > 0
    assert len(df_test) > 0


def test_cross_dataset_experiments_train_val_isolation_and_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """F2 regression: enforce Train/Val disjointness and record train CSV provenance for E1-E5."""
    rng = np.random.default_rng(7)
    n_total = 32
    df_all = pd.DataFrame(
        {
            col: (
                rng.integers(0, 4, size=n_total)
                if col in CATEGORICAL_CODED_COLUMNS
                else rng.normal(50.0, 10.0, size=n_total)
            )
            for col in ML_FEATURE_COLUMNS
        },
        columns=list(ML_FEATURE_COLUMNS),
    )
    df_all["IPV4_SRC_ADDR"] = [f"10.0.0.{i}" for i in range(n_total)]
    df_all["L4_SRC_PORT"] = 1000 + np.arange(n_total)
    df_all["IPV4_DST_ADDR"] = "192.168.1.10"
    df_all["L4_DST_PORT"] = 443
    df_all["Label"] = np.array([i % 2 for i in range(n_total)], dtype=int)
    df_all["Attack"] = ["Benign" if y == 0 else "Exploits" for y in df_all["Label"]]

    source_csv = tmp_path / "NF-UNSW-NB15-v3.csv"
    df_all.to_csv(source_csv, index=False)
    ds_sha = _sha256_file(source_csv)

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir()
    train_idx = list(range(0, 14))
    val_idx = list(range(16, 28))
    test_idx = list(range(28, 32))
    partitions = {}
    for name, idxs in (("train", train_idx), ("validation", val_idx), ("test", test_idx)):
        gz_path = indices_dir / f"{name}_indices.csv.gz"
        with gzip.open(gz_path, "wt", encoding="utf-8", newline="") as f:
            f.write("source_row_index\n")
            for idx_v in idxs:
                f.write(f"{idx_v}\n")
        partitions[name] = {
            "row_count": len(idxs),
            "index_sha256": _sha256_file(gz_path),
        }

    split_manifest = tmp_path / "split_manifest.json"
    split_manifest.write_text(
        json.dumps(
            {
                "dataset_sha256": ds_sha,
                "partitions": partitions,
                "split_policy": {"purge_gap_milliseconds": 300000},
            }
        ),
        encoding="utf-8",
    )

    src_lines = source_csv.read_text(encoding="utf-8").splitlines(keepends=True)

    def _write_slice(name: str, partition: str, start: int, count: int) -> Path:
        out_csv = tmp_path / name
        slice_lines = [src_lines[0]] + src_lines[1 + start : 1 + start + count]
        out_csv.write_text("".join(slice_lines), encoding="utf-8")
        man = out_csv.with_name(f"{out_csv.name}.manifest.json")
        man.write_text(
            json.dumps(
                {
                    "dataset_identity": {"dataset_name": "NF-UNSW-NB15-v3"},
                    "content_checksum": {
                        "partition": partition,
                        "slice_type": "slice",
                        "sample_sha256": _sha256_file(out_csv),
                        "source_dataset_sha256": ds_sha,
                        "skip_rows_offset": start,
                        "sample_rows_extracted": count,
                    },
                }
            ),
            encoding="utf-8",
        )
        return out_csv

    unsw_train_csv = _write_slice("unsw_train_slice.csv", "train", 0, 14)
    unsw_val_csv = _write_slice("unsw_val_slice.csv", "validation", 16, 12)
    # Build synthetic CIC-IDS benchmark with distinct 5-tuple fingerprints and both labels
    df_bench = df_all.iloc[:24].copy()
    df_bench["IPV4_SRC_ADDR"] = [f"172.16.0.{i}" for i in range(24)]
    df_bench["L4_SRC_PORT"] = 20000 + np.arange(24)
    df_bench["Label"] = np.array([i % 2 for i in range(24)], dtype=int)
    df_bench["Attack"] = ["Benign" if y == 0 else "DDoS" for y in df_bench["Label"]]
    benchmark_csv = tmp_path / "cic_benchmark.csv"
    df_bench.to_csv(benchmark_csv, index=False)

    # Create canonical baseline preprocessor & RF artifacts in tmp_path
    prep = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="none"),
        dataset_sha256=EXPECTED_DATASET_SHA256,
        split_manifest_sha256="b" * 64,
    )
    X_u_train = df_all.iloc[train_idx][list(ML_FEATURE_COLUMNS)].reset_index(drop=True)
    y_u_train = df_all.iloc[train_idx]["Label"].to_numpy(dtype=int)
    X_u_train_t = prep.fit_transform(X_u_train)
    prep_art = tmp_path / "prep.joblib"
    prep_man = tmp_path / "prep_manifest.json"
    prep_sha = prep.save(prep_art, prep_man)

    rf = RandomForestClassifier(n_estimators=5, random_state=42).fit(X_u_train_t, y_u_train)
    model_art = tmp_path / "rf_canonical.joblib"
    joblib.dump(rf, model_art)
    model_man = tmp_path / "rf_canonical_manifest.json"
    model_man.write_text(
        json.dumps(
            {
                "run_id": "test-e0-canonical",
                "model_type": "RandomForestClassifier",
                "feature_contract_version": FEATURE_CONTRACT_VERSION,
                "model_artifact_sha256": _sha256_file(model_art),
                "preprocessor_artifact_sha256": prep_sha,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(cross_exp, "DEFAULT_CANONICAL_MODEL", model_art)
    monkeypatch.setattr(cross_exp, "DEFAULT_CANONICAL_MANIFEST", model_man)
    monkeypatch.setattr(cross_exp, "DEFAULT_PREP_ARTIFACT", prep_art)
    monkeypatch.setattr(cross_exp, "DEFAULT_PREP_MANIFEST", prep_man)

    # Passing identical Validation CSV as Train CSV must be rejected
    with pytest.raises(ValueError, match="distinct"):
        run_all_cross_dataset_experiments(
            unsw_val_csv=unsw_val_csv,
            benchmark_csv=benchmark_csv,
            output_report_path=tmp_path / "bad_report.md",
            output_json_path=tmp_path / "bad_summary.json",
            unsw_train_csv=unsw_val_csv,
            split_manifest_path=split_manifest,
            indices_dir=indices_dir,
            source_csv_path=source_csv,
        )

    # Distinct file containing Validation rows passed as Train CSV must be rejected
    wrong_train_copy = _write_slice("val_masquerading_as_train.csv", "validation", 16, 12)
    with pytest.raises(ValueError, match="partition mismatch|overlaps verified"):
        run_all_cross_dataset_experiments(
            unsw_val_csv=unsw_val_csv,
            benchmark_csv=benchmark_csv,
            output_report_path=tmp_path / "bad_report2.md",
            output_json_path=tmp_path / "bad_summary2.json",
            unsw_train_csv=wrong_train_copy,
            split_manifest_path=split_manifest,
            indices_dir=indices_dir,
            source_csv_path=source_csv,
        )

    # Valid run executes E0-E5 cleanly and records unsw_train_csv provenance (never unsw_val_csv)
    report_path = tmp_path / "report.md"
    summary_path = tmp_path / "summary.json"
    results = run_all_cross_dataset_experiments(
        unsw_val_csv=unsw_val_csv,
        benchmark_csv=benchmark_csv,
        output_report_path=report_path,
        output_json_path=summary_path,
        unsw_train_csv=unsw_train_csv,
        ton_csv=tmp_path / "missing_ton.csv",
        split_manifest_path=split_manifest,
        indices_dir=indices_dir,
        source_csv_path=source_csv,
    )

    expected_train_sha = _sha256_file(unsw_train_csv)
    for exp_key in ("E1", "E2", "E5"):
        prov = results[exp_key]["train_provenance"]
        assert prov["dataset"] == unsw_train_csv.name
        assert prov["dataset"] != unsw_val_csv.name
        assert prov["dataset_sha256"] == expected_train_sha

    e3_prov = results["E3"]["train_provenance"]
    assert e3_prov["datasets"] == [unsw_train_csv.name, benchmark_csv.name]
    assert unsw_val_csv.name not in e3_prov["datasets"]
    assert e3_prov["dataset_sha256s"][unsw_train_csv.name] == expected_train_sha
    assert results["E0"]["validation_provenance"]["dataset"] == unsw_val_csv.name
    assert summary_path.is_file()
