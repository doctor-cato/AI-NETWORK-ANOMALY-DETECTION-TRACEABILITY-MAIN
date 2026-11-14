"""Regression tests for cross-dataset isolation, anti-leakage, and Test Lock (Issue #48, #57)."""

from __future__ import annotations

import gzip
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
    _compute_indices_sha256,
    extract_unsw_partition_sample,
)
from scripts.run_cross_dataset_experiments import (
    DEFAULT_BOT_CSV,
    DEFAULT_SPLIT_MANIFEST,
    DEFAULT_TON_CSV,
    _assert_disjoint_sample_rows,
    run_all_cross_dataset_experiments,
    verify_split_manifest_and_test_lock,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _write_canonical_fixture_dataset(
    tmp_path: Path,
    *,
    train_idx: list[int],
    val_idx: list[int],
    test_idx: list[int],
    n_total: int,
) -> tuple[Path, Path, Path, pd.DataFrame, str]:
    rng = np.random.default_rng(7)
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
    df_all["IPV4_SRC_ADDR"] = [f"10.0.0.{i % 250}" for i in range(n_total)]
    df_all["L4_SRC_PORT"] = 1000 + np.arange(n_total)
    df_all["IPV4_DST_ADDR"] = "192.168.1.10"
    df_all["L4_DST_PORT"] = 443
    df_all["Label"] = np.array([i % 2 for i in range(n_total)], dtype=int)
    df_all["Attack"] = ["Benign" if y == 0 else "Exploits" for y in df_all["Label"]]

    source_csv = tmp_path / "NF-UNSW-NB15-v3.csv"
    df_all.to_csv(source_csv, index=False, lineterminator="\n")
    ds_sha = _sha256_file(source_csv)

    indices_dir = tmp_path / "splits"
    indices_dir.mkdir(parents=True, exist_ok=True)
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
                "total_source_rows": n_total,
                "partitions": partitions,
                "split_policy": {"purge_gap_milliseconds": 300000},
            }
        ),
        encoding="utf-8",
    )
    return source_csv, split_manifest, indices_dir, df_all, ds_sha


def _install_mock_canonical_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    df_all: pd.DataFrame,
    train_idx: list[int],
) -> None:
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


def test_sample_names_match_fetcher():
    assert DEFAULT_TON_CSV.name == DATASET_CONFIGS["NF-ToN-IoT-v3"]["sample_name"]
    assert DEFAULT_BOT_CSV.name == DATASET_CONFIGS["NF-BoT-IoT-v3"]["sample_name"]


def test_main_components_zero_regression():
    """Verify that current main components (XGBoost, Isolation Forest) remain intact."""
    xgb_model_path = PROJECT_ROOT / "src" / "network_anomaly" / "models" / "xgboost_model.py"
    xgb_proto_path = PROJECT_ROOT / "src" / "network_anomaly" / "models" / "xgboost_protocol.py"
    xgb_train_path = PROJECT_ROOT / "scripts" / "train_xgboost.py"

    assert xgb_model_path.exists(), "xgboost_model.py must be preserved on main"
    assert xgb_proto_path.exists(), "xgboost_protocol.py must be preserved on main"
    assert xgb_train_path.exists(), "train_xgboost.py must be preserved on main"

    xgb_mod = importlib.import_module("network_anomaly.models.xgboost_model")
    assert hasattr(xgb_mod, "XGBoostModel"), "XGBoostModel class must be intact"

    if_path = PROJECT_ROOT / "src" / "network_anomaly" / "models" / "isolation_forest.py"
    assert if_path.exists(), "isolation_forest.py must be preserved on main"
    line_count = len(if_path.read_text(encoding="utf-8").splitlines())
    assert line_count >= 50
    if_mod = importlib.import_module("network_anomaly.models.isolation_forest")
    assert hasattr(if_mod, "anomaly_scores")


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
    """Enforce Train/Val disjointness and record provenance for E0-E5, E5_XGB, and U0-U4."""
    train_idx = list(range(0, 24))
    val_idx = list(range(26, 46))
    test_idx = list(range(48, 56))
    source_csv, split_manifest, indices_dir, df_all, ds_sha = _write_canonical_fixture_dataset(
        tmp_path,
        train_idx=train_idx,
        val_idx=val_idx,
        test_idx=test_idx,
        n_total=56,
    )

    src_lines = source_csv.read_text(encoding="utf-8").splitlines(keepends=True)

    def _write_slice(name: str, partition: str, start: int, count: int) -> Path:
        out_csv = tmp_path / name
        slice_lines = [src_lines[0]] + src_lines[1 + start : 1 + start + count]
        out_csv.write_bytes("".join(slice_lines).encode("utf-8"))
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

    unsw_train_csv = _write_slice("unsw_train_slice.csv", "train", 0, 24)
    unsw_val_csv = _write_slice("unsw_val_slice.csv", "validation", 26, 20)

    df_bench = df_all.iloc[:30].copy()
    df_bench["IPV4_SRC_ADDR"] = [f"172.16.0.{i}" for i in range(30)]
    df_bench["L4_SRC_PORT"] = 20000 + np.arange(30)
    df_bench["Label"] = np.array([i % 2 for i in range(30)], dtype=int)
    df_bench["Attack"] = ["Benign" if y == 0 else "DDoS" for y in df_bench["Label"]]
    benchmark_csv = tmp_path / "cic_benchmark.csv"
    df_bench.to_csv(benchmark_csv, index=False)

    _install_mock_canonical_artifacts(tmp_path, monkeypatch, df_all, train_idx)

    # Missing unsw_train_csv must fail closed
    with pytest.raises(FileNotFoundError, match="Dedicated UNSW Train sample"):
        run_all_cross_dataset_experiments(
            unsw_val_csv=unsw_val_csv,
            benchmark_csv=benchmark_csv,
            output_report_path=tmp_path / "missing_train.md",
            output_json_path=tmp_path / "missing_train.json",
            split_manifest_path=split_manifest,
            indices_dir=indices_dir,
            source_csv_path=source_csv,
        )

    # Passing Validation CSV as Train CSV must fail closed
    with pytest.raises(ValueError, match="partition mismatch|distinct"):
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

    wrong_train_copy = _write_slice("val_masquerading_as_train.csv", "validation", 26, 20)
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

    report_path = tmp_path / "report.md"
    summary_path = tmp_path / "summary.json"
    results = run_all_cross_dataset_experiments(
        unsw_val_csv=unsw_val_csv,
        benchmark_csv=benchmark_csv,
        output_report_path=report_path,
        output_json_path=summary_path,
        unsw_train_csv=unsw_train_csv,
        ton_csv=tmp_path / "missing_ton.csv",
        bot_csv=tmp_path / "missing_bot.csv",
        split_manifest_path=split_manifest,
        indices_dir=indices_dir,
        source_csv_path=source_csv,
    )

    expected_train_sha = _sha256_file(unsw_train_csv)
    for exp_key in ("E1", "E2", "E5", "E5_XGB", "U0_IF", "U0_AE"):
        prov = results[exp_key]["train_provenance"]
        assert prov["dataset"] == unsw_train_csv.name
        assert prov["dataset"] != unsw_val_csv.name
        assert prov["dataset_sha256"] == expected_train_sha

    e3_prov = results["E3"]["train_provenance"]
    assert e3_prov["datasets"] == [unsw_train_csv.name, benchmark_csv.name]
    assert unsw_val_csv.name not in e3_prov["datasets"]
    assert e3_prov["dataset_sha256s"][unsw_train_csv.name] == expected_train_sha
    assert results["E0"]["validation_provenance"]["dataset"] == unsw_val_csv.name
    assert results["E0"]["held_out_test_evaluation"]["status"] == "BLOCKED_UNDER_TEST_LOCK"
    assert summary_path.is_file()
    assert report_path.is_file()


def test_cross_dataset_runner_supports_non_contiguous_partition_indices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Runner E0-E5/U0-U4 supports non-contiguous partition_indices samples and rejects overlaps."""
    # Interleaved non-contiguous source rows for Train and Validation (both include Benign & Attack)
    train_idx = [i for i in range(0, 56) if (i // 2) % 2 == 0]  # 28 non-contiguous rows
    val_idx = [i for i in range(0, 56) if (i // 2) % 2 == 1]  # 28 non-contiguous rows
    test_idx = list(range(58, 64))
    source_csv, split_manifest, indices_dir, df_all, _ = _write_canonical_fixture_dataset(
        tmp_path,
        train_idx=train_idx,
        val_idx=val_idx,
        test_idx=test_idx,
        n_total=64,
    )

    unsw_train_csv = tmp_path / "unsw_train_noncontig.csv"
    unsw_val_csv = tmp_path / "unsw_val_noncontig.csv"
    extract_unsw_partition_sample(
        output_path=unsw_train_csv,
        source_csv_path=source_csv,
        split_manifest_path=split_manifest,
        indices_dir=indices_dir,
        partition="train",
        sample_rows=24,
        random_seed=42,
    )
    extract_unsw_partition_sample(
        output_path=unsw_val_csv,
        source_csv_path=source_csv,
        split_manifest_path=split_manifest,
        indices_dir=indices_dir,
        partition="validation",
        sample_rows=24,
        random_seed=42,
    )

    df_bench = df_all.iloc[:24].copy()
    df_bench["IPV4_SRC_ADDR"] = [f"172.17.0.{i}" for i in range(24)]
    df_bench["L4_SRC_PORT"] = 25000 + np.arange(24)
    df_bench["Label"] = np.array([i % 2 for i in range(24)], dtype=int)
    df_bench["Attack"] = ["Benign" if y == 0 else "DoS" for y in df_bench["Label"]]
    benchmark_csv = tmp_path / "cic_benchmark.csv"
    df_bench.to_csv(benchmark_csv, index=False)

    _install_mock_canonical_artifacts(tmp_path, monkeypatch, df_all, train_idx)

    # 1. Verify _assert_disjoint_sample_rows allows non-contiguous disjoint manifests
    _assert_disjoint_sample_rows(unsw_train_csv, unsw_val_csv)

    # 2. Verify full E0-E5 & U0-U4 runner executes cleanly on non-contiguous partition_indices
    results = run_all_cross_dataset_experiments(
        unsw_val_csv=unsw_val_csv,
        benchmark_csv=benchmark_csv,
        output_report_path=tmp_path / "noncontig_report.md",
        output_json_path=tmp_path / "noncontig_summary.json",
        unsw_train_csv=unsw_train_csv,
        ton_csv=tmp_path / "missing_ton.csv",
        bot_csv=tmp_path / "missing_bot.csv",
        split_manifest_path=split_manifest,
        indices_dir=indices_dir,
        source_csv_path=source_csv,
    )
    assert results["E0"]["validation_provenance"]["dataset"] == unsw_val_csv.name
    assert results["E1"]["train_provenance"]["dataset"] == unsw_train_csv.name
    assert "U0_IF" in results and "U4" in results

    # 3. Verify _assert_disjoint_sample_rows rejects forged overlapping non-contiguous indices
    val_manifest_path = unsw_val_csv.with_name(f"{unsw_val_csv.name}.manifest.json")
    tampered_man = json.loads(val_manifest_path.read_text(encoding="utf-8"))
    forged_indices = [0] + tampered_man["content_checksum"]["source_row_indices"][1:]
    tampered_man["content_checksum"]["source_row_indices"] = forged_indices
    tampered_man["content_checksum"]["selected_indices_sha256"] = _compute_indices_sha256(
        np.asarray(forged_indices, dtype=np.int64)
    )
    val_manifest_path.write_text(json.dumps(tampered_man), encoding="utf-8")
    with pytest.raises(ValueError, match="overlap"):
        _assert_disjoint_sample_rows(unsw_train_csv, unsw_val_csv)
