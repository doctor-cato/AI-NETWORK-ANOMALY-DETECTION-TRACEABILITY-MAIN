import json
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ALL_COLUMNS,
    DATASET_NAME,
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    validate_feature_selection,
    validate_semantic_column_roles,
)
from network_anomaly.data.split import (
    PARTITION_PURGED_TRAIN_VAL,
    PARTITION_PURGED_VAL_TEST,
    PARTITION_TEST,
    PARTITION_TRAIN,
    PARTITION_VALIDATION,
    SplitConfig,
    audit_split_leakage,
    compute_chronological_split,
    generate_split_manifest,
    load_partition_indices,
    render_leakage_audit_report,
    save_split_artifacts,
)

ROOT = Path(__file__).resolve().parents[2]


def make_synthetic_df(n_rows=100, base_time=1_000_000, time_step=1_000):
    data = {col: np.zeros(n_rows, dtype=np.int64) for col in ALL_COLUMNS}
    data["FLOW_START_MILLISECONDS"] = np.arange(
        base_time, base_time + n_rows * time_step, time_step
    )
    data["FLOW_END_MILLISECONDS"] = data["FLOW_START_MILLISECONDS"] + 10
    data["IPV4_SRC_ADDR"] = [f"192.168.1.{i % 250 + 1}" for i in range(n_rows)]
    data["IPV4_DST_ADDR"] = [f"10.0.0.{i % 250 + 1}" for i in range(n_rows)]
    data["L4_SRC_PORT"] = [(1000 + i % 1000) for i in range(n_rows)]
    data["L4_DST_PORT"] = 80
    data["PROTOCOL"] = 6
    data["Label"] = [0 if i % 5 != 0 else 1 for i in range(n_rows)]
    data["Attack"] = ["Benign" if i % 5 != 0 else "Exploits" for i in range(n_rows)]
    return pd.DataFrame(data)


def test_baseline_features_and_exclusion_contract():
    assert len(ML_FEATURE_COLUMNS) == 47
    assert len(ALL_COLUMNS) == 55
    assert len(TRACE_METADATA_COLUMNS) == 6
    assert len(TARGET_COLUMNS) == 2
    assert validate_semantic_column_roles() is True
    assert validate_feature_selection(ML_FEATURE_COLUMNS) == ML_FEATURE_COLUMNS

    for col in TRACE_METADATA_COLUMNS + TARGET_COLUMNS:
        assert col not in ML_FEATURE_COLUMNS
        with pytest.raises(ValueError, match="forbidden"):
            validate_feature_selection([*ML_FEATURE_COLUMNS, col], require_complete=False)


def test_compute_chronological_split_every_record_assigned_once():
    df = make_synthetic_df(n_rows=100, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(
        purge_gap_milliseconds=50_000, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15
    )
    result = compute_chronological_split(df, config=config)

    parts = result["partitions"]
    train_idx = parts[PARTITION_TRAIN]["indices"]
    p1_idx = parts[PARTITION_PURGED_TRAIN_VAL]["indices"]
    val_idx = parts[PARTITION_VALIDATION]["indices"]
    p2_idx = parts[PARTITION_PURGED_VAL_TEST]["indices"]
    test_idx = parts[PARTITION_TEST]["indices"]

    all_idx = np.concatenate([train_idx, p1_idx, val_idx, p2_idx, test_idx])
    assert len(all_idx) == 100
    assert set(all_idx) == set(range(100))
    # Disjoint check
    for a, b in [(train_idx, val_idx), (val_idx, test_idx), (train_idx, test_idx)]:
        assert set(a).isdisjoint(set(b))


def test_compute_chronological_split_determinism():
    df = make_synthetic_df(n_rows=120)
    res1 = compute_chronological_split(df)
    res2 = compute_chronological_split(df)

    for p in [
        PARTITION_TRAIN,
        PARTITION_VALIDATION,
        PARTITION_TEST,
        PARTITION_PURGED_TRAIN_VAL,
        PARTITION_PURGED_VAL_TEST,
    ]:
        assert np.array_equal(res1["partitions"][p]["indices"], res2["partitions"][p]["indices"])


def test_purge_gap_enforces_temporal_separation():
    # 100 rows, each 10,000ms apart
    df = make_synthetic_df(n_rows=100, base_time=1_000_000, time_step=10_000)
    gap = 60_000
    config = SplitConfig(purge_gap_milliseconds=gap)
    result = compute_chronological_split(df, config=config)

    parts = result["partitions"]
    train_max = parts[PARTITION_TRAIN]["time_coverage"]["max_epoch_ms"]
    val_min = parts[PARTITION_VALIDATION]["time_coverage"]["min_epoch_ms"]
    val_max = parts[PARTITION_VALIDATION]["time_coverage"]["max_epoch_ms"]
    test_min = parts[PARTITION_TEST]["time_coverage"]["min_epoch_ms"]

    assert val_min - train_max >= gap
    assert test_min - val_max >= gap


def test_audit_split_leakage_passes_on_disjoint_partitions():
    df = make_synthetic_df(n_rows=100, base_time=1_000_000, time_step=50_000)
    config = SplitConfig(purge_gap_milliseconds=100_000)
    split_res = compute_chronological_split(df, config=config)
    audit = audit_split_leakage(df, split_res)

    assert audit["status"] == "PASS"
    assert len(audit["blocking_failures"]) == 0
    assert len(audit["temporal_boundary_violations"]) == 0

    for pair_audit in audit["pair_audits"].values():
        assert pair_audit["exact_full_row_overlap"]["distinct_fingerprints"] == 0
        assert pair_audit["source_feature_overlap"]["distinct_fingerprints"] == 0
        assert pair_audit["canonical_flow_group_overlap"]["distinct_groups"] == 0
        assert pair_audit["ml_feature_overlap"]["binary_label_conflicts"] == 0


def test_audit_split_leakage_detects_binary_label_conflict():
    df = make_synthetic_df(n_rows=50, base_time=1_000_000, time_step=10_000)
    # Force identical ML features across all rows
    for col in ML_FEATURE_COLUMNS:
        df[col] = 42

    # Give all train rows Label=0, and all test rows Label=1
    split_res = compute_chronological_split(df, config=SplitConfig(purge_gap_milliseconds=20_000))
    train_idx = split_res["partitions"][PARTITION_TRAIN]["indices"]
    test_idx = split_res["partitions"][PARTITION_TEST]["indices"]

    df.loc[train_idx, "Label"] = 0
    df.loc[test_idx, "Label"] = 1

    audit = audit_split_leakage(df, split_res)

    assert audit["status"] == "FAIL"
    assert any("binary label conflict" in f for f in audit["blocking_failures"])


def test_invalid_data_conditions_raise():
    # Missing FLOW_START_MILLISECONDS
    with pytest.raises(ValueError, match="FLOW_START_MILLISECONDS"):
        compute_chronological_split(pd.DataFrame({"A": [1, 2]}))

    # Empty DataFrame
    with pytest.raises(ValueError, match="empty"):
        compute_chronological_split(pd.DataFrame({"FLOW_START_MILLISECONDS": []}))

    # Negative purge gap
    with pytest.raises(ValueError, match="negative"):
        SplitConfig(purge_gap_milliseconds=-10).validate()

    # Invalid ratios
    with pytest.raises(ValueError, match="sum to 1.0"):
        SplitConfig(train_ratio=0.5, val_ratio=0.5, test_ratio=0.5).validate()

    # Null timestamps
    df_null = make_synthetic_df(n_rows=5)
    df_null.loc[0, "FLOW_START_MILLISECONDS"] = None
    with pytest.raises(ValueError, match="missing or null"):
        compute_chronological_split(df_null)


def test_manifest_schema_and_reproducible_saving():
    df = make_synthetic_df(n_rows=80, base_time=1_000_000, time_step=20_000)
    split_res = compute_chronological_split(df)
    audit = audit_split_leakage(df, split_res)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        indices_dir = tmp_path / "splits"
        indices_dir.mkdir(parents=True, exist_ok=True)

        # Write index files and compute real hashes
        real_hashes = {}
        for p_name, p_data in split_res["partitions"].items():
            idx_file = indices_dir / f"{p_name}_indices.csv.gz"
            import gzip

            with gzip.open(idx_file, "wt", encoding="utf-8") as f:
                f.write("source_row_index\n")
                for idx in p_data["indices"]:
                    f.write(f"{idx}\n")
            from network_anomaly.data.split import _sha256_file

            real_hashes[p_name] = _sha256_file(idx_file)

        manifest = generate_split_manifest(
            split_res,
            audit,
            "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
            real_hashes,
        )

        assert manifest["manifest_schema_version"] == 1
        assert manifest["total_source_rows"] == 80
        assert manifest["features"]["baseline_ml_features_count"] == 47
        assert manifest["features"]["baseline_ml_features_in_order"] == list(ML_FEATURE_COLUMNS)

        report_md = render_leakage_audit_report(manifest)
        written = save_split_artifacts(split_res, manifest, report_md, tmp_path)

        assert "split_manifest" in written
        assert written["split_manifest"].is_file()
        assert "train_indices" in written
        assert written["train_indices"].is_file()

        # Load back and verify SHA-256 pass
        indices = load_partition_indices(
            written["split_manifest"], tmp_path / "splits", PARTITION_TRAIN
        )
        assert len(indices) == len(split_res["partitions"][PARTITION_TRAIN]["indices"])
        assert np.array_equal(indices, split_res["partitions"][PARTITION_TRAIN]["indices"])


def test_real_dataset_split_manifest_and_audit():
    manifest_path = ROOT / "data" / "processed" / "nf_unsw_nb15_v3_split_manifest.json"
    if not manifest_path.is_file():
        pytest.skip("nf_unsw_nb15_v3_split_manifest.json absent; run split script first.")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["dataset_name"] == DATASET_NAME
    assert (
        manifest["dataset_sha256"]
        == "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    )
    assert manifest["total_source_rows"] == 2_365_424
    assert manifest["audit_summary"]["status"] == "PASS"
    assert manifest["audit_summary"]["exact_full_row_overlap"] == 0
    assert manifest["audit_summary"]["source_feature_overlap"] == 0
    assert manifest["audit_summary"]["canonical_flow_group_overlap"] == 0
    assert manifest["audit_summary"]["temporal_boundary_violations"] == 0
    assert manifest["audit_summary"]["binary_label_conflicts"] == 0

    parts = manifest["partitions"]
    assert parts[PARTITION_TRAIN]["row_count"] == 1_655_797
    assert parts[PARTITION_PURGED_TRAIN_VAL]["row_count"] == 9_443
    assert parts[PARTITION_VALIDATION]["row_count"] == 345_371
    assert parts[PARTITION_PURGED_VAL_TEST]["row_count"] == 8_860
    assert parts[PARTITION_TEST]["row_count"] == 345_953

    total_rows = sum(p["row_count"] for p in parts.values())
    assert total_rows == 2_365_424

    # Check attack representation
    for p_name in [PARTITION_TRAIN, PARTITION_VALIDATION, PARTITION_TEST]:
        attacks = parts[p_name]["attack_distribution"]
        assert len(attacks) == 10  # Benign + 9 attack categories
        assert attacks["Worms"] > 0
        assert attacks["Analysis"] > 0
        assert attacks["Backdoor"] > 0
        assert attacks["Shellcode"] > 0
