import json
import tempfile
import time
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
    EXPECTED_ARTIFACT_REL_PATHS,
    PARTITION_PURGED_TRAIN_VAL,
    PARTITION_PURGED_VAL_TEST,
    PARTITION_TEST,
    PARTITION_TRAIN,
    PARTITION_VALIDATION,
    SplitConfig,
    _sha256_file,
    audit_split_leakage,
    compare_artifact_inventories,
    compute_chronological_split,
    generate_split_manifest,
    load_partition_indices,
    render_leakage_audit_report,
    run_split_pipeline,
    save_split_artifacts,
    verify_artifact_reproducibility,
    verify_split_artifacts,
    write_deterministic_index_csv_gz,
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

        # Write index files with deterministic gzip and compute real hashes
        real_hashes = {}
        for p_name, p_data in split_res["partitions"].items():
            idx_file = indices_dir / f"{p_name}_indices.csv.gz"
            real_hashes[p_name] = write_deterministic_index_csv_gz(idx_file, p_data["indices"])

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
        assert manifest["audit_summary"]["ML_READY"] == "BLOCKED"
        assert manifest["interface_for_issue_8"]["ml_readiness"] == "BLOCKED"

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


def test_deterministic_gzip_indices_byte_identity():
    """Verify that writing partition indices twice produces identical SHA-256 byte hashes."""
    indices = np.array([0, 15, 42, 99, 1054, 999999], dtype=np.int64)

    with tempfile.TemporaryDirectory() as tmpdir:
        p1 = Path(tmpdir) / "run1" / "train_indices.csv.gz"
        p2 = Path(tmpdir) / "run2" / "train_indices.csv.gz"

        h1 = write_deterministic_index_csv_gz(p1, indices)
        time.sleep(0.05)  # Ensure system clock advances
        h2 = write_deterministic_index_csv_gz(p2, indices)

        assert h1 == h2
        assert _sha256_file(p1) == _sha256_file(p2)

        # Decompress and verify content
        df_read = pd.read_csv(p1, compression="gzip")
        assert list(df_read.columns) == ["source_row_index"]
        assert np.array_equal(df_read["source_row_index"].to_numpy(), indices)


def test_reproducibility_check_detects_file_byte_mismatch():
    """Verify that file comparison detects modified index files."""
    indices = np.arange(50, dtype=np.int64)

    with tempfile.TemporaryDirectory() as tmpdir:
        f1 = Path(tmpdir) / "pass1" / "test_indices.csv.gz"
        f2 = Path(tmpdir) / "pass2" / "test_indices.csv.gz"

        write_deterministic_index_csv_gz(f1, indices)
        # Pass 2 gets different indices
        write_deterministic_index_csv_gz(f2, np.arange(51, dtype=np.int64))

        h1 = _sha256_file(f1)
        h2 = _sha256_file(f2)
        assert h1 != h2


def test_split_manifest_and_audit_report_explains_ml_duplicates():
    """Verify that manifest and report clearly explain ML duplicates and methodology limits."""
    df = make_synthetic_df(n_rows=60, base_time=1_000_000, time_step=10_000)
    split_res = compute_chronological_split(df)
    audit = audit_split_leakage(df, split_res)
    manifest = generate_split_manifest(
        split_res,
        audit,
        dataset_sha256="4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
        partition_index_hashes={},
    )
    report_md = render_leakage_audit_report(manifest)

    # Distinguishes 4 concepts
    assert "Exact Full-Row Overlap" in report_md
    assert "Source-Feature Overlap" in report_md
    assert "Canonical Flow-Group Overlap" in report_md
    assert "ML-Feature Overlap" in report_md

    # Contains ML readiness gate
    assert "ML_READY: BLOCKED" in report_md
    assert manifest["audit_summary"]["ML_READY"] == "BLOCKED"
    assert manifest["interface_for_issue_8"]["ml_readiness"] == "BLOCKED"

    # Mentions methodology limitations
    assert "Giới hạn quan trọng của phương pháp đánh giá" in report_md
    assert "Tính độc lập của mẫu kiểm thử" in report_md
    assert "Nguy cơ sai lệch đánh giá (Evaluation vs Generalization)" in report_md


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


def test_expected_artifact_inventory_structure():
    """Verify that EXPECTED_ARTIFACT_REL_PATHS contains all 10 required artifacts."""
    assert len(EXPECTED_ARTIFACT_REL_PATHS) == 10
    expected = {
        "data/processed/splits/train_indices.csv.gz",
        "data/processed/splits/purged_train_val_gap_indices.csv.gz",
        "data/processed/splits/validation_indices.csv.gz",
        "data/processed/splits/purged_val_test_gap_indices.csv.gz",
        "data/processed/splits/test_indices.csv.gz",
        "data/processed/nf_unsw_nb15_v3_split_manifest.json",
        "data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json",
        "reports/splits/nf_unsw_nb15_v3_split_manifest.json",
        "reports/splits/nf_unsw_nb15_v3_leakage_audit_report.md",
        "docs/dataset/NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md",
    }
    assert set(EXPECTED_ARTIFACT_REL_PATHS) == expected


def test_verify_artifact_reproducibility_full_inventory_success():
    """Verify that dual-pass reproducibility succeeds across all 10 artifacts on synthetic data."""
    df = make_synthetic_df(n_rows=60, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    fake_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"

    comp = verify_artifact_reproducibility(df, config=config, dataset_digest=fake_sha)
    assert comp["status"] == "PASS"
    assert comp["total_checked"] == 10
    assert len(comp["matches"]) == 10
    assert len(comp["mismatches"]) == 0
    assert set(comp["matches"].keys()) == set(EXPECTED_ARTIFACT_REL_PATHS)


def test_compare_artifact_inventories_detects_changed_markdown_reports():
    """Verify that a modified Markdown report causes reproducibility verification to fail."""
    df = make_synthetic_df(n_rows=40, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    fake_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    fixed_ts = "2026-10-27T00:00:00+00:00"

    with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
        dir1, dir2 = Path(t1), Path(t2)
        run_split_pipeline(df, config, fake_sha, dir1, generated_at_utc=fixed_ts)
        run_split_pipeline(df, config, fake_sha, dir2, generated_at_utc=fixed_ts)

        # Baseline comparison passes
        assert compare_artifact_inventories(dir1, dir2)["status"] == "PASS"

        # Tamper reports/splits markdown report
        rep_file = dir2 / "reports" / "splits" / "nf_unsw_nb15_v3_leakage_audit_report.md"
        rep_file.write_text("tampered content", encoding="utf-8")

        res = compare_artifact_inventories(dir1, dir2)
        assert res["status"] == "FAIL"
        assert any(
            "reports/splits/nf_unsw_nb15_v3_leakage_audit_report.md" in m for m in res["mismatches"]
        )

        # Restore and tamper docs/dataset markdown report
        run_split_pipeline(df, config, fake_sha, dir2, generated_at_utc=fixed_ts)
        docs_file = dir2 / "docs" / "dataset" / "NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md"
        docs_file.write_text("tampered content", encoding="utf-8")

        res2 = compare_artifact_inventories(dir1, dir2)
        assert res2["status"] == "FAIL"
        assert any("docs/dataset/NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md" in m for m in res2["mismatches"])


def test_compare_artifact_inventories_detects_changed_manifests():
    """Verify that modified secondary or root manifests cause reproducibility check to fail."""
    df = make_synthetic_df(n_rows=40, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    fake_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    fixed_ts = "2026-10-27T00:00:00+00:00"

    with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
        dir1, dir2 = Path(t1), Path(t2)
        run_split_pipeline(df, config, fake_sha, dir1, generated_at_utc=fixed_ts)
        run_split_pipeline(df, config, fake_sha, dir2, generated_at_utc=fixed_ts)

        # Tamper secondary manifest
        sec_man = dir2 / "reports" / "splits" / "nf_unsw_nb15_v3_split_manifest.json"
        sec_man.write_text('{"tampered": true}', encoding="utf-8")
        res = compare_artifact_inventories(dir1, dir2)
        assert res["status"] == "FAIL"
        assert any(
            "reports/splits/nf_unsw_nb15_v3_split_manifest.json" in m for m in res["mismatches"]
        )

        # Tamper root manifest
        run_split_pipeline(df, config, fake_sha, dir2, generated_at_utc=fixed_ts)
        root_man = dir2 / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json"
        root_man.write_text('{"tampered": true}', encoding="utf-8")
        res2 = compare_artifact_inventories(dir1, dir2)
        assert res2["status"] == "FAIL"
        assert any("data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json" in m for m in res2["mismatches"])


def test_compare_artifact_inventories_detects_changed_compressed_index():
    """Verify that a modified compressed index file causes reproducibility check to fail."""
    df = make_synthetic_df(n_rows=40, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    fake_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    fixed_ts = "2026-10-27T00:00:00+00:00"

    with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
        dir1, dir2 = Path(t1), Path(t2)
        run_split_pipeline(df, config, fake_sha, dir1, generated_at_utc=fixed_ts)
        run_split_pipeline(df, config, fake_sha, dir2, generated_at_utc=fixed_ts)

        idx_file = dir2 / "data" / "processed" / "splits" / "train_indices.csv.gz"
        write_deterministic_index_csv_gz(idx_file, np.array([999, 1000], dtype=np.int64))

        res = compare_artifact_inventories(dir1, dir2)
        assert res["status"] == "FAIL"
        assert any("train_indices.csv.gz" in m for m in res["mismatches"])


def test_compare_artifact_inventories_detects_missing_file():
    """Verify that a missing expected artifact triggers a clear mismatch error."""
    df = make_synthetic_df(n_rows=40, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    fake_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"
    fixed_ts = "2026-10-27T00:00:00+00:00"

    with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
        dir1, dir2 = Path(t1), Path(t2)
        run_split_pipeline(df, config, fake_sha, dir1, generated_at_utc=fixed_ts)
        run_split_pipeline(df, config, fake_sha, dir2, generated_at_utc=fixed_ts)

        # Remove an artifact from pass 2
        missing_file = dir2 / "docs" / "dataset" / "NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md"
        missing_file.unlink()

        res = compare_artifact_inventories(dir1, dir2)
        assert res["status"] == "FAIL"
        assert any(
            "Pass 2 missing expected artifact: docs/dataset/NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md" in m
            for m in res["mismatches"]
        )


def test_reproducibility_contract_detects_variable_timestamps():
    """Verify variable timestamps cause manifest mismatches unless fixed timestamp is used."""
    df = make_synthetic_df(n_rows=40, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    fake_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"

    with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
        dir1, dir2 = Path(t1), Path(t2)
        run_split_pipeline(df, config, fake_sha, dir1, generated_at_utc="2026-10-27T00:00:00+00:00")
        run_split_pipeline(df, config, fake_sha, dir2, generated_at_utc="2026-10-27T00:00:01+00:00")

        res = compare_artifact_inventories(dir1, dir2)
        assert res["status"] == "FAIL"
        assert any("split_manifest.json" in m for m in res["mismatches"])


def test_audit_split_leakage_detects_flow_end_boundary_crossing():
    """Verify that a flow extending into a later partition's time window triggers a failure."""
    df = make_synthetic_df(n_rows=50, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    split_res = compute_chronological_split(df, config=config)

    # Force a Train flow to have FLOW_END extending into Validation start time
    val_min_start = split_res["partitions"][PARTITION_VALIDATION]["time_coverage"]["min_epoch_ms"]
    train_indices = split_res["partitions"][PARTITION_TRAIN]["indices"]
    df.loc[train_indices[0], "FLOW_END_MILLISECONDS"] = val_min_start + 5_000

    audit_res = audit_split_leakage(df, split_res)
    assert audit_res["status"] == "FAIL"
    assert audit_res["flow_end_crossings"]["train_into_validation"] == 1
    assert any("Temporal boundary violation" in f for f in audit_res["blocking_failures"])


def test_verify_split_artifacts_valid_inventory():
    """Verify that verify_split_artifacts passes on a cleanly generated artifact inventory."""
    df = make_synthetic_df(n_rows=40, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    fake_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        run_split_pipeline(
            df, config, fake_sha, tmp_dir, generated_at_utc="2026-10-27T00:00:00+00:00"
        )
        manifest_path = tmp_dir / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json"

        res = verify_split_artifacts(manifest_path, root_dir=tmp_dir)
        assert res["status"] == "PASS"
        assert len(res["errors"]) == 0
        assert res["total_artifacts_checked"] == 10


def test_verify_split_artifacts_detects_missing_file():
    """Verify that verify_split_artifacts fails when an expected artifact is absent."""
    df = make_synthetic_df(n_rows=40, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    fake_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        run_split_pipeline(
            df, config, fake_sha, tmp_dir, generated_at_utc="2026-10-27T00:00:00+00:00"
        )
        manifest_path = tmp_dir / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json"

        # Remove an index archive
        (tmp_dir / "data" / "processed" / "splits" / "test_indices.csv.gz").unlink()

        res = verify_split_artifacts(manifest_path, root_dir=tmp_dir)
        assert res["status"] == "FAIL"
        assert any(
            "Missing expected artifact: data/processed/splits/test_indices.csv.gz" in e
            for e in res["errors"]
        )


def test_verify_split_artifacts_detects_altered_index_hash():
    """Verify that verify_split_artifacts fails when an index file hash differs from manifest."""
    df = make_synthetic_df(n_rows=40, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    fake_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        run_split_pipeline(
            df, config, fake_sha, tmp_dir, generated_at_utc="2026-10-27T00:00:00+00:00"
        )
        manifest_path = tmp_dir / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json"

        # Modify index file
        idx_path = tmp_dir / "data" / "processed" / "splits" / "train_indices.csv.gz"
        write_deterministic_index_csv_gz(idx_path, np.array([1, 2, 3], dtype=np.int64))

        res = verify_split_artifacts(manifest_path, root_dir=tmp_dir)
        assert res["status"] == "FAIL"
        assert any("SHA-256 mismatch for train_indices.csv.gz" in e for e in res["errors"])


def test_verify_split_artifacts_detects_secondary_manifest_mismatch():
    """Verify that verify_split_artifacts fails when a secondary manifest is tampered with."""
    df = make_synthetic_df(n_rows=40, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    fake_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        run_split_pipeline(
            df, config, fake_sha, tmp_dir, generated_at_utc="2026-10-27T00:00:00+00:00"
        )
        manifest_path = tmp_dir / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json"

        sec_manifest_path = tmp_dir / "reports" / "splits" / "nf_unsw_nb15_v3_split_manifest.json"
        sec_manifest = json.loads(sec_manifest_path.read_text(encoding="utf-8"))
        sec_manifest["total_source_rows"] = 999999
        sec_manifest_path.write_text(json.dumps(sec_manifest), encoding="utf-8")

        res = verify_split_artifacts(manifest_path, root_dir=tmp_dir)
        assert res["status"] == "FAIL"
        assert any("Content mismatch between primary manifest" in e for e in res["errors"])


def test_verify_only_cli_execution_does_not_modify_files():
    """Verify that running --verify-only does not change any byte hashes of on-disk artifacts."""
    import subprocess
    import sys

    df = make_synthetic_df(n_rows=40, base_time=1_000_000, time_step=10_000)
    config = SplitConfig(purge_gap_milliseconds=20_000)
    fake_sha = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"

    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        run_split_pipeline(
            df, config, fake_sha, tmp_dir, generated_at_utc="2026-10-27T00:00:00+00:00"
        )
        manifest_path = tmp_dir / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json"
        output_dir = tmp_dir / "data" / "processed"

        # Record hashes of generated artifacts
        initial_hashes = {}
        for rel in EXPECTED_ARTIFACT_REL_PATHS:
            f = tmp_dir / rel
            assert f.is_file()
            initial_hashes[rel] = _sha256_file(f)

        cmd = [
            sys.executable,
            str(ROOT / "scripts" / "split_and_audit_nf_unsw_nb15_v3.py"),
            "--verify-only",
            "--root-manifest",
            str(manifest_path),
            "--output-dir",
            str(output_dir),
        ]
        proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
        assert proc.returncode == 0, f"CLI verify-only failed: {proc.stderr}\n{proc.stdout}"
        assert "PASS: All 10 split artifacts successfully verified on disk" in proc.stdout

        # Verify every hash is untouched
        for rel, orig_sha in initial_hashes.items():
            assert (
                _sha256_file(tmp_dir / rel) == orig_sha
            ), f"Artifact was modified by --verify-only: {rel}"

    # If the real processed split manifest and indices exist locally, test repo-level CLI too
    repo_manifest = ROOT / "data" / "processed" / "nf_unsw_nb15_v3_split_manifest.json"
    repo_idx = ROOT / "data" / "processed" / "splits" / "train_indices.csv.gz"
    if repo_manifest.is_file() and repo_idx.is_file():
        cmd_repo = [
            sys.executable,
            str(ROOT / "scripts" / "split_and_audit_nf_unsw_nb15_v3.py"),
            "--verify-only",
        ]
        proc_repo = subprocess.run(cmd_repo, cwd=str(ROOT), capture_output=True, text=True)
        assert proc_repo.returncode == 0
