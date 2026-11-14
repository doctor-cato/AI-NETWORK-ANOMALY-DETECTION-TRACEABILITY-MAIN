"""Provenance, canonical index sampling, and anti-leakage tests for fetch_external_dataset (Issue #46, #58)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from scripts.fetch_external_dataset import (
    UNSW_CANONICAL_TRAIN_END,
    UNSW_TEST_LOCK_START,
    UNSW_VALIDATION_START,
    _compute_indices_sha256,
    extract_unsw_partition_sample,
    validate_slice_sampling_parameters,
    verify_unsw_sample_binding,
    verify_unsw_train_membership,
    verify_unsw_validation_membership,
)
from scripts.fetch_external_dataset import (
    main as fetch_main,
)


def _write_unsw_fixture(
    tmp_path: Path,
    *,
    train_rows: list[int],
    val_rows: list[int],
    test_rows: list[int],
    total_rows: int = 15,
) -> tuple[Path, Path, Path]:
    """Create a synthetic canonical UNSW source CSV, split manifest, and gzip partition indices."""
    indices_dir = tmp_path / "splits"
    indices_dir.mkdir(parents=True, exist_ok=True)
    source_csv = tmp_path / "NF-UNSW-NB15-v3.csv"
    lines = ["PROTOCOL,L7_PROTO,Label,Attack"]
    for idx in range(total_rows):
        label = 1 if idx % 3 == 0 else 0
        attack = "Exploits" if label == 1 else "Benign"
        lines.append(f"6,{idx + 10},{label},{attack}")
    source_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")
    dataset_sha256 = hashlib.sha256(source_csv.read_bytes()).hexdigest()

    partitions = {}
    for name, rows in (("train", train_rows), ("validation", val_rows), ("test", test_rows)):
        idx_path = indices_dir / f"{name}_indices.csv.gz"
        pd.DataFrame({"source_row_index": rows}).to_csv(idx_path, index=False, compression="gzip")
        partitions[name] = {
            "row_count": len(rows),
            "index_sha256": hashlib.sha256(idx_path.read_bytes()).hexdigest(),
        }

    split_manifest = tmp_path / "split_manifest.json"
    split_manifest.write_text(
        json.dumps(
            {
                "dataset_name": "NF-UNSW-NB15-v3",
                "dataset_sha256": dataset_sha256,
                "total_source_rows": total_rows,
                "partitions": partitions,
            }
        ),
        encoding="utf-8",
    )
    return source_csv, split_manifest, indices_dir


def test_non_contiguous_validation_extraction_and_companion_manifest(tmp_path: Path) -> None:
    """Index-aware extraction supports non-contiguous indices and emits full provenance."""
    # Non-contiguous Validation indices separated by gaps
    source_csv, split_manifest, indices_dir = _write_unsw_fixture(
        tmp_path,
        train_rows=[0, 2, 4, 6],
        val_rows=[1, 3, 7, 10, 13],
        test_rows=[11, 12, 14],
        total_rows=15,
    )
    out_csv = tmp_path / "out" / "NF-UNSW-NB15-v3-sample50k.csv"
    extract_unsw_partition_sample(
        output_path=out_csv,
        source_csv_path=source_csv,
        split_manifest_path=split_manifest,
        indices_dir=indices_dir,
        partition="validation",
        sample_rows=4,
        random_seed=42,
    )

    assert (
        verify_unsw_sample_binding(
            out_csv,
            split_manifest,
            indices_dir,
            expected_count=4,
            expected_partition="validation",
            source_csv_path=source_csv,
        )
        == 4
    )

    manifest = json.loads(
        out_csv.with_name(f"{out_csv.name}.manifest.json").read_text(encoding="utf-8")
    )
    identity = manifest["dataset_identity"]
    checksum = manifest["content_checksum"]
    provenance = manifest["provenance"]

    assert identity["feature_schema"] == list(ML_FEATURE_COLUMNS)
    assert checksum["partition"] == "validation"
    assert checksum["slice_type"] == "partition_indices"
    assert checksum["source_dataset_sha256"] == hashlib.sha256(source_csv.read_bytes()).hexdigest()
    assert (
        checksum["split_manifest_sha256"] == hashlib.sha256(split_manifest.read_bytes()).hexdigest()
    )
    assert checksum["sample_sha256"] == hashlib.sha256(out_csv.read_bytes()).hexdigest()
    selected = checksum["source_row_indices"]
    assert len(selected) == 4
    assert selected == sorted(selected)
    assert set(selected).issubset({1, 3, 7, 10, 13})
    assert checksum["selected_indices_sha256"] == _compute_indices_sha256(
        pd.Series(selected).to_numpy()
    )
    assert provenance["sampling_method"] == "deterministic_seeded_partition_sample"
    assert provenance["sampling_seed"] == 42

    # Preserves row ordering from canonical source rows
    sampled_df = pd.read_csv(out_csv)
    expected_l7 = [idx + 10 for idx in selected]
    assert sampled_df["L7_PROTO"].tolist() == expected_l7


def test_50k_validation_roundtrip_and_cli_partition_indices(tmp_path: Path) -> None:
    """Valid scaled non-contiguous 50k-equivalent Validation roundtrip passes extract + CLI verify."""
    total_rows = 500
    val_rows = list(range(100, 420, 2))  # 160 non-contiguous validation indices
    train_rows = list(range(0, 90))
    test_rows = list(range(430, 500))
    source_csv, split_manifest, indices_dir = _write_unsw_fixture(
        tmp_path,
        train_rows=train_rows,
        val_rows=val_rows,
        test_rows=test_rows,
        total_rows=total_rows,
    )
    out_dir = tmp_path / "cli_out"
    rc_extract = fetch_main(
        [
            "--dataset",
            "NF-UNSW-NB15-v3",
            "--sample-rows",
            "100",
            "--source-csv",
            str(source_csv),
            "--split-manifest",
            str(split_manifest),
            "--indices-dir",
            str(indices_dir),
            "--output-dir",
            str(out_dir),
            "--random-seed",
            "7",
        ]
    )
    assert rc_extract == 0
    out_csv = out_dir / "NF-UNSW-NB15-v3-validation-sample50k.csv"
    assert len(pd.read_csv(out_csv)) == 100

    rc_verify = fetch_main(
        [
            "--dataset",
            "NF-UNSW-NB15-v3",
            "--verify-only",
            "--partition",
            "validation",
            "--source-csv",
            str(source_csv),
            "--split-manifest",
            str(split_manifest),
            "--indices-dir",
            str(indices_dir),
            "--output-dir",
            str(out_dir),
        ]
    )
    assert rc_verify == 0


def test_tampered_source_rows_and_manifest_sha256_fail_closed(tmp_path: Path) -> None:
    """Tampered rows, modified manifest SHAs, wrong selected_indices_sha256, and missing files fail."""
    source_csv, split_manifest, indices_dir = _write_unsw_fixture(
        tmp_path,
        train_rows=[0, 1, 2],
        val_rows=[5, 7, 9],
        test_rows=[11, 12, 13],
        total_rows=15,
    )
    out_csv = tmp_path / "val.csv"
    extract_unsw_partition_sample(
        output_path=out_csv,
        source_csv_path=source_csv,
        split_manifest_path=split_manifest,
        indices_dir=indices_dir,
        partition="validation",
        sample_rows=2,
    )
    manifest_path = out_csv.with_name(f"{out_csv.name}.manifest.json")
    orig_manifest = manifest_path.read_text(encoding="utf-8")
    orig_csv_bytes = out_csv.read_bytes()
    orig_csv = orig_csv_bytes.decode("utf-8")

    # 1. Tamper sample row content + recompute sample_sha256 -> caught by canonical source verification
    tampered_csv = orig_csv.replace("Benign", "Exploits", 1)
    if tampered_csv == orig_csv:
        tampered_csv = orig_csv.replace("Exploits", "Benign", 1)
    out_csv.write_bytes(tampered_csv.encode("utf-8"))
    man = json.loads(orig_manifest)
    man["content_checksum"]["sample_sha256"] = hashlib.sha256(out_csv.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(man), encoding="utf-8")
    with pytest.raises(ValueError, match="content mismatch vs canonical UNSW source CSV"):
        verify_unsw_sample_binding(out_csv, split_manifest, indices_dir, source_csv_path=source_csv)

    # Restore sample + manifest
    out_csv.write_bytes(orig_csv_bytes)
    manifest_path.write_text(orig_manifest, encoding="utf-8")

    # 2. Incorrect selected_indices_sha256
    bad_sel = json.loads(orig_manifest)
    bad_sel["content_checksum"]["selected_indices_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(bad_sel), encoding="utf-8")
    with pytest.raises(ValueError, match="selected_indices_sha256 mismatch"):
        verify_unsw_sample_binding(out_csv, split_manifest, indices_dir, source_csv_path=source_csv)

    # 3. Incorrect split_manifest_sha256
    bad_split = json.loads(orig_manifest)
    bad_split["content_checksum"]["split_manifest_sha256"] = "f" * 64
    manifest_path.write_text(json.dumps(bad_split), encoding="utf-8")
    with pytest.raises(ValueError, match="split_manifest_sha256"):
        verify_unsw_sample_binding(out_csv, split_manifest, indices_dir, source_csv_path=source_csv)

    # 4. Duplicate indices in sample manifest rejected
    dup_man = json.loads(orig_manifest)
    dup_man["content_checksum"]["source_row_indices"] = [5, 5]
    manifest_path.write_text(json.dumps(dup_man), encoding="utf-8")
    with pytest.raises(ValueError, match="strictly increasing and unique"):
        verify_unsw_sample_binding(out_csv, split_manifest, indices_dir, source_csv_path=source_csv)

    # 5. Tampered partition index_sha256 in split manifest rejected (even if manifest SHA updated)
    manifest_path.write_text(orig_manifest, encoding="utf-8")
    sp_data = json.loads(split_manifest.read_text(encoding="utf-8"))
    orig_split_text = split_manifest.read_text(encoding="utf-8")
    sp_data["partitions"]["validation"]["index_sha256"] = "a" * 64
    split_manifest.write_text(json.dumps(sp_data), encoding="utf-8")
    with pytest.raises(ValueError, match="split_manifest_sha256 does not match"):
        verify_unsw_sample_binding(out_csv, split_manifest, indices_dir, source_csv_path=source_csv)
    man_rebound = json.loads(orig_manifest)
    man_rebound["content_checksum"]["split_manifest_sha256"] = hashlib.sha256(
        split_manifest.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(man_rebound), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_unsw_sample_binding(out_csv, split_manifest, indices_dir, source_csv_path=source_csv)
    split_manifest.write_text(orig_split_text, encoding="utf-8")
    manifest_path.write_text(orig_manifest, encoding="utf-8")


def test_wrong_partition_overlap_bounds_and_test_leakage_fail_closed(tmp_path: Path) -> None:
    """Reject wrong partition membership, train/val/test overlap, out-of-bounds, and Test Lock."""
    source_csv, split_manifest, indices_dir = _write_unsw_fixture(
        tmp_path,
        train_rows=[0, 1, 2],
        val_rows=[5, 6, 7],
        test_rows=[11, 12, 13],
        total_rows=15,
    )
    out_csv = tmp_path / "val.csv"
    extract_unsw_partition_sample(
        output_path=out_csv,
        source_csv_path=source_csv,
        split_manifest_path=split_manifest,
        indices_dir=indices_dir,
        partition="validation",
        sample_rows=2,
    )

    # 1. Wrong expected partition (validation sample verified as train)
    with pytest.raises(ValueError, match="partition mismatch"):
        verify_unsw_sample_binding(
            out_csv,
            split_manifest,
            indices_dir,
            expected_partition="train",
            source_csv_path=source_csv,
        )

    # 2. Sample manifest claiming test index (Test leakage)
    manifest_path = out_csv.with_name(f"{out_csv.name}.manifest.json")
    man = json.loads(manifest_path.read_text(encoding="utf-8"))
    man["content_checksum"]["source_row_indices"] = [5, 11]
    man["content_checksum"]["selected_indices_sha256"] = _compute_indices_sha256(
        pd.Series([5, 11]).to_numpy()
    )
    manifest_path.write_text(json.dumps(man), encoding="utf-8")
    with pytest.raises(ValueError, match="overlaps verified Test"):
        verify_unsw_sample_binding(out_csv, split_manifest, indices_dir, source_csv_path=source_csv)

    # 3. Sample manifest claiming out-of-bounds index >= total_source_rows
    man["content_checksum"]["source_row_indices"] = [5, 999]
    man["content_checksum"]["selected_indices_sha256"] = _compute_indices_sha256(
        pd.Series([5, 999]).to_numpy()
    )
    manifest_path.write_text(json.dumps(man), encoding="utf-8")
    with pytest.raises(ValueError, match="out-of-bounds"):
        verify_unsw_sample_binding(out_csv, split_manifest, indices_dir, source_csv_path=source_csv)

    # 4. Canonical Train/Validation overlap in split indices must fail closed
    overlap_dir = tmp_path / "overlap_splits"
    src2, sp2, idx2 = _write_unsw_fixture(
        tmp_path / "sub",
        train_rows=[0, 1, 5],
        val_rows=[5, 6, 7],
        test_rows=[11, 12, 13],
        total_rows=15,
    )
    with pytest.raises(ValueError, match="Train and Validation split indices overlap"):
        verify_unsw_validation_membership(5, 2, sp2, idx2)
    assert overlap_dir  # unused var guard

    # 5. Missing Test indices fail closed (cannot silently skip Test leakage verification)
    sp3_data = json.loads(split_manifest.read_text(encoding="utf-8"))
    sp3_data["partitions"]["test"].pop("index_sha256")
    sp3 = tmp_path / "no_test_sha.json"
    sp3.write_text(json.dumps(sp3_data), encoding="utf-8")
    with pytest.raises(ValueError, match="index_sha256"):
        verify_unsw_train_membership(0, 2, sp3, indices_dir)

    # 6. Slice-mode chronological guardrails (anti-leakage & Test Lock + purge gap crossing)
    with pytest.raises(ValueError, match="(?i)chronological integrity violation"):
        validate_slice_sampling_parameters("NF-UNSW-NB15-v3", skip_rows=0, sample_rows=50000)
    assert UNSW_CANONICAL_TRAIN_END < UNSW_VALIDATION_START
    with pytest.raises(PermissionError, match="Test Lock Enforced"):
        validate_slice_sampling_parameters(
            "NF-UNSW-NB15-v3", skip_rows=UNSW_TEST_LOCK_START, sample_rows=1000
        )
    with pytest.raises(ValueError, match="crosses the purge gap"):
        validate_slice_sampling_parameters(
            "NF-UNSW-NB15-v3", skip_rows=UNSW_TEST_LOCK_START - 2, sample_rows=10
        )
