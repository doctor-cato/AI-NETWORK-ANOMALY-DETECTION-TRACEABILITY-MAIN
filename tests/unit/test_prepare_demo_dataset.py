"""Unit tests for scripts/prepare_demo_dataset.py (v2 Validation demo CSV contract)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS_DIR = _PROJECT_ROOT / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from prepare_demo_dataset import prepare_demo_dataset  # noqa: E402

from network_anomaly.data.split import _sha256_file  # noqa: E402
from network_anomaly.data.v2_schema import (  # noqa: E402
    ALL_CANONICAL_COLUMNS,
    FEATURE_CONTRACT_ID,
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    compute_flow_features_from_base,
)


def _build_synthetic_val_fixture(tmp_path: Path) -> tuple[Path, Path]:
    rng = np.random.default_rng(42)
    rows = []
    for i in range(260):
        feats = compute_flow_features_from_base(
            duration_ms=float(rng.uniform(5.0, 500.0)),
            bytes_in=float(rng.integers(60, 5000)),
            bytes_out=float(rng.integers(0, 8000)),
            pkts_in=float(rng.integers(1, 30)),
            pkts_out=float(rng.integers(0, 30)),
            protocol_num=6 if i % 3 else 17,
        )
        is_att = i % 2
        row = {
            "timestamp_ms": 1_642_204_800_000 + i * 1000,
            "source_ip": f"10.0.0.{(i % 20) + 1}",
            "source_port": 40000 + i,
            "dest_ip": f"172.16.0.{(i % 5) + 1}",
            "dest_port": 80 if is_att else 443,
            "source_dataset": "AIT-NDS-v2",
            "scenario_or_device": "russellmitchell",
            "flow_id": f"rm:tcp:{i}",
            "raw_protocol_str": "TCP",
            "probe_source": "tstat:tcp_complete",
            **feats,
            "label_binary": is_att,
            "attack_category": "Reconnaissance" if is_att else "Benign",
            "raw_label": "service_scan" if is_att else "http",
            "label_status": "MAPPED_ATTACK" if is_att else "MAPPED_BENIGN",
        }
        rows.append(row)

    df = pd.DataFrame(rows, columns=list(ALL_CANONICAL_COLUMNS))
    val_csv = tmp_path / "ait_val.csv.gz"
    df.to_csv(val_csv, index=False, compression="gzip")

    split_manifest = tmp_path / "v2_split_manifest.json"
    split_manifest.write_text(
        json.dumps({"dataset_sha256": "a" * 64, "split_protocol_version": "v2-scenario-group-purged-v1"}),
        encoding="utf-8",
    )
    return val_csv, split_manifest


def test_prepare_demo_dataset_validation_only_and_no_target_leakage(tmp_path: Path):
    val_csv, split_manifest = _build_synthetic_val_fixture(tmp_path)
    out_dir = tmp_path / "demo"
    manifest = prepare_demo_dataset(
        val_csv_path=val_csv,
        split_manifest_path=split_manifest,
        output_dir=out_dir,
        num_rows=100,
    )

    flows_csv = out_dir / "demo_flows.csv"
    labels_csv = out_dir / "demo_labels.csv"
    assert flows_csv.is_file()
    assert labels_csv.is_file()

    df_flows = pd.read_csv(flows_csv)
    df_labels = pd.read_csv(labels_csv)
    assert len(df_flows) == 100
    assert len(df_labels) == 100
    for tgt in TARGET_COLUMNS:
        assert tgt not in df_flows.columns
    for feat in ML_FEATURE_COLUMNS:
        assert feat in df_flows.columns

    assert manifest["feature_contract_version"] == FEATURE_CONTRACT_ID
    assert manifest["sampling"]["partition"] == "validation"
    assert manifest["sampling"]["train_overlap_count"] == 0
    assert manifest["sampling"]["test_overlap_count"] == 0
    assert manifest["outputs"]["demo_flows_csv"]["sha256"] == _sha256_file(flows_csv)
