"""Dedicated v2 migration guardrails: v1 rejection, anti-leakage, split disjointness, and provenance."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.taxonomy import classify_raw_label
from network_anomaly.data.v2_schema import (
    FEATURE_CONTRACT_ID,
    ML_FEATURE_COLUMNS,
    PROVENANCE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.models.registry import ModelRegistry
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_active_package_has_no_v1_nf_unsw_module():
    """Active package must have completely removed network_anomaly.data.nf_unsw_nb15_v3."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("network_anomaly.data.nf_unsw_nb15_v3")


def test_taxonomy_never_coerces_background_or_unknown_to_benign():
    """Explicit unmapped / background / unknown tokens must NEVER coerce to Benign."""
    for raw in ("", "-", "(empty)", "background", "unknown", "unlabeled", "nan", "completely_new_attack"):
        res = classify_raw_label(raw)
        assert res.canonical_category == "Unmapped", f"{raw!r} coerced to {res.canonical_category}"
        assert res.binary_label is None, f"{raw!r} assigned binary label {res.binary_label}"
        assert res.label_status == "UNMAPPED"


def test_preprocessor_rejects_v1_47_feature_and_leakage_columns():
    """TrainOnlyPreprocessor must reject targets, identifiers, provenance, and 47-col v1 schemas."""
    rng = np.random.default_rng(7)
    base = pd.DataFrame(
        {col: rng.uniform(1.0, 50.0, size=10) for col in ML_FEATURE_COLUMNS}
    )
    for forbidden in TARGET_COLUMNS + TRACE_METADATA_COLUMNS + PROVENANCE_COLUMNS + ("Label", "Attack", "MIN_TTL"):
        bad = base.copy()
        bad[forbidden] = 1.0
        prep = TrainOnlyPreprocessor()
        with pytest.raises(ValueError):
            prep.fit(bad)


def test_model_registry_rejects_v1_contract_without_fallback(tmp_path: Path):
    """ModelRegistry fails closed if preprocessor or model manifest references v1 contract."""
    art_dir = tmp_path / "artifacts"
    man_dir = tmp_path / "reports" / "models"
    (art_dir / "preprocessing").mkdir(parents=True)
    man_dir.mkdir(parents=True)

    # Create dummy v2-named files whose manifests claim v1 NF-UNSW-NB15-v3
    prep_path = art_dir / "preprocessing" / "v2_flow_preprocessor.joblib"
    prep_man = tmp_path / "reports" / "preprocessing" / "v2_flow_preprocessing_manifest.json"
    prep_man.parent.mkdir(parents=True)
    prep_path.write_bytes(b"dummy")
    prep_man.write_text(
        json.dumps({"feature_contract_version": "nf-unsw-nb15-v3-baseline-47", "artifact_sha256": "0" * 64}),
        encoding="utf-8",
    )

    reg = ModelRegistry(
        artifacts_dir=art_dir,
        manifest_root=man_dir,
        preprocessor_path=prep_path,
        preprocessor_manifest_path=prep_man,
        warmup=False,
    )
    assert reg.all_ready is False
    assert reg.ready_count == 0


def test_v2_split_manifest_disjoint_and_ugr16_blocked():
    """Verify real v2 split disjointness and honest UGR16 BLOCKED provenance if manifests exist."""
    split_path = REPO_ROOT / "reports" / "splits" / "v2_split_manifest.json"
    prov_path = REPO_ROOT / "data" / "EXTERNAL_DATASETS_PROVENANCE.json"
    if split_path.is_file():
        sm = json.loads(split_path.read_text(encoding="utf-8"))
        assert sm["feature_contract_version"] == FEATURE_CONTRACT_ID
        train_sc = set(sm["partitions"]["train"]["scenarios"])
        val_sc = set(sm["partitions"]["validation"]["scenarios"])
        test_sc = set(sm["partitions"]["test"]["scenarios"])
        assert train_sc.isdisjoint(val_sc)
        assert train_sc.isdisjoint(test_sc)
        assert val_sc.isdisjoint(test_sc)
        assert sm["leakage_audit"]["scenario_overlap_count"] == 0
        assert sm["leakage_audit"]["scenario_5tuple_ts_overlap_count"] == 0
        assert sm["leakage_audit"]["status"] == "PASS"

    if prov_path.is_file():
        prov = json.loads(prov_path.read_text(encoding="utf-8"))
        assert prov["datasets"]["UGR16"]["status"] == "BLOCKED"
        assert prov["datasets"]["AIT-NDS-v2"]["doi"] == "10.5281/zenodo.13168643"
        assert prov["datasets"]["AIT-NDS-v2"]["derived_from"].startswith("AIT-LDS-v2.0")
