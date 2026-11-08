"""Unit tests for the Train/Validation-only RF diagnostic audit helpers."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import numpy as np
import pandas as pd

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "audit_rf_validation_diagnostics.py"
spec = importlib.util.spec_from_file_location("audit_rf_validation_diagnostics", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_binary_metrics_label_order_and_fpr_definition():
    y = np.array([0, 0, 0, 0, 1, 1, 1])
    pred = np.array([0, 0, 0, 1, 1, 1, 0])
    m = module.binary_metrics(y, pred)
    assert (m["tn"], m["fp"], m["fn"], m["tp"]) == (3, 1, 1, 2)
    assert m["fpr"] == 1 / 4
    assert m["recall"] == 2 / 3
    assert m["precision"] == 2 / 3
    assert m["accuracy"] == 5 / 7


def test_binary_metrics_handles_single_class_subset_without_error():
    y = np.array([0, 0, 0])
    m = module.binary_metrics(y, np.array([0, 0, 1]), np.array([0.1, 0.2, 0.9]))
    assert (m["tn"], m["fp"], m["fn"], m["tp"]) == (2, 1, 0, 0)
    assert m["recall"] is None
    assert "auc" not in m


def test_binary_metrics_empty_subset():
    assert module.binary_metrics(np.array([], dtype=int), np.array([], dtype=int)) == {"n": 0}


def test_taxonomy_summary_distinguishes_models_and_leakage_hypotheses():
    summary = module.build_taxonomy_summary()
    models = summary["canonical_vs_diagnostic_models"]
    assert models["canonical_baseline"]["is_canonical_baseline"] is True
    assert models["canonical_baseline"]["n_estimators"] == 200
    assert models["diagnostic_rf_c0_to_c7"]["is_canonical_baseline"] is False
    assert models["diagnostic_rf_c0_to_c7"]["n_estimators"] == 60
    assert models["diagnostic_single_trees_c8_c9_and_univariate"]["is_canonical_baseline"] is False
    assert models["diagnostic_single_trees_c8_c9_and_univariate"]["n_estimators"] == 1

    hyp = summary["hypothesis_separation"]
    assert set(hyp.keys()) == {
        "1_code_and_pipeline_leakage",
        "2_fingerprint_memorisation",
        "3_dataset_specific_shortcuts",
    }
    limitation = hyp["1_code_and_pipeline_leakage"]["label_shuffle_control_limitation"]
    assert "does NOT prove" in limitation


def test_diagnostic_retrains_c0_to_c9_structure_on_synthetic_data():
    rng = np.random.RandomState(42)
    cols = list(ML_FEATURE_COLUMNS)
    x_tr = pd.DataFrame(rng.normal(size=(40, 47)), columns=cols)
    x_va = pd.DataFrame(rng.normal(size=(20, 47)), columns=cols)
    y_tr = np.array([0] * 25 + [1] * 15, dtype=int)
    y_va = np.array([0] * 12 + [1] * 8, dtype=int)
    h_tr = np.arange(40, dtype=np.uint64)
    h_va = np.array(list(range(10)) + list(range(100, 110)), dtype=np.uint64)
    overlap = np.isin(h_va, h_tr)
    out = {}
    module.diagnostic_retrains(x_tr, x_va, y_tr, y_va, h_tr, h_va, overlap, cols[:15], out)
    retrains = out["diagnostic_retrains"]
    expected_keys = {
        "C0_all_features",
        "C1_drop_MIN_TTL_MAX_TTL",
        "C2_drop_top3_impurity",
        "C3_drop_top5_impurity",
        "C4_drop_TCP_windows",
        "C5_drop_top10_impurity",
        "C6_train_without_validation_fingerprints",
        "C7_label_shuffle_control",
        "C8_single_tree_depth3",
        "C9_single_tree_depth8",
    }
    assert expected_keys.issubset(retrains.keys())
    for key in expected_keys:
        entry = retrains[key]
        assert entry["is_canonical_baseline"] is False
        if key in ("C8_single_tree_depth3", "C9_single_tree_depth8"):
            assert entry["estimator_type"] == "DecisionTreeClassifier"
            assert entry["n_estimators"] == 1
        else:
            assert entry["estimator_type"] == "RandomForestClassifier"
            assert entry["n_estimators"] == 60
    assert retrains["C6_train_without_validation_fingerprints"]["n_train_rows"] == 30
    assert retrains["C7_label_shuffle_control"]["diagnostic_category"] == (
        "harness_sanity_control_not_full_leakage_proof"
    )


def test_audit_never_references_test_index_file():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "test_indices" not in source


def test_committed_validation_audit_json_and_report_consistency():
    manifest_path = REPO_ROOT / "reports" / "models" / "random_forest_manifest.json"
    audit_path = REPO_ROOT / "reports" / "models" / "rf_baseline_validation_audit.json"
    report_path = REPO_ROOT / "reports" / "models" / "rf_baseline_training_report.md"

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    report = report_path.read_text(encoding="utf-8")

    assert audit["model_artifact"]["sha256"] == manifest["model_artifact_sha256"]
    assert audit["validation_confusion_matrix_equals_manifest"] is True
    assert audit["probability_aggregation_determinism"]["manifest_max_abs_probability_diff"] == (
        manifest["reload_verification"]["max_abs_probability_diff"]
    )
    assert "2.220446049250313e-16" in report
    assert "0.0000000000e+00" not in report
    assert "không dùng `C7` để tuyên bố đã chứng minh hoàn toàn không có data leakage" in report
    c_keys = [k for k in audit["diagnostic_retrains"] if k.startswith("C")]
    assert len(c_keys) == 10
    for key in c_keys:
        assert audit["diagnostic_retrains"][key]["is_canonical_baseline"] is False
