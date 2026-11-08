"""Integration tests for Cross-Dataset Generalization evaluation pipeline (Issue #46)."""

import json
from pathlib import Path

import pytest

from network_anomaly.config import ARTIFACTS, PROJECT_ROOT
from scripts.evaluate_cross_dataset import (
    DEFAULT_DATASET_CSV,
    DEFAULT_MODEL_ARTIFACT,
    DEFAULT_MODEL_MANIFEST,
    DEFAULT_PREP_ARTIFACT,
    DEFAULT_PREP_MANIFEST,
    evaluate_cross_dataset,
    generate_markdown_report,
)


def test_cross_dataset_evaluation_runs_and_produces_valid_metrics(tmp_path: Path):
    """Test full cross-dataset evaluation execution and output schema."""
    if not DEFAULT_DATASET_CSV.exists():
        pytest.skip("External dataset sample not downloaded yet.")

    out_json = tmp_path / "test_eval_results.json"
    out_md = tmp_path / "test_eval_report.md"

    results = evaluate_cross_dataset(
        dataset_csv=DEFAULT_DATASET_CSV,
        model_artifact=DEFAULT_MODEL_ARTIFACT,
        model_manifest=DEFAULT_MODEL_MANIFEST,
        preprocessor_artifact=DEFAULT_PREP_ARTIFACT,
        preprocessor_manifest=DEFAULT_PREP_MANIFEST,
        batch_size=20000,
    )

    # 1. Metric presence and bounds
    m = results["metrics"]
    assert 0.0 <= m["accuracy"] <= 1.0
    assert 0.0 <= m["precision"] <= 1.0
    assert 0.0 <= m["recall"] <= 1.0
    assert 0.0 <= m["f1"] <= 1.0
    assert 0.0 <= m["macro_f1"] <= 1.0
    assert 0.0 <= m["false_positive_rate"] <= 1.0

    # 2. Confusion matrix integrity
    cm = m["confusion_matrix"]
    assert cm["tn"] + cm["fp"] + cm["fn"] + cm["tp"] == results["rows_evaluated"]
    assert results["rows_evaluated"] == 100000

    # 3. Report generation
    generate_markdown_report(results, out_md)
    assert out_md.exists()
    assert out_md.stat().st_size > 500

    # 4. OOD shortcut shift verified
    assert results["ood_summary"]["total_shortcut_drift_rows"] > 0


def test_cross_dataset_evaluation_reproducibility():
    """Verify deterministic repeatability: Two independent runs produce identical metrics."""
    if not DEFAULT_DATASET_CSV.exists():
        pytest.skip("External dataset sample not downloaded yet.")

    run1 = evaluate_cross_dataset(
        dataset_csv=DEFAULT_DATASET_CSV,
        model_artifact=DEFAULT_MODEL_ARTIFACT,
        model_manifest=DEFAULT_MODEL_MANIFEST,
        preprocessor_artifact=DEFAULT_PREP_ARTIFACT,
        preprocessor_manifest=DEFAULT_PREP_MANIFEST,
        batch_size=50000,
    )

    run2 = evaluate_cross_dataset(
        dataset_csv=DEFAULT_DATASET_CSV,
        model_artifact=DEFAULT_MODEL_ARTIFACT,
        model_manifest=DEFAULT_MODEL_MANIFEST,
        preprocessor_artifact=DEFAULT_PREP_ARTIFACT,
        preprocessor_manifest=DEFAULT_PREP_MANIFEST,
        batch_size=50000,
    )

    # Metrics must match exactly
    assert run1["metrics"]["accuracy"] == run2["metrics"]["accuracy"]
    assert run1["metrics"]["precision"] == run2["metrics"]["precision"]
    assert run1["metrics"]["recall"] == run2["metrics"]["recall"]
    assert run1["metrics"]["f1"] == run2["metrics"]["f1"]
    assert run1["metrics"]["confusion_matrix"] == run2["metrics"]["confusion_matrix"]
