"""Regression tests for PR #50 acceptance-criteria remediations (#12, #54, #59)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd
import pytest

from network_anomaly.api.db import DatabaseManager
from network_anomaly.api.schemas import HealthResponse
from network_anomaly.api.service import ApiService
from network_anomaly.config import PROJECT_ROOT
from network_anomaly.evaluation.evidence_recovery import render_report


def test_evidence_recovery_renders_rf_vs_if_comparison_and_artifacts():
    """Verify Issue #12 AC3 model comparison is present in reconciled evaluation outputs."""
    summary_path = (
        PROJECT_ROOT / "reports" / "evaluation" / "rf-heldout-ea330b9" / "verified_summary.json"
    )
    report_path = PROJECT_ROOT / "reports" / "evaluation" / "error_analysis_report.md"
    heldout_report_path = (
        PROJECT_ROOT / "reports" / "evaluation" / "rf-heldout-ea330b9" / "error_analysis.md"
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert "model_comparison" in summary
    models = summary["model_comparison"]["models"]
    assert models["random_forest"]["held_out_test_status"] == "EXPERIMENTALLY VALIDATED"
    assert models["isolation_forest"]["held_out_test_status"] == "NOT EVALUATED"
    assert models["isolation_forest"]["blocks_random_forest_acceptance"] is False

    rendered = render_report(summary)
    assert "## Model comparison: Random Forest vs Isolation Forest" in rendered
    assert "Random Forest Baseline" in rendered
    assert "Isolation Forest" in rendered
    assert "NOT EVALUATED" in rendered

    for md_path in (report_path, heldout_report_path):
        text = md_path.read_text(encoding="utf-8")
        assert "## Model comparison: Random Forest vs Isolation Forest" in text


def test_no_pytest_temp_isolation_forest_manifest_tracked():
    """Verify Issue #54 polluted pytest temp manifest is absent from reports/models/."""
    if_manifest = PROJECT_ROOT / "reports" / "models" / "isolation_forest_manifest.json"
    assert (
        not if_manifest.exists()
    ), "reports/models/isolation_forest_manifest.json must not point to pytest temp artifacts"


def test_api_analyze_emits_probabilities_and_scores_per_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Verify Issue #59 AC1 batch anomaly_scores and class probabilities behavior."""
    db = DatabaseManager(tmp_path / "test_api_probs.db")
    service = ApiService(db)

    monkeypatch.setattr(
        service,
        "check_health",
        lambda: HealthResponse(
            status="healthy",
            process_alive=True,
            model_ready=True,
            preprocessor_ready=True,
            db_ready=True,
            version="0.1.0",
            git_commit="abc123",
            timestamp="2026-11-14T00:00:00Z",
            details={},
        ),
    )

    mock_rf = MagicMock()
    mock_rf.model_metadata = {"model_artifact_sha256": "a" * 64}
    mock_rf.preprocessor_metadata = {"artifact_sha256": "b" * 64}
    mock_rf.predict.return_value = pd.DataFrame(
        {
            "prediction": [0, 1],
            "probability_0": [0.91, 0.14],
            "probability_1": [0.09, 0.86],
            "run_id": ["run_prob_01", "run_prob_01"],
        }
    )
    monkeypatch.setattr(service, "_load_inference_pipeline", lambda _: mock_rf)

    res = service.analyze_flows(
        [{"features": {"IN_BYTES": 100}}, {"features": {"IN_BYTES": 9000}}],
        model_name="random_forest",
    )
    assert res.anomaly_scores == [0.09, 0.86]
    assert res.probabilities == [
        {"Benign": 0.91, "Attack": 0.09},
        {"Benign": 0.14, "Attack": 0.86},
    ]
    assert res.results[0].probabilities == {"Benign": 0.91, "Attack": 0.09}

    # Unsupervised model without class probability columns omits probabilities cleanly
    mock_if = MagicMock()
    mock_if.model_metadata = {"model_artifact_sha256": "c" * 64}
    mock_if.preprocessor_metadata = {"artifact_sha256": "b" * 64}
    mock_if.predict.return_value = pd.DataFrame(
        {"prediction": [0, 1], "anomaly_score": [0.22, 0.78]}
    )
    monkeypatch.setattr(service, "_load_inference_pipeline", lambda _: mock_if)

    res_if = service.analyze_flows(
        [{"features": {"IN_BYTES": 100}}, {"features": {"IN_BYTES": 9000}}],
        model_name="isolation_forest",
    )
    assert res_if.anomaly_scores == [0.22, 0.78]
    assert res_if.probabilities is None
    assert res_if.results[0].probabilities is None
