"""Regression tests for Random Forest Error Analysis (Issue #13, PR #50).

Covers:
  - Dynamic extraction of scientific metrics from audit JSON artifacts
  - Total absence of hardcoded static metrics in generated Markdown report
  - Accurate extraction of FP, FN, category ranking, and decision boundary analysis
  - Complete separation between Validation results and held-out Test set
  - CLI --verify-only invocation
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.evaluation.error_analysis import (
    CANONICAL_DECISION_THRESHOLD,
    analyze_classification_boundary,
    analyze_feature_error_patterns,
    compile_data_limitations_summary,
    compute_ranked_attack_category_errors,
    extract_fp_fn_samples,
    generate_error_analysis_report,
    main,
)


def _make_dummy_feature_df(n_samples: int = 20, seed: int = 42) -> pd.DataFrame:
    """Helper to create a valid 47-column DataFrame."""
    rng = np.random.default_rng(seed)
    data = {col: rng.uniform(0.0, 100.0, size=n_samples) for col in ML_FEATURE_COLUMNS}
    return pd.DataFrame(data, columns=list(ML_FEATURE_COLUMNS))


# ==============================================================================
# 1. DYNAMIC EVIDENCE-DRIVEN ERROR ANALYSIS TESTS
# ==============================================================================


def test_compile_data_limitations_summary_dynamic_from_artifacts() -> None:
    """Verify compile_data_limitations_summary extracts dynamic metrics from artifacts."""
    summary = compile_data_limitations_summary()

    # Partitions
    parts = summary["partitions"]
    assert parts["train_rows"] == 1_655_797
    assert parts["validation_rows"] == 345_371
    assert parts["test_rows"] == 345_953
    assert parts["total_source_rows"] == 2_365_424

    # Feature overlap
    overlap = summary["feature_overlap_ambiguity"]
    assert overlap["test_affected_rows"] == 184_067
    assert pytest.approx(overlap["test_overlap_fraction"] * 100.0, abs=0.01) == 53.21

    # Validation reference
    val_ref = summary["validation_reference"]
    assert val_ref["fp"] == 5
    assert val_ref["fn"] == 3
    assert pytest.approx(val_ref["accuracy"], abs=1e-5) == 0.999977
    assert pytest.approx(val_ref["f1"], abs=1e-5) == 0.999869

    # Test attack distribution top categories
    test_att = summary["rare_attack_classes"]["test_attack_distribution"]
    assert test_att["Exploits"] == 10_520
    assert test_att["Fuzzers"] == 7_322
    assert test_att["Generic"] == 5_111


def test_generate_error_analysis_report_contains_no_hardcoded_stale_metrics(tmp_path: Path) -> None:
    """Verify generated error_analysis_report contains zero stale hardcoded metrics."""
    out_rep = tmp_path / "test_report.md"
    generate_error_analysis_report(output_path=out_rep)

    content = out_rep.read_text(encoding="utf-8")

    # Stale hardcoded values MUST NOT exist
    stale_forbidden = [
        "1,654,162",
        "365,608",
        "622 FP",
        "622` FP",
        "172 FN",
        "172` FN",
        "184,087",
        "12,869",
    ]
    for stale in stale_forbidden:
        assert stale not in content, f"Found forbidden stale metric '{stale}' in generated report!"

    # Canonical evidence-driven metrics MUST exist
    expected_canonical = [
        "1,655,797",  # Train rows
        "345,371",  # Validation rows
        "`5` FP",  # Canonical Validation FP
        "FN `3`",  # Canonical Validation FN
        "0.999977",  # Validation accuracy
        "0.999869",  # Validation F1
        "184,067",  # Canonical feature overlap
        "53.21%",  # Overlap percent
        "10,520",  # Exploits in test
        "7,322",  # Fuzzers in test
        "5,111",  # Generic in test
        "BLOCKED / NOT VERIFIED",  # Test execution status without binary
    ]
    for expected in expected_canonical:
        assert (
            expected in content
        ), f"Missing expected canonical metric '{expected}' in generated report!"


# ==============================================================================
# 2. STATISTICAL EXTRACTION & CATEGORY ERROR RANKING TESTS
# ==============================================================================


def test_extract_fp_fn_samples_correctness() -> None:
    """Verify extract_fp_fn_samples extracts FP and FN samples and exemplars accurately."""
    X = _make_dummy_feature_df(6)
    y_true = [0, 0, 0, 1, 1, 1]
    y_pred = [0, 1, 0, 1, 0, 1]
    # Sample 1: y_true=0, y_pred=1 -> FP
    # Sample 4: y_true=1, y_pred=0 -> FN
    prob_attack = [0.1, 0.85, 0.2, 0.95, 0.15, 0.9]
    cats = ["Benign", "Benign", "Benign", "Exploits", "Worms", "Exploits"]
    row_idx = [100, 101, 102, 103, 104, 105]

    res = extract_fp_fn_samples(
        X=X,
        y_true=y_true,
        y_pred=y_pred,
        prob_attack=prob_attack,
        attack_categories=cats,
        row_indices=row_idx,
    )

    assert res["false_positives"]["count"] == 1
    assert res["false_positives"]["row_indices"] == [101]
    assert res["false_positives"]["exemplars"][0]["prob_attack"] == 0.85

    assert res["false_negatives"]["count"] == 1
    assert res["false_negatives"]["row_indices"] == [104]
    assert res["false_negatives"]["exemplars"][0]["attack_category"] == "Worms"
    assert res["false_negatives"]["category_distribution"] == {"Worms": 1}


def test_compute_ranked_attack_category_errors_sorting() -> None:
    """Verify compute_ranked_attack_category_errors sorts by missed detections descending."""
    y_true = [1, 1, 1, 1, 1, 0]
    y_pred = [0, 0, 1, 0, 1, 0]
    cats = ["Exploits", "Exploits", "Exploits", "DoS", "DoS", "Benign"]
    # Exploits: 3 total, 2 missed (FN), 1 detected
    # DoS: 2 total, 1 missed (FN), 1 detected

    ranked = compute_ranked_attack_category_errors(y_true, y_pred, cats)
    assert len(ranked) == 2
    assert ranked[0]["attack_category"] == "Exploits"
    assert ranked[0]["missed_fn"] == 2
    assert ranked[0]["rank"] == 1
    assert ranked[1]["attack_category"] == "DoS"
    assert ranked[1]["missed_fn"] == 1
    assert ranked[1]["rank"] == 2


def test_analyze_feature_error_patterns_and_boundary() -> None:
    """Verify boundary analysis and empirical error pattern calculations."""
    X = _make_dummy_feature_df(10)
    y_true = [0] * 5 + [1] * 5
    y_pred = [0, 1, 0, 0, 0, 1, 1, 1, 0, 1]
    prob_attack = [0.05, 0.85, 0.45, 0.49, 0.1, 0.95, 0.88, 0.52, 0.15, 0.9]

    # Boundary analysis
    boundary = analyze_classification_boundary(y_true, y_pred, prob_attack)
    assert boundary["canonical_threshold"] == CANONICAL_DECISION_THRESHOLD
    assert boundary["uncertainty_band"] == [0.35, 0.65]
    # In band [0.35, 0.65]: 0.45, 0.49, 0.52 -> 3 samples
    assert boundary["samples_in_uncertainty_band"] == 3
    assert boundary["high_confidence_false_positives_p_ge_0_8"] == 1  # 0.85
    assert boundary["high_confidence_false_negatives_p_le_0_2"] == 1  # 0.15

    # Feature pattern shifts
    patterns = analyze_feature_error_patterns(X, y_true, y_pred)
    assert "top_fp_discriminating_features" in patterns
    assert "top_fn_discriminating_features" in patterns
    assert "domain_hypotheses" in patterns


# ==============================================================================
# 3. CLI --verify-only INTEGRATION TESTS
# ==============================================================================


def test_error_analysis_cli_verify_only(capsys: pytest.CaptureFixture) -> None:
    """Verify error_analysis CLI --verify-only executes and outputs JSON summary."""
    exit_code = main(["--verify-only"])
    assert exit_code == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "partitions" in payload
    assert payload["partitions"]["train_rows"] == 1_655_797
    assert payload["partitions"]["validation_rows"] == 345_371
    assert payload["partitions"]["test_rows"] == 345_953
    assert payload["validation_reference"]["fp"] == 5
    assert payload["validation_reference"]["fn"] == 3
