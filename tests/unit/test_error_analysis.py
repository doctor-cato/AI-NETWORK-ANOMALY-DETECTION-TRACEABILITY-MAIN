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

    # Feature pattern shifts and 4-part epistemic separation
    patterns = analyze_feature_error_patterns(X, y_true, y_pred)
    assert "top_fp_discriminating_features" in patterns
    assert "top_fn_discriminating_features" in patterns
    assert "domain_hypotheses" in patterns
    assert "epistemic_separation" in patterns
    ep = patterns["epistemic_separation"]
    assert "verified_observations" in ep
    assert "statistical_associations" in ep
    assert "domain_hypotheses" in ep
    assert "future_experiment_proposals" in ep


def test_fp_by_flow_groups_and_ip_redaction() -> None:
    """Verify P1-05/P2-03: FP flow-group breakdown by protocol, duration, and redacted IPs."""
    from network_anomaly.evaluation.error_analysis import analyze_fp_by_flow_groups

    X = _make_dummy_feature_df(6)
    X["PROTOCOL"] = [6, 6, 17, 17, 6, 6]
    X["FLOW_DURATION_MILLISECONDS"] = [0.0, 25.0, 500.0, 25000.0, 10.0, 100.0]
    y_true = [0, 0, 0, 0, 1, 1]
    y_pred = [0, 1, 1, 0, 1, 0]  # 2 Benign FPs (row 1: TCP/25ms, row 2: UDP/500ms)

    trace_df = pd.DataFrame(
        {
            "IPV4_SRC_ADDR": [
                "192.168.10.1",
                "192.168.10.25",
                "10.0.0.99",
                "10.0.0.99",
                "172.16.0.5",
                "172.16.0.6",
            ],
            "IPV4_DST_ADDR": [
                "8.8.8.8",
                "8.8.4.4",
                "1.1.1.1",
                "1.1.1.1",
                "10.0.0.1",
                "10.0.0.1",
            ],
        }
    )

    grp = analyze_fp_by_flow_groups(X=X, y_true=y_true, y_pred=y_pred, trace_metadata=trace_df)
    assert grp["total_benign"] == 4
    assert grp["total_fp"] == 2
    assert grp["total_tn"] == 2
    assert grp["overall_fpr"] == pytest.approx(0.5)
    assert sum(p["fp_count"] for p in grp["by_protocol"]) == 2
    assert sum(d["fp_count"] for d in grp["by_duration_regime"]) == 2

    anon = grp["by_anonymized_flow_group"]
    assert anon["status"] == "VERIFIED"
    assert anon["ip_redaction_applied"] is True
    assert anon["flow_groups_with_fp"] == 2
    serialized = json.dumps(anon)
    assert "192.168.10.25" not in serialized
    assert "10.0.0.99" not in serialized
    assert all(
        g["anonymized_flow_group_id"].startswith("fg_")
        for g in anon["top_anonymized_fp_groups"]
    )


def test_temporal_window_error_analysis() -> None:
    """Verify P1-05: temporal window error analysis across chronological flow timestamps."""
    from network_anomaly.evaluation.error_analysis import analyze_temporal_window_errors

    y_true = [0, 0, 1, 0, 1, 1, 0, 1, 0, 1]
    y_pred = [0, 1, 1, 0, 0, 1, 0, 0, 1, 1]  # 2 FP, 2 FN

    # Without trace_metadata -> NOT_AVAILABLE
    no_trace = analyze_temporal_window_errors(y_true, y_pred, trace_metadata=None)
    assert no_trace["status"] == "NOT_AVAILABLE"

    # With FLOW_START_MILLISECONDS -> VERIFIED
    trace_df = pd.DataFrame(
        {"FLOW_START_MILLISECONDS": [1000 + i * 500 for i in range(len(y_true))]}
    )
    res = analyze_temporal_window_errors(
        y_true=y_true,
        y_pred=y_pred,
        trace_metadata=trace_df,
        num_windows=2,
    )
    assert res["status"] == "VERIFIED"
    assert res["num_windows"] == 2
    assert sum(w["fp"] for w in res["windows"]) == 2
    assert sum(w["fn"] for w in res["windows"]) == 2
    assert sum(w["total_rows"] for w in res["windows"]) == len(y_true)


def test_uncertainty_analysis_and_model_comparison_status(tmp_path: Path) -> None:
    """Verify P2-04 (Wilson 95% CI & rare class Worms) and P2-05 (RF vs Isolation Forest)."""
    from network_anomaly.evaluation.error_analysis import (
        compile_model_comparison_status,
        compute_uncertainty_analysis,
        validate_evaluation_and_error_consistency,
    )

    unc = compute_uncertainty_analysis(
        y_true=[0, 0, 1, 1, 1],
        y_pred=[0, 1, 1, 0, 1],
        attack_categories=["Benign", "Benign", "Exploits", "Worms", "Worms"],
    )
    assert unc["confidence_level"] == 0.95
    assert "i.i.d." in unc["flow_dependence_caveat"]
    sens = unc["sample_size_sensitivity_by_category"]
    assert "Worms" in sens
    assert sens["Worms"]["test_sample_count"] == 36
    assert sens["Worms"]["is_rare_class"] is True
    # Worms (n=36) CI width at 0 misses (~9.64%) is much wider than Exploits (n=10520, ~0.04%)
    assert sens["Worms"]["ci_95_width_at_zero_misses"] > 0.08
    assert (
        sens["Worms"]["ci_95_width_at_zero_misses"]
        > sens["Exploits"]["ci_95_width_at_zero_misses"] * 100
    )

    comp = compile_model_comparison_status()
    assert comp["models"]["random_forest"]["configuration_id"] == "rf-baseline-canonical-v1"
    assert comp["models"]["isolation_forest"]["blocks_random_forest_acceptance"] is False
    assert "NOT EVALUATED" in comp["models"]["isolation_forest"]["held_out_test_status"]

    # Consistency check and overwrite protection
    with pytest.raises(ValueError, match="!= total"):
        validate_evaluation_and_error_consistency(
            cm_breakdown={
                "tn": 10,
                "fp": 2,
                "fn": 1,
                "tp": 7,
                "benign_total": 12,
                "attack_total": 8,
                "total": 999,
            },
            attack_breakdown={},
        )

    rep_p = tmp_path / "locked_report.md"
    generate_error_analysis_report(output_path=rep_p, allow_overwrite=True)
    with pytest.raises(FileExistsError):
        generate_error_analysis_report(output_path=rep_p, allow_overwrite=False)


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
