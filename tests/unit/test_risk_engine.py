"""Unit tests for Risk Scoring and Multi-Model Aggregation (Issues #108, #109)."""

import pytest

from network_anomaly.risk.aggregation import (
    AggregationPolicy,
    MultiModelDecisionAggregator,
)
from network_anomaly.risk.scoring import RiskScorer, SeverityLevel


def test_risk_scoring_severity_calibration():
    scorer = RiskScorer()

    # 1. Benign background traffic -> LOW severity
    res_low = scorer.compute_risk(
        ai_probability=0.05,
        behavioral_anomaly_score=0.1,
        dest_port=80,
        auth_failure_count=0,
    )
    assert res_low.severity == SeverityLevel.LOW
    assert res_low.score < 30.0
    assert res_low.trigger_adaptive_rotation is False

    # 2. Moderate anomaly on regular port -> MEDIUM severity
    res_med = scorer.compute_risk(
        ai_probability=0.60,
        behavioral_anomaly_score=0.4,
        dest_port=8080,
    )
    assert res_med.severity in (SeverityLevel.MEDIUM, SeverityLevel.HIGH)
    assert res_med.trigger_adaptive_rotation is False

    # 3. Critical high-confidence attack on sensitive port (SSH/RDP/SMB) -> CRITICAL severity & rotation trigger
    res_crit = scorer.compute_risk(
        ai_probability=0.99,
        behavioral_anomaly_score=0.95,
        dest_port=445,  # SMB
        auth_failure_count=4,
    )
    assert res_crit.severity == SeverityLevel.CRITICAL
    assert res_crit.score >= 85.0
    assert res_crit.trigger_adaptive_rotation is True

    # 4. Out-of-Distribution sample capped to avoid false alarm rotation
    res_ood = scorer.compute_risk(
        ai_probability=0.95,
        behavioral_anomaly_score=0.9,
        dest_port=445,
        is_ood=True,
    )
    assert res_ood.is_ood is True
    assert res_ood.score <= 65.0
    assert res_ood.trigger_adaptive_rotation is False


def test_multi_model_decision_aggregation_policies():
    agg = MultiModelDecisionAggregator()

    # RF=0.9, XGB=0.85, IF=0.8, AE=0.75
    # Default WEIGHTED_ENSEMBLE
    res = agg.aggregate(rf_prob=0.9, xgb_prob=0.85, if_score=0.8, ae_error_norm=0.75)
    assert res.is_anomaly is True
    assert res.combined_probability >= 0.80
    assert res.consensus_ratio == 1.0

    # STRICT_CONSENSUS: one model says False -> overall False
    agg_strict = MultiModelDecisionAggregator(policy=AggregationPolicy.STRICT_CONSENSUS)
    res_strict = agg_strict.aggregate(rf_prob=0.9, xgb_prob=0.85, if_score=0.2, ae_error_norm=0.1)
    assert res_strict.is_anomaly is False

    # RANDOM_FOREST_PRIMARY: follows RF
    agg_rf = MultiModelDecisionAggregator(policy=AggregationPolicy.RANDOM_FOREST_PRIMARY)
    res_rf = agg_rf.aggregate(rf_prob=0.95, xgb_prob=0.1)
    assert res_rf.is_anomaly is True
    assert res_rf.combined_probability == 0.95


def test_risk_scoring_non_finite_inputs_fail_closed():
    scorer = RiskScorer()
    non_finite_values = [float("nan"), float("inf"), float("-inf")]

    for bad in non_finite_values:
        # Non-finite AI probability with high behavioral/port/auth signals
        res_ai = scorer.compute_risk(
            ai_probability=bad,
            behavioral_anomaly_score=0.95,
            dest_port=445,
            auth_failure_count=4,
        )
        assert res_ai.component_breakdown["ai_confidence"] == 0.0
        assert res_ai.score <= 65.0
        assert res_ai.severity != SeverityLevel.CRITICAL
        assert res_ai.trigger_adaptive_rotation is False
        assert any("Non-finite AI probability" in reason for reason in res_ai.justification)

        # Non-finite behavioral score with max AI/port/auth signals (would be 75.0 without clamp)
        res_beh = scorer.compute_risk(
            ai_probability=1.0,
            behavioral_anomaly_score=bad,
            dest_port=445,
            auth_failure_count=4,
        )
        assert res_beh.component_breakdown["behavioral_deviation"] == 0.0
        assert res_beh.score <= 65.0
        assert res_beh.severity != SeverityLevel.CRITICAL
        assert res_beh.trigger_adaptive_rotation is False
        assert any(
            "Non-finite behavioral anomaly score" in reason for reason in res_beh.justification
        )


def test_risk_scoring_normalizes_negative_auth_failures():
    scorer = RiskScorer()
    res = scorer.compute_risk(
        ai_probability=0.5,
        behavioral_anomaly_score=0.2,
        auth_failure_count=-5,
    )
    assert res.component_breakdown["auth_failures"] == 0.0
    assert res.score == pytest.approx(30.0)
