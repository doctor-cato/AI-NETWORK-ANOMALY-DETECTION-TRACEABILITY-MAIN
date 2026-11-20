"""Evaluation metrics and held-out Test evaluation helpers for NetFlow Sentinel v2."""

from __future__ import annotations

from network_anomaly.evaluation.metrics import (
    compute_attack_category_breakdown,
    compute_benign_false_positive_breakdown,
    compute_confusion_matrix_breakdown,
    compute_metrics,
    compute_wilson_confidence_interval,
)
from network_anomaly.evaluation.test_evaluation import (
    CANONICAL_DECISION_THRESHOLD,
    evaluate_v2_partition,
    save_confusion_matrix_artifacts,
    verify_index_disjointness,
)

__all__ = [
    "CANONICAL_DECISION_THRESHOLD",
    "compute_attack_category_breakdown",
    "compute_benign_false_positive_breakdown",
    "compute_confusion_matrix_breakdown",
    "compute_metrics",
    "compute_wilson_confidence_interval",
    "evaluate_v2_partition",
    "save_confusion_matrix_artifacts",
    "verify_index_disjointness",
]
