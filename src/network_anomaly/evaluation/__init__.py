"""Evaluation metrics, held-out Test evaluation (Issue #12), and error analysis (Issue #13)."""

from __future__ import annotations

from network_anomaly.evaluation.error_analysis import (
    analyze_classification_boundary,
    analyze_feature_error_patterns,
    compile_data_limitations_summary,
    compute_ranked_attack_category_errors,
    extract_fp_fn_samples,
    generate_error_analysis_report,
    run_full_error_analysis_from_evaluation,
)
from network_anomaly.evaluation.metrics import (
    compute_attack_category_breakdown,
    compute_benign_false_positive_breakdown,
    compute_confusion_matrix_breakdown,
    compute_metrics,
)
from network_anomaly.evaluation.test_evaluation import (
    CANONICAL_DECISION_THRESHOLD,
    TestEvaluationPrerequisiteStatus,
    TestPartitionData,
    check_test_evaluation_prerequisites,
    evaluate_loaded_random_forest_on_test,
    evaluate_random_forest_on_test,
    save_confusion_matrix_artifacts,
    save_predictions_csv,
    stream_test_partition_data,
)

__all__ = [
    "CANONICAL_DECISION_THRESHOLD",
    "TestEvaluationPrerequisiteStatus",
    "TestPartitionData",
    "analyze_classification_boundary",
    "analyze_feature_error_patterns",
    "check_test_evaluation_prerequisites",
    "compile_data_limitations_summary",
    "compute_attack_category_breakdown",
    "compute_benign_false_positive_breakdown",
    "compute_confusion_matrix_breakdown",
    "compute_metrics",
    "compute_ranked_attack_category_errors",
    "evaluate_loaded_random_forest_on_test",
    "evaluate_random_forest_on_test",
    "extract_fp_fn_samples",
    "generate_error_analysis_report",
    "run_full_error_analysis_from_evaluation",
    "save_confusion_matrix_artifacts",
    "save_predictions_csv",
    "stream_test_partition_data",
]
