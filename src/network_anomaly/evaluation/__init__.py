"""Evaluation metrics, held-out Test evaluation (Issue #12), and error analysis (Issue #13)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from network_anomaly.evaluation.error_analysis import (
        analyze_classification_boundary,
        analyze_feature_error_patterns,
        analyze_fp_by_flow_groups,
        analyze_temporal_window_errors,
        compile_data_limitations_summary,
        compile_model_comparison_status,
        compute_ranked_attack_category_errors,
        compute_uncertainty_analysis,
        extract_fp_fn_samples,
        generate_error_analysis_report,
        run_full_error_analysis_from_evaluation,
        validate_evaluation_and_error_consistency,
    )
    from network_anomaly.evaluation.metrics import (
        compute_attack_category_breakdown,
        compute_benign_false_positive_breakdown,
        compute_confusion_matrix_breakdown,
        compute_metrics,
        compute_wilson_confidence_interval,
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
        verify_index_disjointness,
    )

__all__ = [
    "CANONICAL_DECISION_THRESHOLD",
    "TestEvaluationPrerequisiteStatus",
    "TestPartitionData",
    "analyze_classification_boundary",
    "analyze_feature_error_patterns",
    "analyze_fp_by_flow_groups",
    "analyze_temporal_window_errors",
    "check_test_evaluation_prerequisites",
    "compile_data_limitations_summary",
    "compile_model_comparison_status",
    "compute_attack_category_breakdown",
    "compute_benign_false_positive_breakdown",
    "compute_confusion_matrix_breakdown",
    "compute_metrics",
    "compute_ranked_attack_category_errors",
    "compute_uncertainty_analysis",
    "compute_wilson_confidence_interval",
    "evaluate_loaded_random_forest_on_test",
    "evaluate_random_forest_on_test",
    "extract_fp_fn_samples",
    "generate_error_analysis_report",
    "run_full_error_analysis_from_evaluation",
    "save_confusion_matrix_artifacts",
    "save_predictions_csv",
    "stream_test_partition_data",
    "validate_evaluation_and_error_consistency",
    "verify_index_disjointness",
]

_METRICS_EXPORTS = {
    "compute_attack_category_breakdown",
    "compute_benign_false_positive_breakdown",
    "compute_confusion_matrix_breakdown",
    "compute_metrics",
    "compute_wilson_confidence_interval",
}

_TEST_EVALUATION_EXPORTS = {
    "CANONICAL_DECISION_THRESHOLD",
    "TestEvaluationPrerequisiteStatus",
    "TestPartitionData",
    "check_test_evaluation_prerequisites",
    "evaluate_loaded_random_forest_on_test",
    "evaluate_random_forest_on_test",
    "save_confusion_matrix_artifacts",
    "save_predictions_csv",
    "stream_test_partition_data",
    "verify_index_disjointness",
}

_ERROR_ANALYSIS_EXPORTS = {
    "analyze_classification_boundary",
    "analyze_feature_error_patterns",
    "analyze_fp_by_flow_groups",
    "analyze_temporal_window_errors",
    "compile_data_limitations_summary",
    "compile_model_comparison_status",
    "compute_ranked_attack_category_errors",
    "compute_uncertainty_analysis",
    "extract_fp_fn_samples",
    "generate_error_analysis_report",
    "run_full_error_analysis_from_evaluation",
    "validate_evaluation_and_error_consistency",
}


def __getattr__(name: str) -> Any:
    if name in _METRICS_EXPORTS:
        from network_anomaly.evaluation import metrics

        return getattr(metrics, name)
    if name in _TEST_EVALUATION_EXPORTS:
        from network_anomaly.evaluation import test_evaluation

        return getattr(test_evaluation, name)
    if name in _ERROR_ANALYSIS_EXPORTS:
        from network_anomaly.evaluation import error_analysis

        return getattr(error_analysis, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
