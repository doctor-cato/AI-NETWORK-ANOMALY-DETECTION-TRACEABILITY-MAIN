"""Inference pipeline — load artifacts and predict.

Provides verified inference entrypoints for the NF-UNSW-NB15-v3 dataset,
ensuring fail-closed verification on all model and preprocessor artifacts (Issue #53).
"""

from __future__ import annotations

from network_anomaly.inference.predict import (
    InferencePipeline,
    InferenceResult,
    load_verified_model,
    load_verified_preprocessor,
    predict_from_artifact,
    run_inference,
    validate_inference_input,
)

__all__ = [
    "InferencePipeline",
    "InferenceResult",
    "load_verified_model",
    "load_verified_preprocessor",
    "predict_from_artifact",
    "run_inference",
    "validate_inference_input",
]
