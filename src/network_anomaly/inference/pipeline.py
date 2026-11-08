"""Inference pipeline — load artifacts and predict.

Maintains backward-compatibility with legacy predict_from_artifact entrypoint
while integrating with the NF-UNSW-NB15-v3 verified inference engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional, Union

import joblib

from network_anomaly.config import ARTIFACTS
from network_anomaly.inference.predict import (
    InferencePipeline,
    InferenceResult,
    load_verified_model,
    load_verified_preprocessor,
    run_inference,
    validate_inference_input,
)


def predict_from_artifact(
    input_data: Any,
    artifact_path: Optional[Union[str, Path]] = None,
) -> Any:
    """Legacy compatibility loader for predicting directly from a model artifact.

    Parameters
    ----------
    input_data : array-like or pd.DataFrame
        Input features.
    artifact_path : str or Path, optional
        Path to the saved model artifact. Defaults to ARTIFACTS / 'model.joblib'.

    Returns
    -------
    predictions : np.ndarray
        Model predictions.
    """
    path = Path(artifact_path) if artifact_path is not None else ARTIFACTS / "model.joblib"
    model = joblib.load(path)
    return model.predict(input_data)


__all__ = [
    "InferencePipeline",
    "InferenceResult",
    "load_verified_model",
    "load_verified_preprocessor",
    "predict_from_artifact",
    "run_inference",
    "validate_inference_input",
]
