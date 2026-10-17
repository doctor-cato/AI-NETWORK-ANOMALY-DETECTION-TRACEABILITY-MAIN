"""Inference pipeline — load artifacts and predict."""
import joblib

from network_anomaly.config import ARTIFACTS


def predict_from_artifact(input_data, artifact_path=None):
    path = artifact_path or ARTIFACTS / "model.joblib"
    model = joblib.load(path)
    return model.predict(input_data)
