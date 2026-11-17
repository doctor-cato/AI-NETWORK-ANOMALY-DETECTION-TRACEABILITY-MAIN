"""Verified model registry for the four NetFlow Sentinel AI models.

The registry is the single place that knows how to locate, verify, load and
score with the Random Forest, XGBoost, Isolation Forest and Autoencoder
artifacts. Every load goes through the fail-closed ``load_verified`` entrypoints
so a stale digest or a missing companion manifest produces ``UNAVAILABLE`` or
``ERROR`` rather than a silent heuristic score.

Readiness semantics
-------------------
``VALIDATED``  artifact verified, deserialized, and produced a finite score on a
               preprocessor-produced warm-up row.
``LOADED``     artifact verified and deserialized, but warm-up inference failed
               or was not attempted.
``RESEARCH``   loaded, but the model cannot make a live decision (for example a
               missing calibrated threshold). Scores may be inspected but the
               model never contributes to an ensemble decision.
``UNAVAILABLE`` no artifact/manifest at the expected location.
``ERROR``      verification or deserialization raised.

The registry never fabricates scores. If an artifact is absent, callers receive
an explicit status and no prediction for that model.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

import numpy as np
import pandas as pd

from network_anomaly.canonical.feature_contract import get_baseline_47_feature_contract
from network_anomaly.config import PROJECT_ROOT, resolve_artifacts_dir
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.models.autoencoder import AutoencoderModel
from network_anomaly.models.isolation_forest import IsolationForestModel
from network_anomaly.models.random_forest import RandomForestModel
from network_anomaly.models.scoring import (
    PERCENTILE_SEMANTICS,
    PROBABILITY_SEMANTICS,
    extract_threshold,
    normalize_anomaly_score,
    threshold_provenance_is_clean,
)
from network_anomaly.models.xgboost_model import XGBoostModel

MODEL_KEYS: Tuple[str, ...] = (
    "random_forest",
    "xgboost",
    "isolation_forest",
    "autoencoder",
)

DISPLAY_NAMES: Dict[str, str] = {
    "random_forest": "Random Forest",
    "xgboost": "XGBoost",
    "isolation_forest": "Isolation Forest",
    "autoencoder": "Autoencoder",
}


class ModelReadiness(str, Enum):
    LOADED = "LOADED"
    VALIDATED = "VALIDATED"
    RESEARCH = "RESEARCH"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class FeatureContractError(ValueError):
    """Raised when a live event cannot satisfy the 47-feature model contract."""


@dataclass
class ModelStatus:
    model_key: str
    display_name: str
    model_type: str
    readiness: ModelReadiness
    artifact_path: str
    manifest_path: Optional[str] = None
    artifact_sha256: Optional[str] = None
    threshold: Optional[float] = None
    threshold_source: str = "unavailable"
    score_semantics: str = "unavailable"
    reason: Optional[str] = None
    loaded_at_utc: Optional[str] = None
    inference_count: int = 0
    error_count: int = 0
    last_latency_us: Optional[float] = None
    validated: bool = False

    @property
    def decision_ready(self) -> bool:
        return self.readiness in (ModelReadiness.VALIDATED, ModelReadiness.LOADED)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_key": self.model_key,
            "display_name": self.display_name,
            "model_type": self.model_type,
            "readiness": self.readiness.value,
            "artifact_path": self.artifact_path,
            "manifest_path": self.manifest_path,
            "artifact_sha256": self.artifact_sha256,
            "threshold": self.threshold,
            "threshold_source": self.threshold_source,
            "score_semantics": self.score_semantics,
            "reason": self.reason,
            "loaded_at_utc": self.loaded_at_utc,
            "inference_count": self.inference_count,
            "error_count": self.error_count,
            "last_latency_us": self.last_latency_us,
            "validated": self.validated,
        }


@dataclass
class ModelScore:
    model_key: str
    raw_score: float
    normalized_score: Optional[float]
    is_anomaly: Optional[bool]
    threshold: Optional[float]
    score_semantics: str
    latency_us: float
    # Populated when the normalization curve is unavailable
    normalization_note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_key": self.model_key,
            "raw_score": round(float(self.raw_score), 6),
            "normalized_score": (
                None if self.normalized_score is None else round(float(self.normalized_score), 6)
            ),
            "is_anomaly": self.is_anomaly,
            "threshold": self.threshold,
            "score_semantics": self.score_semantics,
            "latency_us": round(float(self.latency_us), 3),
            "normalization_note": self.normalization_note,
        }


@dataclass
class ModelArtifactPaths:
    model_path: Path
    manifest_path: Optional[Path]
    model_type: str


class _SupervisedBackend:
    score_semantics = PROBABILITY_SEMANTICS

    def __init__(self, estimator: Any, threshold: Optional[float], calibration: Any):
        self.estimator = estimator
        self.threshold = threshold
        self.calibration = calibration

    def score(self, X: np.ndarray) -> Tuple[float, Optional[float], Optional[bool], Optional[str]]:
        proba = np.asarray(self.estimator.predict_proba(X), dtype=float)
        if proba.ndim != 2 or proba.shape[1] < 2:
            raise ValueError("Supervised model must expose two-class predict_proba output")
        attack_probability = float(proba[0, 1])
        if self.threshold is None:
            return attack_probability, attack_probability, None, "missing_calibrated_threshold"
        return attack_probability, attack_probability, attack_probability >= self.threshold, None


class _ThresholdBackend:
    """Unsupervised backend: raw score plus empirical percentile normalization."""

    score_semantics = PERCENTILE_SEMANTICS

    def __init__(self, model: Any, threshold: Optional[float], calibration: Any):
        self.model = model
        self.threshold = threshold
        self.calibration = calibration

    def raw_scores(self, X: np.ndarray) -> np.ndarray:
        return np.asarray(self.model.anomaly_scores(X), dtype=float)

    def score(self, X: np.ndarray) -> Tuple[float, Optional[float], Optional[bool], Optional[str]]:
        raw = float(self.raw_scores(X)[0])
        normalized = normalize_anomaly_score(raw, self.calibration)
        note = None
        if normalized is None:
            note = "score_normalization_unavailable"
        if self.threshold is None:
            return raw, normalized, None, note or "missing_calibrated_threshold"
        return raw, normalized, raw >= float(self.threshold), note


class ModelRegistry:
    """Discover, verify, load and score the four canonical model artifacts."""

    def __init__(
        self,
        artifacts_dir: Optional[Path] = None,
        manifest_root: Optional[Path] = None,
        preprocessor_path: Optional[Path] = None,
        preprocessor_manifest_path: Optional[Path] = None,
        warmup: bool = True,
        demo_heuristics: bool = False,
    ):
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else resolve_artifacts_dir()
        self.manifest_root = (
            Path(manifest_root) if manifest_root else PROJECT_ROOT / "reports" / "models"
        )
        self.preprocessor_path = (
            Path(preprocessor_path)
            if preprocessor_path
            else self.artifacts_dir / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
        )
        self.preprocessor_manifest_path = (
            Path(preprocessor_manifest_path)
            if preprocessor_manifest_path
            else PROJECT_ROOT
            / "reports"
            / "preprocessing"
            / "nf_unsw_nb15_v3_preprocessing_manifest.json"
        )
        self.demo_heuristics = demo_heuristics
        self.contract = get_baseline_47_feature_contract()

        self._preprocessor: Any = None
        self._preprocessor_metadata: Dict[str, Any] = {}
        self._preprocessor_error: Optional[str] = None
        self._backends: Dict[str, Any] = {}
        self._statuses: Dict[str, ModelStatus] = {}
        self._warmup_vector: Optional[np.ndarray] = None

        self._load_preprocessor()
        for spec in self._artifact_specs():
            self._load_model(spec)
        if warmup:
            self._warmup()

    # ------------------------------------------------------------------ paths
    def _artifact_specs(self) -> List[ModelArtifactPaths]:
        models_dir = self.artifacts_dir / "models"
        return [
            ModelArtifactPaths(
                models_dir / "random_forest" / "random_forest_baseline.joblib",
                self.manifest_root / "random_forest_manifest.json",
                "RandomForest",
            ),
            ModelArtifactPaths(
                models_dir / "xgboost" / "xgboost_baseline.joblib",
                self.manifest_root / "xgboost_manifest.json",
                "XGBoost",
            ),
            ModelArtifactPaths(
                models_dir / "isolation_forest" / "isolation_forest.joblib",
                self.manifest_root / "isolation_forest_manifest.json",
                "IsolationForest",
            ),
            ModelArtifactPaths(
                models_dir / "autoencoder" / "autoencoder_model.joblib",
                models_dir / "autoencoder" / "autoencoder_manifest.json",
                "Autoencoder",
            ),
        ]

    # ----------------------------------------------------------- preprocessor
    def _load_preprocessor(self) -> None:
        from network_anomaly.inference.predict import load_verified_preprocessor

        try:
            if not self.preprocessor_path.is_file():
                raise FileNotFoundError(
                    f"preprocessor artifact not found: {self.preprocessor_path}"
                )
            preprocessor, metadata = load_verified_preprocessor(
                self.preprocessor_path,
                manifest_path=(
                    self.preprocessor_manifest_path
                    if self.preprocessor_manifest_path.is_file()
                    else None
                ),
            )
            self._preprocessor = preprocessor
            self._preprocessor_metadata = dict(metadata)
            median_row = pd.DataFrame(
                [{name: float(preprocessor.imputed_values_[name]) for name in ML_FEATURE_COLUMNS}]
            )
            self._warmup_vector = preprocessor.transform(median_row).to_numpy(dtype=float)
        except Exception as exc:  # pragma: no cover - exercised per environment
            self._preprocessor = None
            self._warmup_vector = None
            self._preprocessor_error = f"{type(exc).__name__}: {exc}"

    @property
    def preprocessor_ready(self) -> bool:
        return self._preprocessor is not None

    @property
    def preprocessor_error(self) -> Optional[str]:
        return self._preprocessor_error

    @property
    def preprocessor_sha256(self) -> Optional[str]:
        value = self._preprocessor_metadata.get("artifact_sha256")
        return str(value) if value else None

    # ------------------------------------------------------------------ load
    def _status_stub(self, model_key: str, spec: ModelArtifactPaths) -> ModelStatus:
        return ModelStatus(
            model_key=model_key,
            display_name=DISPLAY_NAMES[model_key],
            model_type=spec.model_type,
            readiness=ModelReadiness.UNAVAILABLE,
            artifact_path=str(spec.model_path),
            manifest_path=str(spec.manifest_path) if spec.manifest_path else None,
        )

    def _load_model(self, spec: ModelArtifactPaths) -> None:
        model_key = self._key_for_model_type(spec.model_type)
        status = self._status_stub(model_key, spec)
        self._statuses[model_key] = status

        if not spec.model_path.is_file():
            status.reason = f"artifact not found: {spec.model_path}"
            return
        if spec.manifest_path is None or not Path(spec.manifest_path).is_file():
            status.reason = f"companion manifest not found: {spec.manifest_path}"
            return
        if not self.preprocessor_ready:
            status.readiness = ModelReadiness.ERROR
            status.reason = f"preprocessor unavailable: {self._preprocessor_error}"
            return

        try:
            import json

            manifest = json.loads(Path(spec.manifest_path).read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("model manifest must be a JSON object")
            if not threshold_provenance_is_clean(manifest):
                raise ValueError("threshold provenance violates test-partition leakage guard")

            expected_prep = self.preprocessor_sha256
            backend, threshold, threshold_source = self._load_backend(
                model_key, spec.model_path, spec.manifest_path, manifest, expected_prep
            )
            status.artifact_sha256 = (
                manifest.get("model_artifact_sha256")
                or manifest.get("model_sha256")
                or self._sha256(spec.model_path)
            )
            status.threshold = threshold
            status.threshold_source = threshold_source
            status.score_semantics = backend.score_semantics
            status.loaded_at_utc = datetime.now(timezone.utc).isoformat()
            self._backends[model_key] = backend

            if threshold is None:
                status.readiness = ModelReadiness.RESEARCH
                status.reason = "calibrated decision threshold unavailable"
            else:
                status.readiness = ModelReadiness.LOADED
        except Exception as exc:
            status.readiness = ModelReadiness.ERROR
            status.reason = f"{type(exc).__name__}: {exc}"
            self._backends.pop(model_key, None)

    def _load_backend(
        self,
        model_key: str,
        model_path: Path,
        manifest_path: Path,
        manifest: Dict[str, Any],
        expected_preprocessor_sha256: Optional[str],
    ) -> Tuple[Any, Optional[float], str]:
        if model_key == "random_forest":
            model = RandomForestModel.load_verified(
                model_path,
                manifest_path,
                expected_preprocessor_artifact_sha256=expected_preprocessor_sha256,
            )
            threshold, source = extract_threshold(manifest)
            if threshold is None:
                threshold = 0.5
                source = "default_binary_decision_0.5"
            return _SupervisedBackend(model, threshold, None), threshold, source

        if model_key == "xgboost":
            model = XGBoostModel.load_verified(
                model_path,
                manifest_path,
                expected_preprocessor_artifact_sha256=expected_preprocessor_sha256,
            )
            threshold, source = extract_threshold(manifest)
            if threshold is None:
                threshold = 0.5
                source = "default_binary_decision_0.5"
            return _SupervisedBackend(model, threshold, None), threshold, source

        if model_key == "isolation_forest":
            model = IsolationForestModel.load_verified(
                model_path,
                manifest_path,
                expected_preprocessor_artifact_sha256=expected_preprocessor_sha256,
            )
            threshold, source = extract_threshold(manifest)
            calibration = manifest.get("score_normalization")
            return _ThresholdBackend(model, threshold, calibration), threshold, source

        if model_key == "autoencoder":
            model = AutoencoderModel.load_verified(
                model_path,
                manifest_path,
                expected_preprocessor_sha256=expected_preprocessor_sha256,
            )
            threshold, source = extract_threshold(manifest)
            calibration = manifest.get("score_normalization")
            if calibration is None:
                calibration = self._sidecar_calibration(manifest, model_path.parent)
            return _ThresholdBackend(model, threshold, calibration), threshold, source

        raise ValueError(f"Unsupported model key: {model_key}")

    @staticmethod
    def _sidecar_calibration(manifest: Dict[str, Any], directory: Path) -> Any:
        """Autoencoder artifacts store calibration inside the manifest or a sidecar."""
        import json

        sidecar = directory / "score_normalization.json"
        if sidecar.is_file():
            try:
                return json.loads(sidecar.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return None
        return None

    @staticmethod
    def _key_for_model_type(model_type: str) -> str:
        mapping = {
            "RandomForest": "random_forest",
            "XGBoost": "xgboost",
            "IsolationForest": "isolation_forest",
            "Autoencoder": "autoencoder",
        }
        return mapping[model_type]

    @staticmethod
    def _sha256(path: Path) -> str:
        import hashlib

        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(65536):
                digest.update(chunk)
        return digest.hexdigest()

    def _warmup(self) -> None:
        if self._warmup_vector is None:
            return
        for model_key, backend in list(self._backends.items()):
            status = self._statuses[model_key]
            try:
                raw, normalized, _, note = backend.score(self._warmup_vector)
                if not np.isfinite(raw):
                    raise ValueError("non-finite warm-up score")
                if status.readiness == ModelReadiness.LOADED:
                    status.readiness = ModelReadiness.VALIDATED
                    status.validated = True
                if note and status.reason is None:
                    status.reason = note
            except Exception as exc:
                status.readiness = ModelReadiness.ERROR
                status.reason = f"warm-up inference failed: {type(exc).__name__}: {exc}"
                self._backends.pop(model_key, None)

    # --------------------------------------------------------------- queries
    @property
    def ready_count(self) -> int:
        return sum(1 for s in self._statuses.values() if s.decision_ready)

    @property
    def validated_count(self) -> int:
        return sum(1 for s in self._statuses.values() if s.readiness == ModelReadiness.VALIDATED)

    @property
    def all_ready(self) -> bool:
        return self.preprocessor_ready and self.ready_count == len(MODEL_KEYS)

    @property
    def available_models(self) -> List[str]:
        return [key for key in MODEL_KEYS if key in self._backends]

    def status(self, model_key: str) -> Optional[ModelStatus]:
        return self._statuses.get(model_key)

    def statuses(self) -> List[ModelStatus]:
        return [self._statuses[key] for key in MODEL_KEYS if key in self._statuses]

    def summary(self) -> Dict[str, Any]:
        return {
            "preprocessor": {
                "ready": self.preprocessor_ready,
                "path": str(self.preprocessor_path),
                "sha256": self.preprocessor_sha256,
                "error": self._preprocessor_error,
                "feature_contract_version": self._preprocessor_metadata.get(
                    "feature_contract_version"
                ),
            },
            "models": [status.to_dict() for status in self.statuses()],
            "ready_count": self.ready_count,
            "validated_count": self.validated_count,
            "total_models": len(MODEL_KEYS),
            "ai_ready": self.all_ready,
            "demo_heuristics_enabled": self.demo_heuristics,
        }

    # ------------------------------------------------------------ inference
    def validate_features(self, features: Mapping[str, Any]) -> Dict[str, float]:
        """Validate a live feature mapping against the 47-feature contract."""
        is_valid, invalid = self.contract.validate_features(dict(features))
        if not is_valid:
            raise FeatureContractError(
                "feature contract violation: "
                f"{len(invalid)} of {len(ML_FEATURE_COLUMNS)} features missing or non-finite: "
                f"{invalid[:8]}"
            )
        return {name: float(features[name]) for name in ML_FEATURE_COLUMNS}

    def transform_features(self, features: Mapping[str, Any]) -> np.ndarray:
        """Apply the frozen train-only preprocessor to a validated feature mapping."""
        if not self.preprocessor_ready:
            raise FeatureContractError(
                f"preprocessor unavailable: {self._preprocessor_error or 'not loaded'}"
            )
        validated = self.validate_features(features)
        frame = pd.DataFrame([validated], columns=list(ML_FEATURE_COLUMNS))
        transformed = self._preprocessor.transform(frame)
        return np.asarray(transformed.to_numpy(dtype=float), dtype=float)

    def predict_all(self, features: Mapping[str, Any]) -> Dict[str, ModelScore]:
        """Score one validated feature row with every decision-ready model.

        Models that are unavailable, in error, or RESEARCH-only are omitted from
        the result. An empty result means no model produced a genuine score.
        """
        X = self.transform_features(features)
        return self.predict_all_matrix(X)

    def predict_all_matrix(self, X: np.ndarray) -> Dict[str, ModelScore]:
        results: Dict[str, ModelScore] = {}
        for model_key in MODEL_KEYS:
            backend = self._backends.get(model_key)
            status = self._statuses.get(model_key)
            if backend is None or status is None or not status.decision_ready:
                continue
            start = time.perf_counter()
            try:
                raw, normalized, is_anomaly, note = backend.score(X)
                latency_us = (time.perf_counter() - start) * 1e6
                status.inference_count += 1
                status.last_latency_us = round(latency_us, 3)
                results[model_key] = ModelScore(
                    model_key=model_key,
                    raw_score=raw,
                    normalized_score=normalized,
                    is_anomaly=is_anomaly,
                    threshold=status.threshold,
                    score_semantics=backend.score_semantics,
                    latency_us=latency_us,
                    normalization_note=note,
                )
            except Exception as exc:
                status.error_count += 1
                status.reason = f"inference failed: {type(exc).__name__}: {exc}"
                results.pop(model_key, None)
        return results

    def score_batch(self, model_key: str, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Vectorized batch scoring returning ``(raw_scores, binary_predictions)``."""
        backend = self._backends.get(model_key)
        status = self._statuses.get(model_key)
        if backend is None or status is None or status.threshold is None:
            raise RuntimeError(f"Model '{model_key}' is not decision-ready")
        if isinstance(backend, _SupervisedBackend):
            proba = np.asarray(backend.estimator.predict_proba(X), dtype=float)[:, 1]
            preds = (proba >= float(status.threshold)).astype(np.int64)
            return proba, preds
        raw = np.asarray(backend.raw_scores(X), dtype=float)
        preds = (raw >= float(status.threshold)).astype(np.int64)
        return raw, preds

    def model_object(self, model_key: str) -> Any:
        """Return the underlying loaded model/estimator object for explainability/audit."""
        backend = self._backends.get(model_key)
        if backend is None:
            return None
        if isinstance(backend, _SupervisedBackend):
            return backend.estimator
        return backend.model
