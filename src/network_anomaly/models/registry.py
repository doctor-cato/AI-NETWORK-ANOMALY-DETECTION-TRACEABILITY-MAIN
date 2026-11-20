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

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

from network_anomaly.canonical.feature_contract import get_flow_feature_contract_v2
from network_anomaly.config import PROJECT_ROOT, resolve_artifacts_dir
from network_anomaly.data.v2_schema import FEATURE_CONTRACT_ID, ML_FEATURE_COLUMNS
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
    """Raised when a live event cannot satisfy the 18-feature v2 flow contract."""


RESEARCH_ONLY_MODEL_KEYS = frozenset({"xgboost", "isolation_forest", "autoencoder"})
CROSS_SOURCE_REQUIRED_SPLITS = ("ctu_echo", "ctu_windows7ad")
MIN_CERTIFICATION_RECALL = 0.70
MAX_CERTIFICATION_FPR = 0.10
VALIDATED_YOUDEN_J_THRESHOLDS: Dict[str, float] = {
    "random_forest": 0.382282,
    "xgboost": 0.200761,
}
SUPPORTED_THRESHOLD_PROFILES = ("frozen_default", "validation_youden_j")


def _is_valid_metric_ratio(value: Any) -> Optional[float]:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    val = float(value)
    if val != val or abs(val) == float("inf") or val < 0.0 or val > 1.0:
        return None
    return val


def _extract_split_metrics(manifest: Dict[str, Any], split_key: str) -> Optional[Dict[str, Any]]:
    for parent_key in ("evaluation", "evaluation_summary"):
        parent = manifest.get(parent_key)
        if isinstance(parent, dict) and isinstance(parent.get(split_key), dict):
            return parent[split_key]
    if split_key == "ait_test":
        for fallback_key in ("test_evaluation", "evaluation_metrics"):
            payload = manifest.get(fallback_key)
            if isinstance(payload, dict):
                return payload
    if split_key in CROSS_SOURCE_REQUIRED_SPLITS:
        cross = manifest.get("cross_source_evaluation")
        if isinstance(cross, dict) and isinstance(cross.get(split_key), dict):
            return cross[split_key]
    return None


def _split_eval_status(metrics: Any) -> tuple[bool, bool]:
    if not isinstance(metrics, dict):
        return False, False
    recall = _is_valid_metric_ratio(metrics.get("recall"))
    fpr = _is_valid_metric_ratio(metrics.get("false_positive_rate", metrics.get("fpr")))
    if recall is None or fpr is None:
        return False, False
    return True, (recall >= MIN_CERTIFICATION_RECALL and fpr <= MAX_CERTIFICATION_FPR)


def _evaluate_manifest_readiness_tiers(
    model_key: str,
    manifest: Dict[str, Any],
    *,
    threshold: Optional[float],
    threshold_source: str,
    artifact_sha256: Optional[str],
    expected_prep_sha256: Optional[str],
    expected_split_sha256: Optional[str],
) -> tuple[bool, bool, bool, str]:
    """Compute separated artifact, in-domain, cross-source, and deployment readiness tiers."""
    tp = manifest.get("threshold_provenance")
    tp_clean = not (
        isinstance(tp, dict)
        and (
            tp.get("test_touched") is True
            or str(tp.get("selected_on", "")).strip().lower()
            in ("test", "ait_test", "holdout_test")
        )
    )
    if str(threshold_source).startswith("unavailable") or threshold is None:
        tp_clean = False
    prep_sha = manifest.get("preprocessor_artifact_sha256") or manifest.get("preprocessor_sha256")
    split_sha = manifest.get("split_manifest_sha256")
    prep_ok = (not expected_prep_sha256) or (
        bool(prep_sha) and str(prep_sha) == str(expected_prep_sha256)
    )
    split_ok = (not expected_split_sha256) or (
        bool(split_sha) and str(split_sha) == str(expected_split_sha256)
    )
    artifact_verified = bool(
        artifact_sha256
        and manifest.get("feature_contract_version")
        and tp_clean
        and prep_ok
        and split_ok
    )
    in_domain_evaluated, in_domain_passed = _split_eval_status(
        _extract_split_metrics(manifest, "ait_test")
    )
    cross_source_validated = all(
        _split_eval_status(_extract_split_metrics(manifest, split_name))[1]
        for split_name in CROSS_SOURCE_REQUIRED_SPLITS
    )
    is_research_only = bool(manifest.get("is_research_only", model_key in RESEARCH_ONLY_MODEL_KEYS))
    deployment_tier = (
        "PRODUCTION_ELIGIBLE"
        if (
            artifact_verified
            and in_domain_passed
            and cross_source_validated
            and not is_research_only
        )
        else "RESEARCH_ONLY"
    )
    return artifact_verified, in_domain_evaluated, cross_source_validated, deployment_tier


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
    feature_contract_version: Optional[str] = None
    dataset_provenance: Optional[str] = None
    training_run_id: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    deployment_tier: str = "RESEARCH_ONLY"
    artifact_verified: bool = False
    in_domain_evaluated: bool = False
    cross_source_validated: bool = False

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
            "feature_contract_version": self.feature_contract_version,
            "dataset_provenance": self.dataset_provenance,
            "training_run_id": self.training_run_id,
            "capabilities": list(self.capabilities),
            "deployment_tier": self.deployment_tier,
            "artifact_verified": self.artifact_verified,
            "in_domain_evaluated": self.in_domain_evaluated,
            "cross_source_validated": self.cross_source_validated,
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


def _to_repo_posix(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _as_estimator_input(model_obj: Any, X: Any) -> Any:
    if isinstance(X, pd.DataFrame):
        return X
    arr = np.asarray(X)
    if arr.ndim != 2:
        return X
    estimator = getattr(
        model_obj,
        "_estimator",
        getattr(model_obj, "estimator", getattr(model_obj, "model", model_obj)),
    )
    feature_names = getattr(estimator, "feature_names_in_", None)
    if feature_names is not None and len(feature_names) == arr.shape[1]:
        return pd.DataFrame(arr, columns=list(feature_names))
    return X


class _SupervisedBackend:
    score_semantics = PROBABILITY_SEMANTICS

    def __init__(self, estimator: Any, threshold: Optional[float], calibration: Any):
        self.estimator = estimator
        self.threshold = threshold
        self.calibration = calibration

    def score(self, X: np.ndarray) -> Tuple[float, Optional[float], Optional[bool], Optional[str]]:
        X_in = _as_estimator_input(self.estimator, X)
        proba = np.asarray(self.estimator.predict_proba(X_in), dtype=float)
        if proba.ndim != 2 or proba.shape[1] < 2:
            raise ValueError("Supervised model must expose two-class predict_proba output")
        attack_probability = float(proba[0, 1])
        if self.threshold is None:
            return attack_probability, attack_probability, None, "missing_calibrated_threshold"
        return attack_probability, attack_probability, attack_probability >= self.threshold, None

    def score_batch_detailed(
        self, X: np.ndarray
    ) -> List[Tuple[float, Optional[float], Optional[bool], Optional[str]]]:
        """Score a 2D batch matrix in a single vectorized predict_proba call."""
        X_arr = np.asarray(X)
        if X_arr.shape[0] == 0:
            return []
        X_in = _as_estimator_input(self.estimator, X_arr)
        proba = np.asarray(self.estimator.predict_proba(X_in), dtype=float)
        if proba.ndim != 2 or proba.shape[1] < 2:
            raise ValueError("Supervised model must expose two-class predict_proba output")
        probs = proba[:, 1]
        if self.threshold is None:
            return [
                (float(prob), float(prob), None, "missing_calibrated_threshold") for prob in probs
            ]
        thresh = float(self.threshold)
        return [(float(prob), float(prob), bool(float(prob) >= thresh), None) for prob in probs]


class _ThresholdBackend:
    """Unsupervised backend: raw score plus empirical percentile normalization."""

    score_semantics = PERCENTILE_SEMANTICS

    def __init__(self, model: Any, threshold: Optional[float], calibration: Any):
        self.model = model
        self.threshold = threshold
        self.calibration = calibration

    def raw_scores(self, X: np.ndarray) -> np.ndarray:
        X_in = _as_estimator_input(self.model, X)
        return np.asarray(self.model.anomaly_scores(X_in), dtype=float)

    def score(self, X: np.ndarray) -> Tuple[float, Optional[float], Optional[bool], Optional[str]]:
        raw = float(self.raw_scores(X)[0])
        normalized = normalize_anomaly_score(raw, self.calibration)
        note = None
        if normalized is None:
            note = "score_normalization_unavailable"
        if self.threshold is None:
            return raw, normalized, None, note or "missing_calibrated_threshold"
        return raw, normalized, raw >= float(self.threshold), note

    def score_batch_detailed(
        self, X: np.ndarray
    ) -> List[Tuple[float, Optional[float], Optional[bool], Optional[str]]]:
        """Score a 2D batch matrix in a single vectorized anomaly_scores call."""
        X_arr = np.asarray(X)
        if X_arr.shape[0] == 0:
            return []
        raw_arr = self.raw_scores(X_arr)
        results: List[Tuple[float, Optional[float], Optional[bool], Optional[str]]] = []
        for raw_val in raw_arr:
            raw = float(raw_val)
            normalized = normalize_anomaly_score(raw, self.calibration)
            note = None if normalized is not None else "score_normalization_unavailable"
            if self.threshold is None:
                results.append((raw, normalized, None, note or "missing_calibrated_threshold"))
            else:
                results.append((raw, normalized, bool(raw >= float(self.threshold)), note))
        return results


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
        threshold_profile: str = "frozen_default",
    ):
        if threshold_profile not in SUPPORTED_THRESHOLD_PROFILES:
            raise ValueError(
                f"Unsupported threshold_profile {threshold_profile!r}; "
                f"expected one of {SUPPORTED_THRESHOLD_PROFILES}"
            )
        self.threshold_profile = threshold_profile
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else resolve_artifacts_dir()
        self.manifest_root = (
            Path(manifest_root) if manifest_root else PROJECT_ROOT / "reports" / "models"
        )
        self.preprocessor_path = (
            Path(preprocessor_path)
            if preprocessor_path
            else self.artifacts_dir / "preprocessing" / "v2_flow_preprocessor.joblib"
        )
        self.preprocessor_manifest_path = (
            Path(preprocessor_manifest_path)
            if preprocessor_manifest_path
            else PROJECT_ROOT / "reports" / "preprocessing" / "v2_flow_preprocessing_manifest.json"
        )
        self.demo_heuristics = demo_heuristics
        self.contract = get_flow_feature_contract_v2()

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
        ae_manifest = self.manifest_root / "autoencoder_manifest.json"
        if not ae_manifest.is_file():
            sidecar_ae_manifest = models_dir / "autoencoder" / "autoencoder_manifest.json"
            if sidecar_ae_manifest.is_file():
                ae_manifest = sidecar_ae_manifest
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
                ae_manifest,
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
            if (
                not self._preprocessor_metadata.get("split_manifest_sha256")
                and self.preprocessor_manifest_path.is_file()
            ):
                try:
                    prep_manifest_json = json.loads(
                        self.preprocessor_manifest_path.read_text(encoding="utf-8")
                    )
                    if isinstance(prep_manifest_json, dict) and prep_manifest_json.get(
                        "split_manifest_sha256"
                    ):
                        self._preprocessor_metadata["split_manifest_sha256"] = prep_manifest_json[
                            "split_manifest_sha256"
                        ]
                except (OSError, json.JSONDecodeError, ValueError):
                    pass
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
            artifact_path=_to_repo_posix(spec.model_path),
            manifest_path=_to_repo_posix(spec.manifest_path) if spec.manifest_path else None,
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
            manifest = json.loads(Path(spec.manifest_path).read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("model manifest must be a JSON object")
            if not threshold_provenance_is_clean(manifest):
                raise ValueError("threshold provenance violates test-partition leakage guard")
            contract_ver = manifest.get("feature_contract_version")
            if contract_ver != FEATURE_CONTRACT_ID:
                raise ValueError(
                    f"feature_contract_version mismatch or legacy v1 artifact: "
                    f"expected {FEATURE_CONTRACT_ID!r}, got {contract_ver!r}"
                )
            ds_prov = manifest.get("dataset_provenance") or manifest.get("dataset_name") or ""
            if "NF-UNSW-NB15" in str(ds_prov):
                raise ValueError(
                    f"Retired v1 dataset provenance rejected by v2 ModelRegistry: {ds_prov!r}"
                )

            expected_prep = self.preprocessor_sha256
            expected_split = (
                self._preprocessor_metadata.get("split_manifest_sha256")
                if isinstance(self._preprocessor_metadata, dict)
                else None
            )
            manifest_split = manifest.get("split_manifest_sha256")
            if expected_split and (
                not manifest_split or str(manifest_split) != str(expected_split)
            ):
                raise ValueError(
                    f"split_manifest_sha256 mismatch: {manifest_split} != {expected_split}"
                )
            backend, threshold, threshold_source = self._load_backend(
                model_key, spec.model_path, spec.manifest_path, manifest, expected_prep
            )
            status.artifact_sha256 = (
                manifest.get("model_artifact_sha256")
                or manifest.get("model_sha256")
                or self._sha256(spec.model_path)
            )
            status.feature_contract_version = str(contract_ver)
            status.dataset_provenance = str(ds_prov) if ds_prov else None
            run_id = manifest.get("training_run_id") or manifest.get("run_id")
            status.training_run_id = str(run_id) if run_id else None
            status.threshold = threshold
            status.threshold_source = threshold_source
            status.score_semantics = backend.score_semantics
            status.loaded_at_utc = datetime.now(timezone.utc).isoformat()
            self._backends[model_key] = backend

            art_ver, in_dom_eval, cross_val, dep_tier = _evaluate_manifest_readiness_tiers(
                model_key,
                manifest,
                threshold=threshold,
                threshold_source=threshold_source,
                artifact_sha256=status.artifact_sha256,
                expected_prep_sha256=expected_prep,
                expected_split_sha256=str(expected_split) if expected_split else None,
            )

            if threshold is None:
                status.readiness = ModelReadiness.RESEARCH
                status.reason = "calibrated decision threshold unavailable"
                status.capabilities = ["raw_anomaly_scoring"]
                status.artifact_verified = False
                status.in_domain_evaluated = in_dom_eval
                status.cross_source_validated = False
                status.deployment_tier = "RESEARCH_ONLY"
            else:
                status.readiness = ModelReadiness.LOADED
                if model_key in ("random_forest", "xgboost"):
                    status.capabilities = ["binary_classification", "probability_scoring"]
                else:
                    status.capabilities = ["anomaly_scoring", "percentile_normalization"]
                status.artifact_verified = art_ver
                status.in_domain_evaluated = in_dom_eval
                status.cross_source_validated = cross_val
                status.deployment_tier = dep_tier
        except Exception as exc:
            status.readiness = ModelReadiness.ERROR
            status.reason = f"{type(exc).__name__}: {exc}"
            status.capabilities = []
            status.artifact_verified = False
            status.in_domain_evaluated = False
            status.cross_source_validated = False
            status.deployment_tier = "RESEARCH_ONLY"
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
            if (
                self.threshold_profile == "validation_youden_j"
                and model_key in VALIDATED_YOUDEN_J_THRESHOLDS
            ):
                threshold = VALIDATED_YOUDEN_J_THRESHOLDS[model_key]
                source = "ait_val_youden_j_profile"
            else:
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
            if (
                self.threshold_profile == "validation_youden_j"
                and model_key in VALIDATED_YOUDEN_J_THRESHOLDS
            ):
                threshold = VALIDATED_YOUDEN_J_THRESHOLDS[model_key]
                source = "ait_val_youden_j_profile"
            else:
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
        statuses = self.statuses()
        return {
            "preprocessor": {
                "ready": self.preprocessor_ready,
                "path": _to_repo_posix(self.preprocessor_path),
                "sha256": self.preprocessor_sha256,
                "error": self._preprocessor_error,
                "feature_contract_version": self._preprocessor_metadata.get(
                    "feature_contract_version"
                ),
            },
            "models": [status.to_dict() for status in statuses],
            "ready_count": self.ready_count,
            "validated_count": self.validated_count,
            "cross_source_validated_count": sum(
                1 for status in statuses if status.cross_source_validated
            ),
            "total_models": len(MODEL_KEYS),
            "ai_ready": self.all_ready,
            "ai_ready_semantics": (
                "verified_artifacts_loaded_for_scoped_inference_not_production_certified"
            ),
            "production_ready": any(
                status.deployment_tier == "PRODUCTION_ELIGIBLE" for status in statuses
            ),
            "demo_heuristics_enabled": self.demo_heuristics,
            "threshold_profile": self.threshold_profile,
        }

    # ------------------------------------------------------------ inference
    def validate_features(self, features: Mapping[str, Any]) -> Dict[str, float]:
        """Validate a live feature mapping against the 18-feature v2 flow contract."""
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

    def transform_features_batch(self, feature_dicts: Sequence[Mapping[str, Any]]) -> np.ndarray:
        """Apply the frozen train-only preprocessor to a batch of validated feature mappings."""
        if not self.preprocessor_ready:
            raise FeatureContractError(
                f"preprocessor unavailable: {self._preprocessor_error or 'not loaded'}"
            )
        if not feature_dicts:
            return np.empty((0, len(ML_FEATURE_COLUMNS)), dtype=float)
        validated_rows = [self.validate_features(f) for f in feature_dicts]
        frame = pd.DataFrame(validated_rows, columns=list(ML_FEATURE_COLUMNS))
        transformed = self._preprocessor.transform(frame)
        return np.asarray(transformed.to_numpy(dtype=float), dtype=float)

    def predict_batch_all(
        self, feature_dicts: Sequence[Mapping[str, Any]]
    ) -> List[Dict[str, ModelScore]]:
        """Score a batch of feature mappings with every decision-ready model in vectorized calls."""
        if not feature_dicts:
            return []
        X_batch = self.transform_features_batch(feature_dicts)
        n_rows = len(feature_dicts)
        row_results: List[Dict[str, ModelScore]] = [{} for _ in range(n_rows)]
        for model_key in MODEL_KEYS:
            backend = self._backends.get(model_key)
            status = self._statuses.get(model_key)
            if backend is None or status is None or not status.decision_ready:
                continue
            start = time.perf_counter()
            try:
                batch_tuples = backend.score_batch_detailed(X_batch)
                per_sample_latency_us = ((time.perf_counter() - start) * 1e6) / n_rows
                status.inference_count += n_rows
                status.last_latency_us = round(per_sample_latency_us, 3)
                for row_idx, (raw, normalized, is_anomaly, note) in enumerate(batch_tuples):
                    row_results[row_idx][model_key] = ModelScore(
                        model_key=model_key,
                        raw_score=raw,
                        normalized_score=normalized,
                        is_anomaly=is_anomaly,
                        threshold=status.threshold,
                        score_semantics=backend.score_semantics,
                        latency_us=per_sample_latency_us,
                        normalization_note=note,
                    )
            except Exception as exc:
                status.error_count += 1
                status.reason = f"inference failed: {type(exc).__name__}: {exc}"
                for row_map in row_results:
                    row_map.pop(model_key, None)
        return row_results

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
            X_in = _as_estimator_input(backend.estimator, X)
            proba = np.asarray(backend.estimator.predict_proba(X_in), dtype=float)[:, 1]
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
