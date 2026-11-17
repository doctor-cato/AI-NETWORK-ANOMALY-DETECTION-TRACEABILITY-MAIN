"""Out-of-Distribution (OOD) Detection and Inference Rejection Gate.

Implements Issue #99 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from network_anomaly.config import PROJECT_ROOT

OOD_GATE_SCHEMA_VERSION = 1
DEFAULT_OOD_GATE_PATH = PROJECT_ROOT / "artifacts" / "ml" / "ood_reference_gate.json"


class OODAction(str, Enum):
    PROCEED = "PROCEED"
    ABSTAIN = "ABSTAIN"


@dataclass
class OODDecision:
    action: OODAction
    is_ood: bool
    ood_score: float
    reason: Optional[str] = None
    offending_features: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class OODRejectionGate:
    """Multi-signal Out-of-Distribution detector combining rule boundaries and statistical density."""

    def __init__(
        self,
        std_margin: float = 4.0,
        statistical_threshold: float = 5.0,
    ):
        self.std_margin = std_margin
        self.statistical_threshold = statistical_threshold
        self.feature_names: List[str] = []
        self.means: np.ndarray = np.array([])
        self.stds: np.ndarray = np.array([])
        self.min_bounds: np.ndarray = np.array([])
        self.max_bounds: np.ndarray = np.array([])
        self.is_fitted: bool = False

    def fit(self, X: np.ndarray, feature_names: List[str]) -> OODRejectionGate:
        """Fit empirical distribution bounding box and statistical moments."""
        if X.ndim != 2 or X.shape[0] == 0:
            raise ValueError("X must be a non-empty 2D array")
        if X.shape[1] != len(feature_names):
            raise ValueError(f"Feature count mismatch: {X.shape[1]} vs {len(feature_names)}")

        self.feature_names = list(feature_names)
        self.means = np.mean(X, axis=0)
        self.stds = np.std(X, axis=0)
        # Avoid division by zero for constant features
        self.stds = np.where(self.stds < 1e-6, 1.0, self.stds)

        # Robust bounding box with margin
        self.min_bounds = self.means - self.std_margin * self.stds
        self.max_bounds = self.means + self.std_margin * self.stds
        self.is_fitted = True
        return self

    def evaluate_sample(self, features: Dict[str, float]) -> OODDecision:
        """Evaluate a single feature dictionary against OOD criteria."""
        if not self.is_fitted:
            raise RuntimeError("OODRejectionGate must be fitted before evaluation")

        x_vec = np.zeros(len(self.feature_names), dtype=np.float64)
        missing_feats = []
        for i, name in enumerate(self.feature_names):
            if name in features:
                x_vec[i] = float(features[name])
            else:
                missing_feats.append(name)

        if missing_feats:
            return OODDecision(
                action=OODAction.ABSTAIN,
                is_ood=True,
                ood_score=1.0,
                reason="MISSING_MANDATORY_FEATURES",
                offending_features=missing_feats[:5],
                metadata={"total_missing": len(missing_feats)},
            )

        # Signal 1: Rule-based Range / Bounding Box Check
        offending_bounds = []
        for i, name in enumerate(self.feature_names):
            val = x_vec[i]
            if val < self.min_bounds[i] or val > self.max_bounds[i]:
                offending_bounds.append(name)

        # If multiple features radically breach distribution limits
        if len(offending_bounds) >= 3:
            return OODDecision(
                action=OODAction.ABSTAIN,
                is_ood=True,
                ood_score=0.95,
                reason="FEATURE_BOUNDS_EXTREME_BREACH",
                offending_features=offending_bounds,
                metadata={"breach_count": len(offending_bounds)},
            )

        # Signal 2: Standardized Euclidean / Mahalanobis Distance
        z_scores = np.abs((x_vec - self.means) / self.stds)
        stat_distance = float(np.mean(z_scores))

        if stat_distance > self.statistical_threshold:
            return OODDecision(
                action=OODAction.ABSTAIN,
                is_ood=True,
                ood_score=min(1.0, stat_distance / 10.0),
                reason="STATISTICAL_OUTLIER_DISTANCE",
                offending_features=[self.feature_names[i] for i in np.argsort(z_scores)[-3:][::-1]],
                metadata={"z_mean_distance": round(stat_distance, 3)},
            )

        return OODDecision(
            action=OODAction.PROCEED,
            is_ood=False,
            ood_score=round(stat_distance / 10.0, 4),
            reason=None,
            metadata={"z_mean_distance": round(stat_distance, 3)},
        )

    def to_artifact(self, provenance: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize the fitted reference distribution with explicit provenance."""
        if not self.is_fitted:
            raise RuntimeError("Cannot serialize an unfitted OODRejectionGate")
        return {
            "schema_version": OOD_GATE_SCHEMA_VERSION,
            "artifact_type": "ood_reference_gate",
            "fitted_at_utc": datetime.now(timezone.utc).isoformat(),
            "feature_names": list(self.feature_names),
            "means": [float(v) for v in self.means],
            "stds": [float(v) for v in self.stds],
            "min_bounds": [float(v) for v in self.min_bounds],
            "max_bounds": [float(v) for v in self.max_bounds],
            "std_margin": self.std_margin,
            "statistical_threshold": self.statistical_threshold,
            "provenance": provenance,
        }

    @classmethod
    def from_artifact(cls, payload: Dict[str, Any]) -> "OODRejectionGate":
        """Rebuild a gate from a validated artifact payload."""
        if not isinstance(payload, dict):
            raise ValueError("OOD gate artifact must be a JSON object")
        feature_names = payload.get("feature_names")
        means = payload.get("means")
        stds = payload.get("stds")
        min_bounds = payload.get("min_bounds")
        max_bounds = payload.get("max_bounds")
        if not isinstance(feature_names, list) or not feature_names:
            raise ValueError("OOD gate artifact is missing feature_names")
        arrays = {}
        for label, values in (
            ("means", means),
            ("stds", stds),
            ("min_bounds", min_bounds),
            ("max_bounds", max_bounds),
        ):
            if not isinstance(values, list) or len(values) != len(feature_names):
                raise ValueError(f"OOD gate artifact '{label}' length mismatch")
            arr = np.asarray([float(v) for v in values], dtype=np.float64)
            if not np.all(np.isfinite(arr)):
                raise ValueError(f"OOD gate artifact '{label}' contains non-finite values")
            arrays[label] = arr
        if np.any(arrays["stds"] <= 0):
            raise ValueError("OOD gate artifact contains non-positive standard deviations")

        gate = cls(
            std_margin=float(payload.get("std_margin", 4.0)),
            statistical_threshold=float(payload.get("statistical_threshold", 5.0)),
        )
        gate.feature_names = [str(name) for name in feature_names]
        gate.means = arrays["means"]
        gate.stds = arrays["stds"]
        gate.min_bounds = arrays["min_bounds"]
        gate.max_bounds = arrays["max_bounds"]
        gate.is_fitted = True
        return gate

    def fit_from_frame(self, frame: Any) -> "OODRejectionGate":
        """Fit from a pandas DataFrame using its column order as the feature contract."""
        return self.fit(np.asarray(frame, dtype=np.float64), [str(c) for c in frame.columns])


def save_persisted_ood_gate(
    gate: OODRejectionGate,
    output_path: Optional[Path] = None,
    provenance: Optional[Dict[str, Any]] = None,
) -> Path:
    """Persist a fitted gate so live inference can apply a real OOD boundary."""
    path = Path(output_path) if output_path else DEFAULT_OOD_GATE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = gate.to_artifact(provenance or {})
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_persisted_ood_gate(
    path: Optional[Path] = None,
) -> Optional[OODRejectionGate]:
    """Load the persisted gate when present and structurally valid.

    Returns ``None`` when the artifact is absent or invalid so callers can report
    an honest ``NOT_FITTED`` status instead of inventing a boundary.
    """
    candidate = Path(path) if path else DEFAULT_OOD_GATE_PATH
    if not candidate.is_file():
        return None
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
        gate = OODRejectionGate.from_artifact(payload)
    except (OSError, ValueError):
        return None
    return gate
