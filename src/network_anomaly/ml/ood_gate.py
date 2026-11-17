"""Out-of-Distribution (OOD) Detection and Inference Rejection Gate.

Implements Issue #99 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import numpy as np


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
