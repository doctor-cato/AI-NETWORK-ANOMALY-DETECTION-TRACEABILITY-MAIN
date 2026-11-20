"""Multi-model decision aggregation policies.

Implements Issue #109 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional


class AggregationPolicy(str, Enum):
    WEIGHTED_ENSEMBLE = "WEIGHTED_ENSEMBLE"  # Default recommended: calibrated linear blend
    OOD_AWARE_ENSEMBLE = (
        "OOD_AWARE_ENSEMBLE"  # Shift weights toward XGB+IF under moderate OOD drift
    )
    RANDOM_FOREST_PRIMARY = "RANDOM_FOREST_PRIMARY"  # RF is primary, IF/AE supplementary
    STRICT_CONSENSUS = "STRICT_CONSENSUS"  # All active models must agree
    MAX_SEVERITY = "MAX_SEVERITY"  # Pessimistic fail-closed policy


@dataclass
class AggregatedDecision:
    is_anomaly: bool
    combined_probability: float
    policy_used: AggregationPolicy
    contributing_models: Dict[str, float]
    consensus_ratio: float


class MultiModelDecisionAggregator:
    """Combines predictions from Random Forest, XGBoost, Isolation Forest, and Autoencoder."""

    # Default multi-model weights for NetFlow Sentinel v2 ensemble aggregation
    DEFAULT_WEIGHTS = {
        "random_forest": 0.40,
        "xgboost": 0.30,
        "isolation_forest": 0.15,
        "autoencoder": 0.15,
    }
    OOD_SHIFT_WEIGHTS = {
        "random_forest": 0.15,
        "xgboost": 0.40,
        "isolation_forest": 0.35,
        "autoencoder": 0.10,
    }

    def __init__(
        self,
        policy: AggregationPolicy = AggregationPolicy.WEIGHTED_ENSEMBLE,
        weights: Optional[Dict[str, float]] = None,
    ):
        self.policy = policy
        self.weights = weights or dict(self.DEFAULT_WEIGHTS)

    def aggregate(
        self,
        rf_prob: Optional[float] = None,
        xgb_prob: Optional[float] = None,
        if_score: Optional[float] = None,
        ae_error_norm: Optional[float] = None,
        ood_score: Optional[float] = None,
    ) -> AggregatedDecision:
        """Combine available model probability outputs into a single aggregated decision."""
        models: Dict[str, float] = {}
        if rf_prob is not None:
            models["random_forest"] = float(rf_prob)
        if xgb_prob is not None:
            models["xgboost"] = float(xgb_prob)
        if if_score is not None:
            # Map IF anomaly score (typically negative or 0..1) to probability
            models["isolation_forest"] = float(if_score)
        if ae_error_norm is not None:
            # Normalized reconstruction error [0, 1]
            models["autoencoder"] = float(ae_error_norm)

        if not models:
            return AggregatedDecision(
                is_anomaly=False,
                combined_probability=0.0,
                policy_used=self.policy,
                contributing_models={},
                consensus_ratio=0.0,
            )

        if self.policy in (
            AggregationPolicy.WEIGHTED_ENSEMBLE,
            AggregationPolicy.OOD_AWARE_ENSEMBLE,
        ):
            active_weights = (
                self.OOD_SHIFT_WEIGHTS
                if (
                    self.policy == AggregationPolicy.OOD_AWARE_ENSEMBLE
                    and ood_score is not None
                    and float(ood_score) >= 0.35
                )
                else self.weights
            )
            # Re-normalize weights for available models
            avail_weights = {m: active_weights.get(m, 0.25) for m in models}
            total_w = sum(avail_weights.values())
            norm_w = {m: w / total_w for m, w in avail_weights.items()}

            combined_prob = sum(models[m] * norm_w[m] for m in models)
            is_anomaly = combined_prob >= 0.50

        elif self.policy == AggregationPolicy.RANDOM_FOREST_PRIMARY:
            if "random_forest" in models:
                combined_prob = models["random_forest"]
            else:
                combined_prob = max(models.values())
            is_anomaly = combined_prob >= 0.50

        elif self.policy == AggregationPolicy.STRICT_CONSENSUS:
            is_anomaly = all(p >= 0.50 for p in models.values())
            combined_prob = (
                min(models.values()) if is_anomaly else sum(models.values()) / len(models)
            )

        elif self.policy == AggregationPolicy.MAX_SEVERITY:
            combined_prob = max(models.values())
            is_anomaly = combined_prob >= 0.50

        else:
            raise ValueError(f"Unknown policy: {self.policy}")

        anomaly_count = sum(1 for p in models.values() if p >= 0.50)
        consensus_ratio = anomaly_count / len(models)

        return AggregatedDecision(
            is_anomaly=is_anomaly,
            combined_probability=round(combined_prob, 4),
            policy_used=self.policy,
            contributing_models={k: round(v, 4) for k, v in models.items()},
            consensus_ratio=round(consensus_ratio, 2),
        )
