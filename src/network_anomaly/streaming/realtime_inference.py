"""Real-time multi-model AI inference for the live streaming pipeline.

The engine dispatches each event to the four verified model artifacts through
:class:`network_anomaly.models.registry.ModelRegistry`. It no longer fabricates
scores: when an artifact is missing the event is reported as
``inference_mode="UNAVAILABLE"`` with no per-model predictions, and the caller
can route the event to trace-only handling.

Score semantics
---------------
Random Forest and XGBoost emit a calibrated binary probability (``P(attack)``).
Isolation Forest and Autoencoder emit a raw anomaly score plus its empirical
percentile against the validation benign population. The weighted ensemble is
therefore a *normalized anomaly score*, not a probability of attack; that is
recorded in ``ensemble_score_semantics`` and must be shown as such by clients.

Demo heuristic scoring exists only when ``demo_heuristics=True`` is passed
explicitly. Every demo decision carries ``inference_mode="DEMO_HEURISTIC"``.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np

from network_anomaly.canonical.event import CanonicalSecurityEvent
from network_anomaly.ml.ood_gate import OODRejectionGate
from network_anomaly.models.registry import (
    FeatureContractError,
    ModelRegistry,
    ModelScore,
)
from network_anomaly.risk.aggregation import (
    AggregationPolicy,
    MultiModelDecisionAggregator,
)

ENSEMBLE_SCORE_SEMANTICS = "weighted_normalized_anomaly_score_not_probability"
DEMO_SCORE_SEMANTICS = "demo_heuristic_score_not_model_output"


@dataclass
class LiveInferenceDecision:
    event_id: str
    inference_mode: str
    ensemble_is_anomaly: bool
    ensemble_score: float
    ensemble_score_semantics: str
    is_ood: bool
    ood_reason: Optional[str]
    model_predictions: Dict[str, Dict[str, Any]]
    total_inference_latency_us: float
    per_model_latency_us: Dict[str, float]
    participating_models: List[str] = field(default_factory=list)
    unavailable_models: List[str] = field(default_factory=list)
    abstained_due_to_ood: bool = False
    ood_gate_status: str = "NOT_FITTED"
    ensemble_policy: str = AggregationPolicy.WEIGHTED_ENSEMBLE.value

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _load_ood_gate(
    gate: Optional[OODRejectionGate],
) -> tuple[Optional[OODRejectionGate], str]:
    """Use the supplied gate when fitted; otherwise attempt the persisted reference stats."""
    if gate is not None and gate.is_fitted:
        return gate, "FITTED"
    try:
        from network_anomaly.ml.ood_gate import load_persisted_ood_gate

        persisted = load_persisted_ood_gate()
    except Exception:
        persisted = None
    if persisted is not None and persisted.is_fitted:
        return persisted, "FITTED"
    return None, "NOT_FITTED"


class RealtimeInferenceEngine:
    """Orchestrates real inference across the four verified models with OOD rejection."""

    def __init__(
        self,
        registry: Optional[ModelRegistry] = None,
        ood_gate: Optional[OODRejectionGate] = None,
        aggregator: Optional[MultiModelDecisionAggregator] = None,
        demo_heuristics: bool = False,
    ):
        self.registry = registry or ModelRegistry()
        self.aggregator = aggregator or MultiModelDecisionAggregator(
            policy=AggregationPolicy.WEIGHTED_ENSEMBLE
        )
        self.demo_heuristics = demo_heuristics
        self.ood_gate, self.ood_gate_status = _load_ood_gate(ood_gate)

        self.total_inferences: int = 0
        self.total_anomalies_detected: int = 0
        self.total_ood_events: int = 0
        self.total_unavailable_events: int = 0
        self.total_demo_decisions: int = 0
        self.total_inference_errors: int = 0

    # ------------------------------------------------------------ readiness
    def readiness(self) -> Dict[str, Any]:
        summary = self.registry.summary()
        summary["ood_gate_status"] = self.ood_gate_status
        summary["inference_mode"] = (
            "REAL_MODELS"
            if self.registry.ready_count > 0
            else ("DEMO_HEURISTIC" if self.demo_heuristics else "UNAVAILABLE")
        )
        summary["total_inferences"] = self.total_inferences
        summary["total_unavailable_events"] = self.total_unavailable_events
        summary["total_inference_errors"] = self.total_inference_errors
        return summary

    @property
    def model_ready(self) -> bool:
        return self.registry.ready_count > 0

    # ------------------------------------------------------------ inference
    def infer_event(
        self,
        event: CanonicalSecurityEvent,
        feature_dict: Dict[str, float],
        feature_vector: Optional[np.ndarray] = None,
    ) -> LiveInferenceDecision:
        """Run OOD checks and genuine four-model inference for one security event."""
        start_t = time.perf_counter()
        self.total_inferences += 1

        ood_dec = None
        if self.ood_gate is not None and self.ood_gate.is_fitted:
            ood_dec = self.ood_gate.evaluate_sample(feature_dict)
        is_ood = bool(ood_dec.is_ood) if ood_dec else False
        ood_reason = ood_dec.reason if ood_dec else None
        if is_ood:
            self.total_ood_events += 1

        model_scores: Dict[str, ModelScore] = {}
        failure_reason: Optional[str] = None
        if self.registry.ready_count > 0:
            try:
                model_scores = self.registry.predict_all(feature_dict)
            except FeatureContractError as exc:
                failure_reason = str(exc)
            except Exception as exc:  # pragma: no cover - defensive
                failure_reason = f"{type(exc).__name__}: {exc}"

        if not model_scores:
            if failure_reason:
                self.total_inference_errors += 1
            self.total_unavailable_events += 1
            if self.demo_heuristics:
                return self._demo_decision(event, feature_dict, start_t, is_ood, ood_reason)
            return LiveInferenceDecision(
                event_id=event.event_id,
                inference_mode="UNAVAILABLE",
                ensemble_is_anomaly=False,
                ensemble_score=0.0,
                ensemble_score_semantics=ENSEMBLE_SCORE_SEMANTICS,
                is_ood=is_ood,
                ood_reason=ood_reason or failure_reason,
                model_predictions={},
                total_inference_latency_us=round((time.perf_counter() - start_t) * 1e6, 2),
                per_model_latency_us={},
                participating_models=[],
                unavailable_models=[
                    status.model_key
                    for status in self.registry.statuses()
                    if not status.decision_ready
                ],
                abstained_due_to_ood=is_ood,
                ood_gate_status=self.ood_gate_status,
                ensemble_policy=self.aggregator.policy.value,
            )

        model_predictions: Dict[str, Dict[str, Any]] = {}
        per_model_lat: Dict[str, float] = {}
        aggregate_inputs: Dict[str, float] = {}
        for model_key, score in model_scores.items():
            model_predictions[model_key] = {
                "raw_score": round(float(score.raw_score), 6),
                "score": (
                    None
                    if score.normalized_score is None
                    else round(float(score.normalized_score), 6)
                ),
                "normalized_score": (
                    None
                    if score.normalized_score is None
                    else round(float(score.normalized_score), 6)
                ),
                "is_anomaly": score.is_anomaly,
                "threshold": score.threshold,
                "score_semantics": score.score_semantics,
                "normalization_note": score.normalization_note,
                "latency_us": round(float(score.latency_us), 3),
            }
            per_model_lat[model_key] = round(float(score.latency_us), 3)
            if score.normalized_score is not None:
                aggregate_inputs[model_key] = float(score.normalized_score)

        if not aggregate_inputs:
            self.total_unavailable_events += 1
            return LiveInferenceDecision(
                event_id=event.event_id,
                inference_mode="UNAVAILABLE",
                ensemble_is_anomaly=False,
                ensemble_score=0.0,
                ensemble_score_semantics=ENSEMBLE_SCORE_SEMANTICS,
                is_ood=is_ood,
                ood_reason=ood_reason or "no_model_returned_a_normalized_score",
                model_predictions=model_predictions,
                total_inference_latency_us=round((time.perf_counter() - start_t) * 1e6, 2),
                per_model_latency_us=per_model_lat,
                participating_models=list(model_scores),
                unavailable_models=[
                    status.model_key
                    for status in self.registry.statuses()
                    if not status.decision_ready
                ],
                abstained_due_to_ood=is_ood,
                ood_gate_status=self.ood_gate_status,
                ensemble_policy=self.aggregator.policy.value,
            )

        agg_res = self.aggregator.aggregate(
            rf_prob=aggregate_inputs.get("random_forest"),
            xgb_prob=aggregate_inputs.get("xgboost"),
            if_score=aggregate_inputs.get("isolation_forest"),
            ae_error_norm=aggregate_inputs.get("autoencoder"),
        )

        abstained = is_ood
        ensemble_is_anomaly = bool(agg_res.is_anomaly) and not is_ood
        if ensemble_is_anomaly:
            self.total_anomalies_detected += 1

        return LiveInferenceDecision(
            event_id=event.event_id,
            inference_mode="REAL_MODELS",
            ensemble_is_anomaly=ensemble_is_anomaly,
            ensemble_score=round(float(agg_res.combined_probability), 4),
            ensemble_score_semantics=ENSEMBLE_SCORE_SEMANTICS,
            is_ood=is_ood,
            ood_reason=ood_reason,
            model_predictions=model_predictions,
            total_inference_latency_us=round((time.perf_counter() - start_t) * 1e6, 2),
            per_model_latency_us=per_model_lat,
            participating_models=list(model_scores),
            unavailable_models=[
                status.model_key for status in self.registry.statuses() if not status.decision_ready
            ],
            abstained_due_to_ood=abstained,
            ood_gate_status=self.ood_gate_status,
            ensemble_policy=agg_res.policy_used.value,
        )

    # ------------------------------------------------------------------ demo
    def _demo_decision(
        self,
        event: CanonicalSecurityEvent,
        feature_dict: Dict[str, float],
        start_t: float,
        is_ood: bool,
        ood_reason: Optional[str],
    ) -> LiveInferenceDecision:
        """Explicitly labelled demo heuristic used only when requested by the operator."""
        self.total_demo_decisions += 1
        out_bytes = float(feature_dict.get("bytes_out", 0.0))
        in_bytes = float(feature_dict.get("bytes_in", 0.0))
        is_tcp = float(feature_dict.get("is_tcp", 0.0)) > 0.5
        suspicious = (out_bytes > 10_000) or (is_tcp and in_bytes > 500 and out_bytes == 0.0)
        base = 0.85 if suspicious else 0.08
        predictions = {
            key: {
                "raw_score": base,
                "score": base,
                "normalized_score": base,
                "is_anomaly": suspicious,
                "threshold": 0.5,
                "score_semantics": DEMO_SCORE_SEMANTICS,
                "normalization_note": "demo_mode",
            }
            for key in ("random_forest", "xgboost", "isolation_forest", "autoencoder")
        }
        self.total_anomalies_detected += 1 if suspicious else 0
        return LiveInferenceDecision(
            event_id=event.event_id,
            inference_mode="DEMO_HEURISTIC",
            ensemble_is_anomaly=suspicious,
            ensemble_score=0.85 if suspicious else 0.08,
            ensemble_score_semantics=DEMO_SCORE_SEMANTICS,
            is_ood=is_ood,
            ood_reason=ood_reason,
            model_predictions=predictions,
            total_inference_latency_us=round((time.perf_counter() - start_t) * 1e6, 2),
            per_model_latency_us={
                "random_forest": 0.0,
                "xgboost": 0.0,
                "isolation_forest": 0.0,
                "autoencoder": 0.0,
            },
            participating_models=[],
            unavailable_models=[status.model_key for status in self.registry.statuses()],
            ood_gate_status=self.ood_gate_status,
            ensemble_policy="DEMO_HEURISTIC",
        )
