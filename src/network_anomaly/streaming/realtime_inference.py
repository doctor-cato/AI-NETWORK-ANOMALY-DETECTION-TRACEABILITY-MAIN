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

import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np

from network_anomaly.canonical.event import CanonicalSecurityEvent
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS
from network_anomaly.ml.ood_gate import (
    OODRejectionGate,
    cross_check_same_boundary_embedded_manifest,
    resolve_expected_ood_gate_sha256,
    validate_ood_gate_instance,
)
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
SUPPORTED_RUNTIME_MODES = ("research", "deployment")


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


def _parse_optional_bool_env(name: str) -> Optional[bool]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    norm = raw.lower()
    if norm in {"1", "true", "yes"}:
        return True
    if norm in {"0", "false", "no"}:
        return False
    raise ValueError(f"Invalid boolean value for {name}: {raw!r}")


def resolve_runtime_policy(
    runtime_mode: Optional[str] = None,
    require_ood_gate: Optional[bool] = None,
) -> tuple[str, bool, str]:
    """Resolve effective ``(runtime_mode, require_ood_gate, policy_source)``.

    Defaults fail-closed to ``deployment`` when neither ``runtime_mode`` nor
    ``NETFLOW_RUNTIME_MODE`` is supplied; ``research`` mode is active only when
    explicitly selected.
    """
    if runtime_mode is not None:
        raw_mode = runtime_mode
        policy_source = "explicit_argument"
    else:
        env_mode = os.environ.get("NETFLOW_RUNTIME_MODE", "").strip()
        if env_mode:
            raw_mode = env_mode
            policy_source = "env:NETFLOW_RUNTIME_MODE"
        else:
            raw_mode = "deployment"
            policy_source = "default_fail_closed:deployment"

    norm_mode = str(raw_mode).strip().lower()
    if norm_mode not in SUPPORTED_RUNTIME_MODES:
        raise ValueError(
            f"Unsupported runtime_mode {raw_mode!r}; expected one of {SUPPORTED_RUNTIME_MODES}"
        )

    env_require = (
        _parse_optional_bool_env("NETFLOW_REQUIRE_OOD_GATE") if require_ood_gate is None else None
    )
    requested_require = require_ood_gate if require_ood_gate is not None else env_require
    if norm_mode == "deployment" and requested_require is False:
        raise ValueError("require_ood_gate cannot be False when runtime_mode='deployment'")
    effective_require = (
        bool(requested_require) if requested_require is not None else (norm_mode == "deployment")
    )
    return norm_mode, effective_require, policy_source


def _resolve_runtime_policy(
    runtime_mode: Optional[str],
    require_ood_gate: Optional[bool],
) -> tuple[str, bool]:
    mode, req, _ = resolve_runtime_policy(runtime_mode, require_ood_gate)
    return mode, req


def _load_ood_gate(
    gate: Optional[OODRejectionGate],
    artifacts_dir: Optional[Any] = None,
    expected_preprocessor_sha256: Optional[str] = None,
    *,
    runtime_mode: str = "research",
    require_ood_gate: bool = False,
    expected_ood_gate_sha256: Optional[str] = None,
) -> tuple[Optional[OODRejectionGate], str, Optional[str], Optional[str], str]:
    """Verify supplied research gate or persisted reference artifact.

    Distinguishes missing artifact (``NOT_FITTED``) from corrupted, mismatched,
    unprovenanced, unanchored-in-deployment, or disallowed gate injection (``ERROR``).
    """
    if gate is not None:
        if runtime_mode == "deployment" or require_ood_gate:
            return (
                None,
                "ERROR",
                "ValueError: Direct in-memory ood_gate injection is disallowed when "
                "runtime_mode='deployment' or require_ood_gate=True; persisted verified "
                "artifact is required",
                None,
                "disallowed_in_memory_injection",
            )
        if (
            isinstance(gate, OODRejectionGate)
            and type(getattr(gate, "is_fitted", None)) is bool
            and not gate.is_fitted
        ):
            return (
                None,
                "NOT_FITTED",
                "Explicitly supplied OODRejectionGate is not fitted",
                None,
                "none",
            )
        try:
            meta = validate_ood_gate_instance(
                gate,
                expected_feature_names=ML_FEATURE_COLUMNS,
                expected_preprocessor_sha256=expected_preprocessor_sha256,
                require_provenance=True,
                require_preprocessor_sha256=bool(expected_preprocessor_sha256),
            )
            return gate, "FITTED", None, meta.get("artifact_sha256"), "in_memory_research_gate"
        except Exception as exc:
            return None, "ERROR", f"{type(exc).__name__}: {exc}", None, "invalid_in_memory_gate"

    from pathlib import Path

    from network_anomaly.ml.ood_gate import DEFAULT_OOD_GATE_PATH, verify_ood_gate_artifact

    try:
        trusted_sha, trust_source = resolve_expected_ood_gate_sha256(expected_ood_gate_sha256)
    except Exception as exc:
        return None, "ERROR", f"{type(exc).__name__}: {exc}", None, "invalid_expected_sha256"

    gate_path = (
        Path(artifacts_dir) / "ml" / "ood_reference_gate.json"
        if artifacts_dir is not None
        else DEFAULT_OOD_GATE_PATH
    )
    if not gate_path.is_file():
        return None, "NOT_FITTED", None, None, "none"

    if (runtime_mode == "deployment" or require_ood_gate) and trusted_sha is None:
        return (
            None,
            "ERROR",
            "ValueError: Trusted expected_ood_gate_sha256 (or NETFLOW_OOD_GATE_SHA256) is "
            "required to verify persisted OOD gate in deployment mode; co-located unsigned "
            "manifests share the same filesystem trust boundary",
            None,
            "missing_trusted_expected_sha256",
        )

    try:
        verified_gate, meta = verify_ood_gate_artifact(
            gate_path,
            expected_preprocessor_sha256=expected_preprocessor_sha256,
            expected_sha256=trusted_sha,
        )
        same_boundary_source = cross_check_same_boundary_embedded_manifest(
            gate_path, str(meta["sha256"])
        )
        anchor = trust_source or same_boundary_source or "unanchored_local_artifact"
        return verified_gate, "FITTED", None, str(meta["sha256"]), anchor
    except Exception as exc:
        return None, "ERROR", f"{type(exc).__name__}: {exc}", None, "verification_failed"


class RealtimeInferenceEngine:
    """Orchestrates real inference across the four verified models with OOD rejection."""

    def __init__(
        self,
        registry: Optional[ModelRegistry] = None,
        ood_gate: Optional[OODRejectionGate] = None,
        aggregator: Optional[MultiModelDecisionAggregator] = None,
        demo_heuristics: bool = False,
        runtime_mode: Optional[str] = None,
        require_ood_gate: Optional[bool] = None,
        expected_ood_gate_sha256: Optional[str] = None,
    ):
        self.registry = registry or ModelRegistry()
        self.aggregator = aggregator or MultiModelDecisionAggregator(
            policy=AggregationPolicy.WEIGHTED_ENSEMBLE
        )
        self.demo_heuristics = demo_heuristics
        self.expected_ood_gate_sha256 = (
            expected_ood_gate_sha256.strip().lower()
            if isinstance(expected_ood_gate_sha256, str) and expected_ood_gate_sha256.strip()
            else expected_ood_gate_sha256
        )
        self.runtime_mode, self.require_ood_gate, self.runtime_policy_source = (
            resolve_runtime_policy(runtime_mode, require_ood_gate)
        )
        try:
            self._resolved_expected_ood_gate_sha256, self._resolved_expected_ood_gate_source = (
                resolve_expected_ood_gate_sha256(expected_ood_gate_sha256)
            )
        except Exception:
            self._resolved_expected_ood_gate_sha256, self._resolved_expected_ood_gate_source = (
                None,
                "invalid_expected_sha256",
            )
        (
            self.ood_gate,
            self.ood_gate_status,
            self.ood_gate_error,
            self.ood_gate_sha256,
            self.ood_gate_trust_anchor,
        ) = _load_ood_gate(
            ood_gate,
            artifacts_dir=getattr(self.registry, "artifacts_dir", None),
            expected_preprocessor_sha256=getattr(self.registry, "preprocessor_sha256", None),
            runtime_mode=self.runtime_mode,
            require_ood_gate=self.require_ood_gate,
            expected_ood_gate_sha256=expected_ood_gate_sha256,
        )
        if (
            self.require_ood_gate
            and self.ood_gate_status == "NOT_FITTED"
            and not self.ood_gate_error
        ):
            self.ood_gate_error = "ood_gate_artifact_missing_in_deployment_mode"

        self.total_inferences: int = 0
        self.total_anomalies_detected: int = 0
        self.total_ood_events: int = 0
        self.total_unavailable_events: int = 0
        self.total_demo_decisions: int = 0
        self.total_inference_errors: int = 0

    def _ood_policy_blocked_reason(self) -> Optional[str]:
        """Return fail-closed block reason when OOD gate state violates policy."""
        if self.ood_gate_status == "ERROR":
            return f"ood_gate_invalid: {self.ood_gate_error or 'verification_failed'}"
        if self.require_ood_gate and self.ood_gate_status != "FITTED":
            return f"ood_gate_required_in_{self.runtime_mode}_mode"
        return None

    # ------------------------------------------------------------ readiness
    def readiness(self) -> Dict[str, Any]:
        summary = self.registry.summary()
        ood_block = self._ood_policy_blocked_reason()
        summary["runtime_mode"] = self.runtime_mode
        summary["runtime_policy_source"] = self.runtime_policy_source
        summary["require_ood_gate"] = self.require_ood_gate
        summary["expected_ood_gate_sha256_configured"] = bool(
            self._resolved_expected_ood_gate_sha256
        )
        summary["ood_gate_status"] = self.ood_gate_status
        summary["ood_gate_error"] = self.ood_gate_error
        summary["ood_gate_sha256"] = self.ood_gate_sha256
        summary["ood_gate_trust_anchor"] = self.ood_gate_trust_anchor
        if ood_block is not None:
            summary["ai_ready"] = False
            summary["inference_mode"] = "UNAVAILABLE"
            summary["ood_policy_error"] = ood_block
        else:
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
        return self.registry.ready_count > 0 and self._ood_policy_blocked_reason() is None

    def _unavailable_ood_decision(
        self,
        event_id: str,
        start_t: float,
        ood_reason: str,
        ood_gate_status: str,
    ) -> LiveInferenceDecision:
        return LiveInferenceDecision(
            event_id=event_id,
            inference_mode="UNAVAILABLE",
            ensemble_is_anomaly=False,
            ensemble_score=0.0,
            ensemble_score_semantics=ENSEMBLE_SCORE_SEMANTICS,
            is_ood=True,
            ood_reason=ood_reason,
            model_predictions={},
            total_inference_latency_us=round((time.perf_counter() - start_t) * 1e6, 2),
            per_model_latency_us={},
            participating_models=[],
            unavailable_models=[status.model_key for status in self.registry.statuses()],
            abstained_due_to_ood=True,
            ood_gate_status=ood_gate_status,
            ensemble_policy=self.aggregator.policy.value,
        )

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

        ood_block_reason = self._ood_policy_blocked_reason()
        if ood_block_reason is not None:
            if self.ood_gate_status == "ERROR":
                self.total_inference_errors += 1
            self.total_unavailable_events += 1
            self.total_ood_events += 1
            return self._unavailable_ood_decision(
                event.event_id, start_t, ood_block_reason, self.ood_gate_status
            )

        ood_dec = None
        if self.ood_gate_status == "FITTED":
            if (
                self.ood_gate is None
                or type(getattr(self.ood_gate, "is_fitted", None)) is not bool
                or not self.ood_gate.is_fitted
            ):
                self.total_inference_errors += 1
                self.total_unavailable_events += 1
                self.total_ood_events += 1
                return self._unavailable_ood_decision(
                    event.event_id, start_t, "ood_gate_unavailable_after_init", "ERROR"
                )
            try:
                ood_dec = self.ood_gate.evaluate_sample(feature_dict)
            except Exception as exc:
                self.total_inference_errors += 1
                self.total_unavailable_events += 1
                self.total_ood_events += 1
                return self._unavailable_ood_decision(
                    event.event_id,
                    start_t,
                    f"ood_gate_runtime_error: {type(exc).__name__}: {exc}",
                    "ERROR",
                )
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
