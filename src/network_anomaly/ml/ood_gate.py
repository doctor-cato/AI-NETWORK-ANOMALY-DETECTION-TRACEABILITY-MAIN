"""Out-of-Distribution (OOD) Detection and Inference Rejection Gate.

Implements Issue #99 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

from network_anomaly.config import PROJECT_ROOT
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS

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

        non_finite_feats = [
            name for i, name in enumerate(self.feature_names) if not np.isfinite(x_vec[i])
        ]
        if non_finite_feats:
            return OODDecision(
                action=OODAction.ABSTAIN,
                is_ood=True,
                ood_score=1.0,
                reason="NON_FINITE_FEATURE_VALUE",
                offending_features=non_finite_feats[:5],
                metadata={"total_non_finite": len(non_finite_feats)},
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
    def from_artifact(
        cls,
        payload: Dict[str, Any],
        *,
        expected_feature_names: Optional[Sequence[str]] = None,
        expected_preprocessor_sha256: Optional[str] = None,
    ) -> "OODRejectionGate":
        """Rebuild a gate from a validated artifact payload."""
        if not isinstance(payload, dict):
            raise ValueError("OOD gate artifact must be a JSON object")
        schema_version = payload.get("schema_version")
        if isinstance(schema_version, bool) or schema_version != OOD_GATE_SCHEMA_VERSION:
            raise ValueError(
                f"OOD gate artifact schema_version mismatch: expected {OOD_GATE_SCHEMA_VERSION}, "
                f"got {schema_version!r}"
            )
        if payload.get("artifact_type") != "ood_reference_gate":
            raise ValueError(
                f"OOD gate artifact_type mismatch: got {payload.get('artifact_type')!r}"
            )

        feature_names = payload.get("feature_names")
        means = payload.get("means")
        stds = payload.get("stds")
        min_bounds = payload.get("min_bounds")
        max_bounds = payload.get("max_bounds")
        if not isinstance(feature_names, list) or not feature_names:
            raise ValueError("OOD gate artifact is missing feature_names")
        norm_features = [str(name) for name in feature_names]
        if expected_feature_names is not None and norm_features != [
            str(name) for name in expected_feature_names
        ]:
            raise ValueError("OOD gate feature_names mismatch against expected feature contract")

        std_margin = payload.get("std_margin", 4.0)
        stat_threshold = payload.get("statistical_threshold", 5.0)
        if (
            isinstance(std_margin, bool)
            or not isinstance(std_margin, (int, float))
            or not math.isfinite(float(std_margin))
            or float(std_margin) <= 0.0
        ):
            raise ValueError(f"OOD gate artifact invalid std_margin: {std_margin!r}")
        if (
            isinstance(stat_threshold, bool)
            or not isinstance(stat_threshold, (int, float))
            or not math.isfinite(float(stat_threshold))
            or float(stat_threshold) <= 0.0
        ):
            raise ValueError(f"OOD gate artifact invalid statistical_threshold: {stat_threshold!r}")

        arrays = {}
        for label, values in (
            ("means", means),
            ("stds", stds),
            ("min_bounds", min_bounds),
            ("max_bounds", max_bounds),
        ):
            if not isinstance(values, list) or len(values) != len(feature_names):
                raise ValueError(f"OOD gate artifact '{label}' length mismatch")
            if any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in values):
                raise ValueError(f"OOD gate artifact '{label}' contains non-numeric entries")
            arr = np.asarray([float(v) for v in values], dtype=np.float64)
            if not np.all(np.isfinite(arr)):
                raise ValueError(f"OOD gate artifact '{label}' contains non-finite values")
            arrays[label] = arr
        if np.any(arrays["stds"] <= 0):
            raise ValueError("OOD gate artifact contains non-positive standard deviations")
        if np.any(arrays["min_bounds"] > arrays["max_bounds"]):
            raise ValueError("OOD gate artifact has min_bounds > max_bounds")

        provenance = payload.get("provenance")
        if not isinstance(provenance, dict):
            raise ValueError("OOD gate artifact 'provenance' must be a JSON object")
        fit_rows = provenance.get("fit_rows")
        if isinstance(fit_rows, bool) or not isinstance(fit_rows, int) or fit_rows <= 0:
            raise ValueError(f"OOD gate provenance fit_rows must be positive int, got {fit_rows!r}")
        if expected_preprocessor_sha256 is not None:
            if not isinstance(provenance, dict):
                raise ValueError("OOD gate artifact missing provenance for preprocessor check")
            gate_prep_sha = provenance.get("preprocessor_artifact_sha256")
            if (
                not isinstance(gate_prep_sha, str)
                or gate_prep_sha.strip().lower()
                != str(expected_preprocessor_sha256).strip().lower()
            ):
                raise ValueError(
                    "OOD gate preprocessor_artifact_sha256 mismatch: "
                    f"gate={gate_prep_sha!r} != expected={expected_preprocessor_sha256!r}"
                )

        gate = cls(
            std_margin=float(std_margin),
            statistical_threshold=float(stat_threshold),
        )
        gate.feature_names = norm_features
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
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def verify_ood_gate_artifact(
    path: Optional[Path] = None,
    *,
    expected_preprocessor_sha256: Optional[str] = None,
    expected_sha256: Optional[str] = None,
    expected_feature_names: Optional[Sequence[str]] = ML_FEATURE_COLUMNS,
) -> tuple[OODRejectionGate, Dict[str, Any]]:
    """Verify OOD gate artifact SHA-256, schema, provenance, and rebuild the gate."""
    candidate = Path(path) if path else DEFAULT_OOD_GATE_PATH
    if not candidate.is_file():
        raise FileNotFoundError(f"OOD gate artifact not found at '{candidate}'")
    raw_bytes = candidate.read_bytes()
    actual_sha256 = hashlib.sha256(raw_bytes).hexdigest().lower()
    if expected_sha256 is not None:
        exp = str(expected_sha256).strip().lower()
        if actual_sha256 != exp:
            raise ValueError(
                f"OOD gate artifact SHA-256 mismatch: expected {exp}, got {actual_sha256}"
            )
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"OOD gate artifact JSON unreadable at '{candidate}': {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"OOD gate artifact must be a JSON object at '{candidate}'")
    provenance = payload.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError(f"OOD gate artifact missing 'provenance' metadata at '{candidate}'")
    fit_rows = provenance.get("fit_rows")
    if isinstance(fit_rows, bool) or not isinstance(fit_rows, int) or fit_rows <= 0:
        raise ValueError(f"OOD gate artifact invalid fit_rows={fit_rows!r} at '{candidate}'")
    gate = OODRejectionGate.from_artifact(
        payload,
        expected_feature_names=expected_feature_names,
        expected_preprocessor_sha256=expected_preprocessor_sha256,
    )
    prep_sha = provenance.get("preprocessor_artifact_sha256")
    return gate, {
        "status": "FITTED",
        "path": str(candidate),
        "sha256": actual_sha256,
        "schema_version": payload["schema_version"],
        "artifact_type": payload["artifact_type"],
        "feature_count": len(gate.feature_names),
        "fit_rows": fit_rows,
        "partition": provenance.get("partition"),
        "split_protocol_version": provenance.get("split_protocol_version"),
        "preprocessor_artifact_sha256": (
            str(prep_sha).strip().lower()
            if isinstance(prep_sha, str) and prep_sha.strip()
            else None
        ),
    }


def load_persisted_ood_gate(
    path: Optional[Path] = None,
    *,
    expected_preprocessor_sha256: Optional[str] = None,
    expected_feature_names: Optional[Sequence[str]] = ML_FEATURE_COLUMNS,
    strict: bool = False,
) -> Optional[OODRejectionGate]:
    """Load the persisted gate when present and structurally valid.

    When ``strict=False`` (default), returns ``None`` if the artifact is absent or
    invalid so research callers can report ``NOT_FITTED``. When ``strict=True``,
    corrupted or mismatched artifacts raise ``ValueError`` instead of returning ``None``.
    """
    candidate = Path(path) if path else DEFAULT_OOD_GATE_PATH
    if not candidate.is_file():
        return None
    try:
        gate, _ = verify_ood_gate_artifact(
            candidate,
            expected_preprocessor_sha256=expected_preprocessor_sha256,
            expected_feature_names=expected_feature_names,
        )
    except (OSError, ValueError) as exc:
        if strict:
            raise ValueError(f"Failed to verify OOD gate artifact at '{candidate}': {exc}") from exc
        return None
    return gate
