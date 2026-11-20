"""Out-of-Distribution (OOD) Detection and Inference Rejection Gate.

Implements Issue #99 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

import numpy as np

from network_anomaly.config import PROJECT_ROOT
from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS

OOD_GATE_SCHEMA_VERSION = 1
DEFAULT_OOD_GATE_PATH = PROJECT_ROOT / "artifacts" / "ml" / "ood_reference_gate.json"
_HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def normalize_sha256_hex(value: Any, *, field_name: str = "sha256") -> str:
    """Validate and normalize a 64-char hex SHA-256 string."""
    if not isinstance(value, str):
        raise ValueError(
            f"Invalid {field_name}: expected 64-hex string, got {type(value).__name__}"
        )
    norm = value.strip().lower()
    if not _HEX_SHA256_RE.fullmatch(norm):
        raise ValueError(f"Invalid {field_name}: expected 64-hex SHA-256, got {value!r}")
    return norm


def resolve_expected_ood_gate_sha256(
    explicit_sha256: Optional[str] = None,
) -> tuple[Optional[str], Optional[str]]:
    """Resolve an externally supplied or build-embedded expected OOD gate SHA-256 trust anchor.

    Returns ``(sha256, source)`` from either an explicit caller argument,
    ``NETFLOW_OOD_GATE_SHA256``, or ``NETFLOW_EMBEDDED_OOD_GATE_SHA256``
    (compiled into a trusted launcher/executable outside the writable artifact
    directory). Unsigned manifests co-located with the artifact are intentionally
    NOT treated as independent trust anchors.
    """
    if explicit_sha256 is not None:
        return (
            normalize_sha256_hex(explicit_sha256, field_name="expected_ood_gate_sha256"),
            "explicit_expected_sha256",
        )
    env_sha = os.environ.get("NETFLOW_OOD_GATE_SHA256", "").strip()
    if env_sha:
        return (
            normalize_sha256_hex(env_sha, field_name="NETFLOW_OOD_GATE_SHA256"),
            "env:NETFLOW_OOD_GATE_SHA256",
        )
    embedded_sha = os.environ.get("NETFLOW_EMBEDDED_OOD_GATE_SHA256", "").strip()
    if embedded_sha:
        return (
            normalize_sha256_hex(embedded_sha, field_name="NETFLOW_EMBEDDED_OOD_GATE_SHA256"),
            "build_embedded_sha256",
        )
    return None, None


def cross_check_same_boundary_embedded_manifest(
    gate_path: Path,
    actual_sha256: str,
) -> Optional[str]:
    """Cross-check co-located bundle manifests when present to catch mismatched edits.

    Note: Because co-located unsigned manifests share the same filesystem trust
    boundary as ``gate_path``, passing this check does NOT replace an independent
    trust anchor. Any mismatch or unreadable manifest fails closed.
    """
    resolved = gate_path.resolve()
    if resolved.parent.name != "ml" or resolved.parent.parent.name != "artifacts":
        return None
    bundle_root = resolved.parent.parent.parent
    norm_actual = normalize_sha256_hex(actual_sha256, field_name="actual_sha256")
    rel_key = "artifacts/ml/ood_reference_gate.json"
    saw_manifest = False

    embedded_manifest = bundle_root / "EMBEDDED_ARTIFACTS_MANIFEST.json"
    if embedded_manifest.is_file():
        saw_manifest = True
        try:
            payload = json.loads(embedded_manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"EMBEDDED_ARTIFACTS_MANIFEST.json unreadable at '{embedded_manifest}': {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise ValueError("EMBEDDED_ARTIFACTS_MANIFEST.json must be a JSON object")
        ood_block = payload.get("ood_gate")
        if not isinstance(ood_block, dict) or not ood_block.get("sha256"):
            raise ValueError("EMBEDDED_ARTIFACTS_MANIFEST.json missing ood_gate.sha256")
        man_sha = normalize_sha256_hex(
            ood_block.get("sha256"), field_name="EMBEDDED_ARTIFACTS_MANIFEST.ood_gate.sha256"
        )
        if man_sha != norm_actual:
            raise ValueError(
                "OOD gate artifact SHA-256 mismatch against EMBEDDED_ARTIFACTS_MANIFEST.json: "
                f"manifest={man_sha} != actual={norm_actual}"
            )

    embedded_sums = bundle_root / "EMBEDDED_SHA256SUMS.txt"
    if embedded_sums.is_file():
        saw_manifest = True
        try:
            lines = embedded_sums.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise ValueError(f"EMBEDDED_SHA256SUMS.txt unreadable: {exc}") from exc
        sums_sha: Optional[str] = None
        for line in lines:
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[1].strip().replace("\\", "/") == rel_key:
                sums_sha = normalize_sha256_hex(parts[0], field_name="EMBEDDED_SHA256SUMS")
                break
        if sums_sha is None:
            raise ValueError(f"EMBEDDED_SHA256SUMS.txt missing entry for {rel_key}")
        if sums_sha != norm_actual:
            raise ValueError(
                "OOD gate artifact SHA-256 mismatch against EMBEDDED_SHA256SUMS.txt: "
                f"sums={sums_sha} != actual={norm_actual}"
            )

    companion_manifest = bundle_root / "COMPANION_BUNDLE_MANIFEST.json"
    if companion_manifest.is_file():
        saw_manifest = True
        try:
            payload = json.loads(companion_manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"COMPANION_BUNDLE_MANIFEST.json unreadable at '{companion_manifest}': {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise ValueError("COMPANION_BUNDLE_MANIFEST.json must be a JSON object")
        ood_block = payload.get("ood_gate")
        if not isinstance(ood_block, dict) or not ood_block.get("sha256"):
            raise ValueError("COMPANION_BUNDLE_MANIFEST.json missing ood_gate.sha256")
        man_sha = normalize_sha256_hex(
            ood_block.get("sha256"), field_name="COMPANION_BUNDLE_MANIFEST.ood_gate.sha256"
        )
        if man_sha != norm_actual:
            raise ValueError(
                "OOD gate artifact SHA-256 mismatch against COMPANION_BUNDLE_MANIFEST.json: "
                f"manifest={man_sha} != actual={norm_actual}"
            )

    return "unanchored_same_boundary_manifest" if saw_manifest else None


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
        self.provenance: Optional[Dict[str, Any]] = None
        self.artifact_sha256: Optional[str] = None

    def fit(
        self,
        X: np.ndarray,
        feature_names: List[str],
        provenance: Optional[Dict[str, Any]] = None,
    ) -> OODRejectionGate:
        """Fit empirical distribution bounding box and statistical moments."""
        if (
            isinstance(self.std_margin, bool)
            or not isinstance(self.std_margin, (int, float))
            or not math.isfinite(float(self.std_margin))
            or float(self.std_margin) <= 0.0
        ):
            raise ValueError(f"Invalid std_margin: {self.std_margin!r}")
        if (
            isinstance(self.statistical_threshold, bool)
            or not isinstance(self.statistical_threshold, (int, float))
            or not math.isfinite(float(self.statistical_threshold))
            or float(self.statistical_threshold) <= 0.0
        ):
            raise ValueError(f"Invalid statistical_threshold: {self.statistical_threshold!r}")

        X_arr = np.asarray(X, dtype=np.float64)
        if X_arr.ndim != 2 or X_arr.shape[0] == 0:
            raise ValueError("X must be a non-empty 2D array")
        if not np.all(np.isfinite(X_arr)):
            raise ValueError("X must contain only finite values")
        if X_arr.shape[1] != len(feature_names):
            raise ValueError(f"Feature count mismatch: {X_arr.shape[1]} vs {len(feature_names)}")

        norm_features = [str(name) for name in feature_names]
        if any(not isinstance(name, str) or not name.strip() for name in feature_names):
            raise ValueError("feature_names must contain non-empty strings")
        if len(set(norm_features)) != len(norm_features):
            raise ValueError("feature_names must not contain duplicates")

        if provenance is not None and not isinstance(provenance, dict):
            raise ValueError("provenance must be a dict when supplied")
        prov = dict(provenance) if provenance is not None else {}
        prov.setdefault("fit_rows", int(X_arr.shape[0]))
        prov.setdefault("source", "in_memory_fit")
        fit_rows = prov.get("fit_rows")
        if isinstance(fit_rows, bool) or not isinstance(fit_rows, int) or fit_rows <= 0:
            raise ValueError(f"provenance fit_rows must be positive int, got {fit_rows!r}")

        self.feature_names = norm_features
        self.means = np.mean(X_arr, axis=0)
        self.stds = np.std(X_arr, axis=0)
        # Avoid division by zero for constant features
        self.stds = np.where(self.stds < 1e-6, 1.0, self.stds)

        # Robust bounding box with margin
        self.min_bounds = self.means - self.std_margin * self.stds
        self.max_bounds = self.means + self.std_margin * self.stds
        self.provenance = prov
        self.artifact_sha256 = None
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

    def evaluate_batch(self, feature_dicts: Sequence[Mapping[str, float]]) -> List[OODDecision]:
        """Vectorized batch evaluation of feature dictionaries against OOD criteria."""
        if not self.is_fitted:
            raise RuntimeError("OODRejectionGate must be fitted before evaluation")
        if not feature_dicts:
            return []

        decisions: List[Optional[OODDecision]] = [None] * len(feature_dicts)
        valid_indices: List[int] = []
        valid_rows: List[List[float]] = []

        for idx, row in enumerate(feature_dicts):
            if not all(name in row for name in self.feature_names):
                decisions[idx] = self.evaluate_sample(dict(row))
                continue
            try:
                vals = [float(row[name]) for name in self.feature_names]
            except (TypeError, ValueError):
                decisions[idx] = self.evaluate_sample(dict(row))
                continue
            if not all(math.isfinite(v) for v in vals):
                decisions[idx] = self.evaluate_sample(dict(row))
                continue
            valid_indices.append(idx)
            valid_rows.append(vals)

        if valid_rows:
            X_mat = np.asarray(valid_rows, dtype=np.float64)
            breach_mask = (X_mat < self.min_bounds) | (X_mat > self.max_bounds)
            breach_counts = np.sum(breach_mask, axis=1)
            z_scores = np.abs((X_mat - self.means) / self.stds)
            stat_distances = np.mean(z_scores, axis=1)

            for row_i, orig_idx in enumerate(valid_indices):
                if int(breach_counts[row_i]) >= 3:
                    offending_bounds = [
                        self.feature_names[int(col_i)]
                        for col_i in np.flatnonzero(breach_mask[row_i])
                    ]
                    decisions[orig_idx] = OODDecision(
                        action=OODAction.ABSTAIN,
                        is_ood=True,
                        ood_score=0.95,
                        reason="FEATURE_BOUNDS_EXTREME_BREACH",
                        offending_features=offending_bounds,
                        metadata={"breach_count": len(offending_bounds)},
                    )
                    continue

                stat_distance = float(stat_distances[row_i])
                if stat_distance > self.statistical_threshold:
                    top_idx = np.argsort(z_scores[row_i])[-3:][::-1]
                    decisions[orig_idx] = OODDecision(
                        action=OODAction.ABSTAIN,
                        is_ood=True,
                        ood_score=min(1.0, stat_distance / 10.0),
                        reason="STATISTICAL_OUTLIER_DISTANCE",
                        offending_features=[self.feature_names[int(i)] for i in top_idx],
                        metadata={"z_mean_distance": round(stat_distance, 3)},
                    )
                    continue

                decisions[orig_idx] = OODDecision(
                    action=OODAction.PROCEED,
                    is_ood=False,
                    ood_score=round(stat_distance / 10.0, 4),
                    reason=None,
                    metadata={"z_mean_distance": round(stat_distance, 3)},
                )

        return [d for d in decisions if d is not None]

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
        gate.provenance = dict(provenance)
        gate.artifact_sha256 = None
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
        exp = normalize_sha256_hex(expected_sha256, field_name="expected_sha256")
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
    gate.artifact_sha256 = actual_sha256
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


def validate_ood_gate_instance(
    gate: Any,
    *,
    expected_feature_names: Optional[Sequence[str]] = ML_FEATURE_COLUMNS,
    expected_preprocessor_sha256: Optional[str] = None,
    require_provenance: bool = True,
    require_preprocessor_sha256: bool = False,
) -> Dict[str, Any]:
    """Validate an in-memory OODRejectionGate against contract, array invariants, and provenance."""
    if not isinstance(gate, OODRejectionGate):
        raise ValueError(
            f"OOD gate must be an OODRejectionGate instance, got {type(gate).__name__}"
        )
    if type(gate.is_fitted) is not bool or not gate.is_fitted:
        raise ValueError("OODRejectionGate is not fitted")

    for param_name, param_val in (
        ("std_margin", getattr(gate, "std_margin", None)),
        ("statistical_threshold", getattr(gate, "statistical_threshold", None)),
    ):
        if (
            isinstance(param_val, bool)
            or not isinstance(param_val, (int, float))
            or not math.isfinite(float(param_val))
            or float(param_val) <= 0.0
        ):
            raise ValueError(f"OOD gate invalid {param_name}: {param_val!r}")

    feature_names = getattr(gate, "feature_names", None)
    if not isinstance(feature_names, (list, tuple)) or not feature_names:
        raise ValueError("OOD gate is missing feature_names")
    if any(not isinstance(name, str) or not name.strip() for name in feature_names):
        raise ValueError("OOD gate feature_names must contain non-empty strings")
    norm_features = [str(name) for name in feature_names]
    if len(set(norm_features)) != len(norm_features):
        raise ValueError("OOD gate feature_names contains duplicates")
    if expected_feature_names is not None and norm_features != [
        str(name) for name in expected_feature_names
    ]:
        raise ValueError("OOD gate feature_names mismatch against expected feature contract")

    expected_shape = (len(norm_features),)
    arrays: Dict[str, np.ndarray] = {}
    for label in ("means", "stds", "min_bounds", "max_bounds"):
        raw = getattr(gate, label, None)
        if raw is None or isinstance(raw, (str, bytes)):
            raise ValueError(f"OOD gate missing array '{label}'")
        try:
            arr = np.asarray(raw, dtype=np.float64)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"OOD gate '{label}' is not numeric: {exc}") from exc
        if arr.shape != expected_shape:
            raise ValueError(
                f"OOD gate '{label}' shape mismatch: expected {expected_shape}, got {arr.shape}"
            )
        if not np.all(np.isfinite(arr)):
            raise ValueError(f"OOD gate '{label}' contains non-finite values")
        arrays[label] = arr

    if np.any(arrays["stds"] <= 0.0):
        raise ValueError("OOD gate contains non-positive standard deviations")
    if np.any(arrays["min_bounds"] > arrays["max_bounds"]):
        raise ValueError("OOD gate has min_bounds > max_bounds")

    provenance = getattr(gate, "provenance", None)
    fit_rows: Optional[int] = None
    prep_sha: Optional[str] = None
    if require_provenance or provenance is not None:
        if not isinstance(provenance, dict):
            raise ValueError("OOD gate missing required 'provenance' metadata")
        raw_fit_rows = provenance.get("fit_rows")
        if isinstance(raw_fit_rows, bool) or not isinstance(raw_fit_rows, int) or raw_fit_rows <= 0:
            raise ValueError(
                f"OOD gate provenance fit_rows must be positive int, got {raw_fit_rows!r}"
            )
        fit_rows = raw_fit_rows
        raw_prep_sha = provenance.get("preprocessor_artifact_sha256")
        if raw_prep_sha is not None:
            if not isinstance(raw_prep_sha, str) or not raw_prep_sha.strip():
                raise ValueError(
                    "OOD gate provenance preprocessor_artifact_sha256 must be non-empty str"
                )
            prep_sha = raw_prep_sha.strip().lower()

    if expected_preprocessor_sha256 is not None:
        exp_prep = str(expected_preprocessor_sha256).strip().lower()
        if prep_sha is None:
            if require_preprocessor_sha256:
                raise ValueError("OOD gate missing preprocessor_artifact_sha256 in provenance")
        elif prep_sha != exp_prep:
            raise ValueError(
                "OOD gate preprocessor_artifact_sha256 mismatch: "
                f"gate={prep_sha!r} != expected={expected_preprocessor_sha256!r}"
            )

    art_sha = getattr(gate, "artifact_sha256", None)
    return {
        "status": "FITTED",
        "feature_count": len(norm_features),
        "fit_rows": fit_rows,
        "preprocessor_artifact_sha256": prep_sha,
        "artifact_sha256": (
            str(art_sha).strip().lower() if isinstance(art_sha, str) and art_sha.strip() else None
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
