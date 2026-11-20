"""Local benign baseline calibration for site-specific deployment adaptation.

Computes non-destructive benign score quantiles and fits a local OOD rejection
gate strictly on a provided benign flow DataFrame without modifying any frozen
E0 model or preprocessor artifacts.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

import numpy as np
import pandas as pd

from network_anomaly.data.v2_schema import FEATURE_CONTRACT_ID, ML_FEATURE_COLUMNS
from network_anomaly.ml.ood_gate import OODRejectionGate, normalize_sha256_hex
from network_anomaly.models.registry import MODEL_KEYS, ModelRegistry

LOCAL_CALIBRATION_SCHEMA_VERSION = 1
LOCAL_CALIBRATION_ARTIFACT_TYPE = "local_benign_calibration_profile"


def _canonical_json_sha256(payload: Dict[str, Any]) -> str:
    """Compute SHA-256 over canonical JSON representation of a payload."""
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest().lower()


class LocalBenignCalibrator:
    """Calibrates site-local score quantiles and OOD bounds from benign flows."""

    def __init__(
        self,
        target_fpr: float = 0.01,
        std_margin: float = 4.0,
        statistical_threshold: float = 5.0,
    ) -> None:
        if (
            isinstance(target_fpr, bool)
            or not isinstance(target_fpr, (int, float))
            or not math.isfinite(float(target_fpr))
            or not (0.0 < float(target_fpr) < 1.0)
        ):
            raise ValueError(f"target_fpr must be strictly between 0 and 1, got {target_fpr!r}")
        if (
            isinstance(std_margin, bool)
            or not isinstance(std_margin, (int, float))
            or not math.isfinite(float(std_margin))
            or float(std_margin) <= 0.0
        ):
            raise ValueError(f"std_margin must be positive, got {std_margin!r}")
        if (
            isinstance(statistical_threshold, bool)
            or not isinstance(statistical_threshold, (int, float))
            or not math.isfinite(float(statistical_threshold))
            or float(statistical_threshold) <= 0.0
        ):
            raise ValueError(
                f"statistical_threshold must be positive, got {statistical_threshold!r}"
            )

        self.target_fpr = float(target_fpr)
        self.std_margin = float(std_margin)
        self.statistical_threshold = float(statistical_threshold)
        self.calibrated_thresholds: Dict[str, float] = {}
        self.score_summaries: Dict[str, Dict[str, float]] = {}
        self.ood_gate: Optional[OODRejectionGate] = None
        self.preprocessor_sha256: Optional[str] = None
        self.fit_rows: int = 0
        self.calibrated_at_utc: Optional[str] = None
        self.source_label: str = "local_benign"
        self.profile_sha256: Optional[str] = None
        self.is_fitted: bool = False

    def fit(
        self,
        benign_frame: pd.DataFrame,
        registry: ModelRegistry,
        *,
        source_label: str = "local_benign",
    ) -> "LocalBenignCalibrator":
        """Fit benign quantile thresholds and a local OOD gate from benign v2 flows."""
        if not isinstance(benign_frame, pd.DataFrame) or benign_frame.empty:
            raise ValueError("benign_frame must be a non-empty pandas DataFrame")
        missing_cols = [col for col in ML_FEATURE_COLUMNS if col not in benign_frame.columns]
        if missing_cols:
            raise ValueError(f"benign_frame missing canonical v2 columns: {missing_cols[:8]}")
        if not registry.preprocessor_ready:
            raise RuntimeError(
                f"registry preprocessor is not ready: {registry.preprocessor_error or 'unavailable'}"
            )

        records = benign_frame[list(ML_FEATURE_COLUMNS)].to_dict(orient="records")
        X_transformed = registry.transform_features_batch(records)
        raw_matrix = np.asarray(
            [[float(row[col]) for col in ML_FEATURE_COLUMNS] for row in records],
            dtype=np.float64,
        )

        prov: Dict[str, Any] = {
            "dataset_name": str(source_label),
            "partition": "local_benign",
            "feature_space": "raw_ml_features_18",
            "fit_rows": int(raw_matrix.shape[0]),
        }
        if registry.preprocessor_sha256:
            prov["preprocessor_artifact_sha256"] = registry.preprocessor_sha256

        gate = OODRejectionGate(
            std_margin=self.std_margin,
            statistical_threshold=self.statistical_threshold,
        ).fit(raw_matrix, list(ML_FEATURE_COLUMNS), provenance=prov)

        quantile_level = 1.0 - self.target_fpr
        calibrated_thresholds: Dict[str, float] = {}
        score_summaries: Dict[str, Dict[str, float]] = {}

        for model_key in MODEL_KEYS:
            backend = registry._backends.get(model_key)
            if backend is None:
                continue
            batch_tuples = backend.score_batch_detailed(X_transformed)
            raw_scores = np.asarray([row[0] for row in batch_tuples], dtype=float)
            q_val = float(np.quantile(raw_scores, quantile_level))
            calibrated_thresholds[model_key] = round(q_val, 6)
            score_summaries[model_key] = {
                "sample_count": int(raw_scores.size),
                "quantile_level": round(quantile_level, 6),
                "calibrated_threshold": round(q_val, 6),
                "mean": round(float(np.mean(raw_scores)), 6),
                "std": round(float(np.std(raw_scores)), 6),
                "min": round(float(np.min(raw_scores)), 6),
                "p50": round(float(np.quantile(raw_scores, 0.50)), 6),
                "p95": round(float(np.quantile(raw_scores, 0.95)), 6),
                "p99": round(float(np.quantile(raw_scores, 0.99)), 6),
                "max": round(float(np.max(raw_scores)), 6),
            }

        self.ood_gate = gate
        self.calibrated_thresholds = calibrated_thresholds
        self.score_summaries = score_summaries
        self.preprocessor_sha256 = registry.preprocessor_sha256
        self.fit_rows = int(raw_matrix.shape[0])
        self.calibrated_at_utc = datetime.now(timezone.utc).isoformat()
        self.source_label = str(source_label)
        self.profile_sha256 = None
        self.is_fitted = True
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the local calibration profile as a JSON-compatible dictionary."""
        if not self.is_fitted or self.ood_gate is None or not self.ood_gate.is_fitted:
            raise RuntimeError("LocalBenignCalibrator must be fitted before serialization")
        gate_prov = dict(
            self.ood_gate.provenance
            or {
                "dataset_name": self.source_label,
                "partition": "local_benign",
                "feature_space": "raw_ml_features_18",
                "fit_rows": self.fit_rows,
            }
        )
        return {
            "schema_version": LOCAL_CALIBRATION_SCHEMA_VERSION,
            "artifact_type": LOCAL_CALIBRATION_ARTIFACT_TYPE,
            "calibrated_at_utc": self.calibrated_at_utc,
            "source_label": self.source_label,
            "target_fpr": self.target_fpr,
            "quantile_level": round(1.0 - self.target_fpr, 6),
            "std_margin": self.std_margin,
            "statistical_threshold": self.statistical_threshold,
            "fit_rows": self.fit_rows,
            "feature_contract_version": FEATURE_CONTRACT_ID,
            "preprocessor_sha256": self.preprocessor_sha256,
            "calibrated_thresholds": dict(self.calibrated_thresholds),
            "score_summaries": dict(self.score_summaries),
            "ood_gate": self.ood_gate.to_artifact(gate_prov),
        }

    def save_profile(self, path: Union[str, Path]) -> Path:
        """Persist calibration profile with an embedded SHA-256 integrity digest."""
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        core_payload = self.to_dict()
        payload = dict(core_payload)
        payload["payload_sha256"] = _canonical_json_sha256(core_payload)
        serialized = json.dumps(payload, indent=2) + "\n"
        out_path.write_text(serialized, encoding="utf-8", newline="\n")
        self.profile_sha256 = hashlib.sha256(out_path.read_bytes()).hexdigest().lower()
        return out_path

    @classmethod
    def load_profile(
        cls,
        path: Union[str, Path],
        *,
        expected_sha256: Optional[str] = None,
        expected_preprocessor_sha256: Optional[str] = None,
    ) -> "LocalBenignCalibrator":
        """Load and verify a persisted local benign calibration profile."""
        candidate = Path(path)
        if not candidate.is_file():
            raise FileNotFoundError(f"Local calibration profile not found at '{candidate}'")
        raw_bytes = candidate.read_bytes()
        actual_file_sha256 = hashlib.sha256(raw_bytes).hexdigest().lower()
        if expected_sha256 is not None:
            exp_file_sha = normalize_sha256_hex(expected_sha256, field_name="expected_sha256")
            if actual_file_sha256 != exp_file_sha:
                raise ValueError(
                    "Local calibration profile file SHA-256 mismatch: "
                    f"expected {exp_file_sha}, got {actual_file_sha256}"
                )

        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"Local calibration profile JSON unreadable at '{candidate}': {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise ValueError("Local calibration profile must be a JSON object")

        embedded_sha = payload.get("payload_sha256")
        if not embedded_sha:
            raise ValueError("Local calibration profile missing 'payload_sha256'")
        norm_embedded_sha = normalize_sha256_hex(embedded_sha, field_name="payload_sha256")
        core_payload = {k: v for k, v in payload.items() if k != "payload_sha256"}
        computed_sha = _canonical_json_sha256(core_payload)
        if computed_sha != norm_embedded_sha:
            raise ValueError(
                "Local calibration profile payload_sha256 integrity mismatch: "
                f"embedded={norm_embedded_sha} != computed={computed_sha}"
            )

        schema_version = payload.get("schema_version")
        if isinstance(schema_version, bool) or schema_version != LOCAL_CALIBRATION_SCHEMA_VERSION:
            raise ValueError(
                f"Local calibration schema_version mismatch: expected "
                f"{LOCAL_CALIBRATION_SCHEMA_VERSION}, got {schema_version!r}"
            )
        if payload.get("artifact_type") != LOCAL_CALIBRATION_ARTIFACT_TYPE:
            raise ValueError(
                f"Local calibration artifact_type mismatch: got {payload.get('artifact_type')!r}"
            )
        if payload.get("feature_contract_version") != FEATURE_CONTRACT_ID:
            raise ValueError(
                f"Local calibration feature_contract_version mismatch: "
                f"got {payload.get('feature_contract_version')!r}"
            )

        prep_sha = payload.get("preprocessor_sha256")
        if expected_preprocessor_sha256 is not None:
            exp_prep = str(expected_preprocessor_sha256).strip().lower()
            if not isinstance(prep_sha, str) or prep_sha.strip().lower() != exp_prep:
                raise ValueError(
                    "Local calibration preprocessor_sha256 mismatch: "
                    f"profile={prep_sha!r} != expected={expected_preprocessor_sha256!r}"
                )

        ood_payload = payload.get("ood_gate")
        if not isinstance(ood_payload, dict):
            raise ValueError("Local calibration profile missing 'ood_gate' payload")
        gate = OODRejectionGate.from_artifact(
            ood_payload,
            expected_feature_names=ML_FEATURE_COLUMNS,
            expected_preprocessor_sha256=expected_preprocessor_sha256,
        )

        calibrator = cls(
            target_fpr=float(payload["target_fpr"]),
            std_margin=float(payload.get("std_margin", gate.std_margin)),
            statistical_threshold=float(
                payload.get("statistical_threshold", gate.statistical_threshold)
            ),
        )
        calibrator.ood_gate = gate
        calibrator.calibrated_thresholds = {
            str(k): float(v) for k, v in (payload.get("calibrated_thresholds") or {}).items()
        }
        calibrator.score_summaries = {
            str(k): dict(v) for k, v in (payload.get("score_summaries") or {}).items()
        }
        calibrator.preprocessor_sha256 = (
            str(prep_sha).strip().lower()
            if isinstance(prep_sha, str) and prep_sha.strip()
            else None
        )
        calibrator.fit_rows = int(payload["fit_rows"])
        calibrator.calibrated_at_utc = payload.get("calibrated_at_utc")
        calibrator.source_label = str(payload.get("source_label") or "local_benign")
        calibrator.profile_sha256 = actual_file_sha256
        calibrator.is_fitted = True
        return calibrator
