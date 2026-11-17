"""Threshold Calibration on Independent Validation Partition.

Implements Issue #100 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np


class CalibrationPolicy(str, Enum):
    YOUDEN_J = "YOUDEN_J"
    MAX_F1 = "MAX_F1"
    BUDGET_FPR = "BUDGET_FPR"


@dataclass
class ThresholdManifest:
    model_family: str
    calibration_policy: str
    optimal_threshold: float
    calibrated_at_utc: str
    validation_metrics: Dict[str, float]
    provenance_source: str
    guard_test_partition_excluded: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ThresholdCalibrator:
    """Rigorous threshold calibration strictly isolated from test partition."""

    def __init__(self, partition_name: str = "validation"):
        if "test" in partition_name.lower():
            raise ValueError(
                f"LEAKAGE GUARD VIOLATION: Calibration cannot be performed on '{partition_name}'. "
                f"Threshold calibration MUST only be executed on validation data!"
            )
        self.partition_name = partition_name

    def calibrate(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        model_family: str,
        policy: CalibrationPolicy = CalibrationPolicy.MAX_F1,
        max_fpr: float = 0.01,
        num_thresholds: int = 200,
    ) -> ThresholdManifest:
        """Find optimal decision threshold under specified objective function."""
        y_true = np.asarray(y_true).astype(int)
        y_scores = np.asarray(y_scores).astype(float)

        if len(y_true) != len(y_scores):
            raise ValueError("y_true and y_scores length mismatch")
        if len(np.unique(y_true)) < 2:
            raise ValueError("y_true must contain both positive and negative classes")

        thresholds = np.linspace(np.min(y_scores), np.max(y_scores), num_thresholds)
        best_thresh = 0.5
        best_val = -1.0
        best_metrics: Dict[str, float] = {}

        for th in thresholds:
            y_pred = (y_scores >= th).astype(int)

            tp = np.sum((y_true == 1) & (y_pred == 1))
            fp = np.sum((y_true == 0) & (y_pred == 1))
            fn = np.sum((y_true == 1) & (y_pred == 0))
            tn = np.sum((y_true == 0) & (y_pred == 0))

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            tpr = recall
            youden_j = tpr - fpr

            if policy == CalibrationPolicy.MAX_F1:
                score = f1
            elif policy == CalibrationPolicy.YOUDEN_J:
                score = youden_j
            elif policy == CalibrationPolicy.BUDGET_FPR:
                if fpr <= max_fpr:
                    score = tpr
                else:
                    score = -1.0
            else:
                score = f1

            if score > best_val:
                best_val = score
                best_thresh = float(th)
                best_metrics = {
                    "precision": round(float(precision), 4),
                    "recall": round(float(recall), 4),
                    "f1_score": round(float(f1), 4),
                    "fpr": round(float(fpr), 4),
                    "tpr": round(float(tpr), 4),
                    "youden_j": round(float(youden_j), 4),
                }

        return ThresholdManifest(
            model_family=model_family,
            calibration_policy=policy.value,
            optimal_threshold=round(best_thresh, 4),
            calibrated_at_utc=datetime.now(timezone.utc).isoformat(),
            validation_metrics=best_metrics,
            provenance_source=f"partition:{self.partition_name}",
            guard_test_partition_excluded=True,
        )


def export_threshold_manifest(manifest: ThresholdManifest, output_path: Path) -> None:
    """Write verified calibration manifest to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest.to_dict(), f, indent=2)
