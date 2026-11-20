"""Score normalization helpers shared by live inference and API display.

Unsupervised models (Isolation Forest, Autoencoder) emit unbounded anomaly
scores. Their training manifests store the empirical score distribution on an
independent calibration partition (``score_normalization.score_values`` at the
matching ``quantile_grid``). Mapping a raw score through that curve yields the
empirical percentile of the score relative to the calibration population.

The percentile is a *rank*, not a calibrated probability of attack. Callers must
not present it as ``P(attack)``; the semantics are carried explicitly by
``score_semantics`` in every inference record.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

PROBABILITY_SEMANTICS = "calibrated_binary_probability"
PERCENTILE_SEMANTICS = "empirical_percentile_vs_validation_benign"
RAW_SCORE_SEMANTICS = "raw_anomaly_score"


def validate_score_normalization(calibration: Any) -> Optional[Tuple[List[float], List[float]]]:
    """Validate a manifest score-normalization block.

    Returns ``(quantile_grid, score_values)`` when the block is a usable
    monotone empirical CDF, otherwise ``None``. Calibration derived from the
    test partition is rejected to prevent threshold leakage.
    """
    if not isinstance(calibration, dict):
        return None
    if calibration.get("calibration_partition") not in {"train", "validation"}:
        return None
    if calibration.get("score_direction", "higher_is_more_anomalous") != "higher_is_more_anomalous":
        return None
    grid = calibration.get("quantile_grid")
    values = calibration.get("score_values")
    if not isinstance(grid, list) or not isinstance(values, list) or len(grid) < 2:
        return None
    if len(grid) != len(values):
        return None
    try:
        grid_f = [float(x) for x in grid]
        value_f = [float(x) for x in values]
    except (TypeError, ValueError):
        return None
    if not all(math.isfinite(x) and 0.0 <= x <= 1.0 for x in grid_f):
        return None
    if not all(math.isfinite(x) for x in value_f):
        return None
    if any(grid_f[i] > grid_f[i + 1] for i in range(len(grid_f) - 1)):
        return None
    if any(value_f[i] > value_f[i + 1] for i in range(len(value_f) - 1)):
        return None
    return grid_f, value_f


def normalize_anomaly_score(raw_score: float, calibration: Any) -> Optional[float]:
    """Map a raw anomaly score to its empirical percentile in ``[0, 1]``."""
    curve = validate_score_normalization(calibration)
    if curve is None or not math.isfinite(float(raw_score)):
        return None
    grid_f, value_f = curve
    return float(max(0.0, min(1.0, np.interp(float(raw_score), value_f, grid_f))))


def extract_threshold(
    manifest: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None
) -> Tuple[Optional[float], str]:
    """Return ``(threshold, source)`` from a model manifest.

    Only thresholds whose stored provenance is the validation (or train)
    partition are accepted. A threshold labelled ``test`` is rejected because
    tuning on the reported evaluation partition is leakage.
    """
    candidates = [
        ("manifest.threshold", manifest.get("threshold")),
        ("manifest.calibrated_threshold", manifest.get("calibrated_threshold")),
        (
            "manifest.threshold_calibration.threshold",
            (
                (manifest.get("threshold_calibration") or {}).get("threshold")
                if isinstance(manifest.get("threshold_calibration"), dict)
                else None
            ),
        ),
    ]
    if isinstance(metadata, dict):
        candidates.insert(0, ("metadata.threshold", metadata.get("threshold")))

    for source, value in candidates:
        if value is None or isinstance(value, bool):
            continue
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(numeric):
            continue
        return numeric, source
    return None, "unavailable"


def threshold_provenance_is_clean(manifest: Dict[str, Any]) -> bool:
    """Return True when no calibrated threshold is sourced from the test partition."""
    calibration = manifest.get("threshold_calibration")
    if isinstance(calibration, dict):
        partition = str(calibration.get("calibration_partition", "")).lower()
        if partition == "test":
            return False
    test_summary = manifest.get("test_evaluation")
    if isinstance(test_summary, dict):
        decision = test_summary.get("decision_threshold")
        native = manifest.get("threshold")
        if decision is not None and native is not None and float(decision) != float(native):
            return False
    return True
