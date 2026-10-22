"""Evaluation metrics for network anomaly detection.

Supports binary supervised evaluation, FPR calculation, and per-attack-category error analysis.
Isolation Forest evaluation requires separate score-to-label protocol (documented in docs/EVALUATION.md).
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Sequence, Union

from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def compute_metrics(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    labels: Optional[Sequence[Any]] = None,
) -> Dict[str, Any]:
    """Compute primary evaluation metrics for supervised anomaly detection.

    Parameters
    ----------
    y_true : array-like
        True binary target values (typically 0 for Benign, 1 for Attack).
    y_pred : array-like
        Predicted binary target values.
    labels : array-like, optional
        Order of labels for the confusion matrix. Defaults to [0, 1] for binary classification.

    Returns
    -------
    Dict[str, Any]
        Dictionary with precision, recall, f1, macro_f1, false_positive_rate, and confusion_matrix.
    """
    target_labels = [0, 1] if labels is None else list(labels)
    cm = confusion_matrix(y_true, y_pred, labels=target_labels)

    fpr = 0.0
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        if (fp + tn) > 0:
            fpr = float(fp / (fp + tn))

    return {
        "precision": float(precision_score(y_true, y_pred, average="binary", zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, average="binary", zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, average="binary", zero_division=0)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "false_positive_rate": fpr,
        "fpr": fpr,
        "confusion_matrix": cm.tolist(),
    }


def compute_attack_category_breakdown(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    attack_categories: Sequence[str],
) -> Dict[str, Dict[str, Union[int, float]]]:
    """Compute per-attack-category error analysis and recall.

    Parameters
    ----------
    y_true : array-like of int
        Ground truth binary labels (0 for Benign, 1 for Attack).
    y_pred : array-like of int
        Predicted binary labels (0 for Benign, 1 for Attack).
    attack_categories : array-like of str
        The specific attack category for each row (e.g. 'Exploits', 'DoS', 'Benign').

    Returns
    -------
    Dict[str, Dict[str, Union[int, float]]]
        Dictionary mapping each attack category to:
        - 'total': total occurrences of this category.
        - 'detected': true positive count (predicted 1).
        - 'missed': false negative count (predicted 0).
        - 'detection_rate': recall for this category (detected / total).
    """
    if len(y_true) != len(y_pred) or len(y_true) != len(attack_categories):
        raise ValueError("y_true, y_pred, and attack_categories must have identical lengths")

    categories = sorted(set(attack_categories))
    breakdown: Dict[str, Dict[str, Union[int, float]]] = {}

    for cat in categories:
        indices = [i for i, c in enumerate(attack_categories) if c == cat]
        total = len(indices)
        detected = sum(1 for i in indices if y_pred[i] == 1)
        missed = sum(1 for i in indices if y_pred[i] == 0)
        detection_rate = float(detected / total) if total > 0 else 0.0

        breakdown[cat] = {
            "total": total,
            "detected": detected,
            "missed": missed,
            "detection_rate": detection_rate,
        }

    return breakdown
