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


def _is_positive_attack(label: Any) -> bool:
    """Check if label indicates positive attack class."""
    return label == 1 or label == "1" or label == "Attack"


def _is_negative_benign(label: Any) -> bool:
    """Check if label indicates negative benign class."""
    return label == 0 or label == "0" or label == "Benign"


def compute_attack_category_breakdown(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    attack_categories: Sequence[str],
) -> Dict[str, Dict[str, Union[int, float]]]:
    """Compute per-attack-category error analysis and recall.

    Parameters
    ----------
    y_true : array-like
        Ground truth binary labels (0 / 'Benign' or 1 / 'Attack').
    y_pred : array-like
        Predicted binary labels (0 / 'Benign' or 1 / 'Attack').
    attack_categories : array-like of str
        The specific attack category for each row (e.g. 'Exploits', 'DoS', 'Benign').

    Returns
    -------
    Dict[str, Dict[str, Union[int, float]]]
        Dictionary mapping each category to:
        - For Attack categories (e.g. 'Exploits', 'DoS'):
            - 'total': total occurrences of this attack category.
            - 'detected': true positive count (true attack correctly predicted as Attack).
            - 'missed': false negative count (true attack incorrectly predicted as Benign).
            - 'detection_rate': recall for this attack category (detected / total).
        - For 'Benign':
            - 'total': total benign occurrences.
            - 'false_positive': count where benign was incorrectly predicted as Attack (FP).
            - 'true_negative': count where benign was correctly predicted as Benign (TN).
            - 'false_positive_rate': false positive rate on benign traffic (false_positive / total).
    """
    if len(y_true) != len(y_pred) or len(y_true) != len(attack_categories):
        raise ValueError("y_true, y_pred, and attack_categories must have identical lengths")

    categories = sorted(set(attack_categories))
    breakdown: Dict[str, Dict[str, Union[int, float]]] = {}

    for cat in categories:
        indices = [i for i, c in enumerate(attack_categories) if c == cat]
        total = len(indices)

        if cat == "Benign":
            false_positive = sum(
                1
                for i in indices
                if _is_negative_benign(y_true[i]) and _is_positive_attack(y_pred[i])
            )
            true_negative = sum(
                1
                for i in indices
                if _is_negative_benign(y_true[i]) and _is_negative_benign(y_pred[i])
            )
            fp_rate = float(false_positive / total) if total > 0 else 0.0

            breakdown[cat] = {
                "total": total,
                "false_positive": false_positive,
                "true_negative": true_negative,
                "false_positive_rate": fp_rate,
            }
        else:
            detected = sum(
                1
                for i in indices
                if _is_positive_attack(y_true[i]) and _is_positive_attack(y_pred[i])
            )
            missed = sum(
                1
                for i in indices
                if _is_positive_attack(y_true[i]) and _is_negative_benign(y_pred[i])
            )
            detection_rate = float(detected / total) if total > 0 else 0.0

            breakdown[cat] = {
                "total": total,
                "detected": detected,
                "missed": missed,
                "detection_rate": detection_rate,
            }

    return breakdown
