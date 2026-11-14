"""Evaluation metrics for network anomaly detection.

Supports binary supervised evaluation, FPR calculation, and per-attack-category error analysis.
Isolation Forest evaluation requires a separate score-to-label protocol (see docs/EVALUATION.md).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Union

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def _is_positive_attack(label: Any) -> bool:
    """Check if label indicates positive attack class (rejecting booleans)."""
    if isinstance(label, (bool, np.bool_)):
        return False
    if isinstance(label, (int, np.integer)):
        return int(label) == 1
    if isinstance(label, (float, np.floating)):
        return bool(np.isfinite(label) and float(label) == 1.0)
    if isinstance(label, str):
        return label in ("1", "Attack")
    return False


def _is_negative_benign(label: Any) -> bool:
    """Check if label indicates negative benign class (rejecting booleans)."""
    if isinstance(label, (bool, np.bool_)):
        return False
    if isinstance(label, (int, np.integer)):
        return int(label) == 0
    if isinstance(label, (float, np.floating)):
        return bool(np.isfinite(label) and float(label) == 0.0)
    if isinstance(label, str):
        return label in ("0", "Benign")
    return False


def _is_canonical_binary_label(label: Any) -> bool:
    """Return True if label is a valid canonical binary label (0/1, '0'/'1', 'Benign'/'Attack')."""
    return _is_negative_benign(label) or _is_positive_attack(label)


def _validate_1d_sequence(seq: Any, name: str) -> List[Any]:
    """Validate that input is a non-empty 1D sequence without None, bool, or NaN."""
    if seq is None or isinstance(seq, (str, bytes, dict)):
        raise ValueError(f"'{name}' must be a 1D sequence of labels, got {type(seq).__name__}")
    try:
        arr = np.asarray(seq, dtype=object)
    except Exception as exc:
        raise ValueError(f"Cannot convert '{name}' to 1D array: {exc}") from exc

    if arr.ndim != 1:
        raise ValueError(f"'{name}' must be 1D, got array with ndim={arr.ndim}")
    if len(arr) == 0:
        raise ValueError(f"'{name}' must not be empty.")

    out: List[Any] = []
    for idx, val in enumerate(arr):
        if val is None or isinstance(val, (bool, np.bool_)):
            raise ValueError(
                f"Invalid element in '{name}' at index {idx}: {val!r} (None/bool not allowed)"
            )
        if isinstance(val, (float, np.floating)):
            if not np.isfinite(val):
                raise ValueError(f"Invalid non-finite float in '{name}' at index {idx}: {val!r}")
            if not float(val).is_integer():
                raise ValueError(
                    f"Invalid fractional float label in '{name}' at index {idx}: {val!r} "
                    f"(strict binary integer labels required)"
                )
            val = int(val)
        elif isinstance(val, np.integer):
            val = int(val)
        elif isinstance(val, np.str_):
            val = str(val)
        out.append(val)
    return out


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
        Order of labels for the confusion matrix. When None, inferred from unique
        values in (y_true, y_pred) if canonical binary representation ({0, 1},
        {"0", "1"}, or {"Benign", "Attack"}), else raises ValueError.

    Returns
    -------
    Dict[str, Any]
        Dictionary with accuracy, precision, recall, f1, macro_f1, weighted_f1,
        false_positive_rate, fpr, true_negative_rate, tnr, confusion_matrix, and
        confusion_matrix_labeled.
    """
    y_t = _validate_1d_sequence(y_true, "y_true")
    y_p = _validate_1d_sequence(y_pred, "y_pred")
    if len(y_t) != len(y_p):
        raise ValueError(
            f"y_true and y_pred must have identical lengths, got {len(y_t)} and {len(y_p)}"
        )

    y_all = y_t + y_p
    try:
        unique_vals = set(y_all)
    except TypeError as exc:
        raise ValueError(f"Unhashable label type in y_true or y_pred: {exc}") from exc

    if labels is None:
        if unique_vals.issubset({0, 1}):
            target_labels: List[Any] = [0, 1]
        elif unique_vals.issubset({"0", "1"}):
            target_labels = ["0", "1"]
        elif unique_vals.issubset({"Benign", "Attack"}):
            target_labels = ["Benign", "Attack"]
        else:
            raise ValueError(
                f"Cannot infer canonical label order from unique labels "
                f"{sorted(str(v) for v in unique_vals)}. Please specify 'labels' explicitly."
            )
    else:
        target_labels = _validate_1d_sequence(labels, "labels")
        if len(target_labels) != len(set(target_labels)):
            raise ValueError(f"'labels' must not contain duplicates: {target_labels}")
        if len(target_labels) not in (1, 2):
            raise ValueError(
                f"'labels' for binary classification must have 1 or 2 classes, "
                f"got {len(target_labels)}: {target_labels}"
            )
        # Never allow labels=[0, 1] to silently drop records with invalid labels
        if len(target_labels) == 2:
            invalid_vals = unique_vals - set(target_labels)
            if invalid_vals:
                raise ValueError(
                    f"Found unexpected labels {sorted(str(v) for v in invalid_vals)} "
                    f"outside explicit labels {target_labels}."
                )
        else:
            # Expand single-label binary requests to the full canonical 2-class domain
            # so confusion_matrix stays 2x2 and matches tn/fp/fn/tp counts.
            single_lbl = target_labels[0]
            if not isinstance(single_lbl, bool) and single_lbl in (0, 1):
                target_labels = [0, 1]
            elif single_lbl in ("0", "1"):
                target_labels = ["0", "1"]
            elif single_lbl in ("Benign", "Attack"):
                target_labels = ["Benign", "Attack"]
            else:
                raise ValueError(
                    f"Unsupported single-class binary label {single_lbl!r}; "
                    f"expected canonical binary labels."
                )
            invalid_vals = unique_vals - set(target_labels)
            if invalid_vals:
                raise ValueError(
                    f"Found unexpected labels {sorted(str(v) for v in invalid_vals)} "
                    f"outside domain {sorted(str(v) for v in target_labels)}."
                )

    cm = confusion_matrix(y_t, y_p, labels=target_labels)

    # Resolve positions of negative (Benign) and positive (Attack) classes
    neg_idx = next((i for i, lbl in enumerate(target_labels) if _is_negative_benign(lbl)), None)
    pos_idx = next((i for i, lbl in enumerate(target_labels) if _is_positive_attack(lbl)), None)

    tn = 0
    fp = 0
    fn = 0
    tp = 0
    if (
        neg_idx is not None
        and pos_idx is not None
        and cm.shape == (len(target_labels), len(target_labels))
    ):
        tn = int(cm[neg_idx, neg_idx])
        fp = int(cm[neg_idx, pos_idx])
        fn = int(cm[pos_idx, neg_idx])
        tp = int(cm[pos_idx, pos_idx])
    elif cm.shape == (2, 2):
        # Fallback if custom 2-class labels are supplied in [negative, positive] order
        tn = int(cm[0, 0])
        fp = int(cm[0, 1])
        fn = int(cm[1, 0])
        tp = int(cm[1, 1])
    else:
        # Single-label target_labels case: compute directly from y_t and y_p
        tn = sum(
            1 for yt, yp in zip(y_t, y_p) if _is_negative_benign(yt) and _is_negative_benign(yp)
        )
        fp = sum(
            1 for yt, yp in zip(y_t, y_p) if _is_negative_benign(yt) and _is_positive_attack(yp)
        )
        fn = sum(
            1 for yt, yp in zip(y_t, y_p) if _is_positive_attack(yt) and _is_negative_benign(yp)
        )
        tp = sum(
            1 for yt, yp in zip(y_t, y_p) if _is_positive_attack(yt) and _is_positive_attack(yp)
        )

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    tnr = float(tn / (fp + tn)) if (fp + tn) > 0 else 0.0

    # Identify positive label for binary precision/recall/f1 calculation
    pos_label: Any = 1
    if pos_idx is not None:
        pos_label = target_labels[pos_idx]
    elif any(_is_positive_attack(y) for y in y_t):
        pos_label = next(y for y in y_t if _is_positive_attack(y))
    elif len(target_labels) > 1:
        pos_label = target_labels[1]
    elif len(target_labels) == 1:
        pos_label = target_labels[0]

    return {
        "accuracy": float(accuracy_score(y_t, y_p)),
        "precision": float(
            precision_score(y_t, y_p, pos_label=pos_label, average="binary", zero_division=0)
        ),
        "recall": float(
            recall_score(y_t, y_p, pos_label=pos_label, average="binary", zero_division=0)
        ),
        "f1": float(f1_score(y_t, y_p, pos_label=pos_label, average="binary", zero_division=0)),
        "macro_f1": float(
            f1_score(y_t, y_p, labels=target_labels, average="macro", zero_division=0)
        ),
        "weighted_f1": float(
            f1_score(y_t, y_p, labels=target_labels, average="weighted", zero_division=0)
        ),
        "false_positive_rate": fpr,
        "fpr": fpr,
        "true_negative_rate": tnr,
        "tnr": tnr,
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_labeled": {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
    }


def compute_confusion_matrix_breakdown(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    labels: Optional[Sequence[Any]] = None,
) -> Dict[str, Any]:
    """Compute a detailed confusion matrix breakdown (TN, FP, FN, TP and rates)."""
    metrics = compute_metrics(y_true=y_true, y_pred=y_pred, labels=labels)
    cm_labeled = metrics["confusion_matrix_labeled"]
    tn = int(cm_labeled["tn"])
    fp = int(cm_labeled["fp"])
    fn = int(cm_labeled["fn"])
    tp = int(cm_labeled["tp"])
    total = tn + fp + fn + tp
    benign_total = tn + fp
    attack_total = tp + fn
    return {
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "total": total,
        "benign_total": benign_total,
        "attack_total": attack_total,
        "false_positive_rate": float(fp / benign_total) if benign_total > 0 else 0.0,
        "true_negative_rate": float(tn / benign_total) if benign_total > 0 else 0.0,
        "true_positive_rate": float(tp / attack_total) if attack_total > 0 else 0.0,
        "false_negative_rate": float(fn / attack_total) if attack_total > 0 else 0.0,
        "confusion_matrix": metrics["confusion_matrix"],
    }


def compute_benign_false_positive_breakdown(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    attack_categories: Optional[Sequence[str]] = None,
) -> Dict[str, Union[int, float]]:
    """Compute Benign traffic false positive count, true negative count, and FPR."""
    if attack_categories is not None:
        cat_breakdown = compute_attack_category_breakdown(y_true, y_pred, attack_categories)
        if "Benign" in cat_breakdown:
            return dict(cat_breakdown["Benign"])
        return {
            "total": 0,
            "false_positive": 0,
            "true_negative": 0,
            "false_positive_rate": 0.0,
        }

    cm_info = compute_confusion_matrix_breakdown(y_true, y_pred)
    return {
        "total": int(cm_info["benign_total"]),
        "false_positive": int(cm_info["fp"]),
        "true_negative": int(cm_info["tn"]),
        "false_positive_rate": float(cm_info["false_positive_rate"]),
    }


def compute_attack_category_breakdown(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    attack_categories: Sequence[str],
    expected_categories: Optional[Sequence[str]] = None,
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
    expected_categories : array-like of str, optional
        Expected category names to include even if 0 occurrences are present in the sample.

    Returns
    -------
    Dict[str, Dict[str, Union[int, float]]]
        Dictionary mapping each category to:
        - For Attack categories (e.g. 'Exploits', 'DoS'):
            - 'total': total occurrences of this attack category.
            - 'detected': true positive count (true attack correctly predicted as Attack).
            - 'missed': false negative count (true attack incorrectly predicted as Benign).
            - 'detection_rate': recall for this attack category (detected / total).
            - 'false_negative_rate': miss rate for this attack category (missed / total).
        - For 'Benign':
            - 'total': total benign occurrences.
            - 'false_positive': count where benign was incorrectly predicted as Attack (FP).
            - 'true_negative': count where benign was correctly predicted as Benign (TN).
            - 'false_positive_rate': false positive rate on benign traffic (false_positive / total).
    """
    y_t = _validate_1d_sequence(y_true, "y_true")
    y_p = _validate_1d_sequence(y_pred, "y_pred")
    att = _validate_1d_sequence(attack_categories, "attack_categories")

    if len(y_t) != len(y_p) or len(y_t) != len(att):
        raise ValueError("y_true, y_pred, and attack_categories must have identical lengths")

    # Validate row-by-row label validity and ground-truth consistency between y_true and Attack
    clean_att: List[str] = []
    for idx, (yt_val, yp_val, cat_val) in enumerate(zip(y_t, y_p, att)):
        if not _is_canonical_binary_label(yt_val):
            raise ValueError(f"Invalid binary label in y_true at index {idx}: {yt_val!r}")
        if not _is_canonical_binary_label(yp_val):
            raise ValueError(f"Invalid binary label in y_pred at index {idx}: {yp_val!r}")
        if not isinstance(cat_val, str) or not cat_val.strip():
            raise ValueError(
                f"Invalid attack category at index {idx}: {cat_val!r} (must be non-empty string)"
            )
        cat_str = cat_val.strip()
        if cat_str == "Benign" and not _is_negative_benign(yt_val):
            raise ValueError(
                f"Contradictory ground truth at index {idx}: "
                f"attack_categories={cat_str!r} but y_true={yt_val!r} (expected Benign/0)"
            )
        if cat_str != "Benign" and not _is_positive_attack(yt_val):
            raise ValueError(
                f"Contradictory ground truth at index {idx}: "
                f"attack_categories={cat_str!r} but y_true={yt_val!r} (expected Attack/1)"
            )
        clean_att.append(cat_str)

    category_set = set(clean_att)
    if expected_categories is not None:
        exp_cats = _validate_1d_sequence(expected_categories, "expected_categories")
        for c in exp_cats:
            if not isinstance(c, str) or not c.strip():
                raise ValueError(f"Invalid category name in expected_categories: {c!r}")
            category_set.add(c.strip())

    categories = sorted(category_set)
    breakdown: Dict[str, Dict[str, Union[int, float]]] = {}

    for cat in categories:
        indices = [i for i, c in enumerate(clean_att) if c == cat]
        total = len(indices)

        if cat == "Benign":
            false_positive = sum(
                1 for i in indices if _is_negative_benign(y_t[i]) and _is_positive_attack(y_p[i])
            )
            true_negative = sum(
                1 for i in indices if _is_negative_benign(y_t[i]) and _is_negative_benign(y_p[i])
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
                1 for i in indices if _is_positive_attack(y_t[i]) and _is_positive_attack(y_p[i])
            )
            missed = sum(
                1 for i in indices if _is_positive_attack(y_t[i]) and _is_negative_benign(y_p[i])
            )
            detection_rate = float(detected / total) if total > 0 else 0.0
            fn_rate = float(missed / total) if total > 0 else 0.0

            breakdown[cat] = {
                "total": total,
                "detected": detected,
                "missed": missed,
                "detection_rate": detection_rate,
                "false_negative_rate": fn_rate,
            }

    return breakdown


def compute_wilson_confidence_interval(
    successes: int,
    total: int,
    confidence: float = 0.95,
) -> Dict[str, Union[int, float]]:
    """Compute Wilson score confidence interval for a binomial proportion.

    Used to quantify statistical uncertainty of Recall, Precision, FPR, and
    per-attack-category detection rates (especially rare classes such as Worms).

    Parameters
    ----------
    successes : int
        Number of successes (0 <= successes <= total).
    total : int
        Total number of trials (total >= 0).
    confidence : float, default 0.95
        Confidence level in (0.0, 1.0).

    Returns
    -------
    Dict[str, Union[int, float]]
        Dictionary with successes, total, proportion, ci_lower, ci_upper,
        ci_width, and confidence_level.
    """
    if isinstance(successes, bool) or not isinstance(successes, (int, np.integer)):
        raise ValueError(f"'successes' must be an integer, got {successes!r}")
    if isinstance(total, bool) or not isinstance(total, (int, np.integer)):
        raise ValueError(f"'total' must be an integer, got {total!r}")
    k = int(successes)
    n = int(total)
    if n < 0:
        raise ValueError(f"'total' must be non-negative, got {n}")
    if k < 0 or k > n:
        raise ValueError(f"'successes' ({k}) must satisfy 0 <= successes <= total ({n})")
    if not (0.0 < confidence < 1.0):
        raise ValueError(f"'confidence' must be in (0.0, 1.0), got {confidence}")

    if n == 0:
        return {
            "successes": 0,
            "total": 0,
            "proportion": 0.0,
            "ci_lower": 0.0,
            "ci_upper": 1.0,
            "ci_width": 1.0,
            "confidence_level": float(confidence),
        }

    # Standard normal critical value z for common confidence levels (with Acklam rational approx fallback)  # noqa: E501
    if abs(confidence - 0.95) < 1e-9:
        z = 1.959963984540054
    elif abs(confidence - 0.99) < 1e-9:
        z = 2.5758293035489004
    elif abs(confidence - 0.90) < 1e-9:
        z = 1.6448536269514722
    else:
        from statistics import NormalDist

        z = float(NormalDist().inv_cdf(0.5 + 0.5 * confidence))

    p_hat = float(k) / float(n)
    z2 = z * z
    denom = 1.0 + z2 / float(n)
    center = (p_hat + z2 / (2.0 * float(n))) / denom
    radicand = max(0.0, (p_hat * (1.0 - p_hat) / float(n)) + (z2 / (4.0 * float(n) * float(n))))
    half_width = (z * float(np.sqrt(radicand))) / denom

    ci_lower = max(0.0, min(1.0, center - half_width))
    ci_upper = max(0.0, min(1.0, center + half_width))
    if k == 0:
        ci_lower = 0.0
    if k == n:
        ci_upper = 1.0

    return {
        "successes": k,
        "total": n,
        "proportion": p_hat,
        "ci_lower": float(ci_lower),
        "ci_upper": float(ci_upper),
        "ci_width": float(ci_upper - ci_lower),
        "confidence_level": float(confidence),
    }


__all__ = [
    "compute_metrics",
    "compute_confusion_matrix_breakdown",
    "compute_benign_false_positive_breakdown",
    "compute_attack_category_breakdown",
    "compute_wilson_confidence_interval",
]
