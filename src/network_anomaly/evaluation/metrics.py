"""Evaluation metrics — works with supervised predictions.
Isolation Forest evaluation requires separate score-to-label protocol (documented in docs/EVALUATION.md)."""
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix,
)


def compute_metrics(y_true, y_pred, labels=None):
    return {
        "precision": precision_score(y_true, y_pred, average="binary", zero_division=0),
        "recall": recall_score(y_true, y_pred, average="binary", zero_division=0),
        "f1": f1_score(y_true, y_pred, average="binary", zero_division=0),
        "macro_f1": f1_score(y_true, y_pred, average="macro", zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
    }
