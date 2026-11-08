"""Robust Cross-Dataset Generalization Experiment Framework (Issue #48).

Implements controlled, leak-free experiments E0–E5 to address shortcut collapse:
- E0: Frozen Canonical Random Forest Baseline (47 features, with MIN_TTL/MAX_TTL).
- E1: No-TTL Random Forest (45 features, strictly excluding MIN_TTL and MAX_TTL).
- E2: Environment-Invariant Robust RF (41 features, excluding probe/lab specific artifacts).
- E3: Multi-Domain Joint Training Protocol.
- E4: Leave-One-Dataset-Out (LODO) Evaluation.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS

# 1. Feature Contract Definitions
FEATURES_E0: List[str] = list(ML_FEATURE_COLUMNS)

# E1: Exclude MIN_TTL and MAX_TTL shortcut features
SHORTCUT_TTL_FEATURES: Set[str] = {"MIN_TTL", "MAX_TTL"}
FEATURES_E1: List[str] = [c for c in ML_FEATURE_COLUMNS if c not in SHORTCUT_TTL_FEATURES]

# E2: Exclude TTL + Application L7 artifacts that depend on specific generator infrastructure
ENVIRONMENT_SPECIFIC_FEATURES: Set[str] = {
    "MIN_TTL",
    "MAX_TTL",
    "DNS_QUERY_ID",
    "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER",
    "FTP_COMMAND_RET_CODE",
}
FEATURES_E2: List[str] = [c for c in ML_FEATURE_COLUMNS if c not in ENVIRONMENT_SPECIFIC_FEATURES]


@dataclass
class ExperimentMetrics:
    """Multi-dimensional evaluation metrics for generalization audit."""

    accuracy: float
    precision: float
    recall: float
    f1: float
    macro_f1: float
    false_positive_rate: float
    false_negative_rate: float
    roc_auc: Optional[float]
    confusion_matrix: Dict[str, Any]
    total_evaluated_rows: int
    duration_seconds: float
    per_attack_recall: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accuracy": round(self.accuracy, 6),
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "f1": round(self.f1, 6),
            "macro_f1": round(self.macro_f1, 6),
            "false_positive_rate": round(self.false_positive_rate, 6),
            "false_negative_rate": round(self.false_negative_rate, 6),
            "roc_auc": round(self.roc_auc, 6) if self.roc_auc is not None else None,
            "confusion_matrix": self.confusion_matrix,
            "total_evaluated_rows": self.total_evaluated_rows,
            "duration_seconds": round(self.duration_seconds, 2),
            "per_attack_recall": self.per_attack_recall,
        }


class RobustModelExperiment:
    """Manages training, evaluation, and manifest generation for robust generalization models."""

    def __init__(
        self,
        experiment_id: str,
        feature_set: List[str],
        n_estimators: int = 100,
        max_depth: int = 16,
        random_state: int = 42,
        model_name: Optional[str] = None,
    ) -> None:
        self.experiment_id = experiment_id
        self.feature_set = list(feature_set)
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.model_name = model_name or f"robust_rf_{experiment_id.lower()}"

        self.classifier = RandomForestClassifier(
            n_estimators=self.n_estimators,
            max_depth=self.max_depth,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.is_fitted = False
        self.fitted_at_utc: Optional[str] = None
        self.training_duration_seconds: Optional[float] = None
        self.train_provenance: Dict[str, Any] = {}

    def fit(
        self,
        X_train: pd.DataFrame,
        y_train: np.ndarray,
        train_provenance: Optional[Dict[str, Any]] = None,
    ) -> RobustModelExperiment:
        """Fit the model exclusively on the designated training partition."""
        # Enforce exact feature contract columns
        X_sub = X_train[self.feature_set]

        t0 = time.time()
        self.classifier.fit(X_sub, y_train)
        self.training_duration_seconds = time.time() - t0
        self.is_fitted = True
        self.fitted_at_utc = datetime.now(timezone.utc).isoformat()
        self.train_provenance = train_provenance or {}
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        if not self.is_fitted:
            raise RuntimeError(f"Experiment model {self.experiment_id} is not fitted.")
        X_sub = X[self.feature_set]
        return self.classifier.predict(X_sub)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        if not self.is_fitted:
            raise RuntimeError(f"Experiment model {self.experiment_id} is not fitted.")
        X_sub = X[self.feature_set]
        return self.classifier.predict_proba(X_sub)

    @staticmethod
    def compute_metrics(
        y_true: np.ndarray,
        preds: np.ndarray,
        probs: Optional[np.ndarray] = None,
        attack_names: Optional[List[str]] = None,
        duration_seconds: float = 0.0,
    ) -> ExperimentMetrics:
        """Compute standard ExperimentMetrics from true labels and predictions."""
        acc = float(accuracy_score(y_true, preds))
        prec = float(precision_score(y_true, preds, zero_division=0))
        rec = float(recall_score(y_true, preds, zero_division=0))
        f1 = float(f1_score(y_true, preds, zero_division=0))
        macro_f1 = float(f1_score(y_true, preds, average="macro", zero_division=0))

        cm = confusion_matrix(y_true, preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        roc_auc = None
        if probs is not None:
            try:
                roc_auc = float(roc_auc_score(y_true, probs))
            except Exception:
                pass

        # Per-attack category recall breakdown
        per_attack: Dict[str, float] = {}
        if attack_names is not None:
            for cat in sorted(set(attack_names)):
                mask = np.array([a == cat for a in attack_names])
                if cat == "Benign":
                    cat_correct = int((preds[mask] == 0).sum())
                    per_attack["Benign_Specificity"] = float(cat_correct / mask.sum())
                else:
                    cat_tp = int((preds[mask] == 1).sum())
                    per_attack[cat] = float(cat_tp / mask.sum()) if mask.sum() > 0 else 0.0

        return ExperimentMetrics(
            accuracy=acc,
            precision=prec,
            recall=rec,
            f1=f1,
            macro_f1=macro_f1,
            false_positive_rate=fpr,
            false_negative_rate=fnr,
            roc_auc=roc_auc,
            confusion_matrix={
                "labels": ["Benign (0)", "Attack (1)"],
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
            },
            total_evaluated_rows=len(y_true),
            duration_seconds=duration_seconds,
            per_attack_recall=per_attack,
        )

    def evaluate(
        self,
        X_test: pd.DataFrame,
        y_test: np.ndarray,
        attack_names: Optional[List[str]] = None,
    ) -> ExperimentMetrics:
        """Run multi-dimensional evaluation on external or validation dataset."""
        if not self.is_fitted:
            raise RuntimeError(f"Experiment model {self.experiment_id} is not fitted.")

        t0 = time.time()
        preds = self.predict(X_test)
        dt = time.time() - t0

        probs = None
        try:
            probs = self.predict_proba(X_test)[:, 1]
        except Exception:
            pass

        return self.compute_metrics(
            y_true=y_test,
            preds=preds,
            probs=probs,
            attack_names=attack_names,
            duration_seconds=dt,
        )

    def generate_manifest(
        self,
        eval_metrics: Optional[ExperimentMetrics] = None,
        eval_dataset_name: str = "NF-CSE-CIC-IDS2018-v3",
    ) -> Dict[str, Any]:
        """Generate scientific run manifest for reproducibility."""
        return {
            "experiment_id": self.experiment_id,
            "model_name": self.model_name,
            "model_family": "RandomForestClassifier",
            "feature_contract": {
                "features_count": len(self.feature_set),
                "feature_list": self.feature_set,
                "excluded_shortcuts": [c for c in ML_FEATURE_COLUMNS if c not in self.feature_set],
            },
            "hyperparameters": {
                "n_estimators": self.n_estimators,
                "max_depth": self.max_depth,
                "random_state": self.random_state,
            },
            "training_metadata": {
                "fitted_at_utc": self.fitted_at_utc,
                "duration_seconds": self.training_duration_seconds,
                "provenance": self.train_provenance,
            },
            "evaluation": {
                "target_dataset": eval_dataset_name,
                "metrics": eval_metrics.to_dict() if eval_metrics else None,
            },
        }
