"""Robust Cross-Dataset Generalization Experiment Framework for NetFlow Sentinel v2.

Implements controlled, leak-free experiments across AIT-NDS-v2 and CTU-SME-11:
- E0: Full Canonical 18-feature v2 contract (`canonical-flow-v2-18`).
- E1: Rate-invariant ablation (excluding packet/byte rate features sensitive to capture jitter).
- E2: Base-only 6-feature flow contract (`BASE_FLOW_FEATURE_COLUMNS`).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

from network_anomaly.data.v2_schema import BASE_FLOW_FEATURE_COLUMNS, ML_FEATURE_COLUMNS

# 1. Feature Contract Definitions
FEATURES_E0: List[str] = list(ML_FEATURE_COLUMNS)

# E1: Exclude high-variance throughput rate features to test capture-timing shift
RATE_SENSITIVE_FEATURES: Set[str] = {"bytes_per_sec_in", "bytes_per_sec_out", "pkts_per_sec"}
FEATURES_E1: List[str] = [c for c in ML_FEATURE_COLUMNS if c not in RATE_SENSITIVE_FEATURES]

# E2: Base 6 observed flow fields only
FEATURES_E2: List[str] = list(BASE_FLOW_FEATURE_COLUMNS)


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
    pr_auc: Optional[float]
    confusion_matrix: Dict[str, Any]
    total_evaluated_rows: int
    duration_seconds: float
    per_attack_recall: Dict[str, float] = field(default_factory=dict)
    evaluation_level: str = "CROSS_DOMAIN_TRANSFER"
    leakage_audit: Optional[Dict[str, Any]] = None

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
            "pr_auc": round(self.pr_auc, 6) if self.pr_auc is not None else None,
            "confusion_matrix": self.confusion_matrix,
            "total_evaluated_rows": self.total_evaluated_rows,
            "duration_seconds": round(self.duration_seconds, 2),
            "per_attack_recall": self.per_attack_recall,
            "evaluation_level": self.evaluation_level,
            "leakage_audit": self.leakage_audit,
        }


def compute_fingerprint_disjoint_split(
    df: pd.DataFrame,
    train_size: float = 0.20,
    random_state: int = 42,
    feature_cols: Optional[List[str]] = None,
) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """Compute a strictly 5-tuple fingerprint-disjoint split with full duplicate leakage audit."""
    cols_to_check = feature_cols or FEATURES_E1

    # 1. Compute canonical 5-tuple flow fingerprint (bidirectional)
    if all(
        col in df.columns
        for col in ["source_ip", "source_port", "dest_ip", "dest_port", "protocol_num"]
    ):
        src_ep = df["source_ip"].astype(str) + ":" + df["source_port"].astype(str)
        dst_ep = df["dest_ip"].astype(str) + ":" + df["dest_port"].astype(str)
        cond = src_ep <= dst_ep
        ep1 = np.where(cond, src_ep, dst_ep)
        ep2 = np.where(cond, dst_ep, src_ep)
        groups = pd.Series(ep1) + "__" + pd.Series(ep2) + "__" + df["protocol_num"].astype(str)
    else:
        # Fallback to feature hash grouping if 5-tuple is stripped
        cols_to_hash = [
            c
            for c in df.columns
            if c not in {"label_binary", "attack_category", "raw_label", "label_status"}
        ]
        groups = pd.util.hash_pandas_object(df[cols_to_hash], index=False).astype(str)

    gss = GroupShuffleSplit(n_splits=1, train_size=train_size, random_state=random_state)
    train_idx, test_idx = next(gss.split(df, groups=groups))

    df_train = df.iloc[train_idx].copy().reset_index(drop=True)
    df_test = df.iloc[test_idx].copy().reset_index(drop=True)

    # 2. Audit 5-tuple fingerprint overlap
    train_fps = set(groups.iloc[train_idx])
    test_fps = set(groups.iloc[test_idx])
    overlap_fps = train_fps & test_fps

    # 3. Audit exact feature vector overlap
    train_feat_hashes = set(pd.util.hash_pandas_object(df_train[cols_to_check], index=False))
    test_feat_hashes = pd.util.hash_pandas_object(df_test[cols_to_check], index=False)
    feat_overlap_mask = test_feat_hashes.isin(train_feat_hashes)
    feat_overlap_count = int(feat_overlap_mask.sum())
    feat_overlap_ratio = float(feat_overlap_count / len(df_test)) if len(df_test) > 0 else 0.0

    # 4. Check label conflicts across shared feature hashes
    label_conflict_count = 0
    target_col = (
        "label_binary"
        if "label_binary" in df.columns
        else ("Label" if "Label" in df.columns else None)
    )
    if target_col is not None:
        train_map = dict(
            zip(
                pd.util.hash_pandas_object(df_train[cols_to_check], index=False),
                df_train[target_col],
            )
        )
        test_pairs = zip(
            pd.util.hash_pandas_object(df_test[cols_to_check], index=False), df_test["Label"]
        )
        for h, lbl in test_pairs:
            if h in train_map and train_map[h] != lbl:
                label_conflict_count += 1

    audit_findings = {
        "status": "PASS" if len(overlap_fps) == 0 else "FAIL",
        "train_rows": len(df_train),
        "test_rows": len(df_test),
        "train_fingerprints": len(train_fps),
        "test_fingerprints": len(test_fps),
        "overlap_5tuple_fingerprints": len(overlap_fps),
        "exact_feature_overlap_count": feat_overlap_count,
        "exact_feature_overlap_ratio": round(feat_overlap_ratio, 6),
        "label_conflict_count": label_conflict_count,
        "fingerprint_disjoint_verified": len(overlap_fps) == 0,
    }

    return df_train, df_test, audit_findings


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
        model_family: str = "RandomForestClassifier",
    ) -> None:
        self.experiment_id = experiment_id
        self.feature_set = list(feature_set)
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.model_family = model_family
        self.model_name = model_name or f"robust_{model_family.lower()[:2]}_{experiment_id.lower()}"

        if self.model_family == "HistGradientBoostingClassifier":
            from sklearn.ensemble import HistGradientBoostingClassifier

            self.classifier = HistGradientBoostingClassifier(
                max_iter=self.n_estimators,
                max_depth=self.max_depth,
                random_state=self.random_state,
            )
        elif self.model_family == "RandomForestClassifier":
            self.classifier = RandomForestClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                random_state=self.random_state,
                n_jobs=-1,
            )
        else:
            raise ValueError(f"Unsupported model family: {self.model_family}")

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
        evaluation_level: str = "CROSS_DOMAIN_TRANSFER",
        leakage_audit: Optional[Dict[str, Any]] = None,
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
        pr_auc = None
        if probs is not None:
            try:
                roc_auc = float(roc_auc_score(y_true, probs))
            except Exception:
                pass
            try:
                pr_auc = float(average_precision_score(y_true, probs))
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
            pr_auc=pr_auc,
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
            evaluation_level=evaluation_level,
            leakage_audit=leakage_audit,
        )

    def evaluate(
        self,
        X_test: pd.DataFrame,
        y_test: np.ndarray,
        attack_names: Optional[List[str]] = None,
        evaluation_level: str = "CROSS_DOMAIN_TRANSFER",
        leakage_audit: Optional[Dict[str, Any]] = None,
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
            evaluation_level=evaluation_level,
            leakage_audit=leakage_audit,
        )

    def generate_manifest(
        self,
        eval_metrics: Optional[ExperimentMetrics] = None,
        eval_dataset_name: str = "CTU-SME-11",
    ) -> Dict[str, Any]:
        """Generate scientific run manifest for reproducibility."""
        return {
            "experiment_id": self.experiment_id,
            "model_name": self.model_name,
            "model_family": self.model_family,
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
