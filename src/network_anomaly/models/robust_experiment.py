"""Robust Cross-Dataset Generalization Experiment Framework (Issue #48).

Implements controlled, leak-free experiments E0–E5 to address shortcut collapse:
- E0: Frozen Canonical Random Forest Baseline (47 features, with MIN_TTL/MAX_TTL).
- E1: No-TTL Random Forest (45 features, strictly excluding MIN_TTL and MAX_TTL).
- E2: Environment-Invariant Robust RF (41 features, excluding probe/lab specific artifacts).
- E3: Multi-Domain Joint Training Protocol.
- E4: Leave-One-Dataset-Out (LODO) Evaluation.
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


def compute_score_distribution(scores: np.ndarray) -> Dict[str, float]:
    """Calculate statistical distribution quantiles for continuous anomaly scores."""
    if len(scores) == 0:
        return {
            "mean": 0.0,
            "std": 0.0,
            "min": 0.0,
            "p50": 0.0,
            "p90": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "max": 0.0,
        }
    return {
        "mean": float(np.mean(scores)),
        "std": float(np.std(scores)),
        "min": float(np.min(scores)),
        "p50": float(np.percentile(scores, 50)),
        "p90": float(np.percentile(scores, 90)),
        "p95": float(np.percentile(scores, 95)),
        "p99": float(np.percentile(scores, 99)),
        "max": float(np.max(scores)),
    }


@dataclass
class UnsupervisedExperimentMetrics:
    """Evaluation metrics for unsupervised anomaly detectors (Isolation Forest & Autoencoder)."""

    threshold: float
    calibrated_nominal_fpr: float
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
    benign_score_stats: Dict[str, float]
    attack_score_stats: Dict[str, float]
    per_attack_recall: Dict[str, float] = field(default_factory=dict)
    evaluation_level: str = "CROSS_DOMAIN_TRANSFER"
    leakage_audit: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threshold": round(self.threshold, 6),
            "calibrated_nominal_fpr": round(self.calibrated_nominal_fpr, 4),
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
            "benign_score_stats": {k: round(v, 6) for k, v in self.benign_score_stats.items()},
            "attack_score_stats": {k: round(v, 6) for k, v in self.attack_score_stats.items()},
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
        for col in ["IPV4_SRC_ADDR", "L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT", "PROTOCOL"]
    ):
        src_ep = df["IPV4_SRC_ADDR"].astype(str) + ":" + df["L4_SRC_PORT"].astype(str)
        dst_ep = df["IPV4_DST_ADDR"].astype(str) + ":" + df["L4_DST_PORT"].astype(str)
        cond = src_ep <= dst_ep
        ep1 = np.where(cond, src_ep, dst_ep)
        ep2 = np.where(cond, dst_ep, src_ep)
        groups = pd.Series(ep1) + "__" + pd.Series(ep2) + "__" + df["PROTOCOL"].astype(str)
    else:
        # Fallback to feature hash grouping if 5-tuple is stripped
        cols_to_hash = [c for c in df.columns if c not in {"Label", "Attack"}]
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
    if "Label" in df.columns:
        train_map = dict(
            zip(pd.util.hash_pandas_object(df_train[cols_to_check], index=False), df_train["Label"])
        )
        test_pairs = zip(
            pd.util.hash_pandas_object(df_test[cols_to_check], index=False), df_test["Label"]
        )
        for h, l in test_pairs:
            if h in train_map and train_map[h] != l:
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
        elif self.model_family == "XGBClassifier":
            import xgboost as xgb

            self.classifier = xgb.XGBClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                random_state=self.random_state,
                eval_metric="logloss",
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
        eval_dataset_name: str = "NF-CSE-CIC-IDS2018-v3",
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


class UnsupervisedAnomalyExperiment:
    """Manages unsupervised anomaly detection experiments for Isolation Forest and Autoencoder."""

    def __init__(
        self,
        experiment_id: str,
        feature_set: List[str],
        model_family: str = "IsolationForest",
        random_state: int = 42,
        model_name: Optional[str] = None,
        # Isolation Forest options
        n_estimators: int = 100,
        contamination: str = "auto",
        # Autoencoder options
        hidden_layer_sizes: Tuple[int, ...] = (32, 16, 32),
        max_iter: int = 25,
    ) -> None:
        self.experiment_id = experiment_id
        self.feature_set = list(feature_set)
        self.model_family = model_family
        self.random_state = random_state
        self.model_name = (
            model_name or f"unsupervised_{model_family.lower()[:2]}_{experiment_id.lower()}"
        )
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.hidden_layer_sizes = hidden_layer_sizes
        self.max_iter = max_iter

        if self.model_family == "IsolationForest":
            from sklearn.ensemble import IsolationForest

            self.detector = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.random_state,
                n_jobs=-1,
            )
        elif self.model_family == "Autoencoder":
            from sklearn.neural_network import MLPRegressor

            self.detector = MLPRegressor(
                hidden_layer_sizes=self.hidden_layer_sizes,
                activation="relu",
                solver="adam",
                max_iter=self.max_iter,
                random_state=self.random_state,
                early_stopping=True,
                n_iter_no_change=5,
            )
        else:
            raise ValueError(f"Unsupported unsupervised model family: {self.model_family}")

        self.is_fitted = False
        self.threshold: Optional[float] = None
        self.calibrated_nominal_fpr: Optional[float] = None
        self.fitted_at_utc: Optional[str] = None
        self.training_duration_seconds: Optional[float] = None
        self.train_provenance: Dict[str, Any] = {}

    def fit(
        self,
        X_benign_train: pd.DataFrame,
        train_provenance: Optional[Dict[str, Any]] = None,
    ) -> UnsupervisedAnomalyExperiment:
        """Fit exclusively on benign normal traffic (Label == 0)."""
        X_sub = X_benign_train[self.feature_set].to_numpy(dtype=np.float32)

        t0 = time.time()
        if self.model_family == "IsolationForest":
            self.detector.fit(X_sub)
        elif self.model_family == "Autoencoder":
            self.detector.fit(X_sub, X_sub)
        self.training_duration_seconds = time.time() - t0
        self.is_fitted = True
        self.fitted_at_utc = datetime.now(timezone.utc).isoformat()
        self.train_provenance = train_provenance or {}
        return self

    def anomaly_scores(self, X: pd.DataFrame) -> np.ndarray:
        """Compute anomaly scores where larger value means MORE anomalous."""
        if not self.is_fitted:
            raise RuntimeError(f"Detector {self.experiment_id} is not fitted.")
        X_sub = X[self.feature_set].to_numpy(dtype=np.float32)
        if self.model_family == "IsolationForest":
            # scikit-learn decision_function is lower for anomalies -> negate so higher = anomaly
            return -np.asarray(self.detector.decision_function(X_sub), dtype=np.float64)
        elif self.model_family == "Autoencoder":
            X_hat = self.detector.predict(X_sub)
            return np.mean((X_sub - X_hat) ** 2, axis=1, dtype=np.float64)
        raise RuntimeError("Unknown model family state.")

    def calibrate_threshold(
        self,
        X_val_benign: pd.DataFrame,
        nominal_fpr: float = 0.05,
    ) -> float:
        """Calibrate decision threshold strictly on held-out benign validation traffic."""
        if not self.is_fitted:
            raise RuntimeError(f"Detector {self.experiment_id} is not fitted.")
        val_scores = self.anomaly_scores(X_val_benign)
        percentile = 100.0 * (1.0 - nominal_fpr)
        tau = float(np.percentile(val_scores, percentile))
        self.threshold = tau
        self.calibrated_nominal_fpr = nominal_fpr
        return tau

    def predict(
        self,
        X: pd.DataFrame,
        threshold: Optional[float] = None,
    ) -> np.ndarray:
        """Predict binary decision (1 = anomalous, 0 = benign)."""
        if not self.is_fitted:
            raise RuntimeError(f"Detector {self.experiment_id} is not fitted.")
        eff_tau = threshold if threshold is not None else self.threshold
        if eff_tau is None:
            raise ValueError(
                f"No decision threshold calibrated or provided for {self.experiment_id}. "
                "Call calibrate_threshold(X_val_benign) first."
            )
        scores = self.anomaly_scores(X)
        return (scores >= eff_tau).astype(int)

    def evaluate(
        self,
        X_test: pd.DataFrame,
        y_test: np.ndarray,
        attack_names: Optional[List[str]] = None,
        threshold: Optional[float] = None,
        evaluation_level: str = "CROSS_DOMAIN_TRANSFER",
        leakage_audit: Optional[Dict[str, Any]] = None,
    ) -> UnsupervisedExperimentMetrics:
        """Evaluate detector with complete score distributions and thresholded metrics."""
        if not self.is_fitted:
            raise RuntimeError(f"Detector {self.experiment_id} is not fitted.")

        eff_tau = threshold if threshold is not None else self.threshold
        if eff_tau is None:
            raise ValueError(
                "No decision threshold specified. Calibrate threshold before evaluation."
            )

        t0 = time.time()
        scores = self.anomaly_scores(X_test)
        dt = time.time() - t0
        preds = (scores >= eff_tau).astype(int)

        acc = float(accuracy_score(y_test, preds))
        prec = float(precision_score(y_test, preds, zero_division=0))
        rec = float(recall_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds, zero_division=0))
        macro_f1 = float(f1_score(y_test, preds, average="macro", zero_division=0))

        cm = confusion_matrix(y_test, preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        roc_auc = None
        pr_auc = None
        try:
            roc_auc = float(roc_auc_score(y_test, scores))
        except Exception:
            pass
        try:
            pr_auc = float(average_precision_score(y_test, scores))
        except Exception:
            pass

        benign_mask = y_test == 0
        attack_mask = y_test == 1
        benign_scores = scores[benign_mask]
        attack_scores = scores[attack_mask]

        benign_stats = compute_score_distribution(benign_scores)
        attack_stats = compute_score_distribution(attack_scores)

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

        return UnsupervisedExperimentMetrics(
            threshold=eff_tau,
            calibrated_nominal_fpr=(
                self.calibrated_nominal_fpr if self.calibrated_nominal_fpr is not None else 0.05
            ),
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
                "labels": ["Benign (0)", "Anomaly (1)"],
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
            },
            total_evaluated_rows=len(y_test),
            duration_seconds=dt,
            benign_score_stats=benign_stats,
            attack_score_stats=attack_stats,
            per_attack_recall=per_attack,
            evaluation_level=evaluation_level,
            leakage_audit=leakage_audit,
        )

    def generate_manifest(
        self,
        eval_metrics: Optional[UnsupervisedExperimentMetrics] = None,
        eval_dataset_name: str = "NF-CSE-CIC-IDS2018-v3",
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
            "calibration": {
                "threshold": self.threshold,
                "nominal_fpr": self.calibrated_nominal_fpr,
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
