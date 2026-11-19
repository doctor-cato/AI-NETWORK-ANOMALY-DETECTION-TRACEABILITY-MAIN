"""Stage-2 6-Class Attack Classifier Sidecar (Canonical Taxonomy-v2).

Provides a lightweight sidecar classifier that refines Stage-1 binary anomaly
detections into one of the 5 non-Benign canonical attack categories:
  - Credential_Attack
  - Data_Exfiltration
  - Exploitation_And_C2
  - Post_Exploitation_Discovery
  - Reconnaissance

When the full `.joblib` RandomForest estimator is present and passes SHA-256
verification against `reports/experiments/ml/multiclass_stage2_manifest.json`,
it is used directly. When the `.joblib` artifact is absent (e.g., on a clean CI
runner), `Stage2MulticlassClassifier.try_load_default()` seamlessly falls back
to the tracked 18-D preprocessed per-class centroid & diagonal-std profile
stored inside `multiclass_stage2_manifest.json` using softmax inverse-Mahalanobis
probabilities across the 5 attack classes.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import joblib
import numpy as np

from network_anomaly.config import PROJECT_ROOT

logger = logging.getLogger(__name__)

CANONICAL_6_CLASSES: Tuple[str, ...] = (
    "Benign",
    "Credential_Attack",
    "Data_Exfiltration",
    "Exploitation_And_C2",
    "Post_Exploitation_Discovery",
    "Reconnaissance",
)

ATTACK_ONLY_CLASSES: Tuple[str, ...] = tuple(c for c in CANONICAL_6_CLASSES if c != "Benign")

DEFAULT_STAGE2_ARTIFACT_PATH: Path = (
    PROJECT_ROOT / "artifacts" / "experiments" / "multiclass_stage2" / "rf_multiclass_stage2.joblib"
)
DEFAULT_STAGE2_MANIFEST_PATH: Path = (
    PROJECT_ROOT / "reports" / "experiments" / "ml" / "multiclass_stage2_manifest.json"
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest().lower()


class Stage2MulticlassClassifier:
    """Sidecar 6-class attack classifier with estimator + centroid fallback modes."""

    def __init__(
        self,
        *,
        estimator: Any = None,
        classes: Sequence[str] = CANONICAL_6_CLASSES,
        class_centroids: Optional[Dict[str, Sequence[float]]] = None,
        class_stds: Optional[Dict[str, Sequence[float]]] = None,
        mode: str = "centroid",
        manifest: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.estimator = estimator
        self.classes: Tuple[str, ...] = tuple(classes)
        self.attack_classes: Tuple[str, ...] = tuple(c for c in self.classes if c != "Benign")
        self.mode = mode
        self.manifest = manifest or {}

        self._centroids: Dict[str, np.ndarray] = {}
        self._stds: Dict[str, np.ndarray] = {}
        if class_centroids and class_stds:
            for cname in self.attack_classes:
                if cname in class_centroids and cname in class_stds:
                    self._centroids[cname] = np.asarray(class_centroids[cname], dtype=np.float64)
                    self._stds[cname] = np.maximum(
                        np.asarray(class_stds[cname], dtype=np.float64), 1e-3
                    )

        if self.mode == "estimator" and self.estimator is None:
            raise ValueError("estimator mode requires a non-None estimator")
        if self.mode == "centroid" and len(self._centroids) != len(self.attack_classes):
            missing = [c for c in self.attack_classes if c not in self._centroids]
            raise ValueError(f"centroid mode missing class_centroids/stds for: {missing}")

        self._attack_centroids_mat: Optional[np.ndarray] = None
        self._attack_stds_mat: Optional[np.ndarray] = None
        if len(self._centroids) == len(self.attack_classes):
            self._attack_centroids_mat = np.stack(
                [self._centroids[c] for c in self.attack_classes], axis=0
            )
            self._attack_stds_mat = np.stack([self._stds[c] for c in self.attack_classes], axis=0)

    @classmethod
    def from_manifest(
        cls,
        manifest_path: Path = DEFAULT_STAGE2_MANIFEST_PATH,
        *,
        artifact_path: Optional[Path] = DEFAULT_STAGE2_ARTIFACT_PATH,
        expected_preprocessor_sha256: Optional[str] = None,
    ) -> "Stage2MulticlassClassifier":
        """Load classifier from manifest, using `.joblib` if present and hash-verified."""
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if expected_preprocessor_sha256 is not None:
            expected_preproc = expected_preprocessor_sha256.strip().lower()
            actual_preproc = (
                str(manifest_data.get("preprocessor_artifact_sha256", "")).strip().lower()
            )
            if not actual_preproc or actual_preproc != expected_preproc:
                raise ValueError(
                    f"Stage-2 manifest preprocessor SHA-256 mismatch: "
                    f"expected {expected_preproc}, got {actual_preproc or '<missing>'}"
                )
        classes = tuple(manifest_data.get("classes", CANONICAL_6_CLASSES))
        class_centroids = manifest_data.get("class_centroids")
        class_stds = manifest_data.get("class_stds")
        expected_sha = str(manifest_data.get("model_artifact_sha256", "")).strip().lower()

        if artifact_path is not None and artifact_path.is_file():
            actual_sha = _sha256_file(artifact_path)
            if expected_sha and actual_sha != expected_sha:
                raise ValueError(
                    f"Stage-2 artifact SHA-256 mismatch for {artifact_path}: "
                    f"expected {expected_sha}, got {actual_sha}"
                )
            estimator = joblib.load(artifact_path)
            return cls(
                estimator=estimator,
                classes=classes,
                class_centroids=class_centroids,
                class_stds=class_stds,
                mode="estimator",
                manifest=manifest_data,
            )

        logger.info(
            "Stage-2 .joblib artifact absent (%s); using lightweight centroid profile from %s",
            artifact_path,
            manifest_path,
        )
        return cls(
            estimator=None,
            classes=classes,
            class_centroids=class_centroids,
            class_stds=class_stds,
            mode="centroid",
            manifest=manifest_data,
        )

    @classmethod
    def try_load_default(
        cls,
        *,
        artifact_path: Path = DEFAULT_STAGE2_ARTIFACT_PATH,
        manifest_path: Path = DEFAULT_STAGE2_MANIFEST_PATH,
        expected_preprocessor_sha256: Optional[str] = None,
    ) -> Optional["Stage2MulticlassClassifier"]:
        """Attempt to load the default Stage-2 classifier; return None if manifest is absent."""
        if not manifest_path.is_file():
            return None
        try:
            return cls.from_manifest(
                manifest_path=manifest_path,
                artifact_path=artifact_path,
                expected_preprocessor_sha256=expected_preprocessor_sha256,
            )
        except Exception as exc:
            logger.warning("Failed to load default Stage-2 classifier: %s", exc)
            return None

    def _predict_attack_probs_estimator(self, X_2d: np.ndarray) -> np.ndarray:
        raw_probs = np.asarray(self.estimator.predict_proba(X_2d), dtype=np.float64)
        est_classes = getattr(self.estimator, "classes_", list(range(len(self.classes))))
        idx_by_name: Dict[str, int] = {}
        for col_idx, raw_cls in enumerate(est_classes):
            if isinstance(raw_cls, (int, np.integer)) and 0 <= int(raw_cls) < len(self.classes):
                idx_by_name[self.classes[int(raw_cls)]] = col_idx
            else:
                idx_by_name[str(raw_cls)] = col_idx

        attack_probs = np.zeros((X_2d.shape[0], len(self.attack_classes)), dtype=np.float64)
        for j, cname in enumerate(self.attack_classes):
            if cname in idx_by_name:
                attack_probs[:, j] = raw_probs[:, idx_by_name[cname]]

        row_sums = attack_probs.sum(axis=1, keepdims=True)
        uniform = np.full_like(attack_probs, 1.0 / max(1, len(self.attack_classes)))
        return np.where(row_sums > 1e-12, attack_probs / np.maximum(row_sums, 1e-12), uniform)

    def _predict_attack_probs_centroid(self, X_2d: np.ndarray) -> np.ndarray:
        if self._attack_centroids_mat is None or self._attack_stds_mat is None:
            raise RuntimeError("Centroid matrices are not initialized")
        # X_2d: (N, D), centroids: (K, D), stds: (K, D) -> diff: (N, K, D)
        diff = (X_2d[:, None, :] - self._attack_centroids_mat[None, :, :]) / (
            self._attack_stds_mat[None, :, :]
        )
        mean_sq_mahal = np.mean(diff * diff, axis=2)  # (N, K)
        logits = -0.5 * mean_sq_mahal
        logits = logits - np.max(logits, axis=1, keepdims=True)
        exp_logits = np.exp(logits)
        return exp_logits / np.sum(exp_logits, axis=1, keepdims=True)

    def predict_batch(self, X_mat: np.ndarray) -> List[Tuple[str, float]]:
        """Predict `(attack_category, confidence)` for a batch of 18-D preprocessed flows."""
        arr = np.asarray(X_mat, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        if arr.ndim != 2:
            raise ValueError(f"Expected 1D or 2D array, got shape {arr.shape}")
        if arr.shape[0] == 0:
            return []

        if self.mode == "estimator":
            probs = self._predict_attack_probs_estimator(arr)
        else:
            probs = self._predict_attack_probs_centroid(arr)

        best_indices = np.argmax(probs, axis=1)
        results: List[Tuple[str, float]] = []
        for row_idx, cls_idx in enumerate(best_indices):
            conf = float(np.clip(probs[row_idx, cls_idx], 0.0, 1.0))
            results.append((self.attack_classes[int(cls_idx)], conf))
        return results

    def predict_one(self, X_row: np.ndarray) -> Tuple[str, float]:
        """Predict `(attack_category, confidence)` for a single 18-D preprocessed flow."""
        return self.predict_batch(np.asarray(X_row, dtype=np.float64).reshape(1, -1))[0]
