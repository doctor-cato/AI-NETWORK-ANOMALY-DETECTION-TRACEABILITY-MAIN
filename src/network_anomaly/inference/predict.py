"""CSV Inference Pipeline for NF-UNSW-NB15-v3 network flow anomaly detection.

Provides end-to-end, reproducible, and verifiable inference on new network flows:
1. Validates input CSV existence, non-emptiness, and NF-UNSW-NB15-v3 schema contract.
2. Enforces the ordered 47 baseline ML features while strictly rejecting targets
   and trace-only metadata from feature input.
3. Loads and verifies train-only preprocessing artifact (from Issue #8) with strict SHA-256
   and companion manifest integrity checks (fail-closed).
4. Loads and verifies trained model artifact (Issue #10/#11) with SHA-256 and companion
   manifest provenance verification.
5. Transforms data using frozen preprocessor state (zero refitting / zero leakage).
6. Generates row-aligned predictions and prediction probabilities/scores.
7. Exports results to CSV preserving input row identity.
8. Writes comprehensive traceability metadata JSON recording all run provenance.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
import sklearn

from network_anomaly.config import PROJECT_ROOT
from network_anomaly.data.nf_unsw_nb15_v3 import (
    ML_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.preprocessing import (
    FEATURE_CONTRACT_VERSION,
    PREPROCESSING_POLICY_VERSION,
    TrainOnlyPreprocessor,
    audit_column_tokens,
)


def _sha256_file(path: Union[str, Path]) -> str:
    """Compute hex SHA-256 digest of a file in 64KB blocks."""
    path = Path(path)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _get_git_commit() -> str:
    """Retrieve git HEAD commit SHA, or 'unknown' if unavailable."""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
            cwd=PROJECT_ROOT,
        ).strip()
    except Exception:
        return "unknown"


def validate_inference_input(
    df: pd.DataFrame,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Validate and prepare inference input according to NF-UNSW-NB15-v3 contract.

    Enforces:
    - Input must be a non-empty pandas DataFrame.
    - All 47 required baseline ML features must be present in the CSV.
    - Column ordering is reordered to exact canonical contract order (ML_FEATURE_COLUMNS).
    - Targets (Label, Attack) and trace metadata (IPs, Ports, Timestamps) are strictly
      excluded from the feature matrix X.
    - Non-numeric / invalid tokens are detected via token auditing; unparseable strings
      raise a clear ValueError with sample offending tokens.
    - Preserves input row identity (row_id).

    Parameters
    ----------
    df : pd.DataFrame
        Input DataFrame loaded from CSV.

    Returns
    -------
    X_ordered : pd.DataFrame
        Cleaned feature matrix containing the 47 baseline ML features in contract order.
    summary : Dict[str, Any]
        Audit summary including row count, extra columns excluded, and row IDs.

    Raises
    ------
    TypeError
        If df is not a pandas DataFrame.
    ValueError
        If df is empty, missing required features, or contains unparseable values.
    """
    if not isinstance(df, pd.DataFrame):
        raise TypeError(f"Input must be a pandas DataFrame, got {type(df).__name__}")

    if len(df) == 0:
        raise ValueError("Input DataFrame is empty (contains 0 rows)")

    # 1. Enforce presence of all 47 baseline ML features
    missing_features = [col for col in ML_FEATURE_COLUMNS if col not in df.columns]
    if missing_features:
        raise ValueError(
            f"Input data is missing {len(missing_features)} required baseline ML feature(s): "
            f"{missing_features}"
        )

    # 2. Reorder columns to exact canonical ML contract order
    X_ordered = df[list(ML_FEATURE_COLUMNS)].copy()

    # 3. Categorize extra columns
    input_columns = list(df.columns)
    extra_columns = [col for col in input_columns if col not in ML_FEATURE_COLUMNS]
    target_columns_present = [col for col in input_columns if col in TARGET_COLUMNS]
    trace_metadata_present = [col for col in input_columns if col in TRACE_METADATA_COLUMNS]
    other_extra_columns = [
        col
        for col in extra_columns
        if col not in TARGET_COLUMNS and col not in TRACE_METADATA_COLUMNS
    ]

    # 4. Audit each feature column for invalid / unparseable numeric tokens
    # Note: audit_column_tokens converts valid missing tokens (NaN, null, Inf) to np.nan
    # for downstream imputation by fitted preprocessor; raises ValueError on unparseable tokens.
    for col in ML_FEATURE_COLUMNS:
        audit_column_tokens(X_ordered[col], col)

    # 5. Extract or generate row identities
    if "row_id" in df.columns:
        row_ids = df["row_id"].values
    elif "id" in df.columns:
        row_ids = df["id"].values
    else:
        row_ids = np.arange(len(df), dtype=np.int64)

    summary = {
        "row_count": len(df),
        "feature_count": len(ML_FEATURE_COLUMNS),
        "features_in_order": list(ML_FEATURE_COLUMNS),
        "extra_columns_count": len(extra_columns),
        "extra_columns": extra_columns,
        "target_columns_excluded": target_columns_present,
        "trace_metadata_excluded": trace_metadata_present,
        "other_extra_columns_excluded": other_extra_columns,
        "row_ids": row_ids,
    }

    return X_ordered, summary


def load_verified_preprocessor(
    artifact_path: Union[str, Path],
    manifest_path: Optional[Union[str, Path]] = None,
    split_manifest_path: Optional[Union[str, Path]] = None,
) -> Tuple[TrainOnlyPreprocessor, Dict[str, Any]]:
    """Load and verify train-only preprocessor artifact with strict integrity checks.

    Parameters
    ----------
    artifact_path : str or Path
        Path to saved preprocessor .joblib artifact.
    manifest_path : str or Path, optional
        Path to companion JSON manifest. If omitted, standard locations are searched.
    split_manifest_path : str or Path, optional
        Path to split manifest if split consistency validation is required.

    Returns
    -------
    preprocessor : TrainOnlyPreprocessor
        Verified and loaded preprocessor instance.
    metadata : Dict[str, Any]
        Preprocessor metadata and hashes.

    Raises
    ------
    FileNotFoundError
        If artifact or companion manifest cannot be found.
    ValueError
        If hash mismatch or manifest schema validation fails.
    """
    artifact_path = Path(artifact_path)
    if not artifact_path.is_file():
        raise FileNotFoundError(f"Preprocessing artifact not found at '{artifact_path}'")

    if manifest_path is None:
        candidates = [
            artifact_path.with_suffix(".json"),
            artifact_path.parent / f"{artifact_path.stem}_manifest.json",
            artifact_path.parent / "manifest.json",
            artifact_path.parent / "nf_unsw_nb15_v3_preprocessing_manifest.json",
            PROJECT_ROOT
            / "reports"
            / "preprocessing"
            / "nf_unsw_nb15_v3_preprocessing_manifest.json",
        ]
        for c in candidates:
            if c.is_file():
                manifest_path = c
                break

    if manifest_path is None or not Path(manifest_path).is_file():
        raise FileNotFoundError(
            f"Companion manifest for preprocessor not found. Checked candidate: {manifest_path}. "
            "A verified preprocessor requires a valid companion JSON manifest."
        )

    manifest_path = Path(manifest_path)
    manifest_sha = _sha256_file(manifest_path)
    artifact_sha = _sha256_file(artifact_path)

    preprocessor = TrainOnlyPreprocessor.load_verified(
        artifact_path=artifact_path,
        manifest_path=manifest_path,
        split_manifest_path=split_manifest_path,
    )

    prep_meta = preprocessor.get_metadata()
    metadata = {
        "artifact_path": str(artifact_path),
        "artifact_sha256": artifact_sha,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha,
        "feature_contract_version": prep_meta.get(
            "feature_contract_version", FEATURE_CONTRACT_VERSION
        ),
        "preprocessing_policy_version": prep_meta.get(
            "preprocessing_policy_version", PREPROCESSING_POLICY_VERSION
        ),
        "train_row_count": preprocessor.train_row_count_,
        "fitted_at_utc": preprocessor.fitted_at_utc_,
    }
    return preprocessor, metadata


def _canonical_model_family(model_type: str) -> str:
    """Map model class and manifest type aliases to canonical model family identifiers."""
    normalized = model_type.strip()
    aliases = {
        "RandomForest": "random_forest",
        "RandomForestClassifier": "random_forest",
        "RandomForestModel": "random_forest",
        "IsolationForest": "isolation_forest",
        "IsolationForestModel": "isolation_forest",
        "XGBoost": "xgboost",
        "XGBClassifier": "xgboost",
        "XGBoostModel": "xgboost",
        "HistGradientBoostingClassifier": "hist_gradient_boosting",
    }
    return aliases.get(normalized, normalized)


def load_verified_model(
    model_artifact_path: Union[str, Path],
    manifest_path: Optional[Union[str, Path]] = None,
    expected_preprocessor_sha256: Optional[str] = None,
) -> Tuple[Any, Dict[str, Any]]:
    """Load and verify a trained model artifact with provenance verification.

    Parameters
    ----------
    model_artifact_path : str or Path
        Path to saved model .joblib artifact.
    manifest_path : str or Path, optional
        Path to companion model JSON manifest.
    expected_preprocessor_sha256 : str, optional
        Expected SHA-256 of preprocessor for cross-artifact compatibility check.

    Returns
    -------
    model : Any
        Deserialized model object.
    model_metadata : Dict[str, Any]
        Model metadata including run_id, model_type, SHA-256, and class mapping.

    Raises
    ------
    FileNotFoundError
        If model artifact or specified manifest is not found.
    ValueError
        If SHA-256 mismatches, contract mismatches, or preprocessor incompatibility is found.
    RuntimeError
        If model deserialization fails.
    """
    model_path = Path(model_artifact_path)
    if not model_path.is_file():
        raise FileNotFoundError(f"Model artifact not found at '{model_path}'")

    model_sha256 = _sha256_file(model_path)

    if manifest_path is None:
        stem_lower = model_path.stem.lower()
        candidates = [
            model_path.with_suffix(".json"),
            model_path.parent / f"{model_path.stem}_manifest.json",
            model_path.parent / "manifest.json",
            PROJECT_ROOT / "reports" / "models" / f"{model_path.stem}_manifest.json",
        ]
        if "random_forest" in stem_lower:
            candidates.insert(
                2, PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json"
            )
            candidates.insert(3, model_path.parent / "random_forest_manifest.json")
        elif "isolation_forest" in stem_lower:
            candidates.insert(
                2, PROJECT_ROOT / "reports" / "models" / "isolation_forest_manifest.json"
            )
            candidates.insert(3, model_path.parent / "isolation_forest_manifest.json")
        elif "xgboost" in stem_lower:
            candidates.insert(2, PROJECT_ROOT / "reports" / "models" / "xgboost_manifest.json")
            candidates.insert(3, model_path.parent / "xgboost_manifest.json")
        for c in candidates:
            if c.is_file():
                manifest_path = c
                break

    if manifest_path is None or not Path(manifest_path).is_file():
        raise FileNotFoundError(
            f"Companion manifest for model not found for '{model_path}'. "
            "A verified model requires a valid companion JSON manifest (Issue #53 fail-closed)."
        )

    man_p = Path(manifest_path)
    try:
        manifest_data = json.loads(man_p.read_text(encoding="utf-8"))
    except Exception as e:
        raise ValueError(f"Failed to parse model manifest JSON at '{man_p}': {e}")

    if not isinstance(manifest_data, dict):
        raise ValueError(
            f"Model manifest JSON must be a dict/object at '{man_p}', "
            f"got {type(manifest_data).__name__}"
        )

    # Verify model artifact sha256 (mandatory byte-by-byte check)
    expected_sha = manifest_data.get("model_artifact_sha256")
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha):
        raise ValueError(
            f"Model manifest at '{man_p}' missing required field 'model_artifact_sha256'"
        )
    if expected_sha.strip().lower() != model_sha256.lower():
        raise ValueError(
            f"Model artifact SHA-256 mismatch: expected {expected_sha}, got {model_sha256}"
        )

    # Verify feature contract (mandatory contract version check)
    feat_contract = manifest_data.get("feature_contract_version")
    if not feat_contract or not isinstance(feat_contract, str):
        raise ValueError(
            f"Model manifest at '{man_p}' missing required field 'feature_contract_version'"
        )
    if feat_contract != FEATURE_CONTRACT_VERSION:
        raise ValueError(
            f"Model feature contract version '{feat_contract}' does not match "
            f"expected '{FEATURE_CONTRACT_VERSION}'"
        )

    # A caller-supplied digest cannot replace the model's companion binding.
    prep_sha = manifest_data.get("preprocessor_artifact_sha256")
    if not isinstance(prep_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", prep_sha):
        raise ValueError("Model manifest missing required field 'preprocessor_artifact_sha256'")
    if expected_preprocessor_sha256 and prep_sha.lower() != expected_preprocessor_sha256.lower():
        raise ValueError(
            f"Model was trained with preprocessor SHA-256 '{prep_sha}', "
            f"but current preprocessor artifact has SHA-256 '{expected_preprocessor_sha256}'. "
            "Inference pipeline requires exact preprocessor compatibility."
        )

    # Verify model_type is explicitly declared before deserialization
    manifest_model_type = manifest_data.get("model_type")
    if (
        not isinstance(manifest_model_type, str)
        or not manifest_model_type.strip()
        or manifest_model_type.strip().lower() == "unknown"
    ):
        raise ValueError(f"Model manifest at '{man_p}' missing required field 'model_type'")
    manifest_model_type = manifest_model_type.strip()
    expected_family = _canonical_model_family(manifest_model_type)

    man_sha = _sha256_file(man_p)
    model_metadata: Dict[str, Any] = {
        "model_artifact_path": str(model_path),
        "model_artifact_sha256": model_sha256,
        "model_manifest_path": str(man_p),
        "model_manifest_sha256": man_sha,
        "model_type": manifest_model_type,
        "run_id": manifest_data.get("run_id", "untracked"),
        "feature_contract_version": feat_contract,
        "class_mapping": manifest_data.get("class_mapping"),
        "hyperparameters": manifest_data.get("hyperparameters", {}),
        "raw_manifest": manifest_data,
    }

    if expected_family == "isolation_forest":
        from network_anomaly.models.isolation_forest import IsolationForestModel

        model = IsolationForestModel.load_verified(
            model_path,
            man_p,
            expected_preprocessor_artifact_sha256=expected_preprocessor_sha256,
        )
        return model, model_metadata

    # CRITICAL: Only deserialize AFTER all cryptographic hashes and contracts have passed!
    try:
        loaded_obj = joblib.load(model_path)
    except Exception as e:
        raise RuntimeError(f"Failed to deserialize model artifact from '{model_path}': {e}")

    from sklearn.ensemble import IsolationForest

    if isinstance(loaded_obj, dict) and "estimator" in loaded_obj:
        # Artifact is a serialization payload dictionary (e.g. from RandomForestModel.save)
        model = loaded_obj["estimator"]
        payload_model_type = loaded_obj.get("model_type")
        estimator = model
        if not model_metadata.get("class_mapping") and "classes" in loaded_obj:
            classes = loaded_obj["classes"]
            if classes is not None and isinstance(classes, list):
                model_metadata["class_mapping"] = {
                    str(c): "Attack" if str(c) == "1" else "Benign" for c in classes
                }
    else:
        model = loaded_obj
        payload_model_type = getattr(loaded_obj, "model_type", None)
        # Only unwrap private `_estimator` (our repo wrapper convention); sklearn
        # ensembles expose public `.estimator` as the base template class, not self.
        private_est = getattr(loaded_obj, "_estimator", None)
        estimator = private_est if private_est is not None else loaded_obj

    estimator_name = type(estimator).__name__
    if isinstance(estimator, IsolationForest) or (
        payload_model_type is not None
        and _canonical_model_family(str(payload_model_type)) == "isolation_forest"
    ):
        raise ValueError(
            f"Model type mismatch between manifest ('{manifest_model_type}') and "
            f"deserialized payload (model_type={payload_model_type!r}, estimator='{estimator_name}'): "
            "IsolationForest artifacts must declare model_type='IsolationForest'"
        )

    estimator_family = _canonical_model_family(estimator_name)
    if estimator_family != expected_family or (
        payload_model_type is not None
        and _canonical_model_family(str(payload_model_type)) != expected_family
    ):
        raise ValueError(
            f"Model type mismatch between manifest ('{manifest_model_type}') and "
            f"deserialized payload (model_type={payload_model_type!r}, estimator='{estimator_name}')"
        )

    return model, model_metadata


@dataclass
class InferenceResult:
    """Result object encapsulating predictions, metadata, and output locations."""

    predictions_df: pd.DataFrame
    metadata: Dict[str, Any]
    output_path: Optional[Path] = None
    metadata_path: Optional[Path] = None


class InferencePipeline:
    """End-to-end inference pipeline for NF-UNSW-NB15-v3 network flow anomaly detection."""

    def __init__(
        self,
        preprocessor: TrainOnlyPreprocessor,
        model: Any,
        preprocessor_metadata: Dict[str, Any],
        model_metadata: Dict[str, Any],
        eligibility_gate: Any = None,
    ) -> None:
        self.preprocessor = preprocessor
        self.model = model
        self.preprocessor_metadata = preprocessor_metadata
        self.model_metadata = model_metadata
        self.eligibility_gate = eligibility_gate

    @classmethod
    def from_artifacts(
        cls,
        model_artifact_path: Union[str, Path],
        preprocessor_artifact_path: Optional[Union[str, Path]] = None,
        model_manifest_path: Optional[Union[str, Path]] = None,
        preprocessor_manifest_path: Optional[Union[str, Path]] = None,
        split_manifest_path: Optional[Union[str, Path]] = None,
        eligibility_gate: Any = None,
    ) -> "InferencePipeline":
        """Instantiate InferencePipeline by loading verified preprocessor and model artifacts."""
        model_path = Path(model_artifact_path)
        if preprocessor_artifact_path is None:
            default_prep = (
                PROJECT_ROOT / "artifacts" / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
            )
            candidate_preprocessors = [
                default_prep,
                model_path.parent / "nf_unsw_nb15_v3_preprocessor.joblib",
                model_path.parent / "test_preprocessor.joblib",
                model_path.parent / "preprocessor.joblib",
            ]
            for cp in candidate_preprocessors:
                if cp.is_file():
                    preprocessor_artifact_path = cp
                    break
            if preprocessor_artifact_path is None:
                preprocessor_artifact_path = default_prep

        preprocessor, prep_meta = load_verified_preprocessor(
            artifact_path=preprocessor_artifact_path,
            manifest_path=preprocessor_manifest_path,
            split_manifest_path=split_manifest_path,
        )

        model, model_meta = load_verified_model(
            model_artifact_path=model_artifact_path,
            manifest_path=model_manifest_path,
            expected_preprocessor_sha256=prep_meta.get("artifact_sha256"),
        )

        return cls(
            preprocessor=preprocessor,
            model=model,
            preprocessor_metadata=prep_meta,
            model_metadata=model_meta,
            eligibility_gate=eligibility_gate,
        )

    def predict(
        self,
        df: pd.DataFrame,
        run_id: Optional[str] = None,
    ) -> pd.DataFrame:
        """Run preprocessing and model prediction on an input DataFrame.

        Guarantees:
        - Neither preprocessor nor model is ever refitted.
        - Exact 47 baseline ML features are selected in canonical order.
        - Output DataFrame has exact same row count and alignment as input.
        - Traceability identifiers (run_id, model SHA-256, preprocessor SHA-256) included.
        - Output probabilities included if model supports predict_proba.
        - Output anomaly scores included if model supports decision_function/score_samples.
        """
        if self.eligibility_gate is not None and isinstance(df, pd.DataFrame) and len(df) > 0:
            decision = self.eligibility_gate.evaluate(
                df=df,
                model_artifact_sha256=self.model_metadata.get("model_artifact_sha256"),
                preprocessor_artifact_sha256=self.preprocessor_metadata.get("artifact_sha256"),
                feature_contract_version=self.model_metadata.get("feature_contract_version"),
            )
            if not decision.can_proceed_to_ml:
                abstain_run_id = run_id or f"inference-{uuid.uuid4().hex[:12]}"
                if "row_id" in df.columns:
                    row_ids = df["row_id"].to_numpy()
                elif "id" in df.columns:
                    row_ids = df["id"].to_numpy()
                else:
                    row_ids = np.arange(len(df), dtype=np.int64)
                return pd.DataFrame(
                    {
                        "row_id": row_ids,
                        "prediction": pd.Series([pd.NA] * len(df), dtype="Int64"),
                        "model_type": self.model_metadata.get(
                            "model_type", type(self.model).__name__
                        ),
                        "run_id": abstain_run_id,
                        "model_artifact_sha256": self.model_metadata.get("model_artifact_sha256"),
                        "preprocessor_artifact_sha256": self.preprocessor_metadata.get(
                            "artifact_sha256"
                        ),
                        "inference_status": "ABSTAINED",
                        "abstention_reason": "; ".join(decision.abstention_reasons)
                        or "Eligibility gate rejected the batch",
                    }
                )

        X_ordered, summary = validate_inference_input(df)

        # 1. Transform features with train-only frozen preprocessor state
        X_trans = self.preprocessor.transform(X_ordered, partition_name="inference")

        # 2. Predict with model
        preds = self.model.predict(X_trans)
        preds_arr = np.asarray(preds)
        if (
            preds_arr.dtype == bool
            or any(isinstance(v, (bool, np.bool_)) for v in preds_arr.flat)
            or any(v not in (0, 1) for v in np.unique(preds_arr))
        ):
            raise ValueError(
                "Verified model predict() produced non-binary labels: "
                f"{np.unique(preds_arr).tolist()}. Expected strictly {{0, 1}}."
            )

        now_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        inference_run_id = run_id or f"inference-{now_str}-{uuid.uuid4().hex[:6]}"

        # 3. Collect probability columns if available
        proba_cols: Dict[str, np.ndarray] = {}
        if hasattr(self.model, "predict_proba"):
            try:
                probas = self.model.predict_proba(X_trans)
                classes = getattr(self.model, "classes_", None)
                if classes is None and hasattr(self.model, "estimator"):
                    classes = getattr(self.model.estimator, "classes_", None)
                class_map = self.model_metadata.get("class_mapping") or {}
                if classes is not None and len(classes) == probas.shape[1]:
                    for i, c in enumerate(classes):
                        c_str = str(c)
                        label = class_map.get(c_str, f"class_{c_str}")
                        proba_cols[f"probability_{label}"] = probas[:, i]
                else:
                    for i in range(probas.shape[1]):
                        proba_cols[f"probability_{i}"] = probas[:, i]
            except Exception:
                pass

        # 4. Collect anomaly score / decision score columns if available
        score_cols: Dict[str, np.ndarray] = {}
        if hasattr(self.model, "decision_function"):
            try:
                score_cols["decision_score"] = self.model.decision_function(X_trans)
            except Exception:
                pass
        elif hasattr(self.model, "score_samples"):
            try:
                score_cols["anomaly_score"] = self.model.score_samples(X_trans)
            except Exception:
                pass

        # 5. Build output DataFrame preserving row identity
        out_dict: Dict[str, Any] = {
            "row_id": summary["row_ids"],
            "prediction": preds,
            "model_type": self.model_metadata.get("model_type", type(self.model).__name__),
            "run_id": inference_run_id,
            "model_artifact_sha256": self.model_metadata.get("model_artifact_sha256", "unknown"),
            "preprocessor_artifact_sha256": self.preprocessor_metadata.get(
                "artifact_sha256", "unknown"
            ),
        }
        out_dict.update(proba_cols)
        out_dict.update(score_cols)

        df_out = pd.DataFrame(out_dict)
        if len(df_out) != len(df):
            raise RuntimeError(
                f"Output row count ({len(df_out)}) does not match input row count ({len(df)})"
            )

        return df_out

    def run(
        self,
        input_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
        metadata_path: Optional[Union[str, Path]] = None,
        run_id: Optional[str] = None,
    ) -> InferenceResult:
        """Execute end-to-end inference from input CSV to output CSV and metadata."""
        input_p = Path(input_path)
        if not input_p.is_file():
            raise FileNotFoundError(f"Input file not found at '{input_p}'")

        if input_p.stat().st_size == 0:
            raise ValueError(f"Input file at '{input_p}' is empty (0 bytes)")

        input_sha256 = _sha256_file(input_p)

        output_p: Optional[Path] = None
        if output_path is not None:
            output_p = Path(output_path)
            if input_p.resolve() == output_p.resolve():
                raise ValueError("Output path cannot overwrite input path")

        # Read input CSV
        try:
            df_input = pd.read_csv(input_p)
        except Exception as e:
            raise ValueError(f"Failed to parse input CSV at '{input_p}': {e}")

        if len(df_input) == 0:
            raise ValueError(f"Input CSV contains 0 data rows at '{input_p}'")

        now_str = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        inference_run_id = run_id or f"inference-{now_str}-{uuid.uuid4().hex[:8]}"
        start_time_utc = datetime.now(timezone.utc).isoformat()

        # Run prediction
        predictions_df = self.predict(df_input, run_id=inference_run_id)

        output_sha256 = None
        if output_p is not None:
            output_p.parent.mkdir(parents=True, exist_ok=True)
            # Atomic file write via temporary file
            temp_file = tempfile.NamedTemporaryFile(
                mode="w",
                dir=str(output_p.parent),
                delete=False,
                suffix=".tmp",
                newline="",
                encoding="utf-8",
            )
            temp_path = Path(temp_file.name)
            try:
                predictions_df.to_csv(temp_path, index=False)
                temp_file.close()
                temp_path.replace(output_p)
            finally:
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except OSError:
                        pass
            output_sha256 = _sha256_file(output_p)

        environment = {
            "python": sys.version,
            "platform": sys.platform,
            "pandas": pd.__version__,
            "numpy": np.__version__,
            "scikit-learn": sklearn.__version__,
            "joblib": joblib.__version__,
        }

        metadata = {
            "run_id": inference_run_id,
            "timestamp_utc": start_time_utc,
            "input_file_path": str(input_p),
            "input_file_sha256": input_sha256,
            "input_row_count": len(df_input),
            "output_file_path": str(output_p) if output_p else None,
            "output_file_sha256": output_sha256,
            "model_artifact_path": self.model_metadata.get("model_artifact_path"),
            "model_artifact_sha256": self.model_metadata.get("model_artifact_sha256"),
            "model_manifest_path": self.model_metadata.get("model_manifest_path"),
            "model_manifest_sha256": self.model_metadata.get("model_manifest_sha256"),
            "model_type": self.model_metadata.get("model_type"),
            "model_configuration": self.model_metadata.get("hyperparameters", {}),
            "preprocessor_artifact_path": self.preprocessor_metadata.get("artifact_path"),
            "preprocessor_artifact_sha256": self.preprocessor_metadata.get("artifact_sha256"),
            "preprocessor_manifest_path": self.preprocessor_metadata.get("manifest_path"),
            "preprocessor_manifest_sha256": self.preprocessor_metadata.get("manifest_sha256"),
            "feature_contract_version": FEATURE_CONTRACT_VERSION,
            "preprocessing_policy_version": PREPROCESSING_POLICY_VERSION,
            "environment": environment,
            "git_commit": _get_git_commit(),
            "prediction_count": int(predictions_df["prediction"].notna().sum()),
            "error_count": 0,
            "execution_status": (
                "ABSTAINED" if predictions_df["prediction"].isna().any() else "SUCCESS"
            ),
        }

        metadata_p: Optional[Path] = None
        if output_p is not None:
            if metadata_path is None:
                metadata_p = output_p.with_name(f"{output_p.stem}.metadata.json")
            else:
                metadata_p = Path(metadata_path)
            metadata_p.parent.mkdir(parents=True, exist_ok=True)
            metadata_p.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

        return InferenceResult(
            predictions_df=predictions_df,
            metadata=metadata,
            output_path=output_p,
            metadata_path=metadata_p,
        )


def run_inference(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    model_artifact_path: Union[str, Path],
    preprocessor_artifact_path: Optional[Union[str, Path]] = None,
    model_manifest_path: Optional[Union[str, Path]] = None,
    preprocessor_manifest_path: Optional[Union[str, Path]] = None,
    metadata_path: Optional[Union[str, Path]] = None,
    run_id: Optional[str] = None,
    eligibility_gate: Any = None,
) -> InferenceResult:
    """Convenience functional interface to execute verified CSV inference."""
    pipeline = InferencePipeline.from_artifacts(
        model_artifact_path=model_artifact_path,
        preprocessor_artifact_path=preprocessor_artifact_path,
        model_manifest_path=model_manifest_path,
        preprocessor_manifest_path=preprocessor_manifest_path,
        eligibility_gate=eligibility_gate,
    )
    return pipeline.run(
        input_path=input_path,
        output_path=output_path,
        metadata_path=metadata_path,
        run_id=run_id,
    )


def predict_from_artifact(
    input_data: Any,
    artifact_path: Optional[Union[str, Path]] = None,
    manifest_path: Optional[Union[str, Path]] = None,
    preprocessor_artifact_path: Optional[Union[str, Path]] = None,
    preprocessor_manifest_path: Optional[Union[str, Path]] = None,
) -> Any:
    """Verified prediction loader executing through InferencePipeline (Issue #53).

    Eliminates unverified deserialization bypasses by routing all execution
    through InferencePipeline.from_artifacts with fail-closed cryptographic
    and contract verification.
    """
    default_model = (
        PROJECT_ROOT / "artifacts" / "models" / "random_forest" / "random_forest_baseline.joblib"
    )
    path = Path(artifact_path) if artifact_path is not None else default_model
    pipeline = InferencePipeline.from_artifacts(
        model_artifact_path=path,
        preprocessor_artifact_path=preprocessor_artifact_path,
        model_manifest_path=manifest_path,
        preprocessor_manifest_path=preprocessor_manifest_path,
    )
    if isinstance(input_data, pd.DataFrame):
        preds_df = pipeline.predict(input_data)
        return preds_df["prediction"].to_numpy()
    elif isinstance(input_data, np.ndarray):
        df_input = pd.DataFrame(input_data, columns=list(ML_FEATURE_COLUMNS))
        preds_df = pipeline.predict(df_input)
        return preds_df["prediction"].to_numpy()
    else:
        df_input = pd.DataFrame(input_data)
        preds_df = pipeline.predict(df_input)
        return preds_df["prediction"].to_numpy()
