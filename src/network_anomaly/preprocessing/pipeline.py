"""NetFlow Sentinel v2 train-only preprocessing pipeline.

Implements a reusable, leak-free preprocessing pipeline for the canonical
18-feature v2 flow contract (`canonical-flow-v2-18`):
1. Validates exact 18-feature ML contract and strict exclusion of targets,
   identifiers, ports, timestamps, and source role labels.
2. Fits imputers, vocabularies, and scalers EXCLUSIVELY on Train.
3. Freezes all learned state so Validation and Test receive immutable transforms.
4. Audits missing, NaN, +Inf, -Inf, and rejects unparseable numeric tokens.
5. Saves versioned artifacts with SHA-256 companion manifests and fail-closed verification.
"""

from __future__ import annotations

import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd

from network_anomaly.data.split import (
    SPLIT_PROTOCOL_VERSION,
    _sha256_file,
    verify_split_artifacts,
)
from network_anomaly.data.v2_schema import (
    CATEGORICAL_CODED_COLUMNS,
    DATASET_SUITE_NAME,
    FEATURE_CONTRACT_ID,
    ML_FEATURE_COLUMNS,
    QUANTITATIVE_ML_COLUMNS,
    validate_feature_selection,
    validate_semantic_column_roles,
)

PREPROCESSING_POLICY_VERSION = "v2-flow-preprocessing-v1"
FEATURE_CONTRACT_VERSION = FEATURE_CONTRACT_ID
ARTIFACT_TYPE = "v2-flow-train-only-preprocessor"

VALID_SCALER_TYPES = {"none", "robust", "asinh_robust", "standard", "minmax"}
VALID_UNKNOWN_CATEGORIES_STRATEGIES = {"passthrough", "sentinel", "error"}
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

REQUIRED_COMPANION_MANIFEST_FIELDS: Dict[str, type] = {
    "artifact_type": str,
    "artifact_version": int,
    "dataset_name": str,
    "dataset_sha256": str,
    "split_protocol_version": str,
    "split_manifest_sha256": str,
    "feature_contract_version": str,
    "baseline_ml_features_count": int,
    "baseline_ml_features_in_order": list,
    "output_features_count": int,
    "output_features_in_order": list,
    "preprocessing_policy_version": str,
    "config": dict,
    "train_row_count": int,
    "fitted_at_utc": str,
    "artifact_path": str,
    "artifact_sha256": str,
    "fitted_parameters_summary": dict,
}


def _valid_sha256(val: Any) -> bool:
    return isinstance(val, str) and bool(_SHA256_RE.match(val)) and val != "0" * 64


@dataclass(frozen=True)
class PreprocessingConfig:
    """Configuration for train-only preprocessing."""

    scaler_type: str = "robust"
    imputer_strategy_quantitative: str = "median"
    imputer_strategy_categorical: str = "mode"
    add_missing_indicators: bool = False
    handle_unknown_categories: str = "passthrough"

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.scaler_type not in VALID_SCALER_TYPES:
            raise ValueError(
                f"Invalid scaler_type: '{self.scaler_type}'. Supported: {sorted(VALID_SCALER_TYPES)}"
            )
        if self.imputer_strategy_quantitative != "median":
            raise ValueError(
                f"Unsupported quantitative imputer strategy: '{self.imputer_strategy_quantitative}'. "
                "Policy requires 'median'."
            )
        if self.imputer_strategy_categorical != "mode":
            raise ValueError(
                f"Unsupported categorical imputer strategy: '{self.imputer_strategy_categorical}'. "
                "Policy requires 'mode'."
            )
        if self.handle_unknown_categories not in VALID_UNKNOWN_CATEGORIES_STRATEGIES:
            raise ValueError(
                f"Invalid handle_unknown_categories: '{self.handle_unknown_categories}'. "
                f"Supported: {sorted(VALID_UNKNOWN_CATEGORIES_STRATEGIES)}"
            )


def audit_column_tokens(
    series: pd.Series, column_name: str, return_masks: bool = False
) -> Union[
    Tuple[Dict[str, int], np.ndarray],
    Tuple[Dict[str, int], np.ndarray, Dict[str, np.ndarray]],
]:
    """Audit values in a column for missingness, non-finite states, and invalid numeric tokens."""
    total = len(series)
    missing_count = 0
    nan_count = 0
    pos_inf_count = 0
    neg_inf_count = 0
    invalid_tokens = []

    missing_mask = np.zeros(total, dtype=bool)
    nan_mask = np.zeros(total, dtype=bool)
    pos_inf_mask = np.zeros(total, dtype=bool)
    neg_inf_mask = np.zeros(total, dtype=bool)

    if pd.api.types.is_numeric_dtype(series.dtype):
        vals = series.to_numpy(dtype=np.float64, copy=True)
        pos_inf_mask = np.isposinf(vals)
        neg_inf_mask = np.isneginf(vals)
        nan_mask = np.isnan(vals)

        pos_inf_count = int(pos_inf_mask.sum())
        neg_inf_count = int(neg_inf_mask.sum())
        nan_count = int(nan_mask.sum())
        finite_count = total - (pos_inf_count + neg_inf_count + nan_count)
        vals[pos_inf_mask | neg_inf_mask] = np.nan
        cleaned_array = vals
    else:
        cleaned_array = np.empty(total, dtype=np.float64)
        for i, val in enumerate(series):
            if isinstance(val, str) and val == "":
                missing_count += 1
                missing_mask[i] = True
                cleaned_array[i] = np.nan
                continue
            if val is None or pd.isna(val):
                nan_count += 1
                nan_mask[i] = True
                cleaned_array[i] = np.nan
                continue
            val_str = str(val).strip()
            val_lower = val_str.lower()
            if val_lower in {"nan", "null", "none"}:
                nan_count += 1
                nan_mask[i] = True
                cleaned_array[i] = np.nan
            elif val_lower in {"inf", "+inf", "infinity", "+infinity"}:
                pos_inf_count += 1
                pos_inf_mask[i] = True
                cleaned_array[i] = np.nan
            elif val_lower in {"-inf", "-infinity"}:
                neg_inf_count += 1
                neg_inf_mask[i] = True
                cleaned_array[i] = np.nan
            else:
                try:
                    num = float(val_str)
                    if math.isnan(num):
                        nan_count += 1
                        nan_mask[i] = True
                        cleaned_array[i] = np.nan
                    elif math.isinf(num):
                        if num > 0:
                            pos_inf_count += 1
                            pos_inf_mask[i] = True
                        else:
                            neg_inf_count += 1
                            neg_inf_mask[i] = True
                        cleaned_array[i] = np.nan
                    else:
                        cleaned_array[i] = num
                except (ValueError, TypeError):
                    invalid_tokens.append((i, val_str))

        if invalid_tokens:
            examples = invalid_tokens[:5]
            raise ValueError(
                f"Column '{column_name}' contains {len(invalid_tokens)} invalid numeric token(s) "
                f"that cannot be converted to float. Examples: {examples}"
            )
        finite_count = total - (missing_count + nan_count + pos_inf_count + neg_inf_count)

    audit_counts = {
        "total": total,
        "missing": missing_count,
        "nan": nan_count,
        "positive_infinity": pos_inf_count,
        "negative_infinity": neg_inf_count,
        "invalid_numeric": len(invalid_tokens),
        "total_non_finite": missing_count + nan_count + pos_inf_count + neg_inf_count,
        "finite": finite_count,
    }
    if return_masks:
        return (
            audit_counts,
            cleaned_array,
            {
                "missing": missing_mask,
                "nan": nan_mask,
                "pos_inf": pos_inf_mask,
                "neg_inf": neg_inf_mask,
            },
        )
    return audit_counts, cleaned_array


class TrainOnlyPreprocessor:
    """Preprocess canonical v2 flow features strictly using Train partition state."""

    def __init__(
        self,
        config: Optional[PreprocessingConfig] = None,
        dataset_sha256: Optional[str] = None,
        split_manifest_sha256: Optional[str] = None,
        split_protocol_version: str = SPLIT_PROTOCOL_VERSION,
        dataset_name: str = DATASET_SUITE_NAME,
    ):
        self.config = config or PreprocessingConfig()
        self.config.validate()
        self.dataset_sha256 = dataset_sha256
        self.split_manifest_sha256 = split_manifest_sha256
        self.split_protocol_version = split_protocol_version
        self.dataset_name = dataset_name

        self.is_fitted_: bool = False
        self.imputed_values_: Dict[str, float] = {}
        self.scaler_params_: Dict[str, Dict[str, float]] = {}
        self.category_vocabularies_: Dict[str, List[int]] = {}
        self.constant_features_: List[str] = []
        self.all_missing_columns_: List[str] = []
        self.indicator_features_: List[Tuple[str, str]] = []
        self.audit_counts_train_: Dict[str, Dict[str, int]] = {}
        self.train_row_count_: int = 0
        self.fitted_at_utc_: Optional[str] = None

    def fit(self, X: pd.DataFrame, y: Any = None) -> "TrainOnlyPreprocessor":
        """Fit imputer, vocabularies, and scaler strictly on training matrix X."""
        if not isinstance(X, pd.DataFrame):
            raise TypeError(f"X must be a pandas DataFrame, got {type(X)}")
        validate_feature_selection(X.columns, require_complete=True)
        validate_semantic_column_roles()
        if len(X) == 0:
            raise ValueError("Cannot fit preprocessor on an empty training set")

        self.train_row_count_ = len(X)
        self.imputed_values_ = {}
        self.scaler_params_ = {}
        self.category_vocabularies_ = {}
        self.constant_features_ = []
        self.all_missing_columns_ = []
        self.indicator_features_ = []
        self.audit_counts_train_ = {}

        cleaned_train_arrays: Dict[str, np.ndarray] = {}
        for col in ML_FEATURE_COLUMNS:
            col_audit, cleaned_arr = audit_column_tokens(X[col], col, return_masks=False)
            self.audit_counts_train_[col] = col_audit
            cleaned_train_arrays[col] = cleaned_arr

            if self.config.add_missing_indicators:
                for key, ind in (
                    ("missing", "missing"),
                    ("nan", "nan"),
                    ("positive_infinity", "pos_inf"),
                    ("negative_infinity", "neg_inf"),
                ):
                    if col_audit[key] > 0:
                        self.indicator_features_.append((col, ind))

            finite_values = cleaned_arr[~np.isnan(cleaned_arr)]
            if len(finite_values) == 0:
                self.all_missing_columns_.append(col)
                self.imputed_values_[col] = 0.0
                if col in CATEGORICAL_CODED_COLUMNS:
                    self.category_vocabularies_[col] = [0]
                continue

            if np.isclose(float(np.min(finite_values)), float(np.max(finite_values)), atol=1e-9):
                self.constant_features_.append(col)

            if col in CATEGORICAL_CODED_COLUMNS:
                int_vals = finite_values.astype(np.int64)
                mode_vals = pd.Series(int_vals).mode()
                mode_val = int(mode_vals.iloc[0]) if len(mode_vals) > 0 else 0
                self.imputed_values_[col] = float(mode_val)
                self.category_vocabularies_[col] = sorted(list(set(int_vals.tolist())))
            else:
                self.imputed_values_[col] = float(np.median(finite_values))

        if self.config.scaler_type != "none":
            for col in QUANTITATIVE_ML_COLUMNS:
                arr = cleaned_train_arrays[col].copy()
                arr[np.isnan(arr)] = self.imputed_values_[col]
                if self.config.scaler_type == "robust":
                    med = float(np.median(arr))
                    iqr = float(np.percentile(arr, 75) - np.percentile(arr, 25))
                    self.scaler_params_[col] = {"center": med, "scale": iqr if iqr > 1e-9 else 1.0}
                elif self.config.scaler_type == "asinh_robust":
                    t_arr = np.arcsinh(arr)
                    med = float(np.median(t_arr))
                    iqr = float(np.percentile(t_arr, 75) - np.percentile(t_arr, 25))
                    self.scaler_params_[col] = {"center": med, "scale": iqr if iqr > 1e-9 else 1.0, "transform": "arcsinh"}
                elif self.config.scaler_type == "standard":
                    mean = float(np.mean(arr))
                    std = float(np.std(arr))
                    self.scaler_params_[col] = {"center": mean, "scale": std if std > 1e-9 else 1.0}
                elif self.config.scaler_type == "minmax":
                    lo = float(np.min(arr))
                    rng = float(np.max(arr) - lo)
                    self.scaler_params_[col] = {"center": lo, "scale": rng if rng > 1e-9 else 1.0}

        self.fitted_at_utc_ = datetime.now(timezone.utc).isoformat()
        self.is_fitted_ = True
        return self

    def transform(
        self,
        X: pd.DataFrame,
        partition_name: Optional[str] = None,
    ) -> pd.DataFrame:
        """Transform input features using frozen Train state."""
        if not self.is_fitted_:
            raise RuntimeError("Preprocessor has not been fitted. Call fit(X_train) first.")
        if not isinstance(X, pd.DataFrame):
            raise TypeError(f"X must be a pandas DataFrame, got {type(X)}")

        validate_feature_selection(X.columns, require_complete=True)

        transformed_cols: Dict[str, np.ndarray] = {}
        token_masks_by_col: Dict[str, Dict[str, np.ndarray]] = {}

        for col in ML_FEATURE_COLUMNS:
            _, cleaned_arr, masks = audit_column_tokens(X[col], col, return_masks=True)
            token_masks_by_col[col] = masks
            cleaned_arr[np.isnan(cleaned_arr)] = self.imputed_values_[col]

            if self.config.scaler_type != "none" and col in self.scaler_params_:
                params = self.scaler_params_[col]
                if self.config.scaler_type == "asinh_robust" or params.get("transform") == "arcsinh":
                    cleaned_arr = np.arcsinh(cleaned_arr)
                cleaned_arr = (cleaned_arr - params["center"]) / params["scale"]

            if col in CATEGORICAL_CODED_COLUMNS:
                cleaned_arr = np.round(cleaned_arr)
                known_vocab = set(self.category_vocabularies_.get(col, []))
                int_codes = cleaned_arr.astype(np.int64)
                unknown_mask = ~np.isin(int_codes, list(known_vocab))
                if np.any(unknown_mask):
                    if self.config.handle_unknown_categories == "error":
                        raise ValueError(
                            f"Unseen category in '{col}': {sorted(set(int_codes[unknown_mask].tolist()))}"
                        )
                    elif self.config.handle_unknown_categories == "sentinel":
                        cleaned_arr[unknown_mask] = self.imputed_values_[col]

            transformed_cols[col] = cleaned_arr

        if self.config.add_missing_indicators and self.indicator_features_:
            for col, ind_type in self.indicator_features_:
                mask = token_masks_by_col.get(col, {}).get(ind_type, np.zeros(len(X), dtype=bool))
                transformed_cols[f"{col}__is_{ind_type}"] = mask.astype(np.float64)

        output_cols = list(ML_FEATURE_COLUMNS) + [
            f"{c}__is_{t}" for c, t in self.indicator_features_
        ]
        df_out = pd.DataFrame(transformed_cols, index=X.index, columns=output_cols)
        if not np.all(np.isfinite(df_out.to_numpy())):
            raise RuntimeError(
                f"Post-transformation output has non-finite values in partition '{partition_name}'"
            )
        return df_out

    def fit_transform(self, X: pd.DataFrame, y: Any = None) -> pd.DataFrame:
        return self.fit(X, y).transform(X, partition_name="train")

    def get_metadata(self) -> Dict[str, Any]:
        if not self.is_fitted_:
            raise RuntimeError("Preprocessor has not been fitted")
        output_cols = list(ML_FEATURE_COLUMNS) + [
            f"{c}__is_{t}" for c, t in self.indicator_features_
        ]
        return {
            "artifact_type": ARTIFACT_TYPE,
            "artifact_version": 2,
            "dataset_name": self.dataset_name,
            "dataset_sha256": self.dataset_sha256 or "",
            "split_protocol_version": self.split_protocol_version,
            "split_manifest_sha256": self.split_manifest_sha256 or "",
            "feature_contract_version": FEATURE_CONTRACT_VERSION,
            "baseline_ml_features_count": len(ML_FEATURE_COLUMNS),
            "baseline_ml_features_in_order": list(ML_FEATURE_COLUMNS),
            "output_features_count": len(output_cols),
            "output_features_in_order": output_cols,
            "categorical_coded_columns": list(CATEGORICAL_CODED_COLUMNS),
            "quantitative_ml_columns": list(QUANTITATIVE_ML_COLUMNS),
            "preprocessing_policy_version": PREPROCESSING_POLICY_VERSION,
            "config": asdict(self.config),
            "train_row_count": self.train_row_count_,
            "fitted_at_utc": self.fitted_at_utc_,
            "constant_features": list(self.constant_features_),
            "all_missing_columns": list(self.all_missing_columns_),
            "indicator_features": [f"{c}__is_{t}" for c, t in self.indicator_features_],
            "environment": {
                "python": sys.version,
                "numpy": np.__version__,
                "pandas": pd.__version__,
                "joblib": joblib.__version__,
            },
        }

    def save(self, artifact_path: Path, manifest_path: Optional[Path] = None) -> str:
        if not self.is_fitted_:
            raise RuntimeError("Cannot save an unfitted preprocessor")
        if not _valid_sha256(self.dataset_sha256):
            raise ValueError("dataset_sha256 must be a valid non-placeholder 64-hex SHA-256")
        if not _valid_sha256(self.split_manifest_sha256):
            raise ValueError("split_manifest_sha256 must be a valid non-placeholder 64-hex SHA-256")

        artifact_path = Path(artifact_path)
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "metadata": self.get_metadata(),
            "fitted_state": {
                "imputed_values": self.imputed_values_,
                "scaler_params": self.scaler_params_,
                "category_vocabularies": self.category_vocabularies_,
                "constant_features": self.constant_features_,
                "all_missing_columns": self.all_missing_columns_,
                "indicator_features": self.indicator_features_,
                "audit_counts_train": self.audit_counts_train_,
                "train_row_count": self.train_row_count_,
                "fitted_at_utc": self.fitted_at_utc_,
            },
        }
        joblib.dump(payload, artifact_path, compress=3)
        artifact_sha256 = _sha256_file(artifact_path)

        if manifest_path is not None:
            manifest_path = Path(manifest_path)
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_data = {
                **self.get_metadata(),
                "artifact_path": str(artifact_path.name),
                "artifact_sha256": artifact_sha256,
                "fitted_parameters_summary": {
                    "imputed_values_count": len(self.imputed_values_),
                    "scaler_params_count": len(self.scaler_params_),
                    "constant_features_count": len(self.constant_features_),
                    "all_missing_columns_count": len(self.all_missing_columns_),
                    "indicator_features_count": len(self.indicator_features_),
                },
            }
            manifest_path.write_text(json.dumps(manifest_data, indent=2) + "\n", encoding="utf-8")

        return artifact_sha256

    @classmethod
    def load(
        cls,
        artifact_path: Union[str, Path],
        expected_dataset_sha256: Optional[str] = None,
        expected_manifest_sha256: Optional[str] = None,
    ) -> "TrainOnlyPreprocessor":
        artifact_path = Path(artifact_path)
        if not artifact_path.is_file():
            raise FileNotFoundError(f"Preprocessor artifact not found: {artifact_path}")
        payload = joblib.load(artifact_path)
        if not isinstance(payload, dict) or "metadata" not in payload or "fitted_state" not in payload:
            raise ValueError(f"Corrupted preprocessor artifact schema in {artifact_path}")

        metadata = payload["metadata"]
        fitted_state = payload["fitted_state"]

        if metadata.get("artifact_type") != ARTIFACT_TYPE:
            raise ValueError(f"Invalid artifact type (v1 artifacts rejected): {metadata.get('artifact_type')}")
        if metadata.get("feature_contract_version") != FEATURE_CONTRACT_VERSION:
            raise ValueError(
                f"Feature contract version mismatch: expected {FEATURE_CONTRACT_VERSION}, "
                f"got {metadata.get('feature_contract_version')}"
            )
        if metadata.get("preprocessing_policy_version") != PREPROCESSING_POLICY_VERSION:
            raise ValueError(
                f"Preprocessing policy version mismatch: expected {PREPROCESSING_POLICY_VERSION}, "
                f"got {metadata.get('preprocessing_policy_version')}"
            )
        if metadata.get("split_protocol_version") != SPLIT_PROTOCOL_VERSION:
            raise ValueError(
                f"Split protocol version mismatch: expected {SPLIT_PROTOCOL_VERSION}, "
                f"got {metadata.get('split_protocol_version')}"
            )
        if metadata.get("baseline_ml_features_in_order") != list(ML_FEATURE_COLUMNS):
            raise ValueError("Artifact baseline feature columns or order do not match v2 contract")

        out_features = metadata.get("output_features_in_order")
        out_count = metadata.get("output_features_count")
        if not isinstance(out_features, list) or not isinstance(out_count, int) or len(out_features) != out_count:
            raise ValueError("Corrupted output features contract in artifact metadata")

        if expected_dataset_sha256 is not None and metadata.get("dataset_sha256") != expected_dataset_sha256:
            raise ValueError("Dataset SHA-256 mismatch in preprocessor artifact")
        if expected_manifest_sha256 is not None and metadata.get("split_manifest_sha256") != expected_manifest_sha256:
            raise ValueError("Split manifest SHA-256 mismatch in preprocessor artifact")

        config = PreprocessingConfig(**metadata.get("config", {}))
        preprocessor = cls(
            config=config,
            dataset_sha256=metadata.get("dataset_sha256"),
            split_manifest_sha256=metadata.get("split_manifest_sha256"),
            split_protocol_version=metadata.get("split_protocol_version", SPLIT_PROTOCOL_VERSION),
            dataset_name=metadata.get("dataset_name", DATASET_SUITE_NAME),
        )
        preprocessor.imputed_values_ = fitted_state["imputed_values"]
        preprocessor.scaler_params_ = fitted_state["scaler_params"]
        preprocessor.category_vocabularies_ = fitted_state["category_vocabularies"]
        preprocessor.constant_features_ = fitted_state.get("constant_features", [])
        preprocessor.all_missing_columns_ = fitted_state.get("all_missing_columns", [])
        preprocessor.indicator_features_ = [
            tuple(item) for item in fitted_state.get("indicator_features", [])
        ]
        preprocessor.audit_counts_train_ = fitted_state.get("audit_counts_train", {})
        preprocessor.train_row_count_ = fitted_state.get("train_row_count", 0)
        preprocessor.fitted_at_utc_ = fitted_state.get("fitted_at_utc")
        preprocessor.is_fitted_ = True
        return preprocessor

    @classmethod
    def load_verified(
        cls,
        artifact_path: Union[str, Path],
        manifest_path: Union[str, Path],
        split_manifest_path: Optional[Union[str, Path]] = None,
        dataset_path: Optional[Union[str, Path]] = None,
        expected_dataset_sha256: Optional[str] = None,
    ) -> "TrainOnlyPreprocessor":
        report = verify_preprocessing_artifact(
            artifact_path=artifact_path,
            manifest_path=manifest_path,
            split_manifest_path=split_manifest_path,
            dataset_path=dataset_path,
            expected_dataset_sha256=expected_dataset_sha256,
        )
        if report["status"] != "PASS":
            raise ValueError(f"Preprocessor artifact verification failed: {'; '.join(report['errors'])}")
        preprocessor = report.get("preprocessor")
        if not isinstance(preprocessor, cls):
            raise ValueError("Verified preprocessor instance not available")
        return preprocessor


def verify_zero_duration_retention(
    X_before: pd.DataFrame,
    X_after: pd.DataFrame,
    duration_col: str = "duration_ms",
) -> Dict[str, Any]:
    """Verify that zero-duration flows in X_before are retained (not dropped) in X_after."""
    if not isinstance(X_before, pd.DataFrame) or not isinstance(X_after, pd.DataFrame):
        return {"status": "NOT VERIFIED", "reason": "Inputs must be DataFrames", "zero_duration_flows_count": 0, "zero_duration_retained": False}
    if duration_col not in X_before.columns or duration_col not in X_after.columns:
        return {"status": "NOT VERIFIED", "reason": f"Missing {duration_col}", "zero_duration_flows_count": 0, "zero_duration_retained": False}
    if X_before.index.has_duplicates or X_after.index.has_duplicates:
        return {"status": "NOT VERIFIED", "reason": "Duplicate index", "zero_duration_flows_count": 0, "zero_duration_retained": False}

    raw_num = pd.to_numeric(X_before[duration_col], errors="coerce")
    zero_indices = X_before.index[(raw_num == 0.0) & raw_num.notna()]
    zero_count = int(len(zero_indices))
    if zero_count == 0:
        return {"status": "NOT APPLICABLE", "reason": "No zero-duration flows", "zero_duration_flows_count": 0, "zero_duration_retained": True}
    if len(X_after) != len(X_before) or len(zero_indices.difference(X_after.index)) > 0:
        return {"status": "FAIL", "reason": "Zero-duration flows were dropped", "zero_duration_flows_count": zero_count, "zero_duration_retained": False}
    return {"status": "PASS", "reason": f"All {zero_count} zero-duration flows retained", "zero_duration_flows_count": zero_count, "zero_duration_retained": True}


def verify_preprocessing_artifact(
    artifact_path: Union[str, Path],
    manifest_path: Union[str, Path],
    split_manifest_path: Optional[Union[str, Path]] = None,
    dataset_path: Optional[Union[str, Path]] = None,
    expected_dataset_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Fail-closed verification of v2 preprocessor artifact and companion manifest before deserialization."""
    errors: List[str] = []
    artifact_path = Path(artifact_path)
    manifest_path = Path(manifest_path)

    if not artifact_path.is_file():
        errors.append(f"Artifact file not found: {artifact_path}")
    if not manifest_path.is_file():
        errors.append(f"Companion manifest file not found: {manifest_path}")
    if errors:
        return {"status": "FAIL", "errors": errors, "artifact_path": str(artifact_path), "manifest_path": str(manifest_path), "metadata": {}}

    manifest_json: Dict[str, Any] = {}
    try:
        parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict) or not parsed:
            errors.append("Companion manifest is empty or not a JSON object")
        else:
            manifest_json = parsed
    except Exception as exc:
        errors.append(f"Error reading companion manifest JSON: {exc}")

    if manifest_json:
        for field, exp_type in REQUIRED_COMPANION_MANIFEST_FIELDS.items():
            val = manifest_json.get(field)
            if val is None:
                errors.append(f"Companion manifest missing required field: '{field}'")
            elif exp_type is int and isinstance(val, bool):
                errors.append(f"Field '{field}' must be int, got bool")
            elif not isinstance(val, exp_type):
                errors.append(f"Field '{field}' must be {exp_type.__name__}, got {type(val).__name__}")
            elif isinstance(val, str) and not val.strip():
                errors.append(f"Field '{field}' must not be empty")

        if manifest_json.get("artifact_type") != ARTIFACT_TYPE:
            errors.append(
                f"Invalid artifact_type: expected '{ARTIFACT_TYPE}', got '{manifest_json.get('artifact_type')}'"
            )
        if manifest_json.get("artifact_version") != 2:
            errors.append(f"Invalid artifact_version: expected 2, got {manifest_json.get('artifact_version')}")
        if not _valid_sha256(manifest_json.get("dataset_sha256")):
            errors.append("Invalid or placeholder dataset_sha256 in companion manifest")
        if not _valid_sha256(manifest_json.get("split_manifest_sha256")):
            errors.append("Invalid or placeholder split_manifest_sha256 in companion manifest")
        if expected_dataset_sha256 is not None and manifest_json.get("dataset_sha256") != expected_dataset_sha256:
            errors.append("Dataset SHA-256 in manifest does not match expected value")
        if manifest_json.get("split_protocol_version") != SPLIT_PROTOCOL_VERSION:
            errors.append(f"Invalid split_protocol_version: {manifest_json.get('split_protocol_version')}")
        if manifest_json.get("feature_contract_version") != FEATURE_CONTRACT_VERSION:
            errors.append(f"Invalid feature_contract_version: {manifest_json.get('feature_contract_version')}")
        if manifest_json.get("preprocessing_policy_version") != PREPROCESSING_POLICY_VERSION:
            errors.append(f"Invalid preprocessing_policy_version: {manifest_json.get('preprocessing_policy_version')}")
        if manifest_json.get("baseline_ml_features_count") != len(ML_FEATURE_COLUMNS):
            errors.append("baseline_ml_features_count mismatch")
        if manifest_json.get("baseline_ml_features_in_order") != list(ML_FEATURE_COLUMNS):
            errors.append("baseline_ml_features_in_order mismatch")

    actual_artifact_sha256 = _sha256_file(artifact_path)
    if manifest_json and manifest_json.get("artifact_sha256") != actual_artifact_sha256:
        errors.append(
            f"Artifact SHA-256 mismatch: expected {actual_artifact_sha256}, "
            f"recorded {manifest_json.get('artifact_sha256')}"
        )

    if dataset_path is not None:
        ds_p = Path(dataset_path)
        if not ds_p.is_file():
            errors.append(f"Referenced dataset file not found: {ds_p}")
        else:
            actual_ds_sha = _sha256_file(ds_p)
            if manifest_json and manifest_json.get("dataset_sha256") != actual_ds_sha:
                errors.append("Raw dataset SHA-256 mismatch against companion manifest")

    if split_manifest_path is not None:
        sm_res = verify_split_artifacts(Path(split_manifest_path))
        if sm_res["status"] != "PASS":
            errors.extend(sm_res["errors"])
        else:
            actual_sm_sha = _sha256_file(Path(split_manifest_path))
            if manifest_json and manifest_json.get("split_manifest_sha256") != actual_sm_sha:
                errors.append("Companion manifest split_manifest_sha256 mismatch")

    if errors:
        return {
            "status": "FAIL",
            "errors": errors,
            "artifact_path": str(artifact_path),
            "manifest_path": str(manifest_path),
            "metadata": {},
        }

    preprocessor = None
    meta: Dict[str, Any] = {}
    try:
        preprocessor = TrainOnlyPreprocessor.load(
            artifact_path=artifact_path,
            expected_dataset_sha256=manifest_json.get("dataset_sha256"),
            expected_manifest_sha256=manifest_json.get("split_manifest_sha256"),
        )
        meta = preprocessor.get_metadata()
    except Exception as exc:
        errors.append(f"Error loading preprocessor artifact: {exc}")

    if preprocessor is not None and manifest_json:
        for k in (
            "dataset_name",
            "dataset_sha256",
            "split_manifest_sha256",
            "split_protocol_version",
            "feature_contract_version",
            "preprocessing_policy_version",
            "output_features_count",
            "output_features_in_order",
            "train_row_count",
            "config",
        ):
            if manifest_json.get(k) != meta.get(k):
                errors.append(f"Metadata mismatch between artifact and manifest for '{k}'")

    status = "PASS" if not errors else "FAIL"
    return {
        "status": status,
        "errors": errors,
        "artifact_path": str(artifact_path),
        "manifest_path": str(manifest_path),
        "metadata": meta,
        "preprocessor": preprocessor if status == "PASS" else None,
    }
