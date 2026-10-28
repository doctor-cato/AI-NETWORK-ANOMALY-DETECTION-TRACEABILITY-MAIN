"""NF-UNSW-NB15-v3 train-only preprocessing pipeline.

This module implements a reusable, leak-free preprocessing pipeline for NF-UNSW-NB15-v3:
1. Validates the 47-feature baseline ML contract and strict exclusion of targets and trace metadata.
2. Fits imputers, vocabularies, and optional scalers EXCLUSIVELY on the training partition.
3. Freezes all learned state so Validation and Test receive only immutable transforms.
4. Audits missing, NaN, positive infinity, negative infinity, and rejects invalid numeric tokens.
5. Saves versioned, verifiable preprocessing artifacts with complete provenance metadata.
6. Enforces strict companion manifest verification with fail-closed integrity checks.
"""

from __future__ import annotations

import json
import math
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd

from network_anomaly.data.nf_unsw_nb15_v3 import (
    CATEGORICAL_CODED_COLUMNS,
    DATASET_NAME,
    ML_FEATURE_COLUMNS,
    QUANTITATIVE_ML_COLUMNS,
    TARGET_COLUMNS,
    validate_feature_selection,
    validate_semantic_column_roles,
)
from network_anomaly.data.split import (
    SPLIT_PROTOCOL_VERSION,
    _sha256_file,
    load_partition_indices,
    verify_split_artifacts,
)

PREPROCESSING_POLICY_VERSION = "nf-unsw-nb15-v3-preprocessing-v1"
FEATURE_CONTRACT_VERSION = "nf-unsw-nb15-v3-baseline-47"
EXPECTED_DATASET_SHA256 = "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5"

VALID_SCALER_TYPES = {"none", "robust", "standard", "minmax"}
VALID_UNKNOWN_CATEGORIES_STRATEGIES = {"passthrough", "sentinel", "error"}

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


@dataclass(frozen=True)
class PreprocessingConfig:
    """Configuration for train-only preprocessing."""

    scaler_type: str = "none"
    imputer_strategy_quantitative: str = "median"
    imputer_strategy_categorical: str = "mode"
    add_missing_indicators: bool = False
    handle_unknown_categories: str = "passthrough"

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.scaler_type not in VALID_SCALER_TYPES:
            raise ValueError(
                f"Invalid scaler_type: '{self.scaler_type}'. "
                f"Supported: {sorted(VALID_SCALER_TYPES)}"
            )
        if self.imputer_strategy_quantitative != "median":
            strat = self.imputer_strategy_quantitative
            raise ValueError(
                f"Unsupported quantitative imputer strategy: '{strat}'. "
                "Baseline policy requires 'median'."
            )
        if self.imputer_strategy_categorical != "mode":
            raise ValueError(
                f"Unsupported categorical imputer strategy: '{self.imputer_strategy_categorical}'. "
                "Baseline policy requires 'mode'."
            )
        if self.handle_unknown_categories not in VALID_UNKNOWN_CATEGORIES_STRATEGIES:
            raise ValueError(
                f"Invalid handle_unknown_categories: '{self.handle_unknown_categories}'. "
                f"Supported: {sorted(VALID_UNKNOWN_CATEGORIES_STRATEGIES)}"
            )


def audit_column_tokens(series: pd.Series, column_name: str, return_masks: bool = False) -> Union[
    Tuple[Dict[str, int], np.ndarray],
    Tuple[Dict[str, int], np.ndarray, Dict[str, np.ndarray]],
]:
    """Audit values in a column for missingness, non-finite states, and invalid numeric tokens.

    Preserves distinct counts for:
    - blank/missing (literal empty string '' from CSV)
    - NaN (literal string 'nan' or float NaN)
    - positive infinity (literal string 'inf' or float inf)
    - negative infinity (literal string '-inf' or float -inf)
    - invalid numeric (unparseable strings, raises ValueError fail-closed)

    Returns
    -------
    audit_counts : dict
        Detailed counts of missing, nan, pos/neg infinity, invalid numeric, finite.
    cleaned_float_array : np.ndarray
        Float64 array where non-finite tokens (missing, nan, +inf, -inf) are represented as np.nan.
    token_masks : dict, optional
        Boolean masks for 'missing', 'nan', 'pos_inf', 'neg_inf' (returned if return_masks=True).

    Raises
    ------
    ValueError
        If any token cannot be parsed into a numeric representation (invalid numeric token).
    """
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

        # In numeric pandas series, infinities are distinct float values.
        # Map infinities to np.nan sentinel for downstream imputation
        vals[pos_inf_mask | neg_inf_mask] = np.nan
        cleaned_array = vals
    else:
        # Object / string dtype: inspect individual elements
        cleaned_array = np.empty(total, dtype=np.float64)
        for i, val in enumerate(series):
            # Check for literal empty cell first, safely avoiding boolean evaluation on pd.NA
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
                f"that cannot be converted to float. Examples (index, token): {examples}"
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
        masks = {
            "missing": missing_mask,
            "nan": nan_mask,
            "pos_inf": pos_inf_mask,
            "neg_inf": neg_inf_mask,
        }
        return audit_counts, cleaned_array, masks

    return audit_counts, cleaned_array


class TrainOnlyPreprocessor:
    """Preprocess NF-UNSW-NB15-v3 features strictly using training partition state.

    Enforces:
    - 47 baseline ML features contract in exact order.
    - Strict rejection of targets (Label, Attack) and trace metadata (IPs, Ports, Timestamps).
    - Fit parameters (imputer medians/modes, scalers, vocabularies) learned from Train ONLY.
    - Zero data leakage into Validation or Test.
    - Preservation of categorical-coded integer fields (never continuous scaling).
    """

    def __init__(
        self,
        config: Optional[PreprocessingConfig] = None,
        dataset_sha256: Optional[str] = None,
        split_manifest_sha256: Optional[str] = None,
        split_protocol_version: str = SPLIT_PROTOCOL_VERSION,
    ):
        self.config = config or PreprocessingConfig()
        self.config.validate()
        self.dataset_sha256 = dataset_sha256
        self.split_manifest_sha256 = split_manifest_sha256
        self.split_protocol_version = split_protocol_version

        # Fitted attributes (populated strictly during fit)
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
        """Fit preprocessor parameters EXCLUSIVELY on the training feature matrix X.

        Parameters
        ----------
        X : pd.DataFrame
            Training feature matrix. Must strictly contain the 47 baseline ML features
            in exact order, with no target or trace metadata columns.
        y : Any, optional
            Ignored. Passed for compatibility with standard estimator interfaces.
            Target data is strictly prohibited from influencing preprocessing parameters.

        Returns
        -------
        self : TrainOnlyPreprocessor
        """
        if not isinstance(X, pd.DataFrame):
            raise TypeError(f"X must be a pandas DataFrame, got {type(X)}")

        # 1. Enforce feature contract
        validate_feature_selection(X.columns, require_complete=True)
        validate_semantic_column_roles()

        total_rows = len(X)
        if total_rows == 0:
            raise ValueError("Cannot fit preprocessor on an empty training set")

        self.train_row_count_ = total_rows
        self.imputed_values_ = {}
        self.scaler_params_ = {}
        self.category_vocabularies_ = {}
        self.constant_features_ = []
        self.all_missing_columns_ = []
        self.indicator_features_ = []
        self.audit_counts_train_ = {}

        # 2. Audit and learn imputers and vocabularies on Train
        cleaned_train_arrays: Dict[str, np.ndarray] = {}

        for col in ML_FEATURE_COLUMNS:
            series = X[col]
            col_audit, cleaned_arr = audit_column_tokens(series, col, return_masks=False)
            self.audit_counts_train_[col] = col_audit
            cleaned_train_arrays[col] = cleaned_arr

            # Register missingness indicators if enabled (learned strictly from Train)
            if self.config.add_missing_indicators:
                if col_audit["missing"] > 0:
                    self.indicator_features_.append((col, "missing"))
                if col_audit["nan"] > 0:
                    self.indicator_features_.append((col, "nan"))
                if col_audit["positive_infinity"] > 0:
                    self.indicator_features_.append((col, "pos_inf"))
                if col_audit["negative_infinity"] > 0:
                    self.indicator_features_.append((col, "neg_inf"))

            finite_mask = ~np.isnan(cleaned_arr)
            finite_values = cleaned_arr[finite_mask]

            if len(finite_values) == 0:
                # Edge case: all values in Train are missing / non-finite
                self.all_missing_columns_.append(col)
                fallback_val = 0.0
                self.imputed_values_[col] = fallback_val
                if col in CATEGORICAL_CODED_COLUMNS:
                    self.category_vocabularies_[col] = [0]
                continue

            # Check if feature is constant on Train
            min_val = float(np.min(finite_values))
            max_val = float(np.max(finite_values))
            if np.isclose(min_val, max_val, atol=1e-9):
                self.constant_features_.append(col)

            if col in CATEGORICAL_CODED_COLUMNS:
                # Categorical-coded: compute mode of finite values
                int_vals = finite_values.astype(np.int64)
                series_finite = pd.Series(int_vals)
                mode_vals = series_finite.mode()
                mode_val = int(mode_vals.iloc[0]) if len(mode_vals) > 0 else 0
                self.imputed_values_[col] = float(mode_val)
                self.category_vocabularies_[col] = sorted(list(set(int_vals)))
            else:
                # Quantitative: compute median of finite values
                median_val = float(np.median(finite_values))
                self.imputed_values_[col] = median_val

        # 3. Fit scaler parameters ONLY on QUANTITATIVE_ML_COLUMNS
        # Note: CATEGORICAL_CODED_COLUMNS are strictly excluded from continuous scaling
        if self.config.scaler_type != "none":
            for col in QUANTITATIVE_ML_COLUMNS:
                arr = cleaned_train_arrays[col].copy()
                # Impute missing values with train median for scaler parameter computation
                nan_mask = np.isnan(arr)
                arr[nan_mask] = self.imputed_values_[col]

                if self.config.scaler_type == "robust":
                    med = float(np.median(arr))
                    q25 = float(np.percentile(arr, 25))
                    q75 = float(np.percentile(arr, 75))
                    iqr = q75 - q25
                    scale = iqr if iqr > 1e-9 else 1.0
                    self.scaler_params_[col] = {"center": med, "scale": scale}
                elif self.config.scaler_type == "standard":
                    mean = float(np.mean(arr))
                    std = float(np.std(arr))
                    scale = std if std > 1e-9 else 1.0
                    self.scaler_params_[col] = {"center": mean, "scale": scale}
                elif self.config.scaler_type == "minmax":
                    min_val = float(np.min(arr))
                    max_val = float(np.max(arr))
                    rng = max_val - min_val
                    scale = rng if rng > 1e-9 else 1.0
                    self.scaler_params_[col] = {"center": min_val, "scale": scale}

        self.fitted_at_utc_ = datetime.now(timezone.utc).isoformat()
        self.is_fitted_ = True
        return self

    def transform(
        self,
        X: pd.DataFrame,
        partition_name: Optional[str] = None,
    ) -> pd.DataFrame:
        """Transform input features using the frozen state fitted on Train.

        Parameters
        ----------
        X : pd.DataFrame
            Feature matrix to transform. Must contain the 47 baseline ML features
            in exact order. Input DataFrame is never modified in-place.
        partition_name : str, optional
            Identifier for logging and audit purposes (e.g., 'validation', 'test').

        Returns
        -------
        X_out : pd.DataFrame
            Cleaned and transformed DataFrame with exact feature columns in contract order.
        """
        if not self.is_fitted_:
            raise RuntimeError("Preprocessor has not been fitted. Call fit(X_train) first.")

        if not isinstance(X, pd.DataFrame):
            raise TypeError(f"X must be a pandas DataFrame, got {type(X)}")

        # 1. Enforce feature contract on transform input
        validate_feature_selection(X.columns, require_complete=True)

        transformed_cols: Dict[str, np.ndarray] = {}
        token_masks_by_col: Dict[str, Dict[str, np.ndarray]] = {}

        # 2. Audit and transform each column using frozen train parameters
        for col in ML_FEATURE_COLUMNS:
            series = X[col]
            _, cleaned_arr, masks = audit_column_tokens(series, col, return_masks=True)
            token_masks_by_col[col] = masks

            # Impute non-finite values (missing, nan, inf) using train fitted value
            nan_mask = np.isnan(cleaned_arr)
            cleaned_arr[nan_mask] = self.imputed_values_[col]

            # Scale quantitative columns if scaler was fitted
            if self.config.scaler_type != "none" and col in self.scaler_params_:
                params = self.scaler_params_[col]
                center = params["center"]
                scale = params["scale"]
                cleaned_arr = (cleaned_arr - center) / scale

            # If categorical-coded, check categories and handle unknowns
            if col in CATEGORICAL_CODED_COLUMNS:
                cleaned_arr = np.round(cleaned_arr)
                known_vocab = set(self.category_vocabularies_.get(col, []))
                int_codes = cleaned_arr.astype(np.int64)
                unknown_mask = ~np.isin(int_codes, list(known_vocab))

                if np.any(unknown_mask):
                    if self.config.handle_unknown_categories == "error":
                        unknown_vals = sorted(list(set(int_codes[unknown_mask])))
                        vocab_list = sorted(list(known_vocab))
                        raise ValueError(
                            f"Unseen category encountered in column '{col}' during transform: "
                            f"{unknown_vals}. Known categories from Train: {vocab_list}"
                        )
                    elif self.config.handle_unknown_categories == "sentinel":
                        cleaned_arr[unknown_mask] = self.imputed_values_[col]
                    elif self.config.handle_unknown_categories == "passthrough":
                        pass

            transformed_cols[col] = cleaned_arr

        # 3. Append missingness indicators if enabled
        if self.config.add_missing_indicators and self.indicator_features_:
            for col, ind_type in self.indicator_features_:
                ind_col_name = f"{col}__is_{ind_type}"
                col_masks = token_masks_by_col.get(col, {})
                mask = col_masks.get(ind_type, np.zeros(len(X), dtype=bool))
                transformed_cols[ind_col_name] = mask.astype(np.float64)

        output_cols = list(ML_FEATURE_COLUMNS) + [
            f"{c}__is_{t}" for c, t in self.indicator_features_
        ]
        df_out = pd.DataFrame(transformed_cols, index=X.index, columns=output_cols)

        # Assert no NaNs, no Infs, finite output
        if not np.all(np.isfinite(df_out.to_numpy())):
            raise RuntimeError(
                f"Post-transformation output has non-finite values in partition '{partition_name}'"
            )

        return df_out

    def fit_transform(self, X: pd.DataFrame, y: Any = None) -> pd.DataFrame:
        """Fit on training data X and return the transformed training data."""
        return self.fit(X, y).transform(X, partition_name="train")

    def get_metadata(self) -> Dict[str, Any]:
        """Return complete provenance and fitted parameters metadata."""
        if not self.is_fitted_:
            raise RuntimeError("Preprocessor has not been fitted")

        output_cols = list(ML_FEATURE_COLUMNS) + [
            f"{c}__is_{t}" for c, t in self.indicator_features_
        ]

        return {
            "artifact_type": "nf-unsw-nb15-v3-train-only-preprocessor",
            "artifact_version": 1,
            "dataset_name": DATASET_NAME,
            "dataset_sha256": self.dataset_sha256 or EXPECTED_DATASET_SHA256,
            "split_protocol_version": self.split_protocol_version,
            "split_manifest_sha256": self.split_manifest_sha256,
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
        """Save fitted preprocessor artifact and companion manifest.

        Returns the SHA-256 hash of the saved artifact.
        """
        if not self.is_fitted_:
            raise RuntimeError("Cannot save an unfitted preprocessor")

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

        # Save joblib binary
        joblib.dump(payload, artifact_path, compress=3)
        artifact_sha256 = _sha256_file(artifact_path)

        # Save companion JSON manifest if requested
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
        """Load a saved preprocessor artifact from disk.

        IMPORTANT SAFETY AND PROVENANCE NOTICE:
        This is a low-level compatibility loader that deserializes the artifact
        using joblib.load() without verifying an independent companion manifest.
        For production and inference environments, callers SHOULD use
        `TrainOnlyPreprocessor.load_verified()` instead, which guarantees integrity
        checks (artifact SHA-256, companion manifest schema, split/dataset hashes)
        BEFORE any deserialization occurs.

        This method validates all embedded contract metadata:
        - artifact_type, dataset_name, feature_contract_version,
        - preprocessing_policy_version, split_protocol_version,
        - baseline_ml_features columns and order,
        - output_features count and order,
        - expected checksums (if provided).

        Parameters
        ----------
        artifact_path : str or Path
            Path to the saved .joblib artifact.
        expected_dataset_sha256 : str, optional
            Expected SHA-256 of the dataset. Mismatch raises ValueError.
        expected_manifest_sha256 : str, optional
            Expected SHA-256 of the split manifest. Mismatch raises ValueError.

        Returns
        -------
        preprocessor : TrainOnlyPreprocessor
        """
        artifact_path = Path(artifact_path)
        if not artifact_path.is_file():
            raise FileNotFoundError(f"Preprocessor artifact not found: {artifact_path}")

        payload = joblib.load(artifact_path)
        if (
            not isinstance(payload, dict)
            or "metadata" not in payload
            or "fitted_state" not in payload
        ):
            raise ValueError(f"Corrupted preprocessor artifact schema in {artifact_path}")

        metadata = payload["metadata"]
        fitted_state = payload["fitted_state"]

        # Validate metadata integrity
        if metadata.get("artifact_type") != "nf-unsw-nb15-v3-train-only-preprocessor":
            raise ValueError(f"Invalid artifact type: {metadata.get('artifact_type')}")

        if metadata.get("dataset_name") != DATASET_NAME:
            actual_ds = metadata.get("dataset_name")
            raise ValueError(f"Dataset name mismatch: expected {DATASET_NAME}, got {actual_ds}")

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

        features_in_order = metadata.get("baseline_ml_features_in_order")
        if features_in_order != list(ML_FEATURE_COLUMNS):
            raise ValueError("Artifact baseline feature columns or order do not match contract")

        out_features = metadata.get("output_features_in_order")
        out_count = metadata.get("output_features_count")
        if (
            not isinstance(out_features, list)
            or not isinstance(out_count, int)
            or len(out_features) != out_count
        ):
            raise ValueError("Corrupted output features contract in artifact metadata")

        # Validate checksums if supplied
        if expected_dataset_sha256 is not None:
            artifact_ds_sha = metadata.get("dataset_sha256")
            if artifact_ds_sha != expected_dataset_sha256:
                raise ValueError(
                    f"Dataset SHA-256 mismatch in artifact: expected {expected_dataset_sha256}, "
                    f"artifact recorded {artifact_ds_sha}"
                )

        if expected_manifest_sha256 is not None:
            artifact_sm_sha = metadata.get("split_manifest_sha256")
            if artifact_sm_sha != expected_manifest_sha256:
                raise ValueError(
                    f"Split manifest SHA-256 mismatch in artifact: "
                    f"expected {expected_manifest_sha256}, artifact recorded {artifact_sm_sha}"
                )

        # Restore preprocessor instance
        config_dict = metadata.get("config", {})
        config = PreprocessingConfig(**config_dict)
        preprocessor = cls(
            config=config,
            dataset_sha256=metadata.get("dataset_sha256"),
            split_manifest_sha256=metadata.get("split_manifest_sha256"),
            split_protocol_version=metadata.get("split_protocol_version", SPLIT_PROTOCOL_VERSION),
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
        expected_dataset_sha256: str = EXPECTED_DATASET_SHA256,
    ) -> "TrainOnlyPreprocessor":
        """Load and verify a preprocessor artifact with strict provenance checking.

        This is the RECOMMENDED entrypoint for production and inference.
        It strictly verifies:
        1. Companion manifest existence, JSON syntax, and schema completeness.
        2. Exact SHA-256 integrity of the .joblib artifact BEFORE deserialization.
        3. Feature contract version, policy version, split protocol version, and dataset hash.
        4. Consistency with split manifest and raw dataset file (if provided).
        5. Internal artifact metadata consistency with companion manifest.

        Parameters
        ----------
        artifact_path : str or Path
            Path to the saved .joblib artifact.
        manifest_path : str or Path
            Path to the companion .json manifest.
        split_manifest_path : str or Path, optional
            Path to the official split manifest.
        dataset_path : str or Path, optional
            Path to the raw dataset CSV file for direct byte verification.
        expected_dataset_sha256 : str
            Expected SHA-256 of the dataset (defaults to official contract).

        Returns
        -------
        preprocessor : TrainOnlyPreprocessor
            Verified and loaded preprocessor instance.

        Raises
        ------
        ValueError
            If any verification check fails.
        """
        report = verify_preprocessing_artifact(
            artifact_path=artifact_path,
            manifest_path=manifest_path,
            split_manifest_path=split_manifest_path,
            dataset_path=dataset_path,
            expected_dataset_sha256=expected_dataset_sha256,
        )
        if report["status"] != "PASS":
            err_msg = "; ".join(report.get("errors", []))
            raise ValueError(f"Preprocessor artifact verification failed: {err_msg}")

        return cls.load(
            artifact_path=artifact_path,
            expected_dataset_sha256=expected_dataset_sha256,
        )


def load_and_preprocess_split(
    manifest_path: Union[str, Path],
    dataset_path: Union[str, Path],
    indices_dir: Union[str, Path],
    scaler_type: str = "none",
    add_missing_indicators: bool = False,
    handle_unknown_categories: str = "passthrough",
    config: Optional[PreprocessingConfig] = None,
    save_artifact_path: Optional[Union[str, Path]] = None,
    save_manifest_path: Optional[Union[str, Path]] = None,
) -> Tuple[
    Tuple[pd.DataFrame, pd.Series, pd.Series],
    Tuple[pd.DataFrame, pd.Series, pd.Series],
    Tuple[pd.DataFrame, pd.Series, pd.Series],
    TrainOnlyPreprocessor,
    Dict[str, Any],
]:
    """Consumer interface for modeling issues: load and preprocess train/val/test partitions.

    Guarantees:
    - Preprocessing is fitted EXCLUSIVELY on Train.
    - Validation and Test receive only frozen transforms.
    - Features strictly match the baseline ML features contract.
    - Preserves distinct missing vs non-finite states via keep_default_na=False.
    - Returns (X, y_label, y_attack) for each partition.

    Parameters
    ----------
    manifest_path : Path or str
        Path to official split manifest.
    dataset_path : Path or str
        Path to verified raw NF-UNSW-NB15-v3 CSV.
    indices_dir : Path or str
        Directory containing partition index files (*_indices.csv.gz).
    scaler_type : str
        Scaler type: 'none', 'robust', 'standard', 'minmax'. Default 'none'.
    add_missing_indicators : bool
        Whether to generate missingness indicator columns learned from Train.
    handle_unknown_categories : str
        Strategy for unseen categories: 'passthrough', 'sentinel', 'error'.
    config : PreprocessingConfig, optional
        Explicit configuration. If provided, overrides individual flags.
    save_artifact_path : Path or str, optional
        Path to save fitted preprocessor .joblib.
    save_manifest_path : Path or str, optional
        Path to save companion preprocessor manifest .json.

    Returns
    -------
    train_data : Tuple[pd.DataFrame, pd.Series, pd.Series]
        (X_train, y_train_label, y_train_attack)
    val_data : Tuple[pd.DataFrame, pd.Series, pd.Series]
        (X_val, y_val_label, y_val_attack)
    test_data : Tuple[pd.DataFrame, pd.Series, pd.Series]
        (X_test, y_test_label, y_test_attack)
    preprocessor : TrainOnlyPreprocessor
        The fitted preprocessor instance.
    audit_report : dict
        Audit report containing non-finite counts, row counts, and fit metadata.
    """
    manifest_path = Path(manifest_path)
    dataset_path = Path(dataset_path)
    indices_dir = Path(indices_dir)

    if not manifest_path.is_file():
        raise FileNotFoundError(f"Split manifest not found: {manifest_path}")
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    # 1. Verify split artifacts
    split_verification = verify_split_artifacts(manifest_path, dataset_path=dataset_path)
    if split_verification["status"] != "PASS":
        raise ValueError(f"Split artifact verification failed: {split_verification['errors']}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    dataset_sha256 = manifest["dataset_sha256"]
    manifest_sha256 = _sha256_file(manifest_path)

    # 2. Load partition indices
    train_indices = load_partition_indices(manifest, indices_dir, "train")
    val_indices = load_partition_indices(manifest, indices_dir, "validation")
    test_indices = load_partition_indices(manifest, indices_dir, "test")

    # 3. Read dataset columns (47 ML features + 2 targets) with keep_default_na=False
    # This prevents pandas from silently collapsing empty string '' into NaN
    cols_to_read = list(ML_FEATURE_COLUMNS) + list(TARGET_COLUMNS)
    df_raw = pd.read_csv(
        dataset_path,
        usecols=cols_to_read,
        keep_default_na=False,
        low_memory=False,
    )

    # Verify column presence
    validate_feature_selection(df_raw[list(ML_FEATURE_COLUMNS)].columns)

    # 4. Partition data
    df_train = df_raw.iloc[train_indices]
    df_val = df_raw.iloc[val_indices]
    df_test = df_raw.iloc[test_indices]

    X_train_raw = df_train[list(ML_FEATURE_COLUMNS)]
    y_train_label = df_train["Label"]
    y_train_attack = df_train["Attack"]

    X_val_raw = df_val[list(ML_FEATURE_COLUMNS)]
    y_val_label = df_val["Label"]
    y_val_attack = df_val["Attack"]

    X_test_raw = df_test[list(ML_FEATURE_COLUMNS)]
    y_test_label = df_test["Label"]
    y_test_attack = df_test["Attack"]

    # 5. Fit preprocessor EXCLUSIVELY on Train
    if config is None:
        config = PreprocessingConfig(
            scaler_type=scaler_type,
            add_missing_indicators=add_missing_indicators,
            handle_unknown_categories=handle_unknown_categories,
        )
    config.validate()

    preprocessor = TrainOnlyPreprocessor(
        config=config,
        dataset_sha256=dataset_sha256,
        split_manifest_sha256=manifest_sha256,
    )
    preprocessor.fit(X_train_raw)

    # 6. Transform partitions using frozen state
    X_train = preprocessor.transform(X_train_raw, partition_name="train")
    X_val = preprocessor.transform(X_val_raw, partition_name="validation")
    X_test = preprocessor.transform(X_test_raw, partition_name="test")

    # 7. Save artifact if requested
    saved_sha256 = None
    if save_artifact_path is not None:
        saved_sha256 = preprocessor.save(
            artifact_path=Path(save_artifact_path),
            manifest_path=Path(save_manifest_path) if save_manifest_path else None,
        )

    # 8. Compile audit report
    audit_report = {
        "status": "PASS",
        "dataset_sha256": dataset_sha256,
        "split_manifest_sha256": manifest_sha256,
        "preprocessor_artifact_sha256": saved_sha256,
        "fit_boundary": "TRAIN_ONLY",
        "scaler_type": config.scaler_type,
        "row_counts": {
            "train": len(X_train),
            "validation": len(X_val),
            "test": len(X_test),
        },
        "constant_features": preprocessor.constant_features_,
        "all_missing_columns": preprocessor.all_missing_columns_,
        "indicator_features": [f"{c}__is_{t}" for c, t in preprocessor.indicator_features_],
        "train_audit_counts": preprocessor.audit_counts_train_,
    }

    train_data = (X_train, y_train_label, y_train_attack)
    val_data = (X_val, y_val_label, y_val_attack)
    test_data = (X_test, y_test_label, y_test_attack)

    return train_data, val_data, test_data, preprocessor, audit_report


def verify_preprocessing_artifact(
    artifact_path: Union[str, Path],
    manifest_path: Union[str, Path],
    split_manifest_path: Optional[Union[str, Path]] = None,
    dataset_path: Optional[Union[str, Path]] = None,
    expected_dataset_sha256: str = EXPECTED_DATASET_SHA256,
) -> Dict[str, Any]:
    """Inspect and verify a preprocessor artifact, companion manifest, and split consistency.

    Fails closed if the companion manifest is missing, if any file hash mismatches,
    or if metadata fields (feature contract, policy version, split ID) do not align.

    CRITICAL SECURITY & INTEGRITY NOTICE:
    A joblib artifact must only be loaded from a trusted source. Pickle-based
    deserialization is dangerous if an artifact has been tampered with.
    Therefore, this function rigorously validates file existence, manifest JSON
    schema, required contract fields, and the exact SHA-256 hash of the artifact
    file BEFORE invoking deserialization. If any integrity check or checksum
    mismatch is detected, this function immediately returns FAIL without loading
    the joblib artifact.
    Note that a checksum declared in a companion manifest stored alongside the
    artifact provides consistency checking, but is not an independent authenticity
    guarantee if both files can be modified by an attacker.

    Parameters
    ----------
    artifact_path : Path or str
        Path to the saved .joblib artifact. Required.
    manifest_path : Path or str
        Path to companion .json manifest. Required.
    split_manifest_path : Path or str, optional
        Path to official split manifest. When provided, verifies consistency of
        split_manifest_sha256, split_protocol_version, and dataset_sha256.
    dataset_path : Path or str, optional
        Path to raw dataset CSV file. When provided, computes actual SHA-256
        directly from file bytes on disk and cross-checks against expected hash.
    expected_dataset_sha256 : str
        Expected dataset SHA-256 hash.

    Returns
    -------
    dict
        Verification findings with PASS/FAIL status and detailed error list.
    """
    errors: List[str] = []
    artifact_path = Path(artifact_path)
    manifest_path = Path(manifest_path)

    # 1. Check artifact file existence
    if not artifact_path.is_file():
        errors.append(f"Artifact file not found: {artifact_path}")

    # 2. Check companion manifest file existence (MANDATORY per policy)
    if not manifest_path.is_file():
        errors.append(f"Companion manifest file not found: {manifest_path}")

    if errors:
        return {
            "status": "FAIL",
            "errors": errors,
            "artifact_path": str(artifact_path),
            "manifest_path": str(manifest_path),
            "metadata": {},
        }

    # 3. Load and validate companion manifest JSON first
    manifest_json: Dict[str, Any] = {}
    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
        parsed = json.loads(manifest_text)
        if not isinstance(parsed, dict) or len(parsed) == 0:
            errors.append("Companion manifest is empty or not a valid JSON object")
        else:
            manifest_json = parsed
    except Exception as e:
        errors.append(f"Error reading companion manifest JSON: {e}")

    # 4. Strictly validate companion manifest schema and required fields
    if manifest_json:
        for field, exp_type in REQUIRED_COMPANION_MANIFEST_FIELDS.items():
            if field not in manifest_json or manifest_json[field] is None:
                errors.append(f"Companion manifest missing required field: '{field}'")
            else:
                val = manifest_json[field]
                if exp_type is int and isinstance(val, bool):
                    errors.append(f"Companion manifest field '{field}' must be int, got bool")
                elif not isinstance(val, exp_type):
                    errors.append(
                        f"Companion manifest field '{field}' must be {exp_type.__name__}, "
                        f"got {type(val).__name__}"
                    )
                elif isinstance(val, str) and not val.strip():
                    errors.append(f"Companion manifest field '{field}' must not be empty")

        # Validate companion manifest semantics and contract values
        if manifest_json.get("artifact_type") != "nf-unsw-nb15-v3-train-only-preprocessor":
            errors.append(
                f"Invalid artifact_type in companion manifest: "
                f"expected 'nf-unsw-nb15-v3-train-only-preprocessor', "
                f"got '{manifest_json.get('artifact_type')}'"
            )

        if manifest_json.get("artifact_version") != 1:
            errors.append(
                f"Invalid artifact_version in companion manifest: "
                f"expected 1, got {manifest_json.get('artifact_version')}"
            )

        if manifest_json.get("dataset_name") != DATASET_NAME:
            errors.append(
                f"Invalid dataset_name in companion manifest: "
                f"expected '{DATASET_NAME}', got '{manifest_json.get('dataset_name')}'"
            )

        if manifest_json.get("dataset_sha256") != expected_dataset_sha256:
            errors.append(
                f"Dataset SHA-256 in manifest does not match expected ({expected_dataset_sha256})"
            )

        if manifest_json.get("split_protocol_version") != SPLIT_PROTOCOL_VERSION:
            errors.append(
                f"Invalid split_protocol_version in companion manifest: "
                f"expected '{SPLIT_PROTOCOL_VERSION}', "
                f"got '{manifest_json.get('split_protocol_version')}'"
            )

        if manifest_json.get("feature_contract_version") != FEATURE_CONTRACT_VERSION:
            errors.append(
                f"Invalid feature_contract_version in companion manifest: "
                f"expected '{FEATURE_CONTRACT_VERSION}', "
                f"got '{manifest_json.get('feature_contract_version')}'"
            )

        if manifest_json.get("preprocessing_policy_version") != PREPROCESSING_POLICY_VERSION:
            errors.append(
                f"Invalid preprocessing_policy_version in companion manifest: "
                f"expected '{PREPROCESSING_POLICY_VERSION}', "
                f"got '{manifest_json.get('preprocessing_policy_version')}'"
            )

        if manifest_json.get("baseline_ml_features_count") != len(ML_FEATURE_COLUMNS):
            errors.append(
                f"Companion manifest 'baseline_ml_features_count' mismatch: "
                f"expected {len(ML_FEATURE_COLUMNS)}, "
                f"got {manifest_json.get('baseline_ml_features_count')}"
            )

        if manifest_json.get("baseline_ml_features_in_order") != list(ML_FEATURE_COLUMNS):
            errors.append(
                "Companion manifest 'baseline_ml_features_in_order' does not match contract columns"
            )

        train_rows = manifest_json.get("train_row_count")
        if isinstance(train_rows, int) and not isinstance(train_rows, bool) and train_rows <= 0:
            errors.append(
                f"Companion manifest 'train_row_count' must be positive, got {train_rows}"
            )

        out_features = manifest_json.get("output_features_in_order")
        out_count = manifest_json.get("output_features_count")
        if (
            isinstance(out_features, list)
            and isinstance(out_count, int)
            and not isinstance(out_count, bool)
        ):
            if len(out_features) != out_count:
                errors.append(
                    f"Companion manifest 'output_features_count' ({out_count}) "
                    f"does not match length of 'output_features_in_order' ({len(out_features)})"
                )

    # 5. Verify artifact SHA-256 on disk against companion manifest recorded hash
    actual_artifact_sha256 = _sha256_file(artifact_path)
    if manifest_json and "artifact_sha256" in manifest_json:
        recorded_artifact_sha = manifest_json.get("artifact_sha256")
        if recorded_artifact_sha != actual_artifact_sha256:
            errors.append(
                f"Artifact SHA-256 mismatch in manifest: "
                f"expected {actual_artifact_sha256}, recorded {recorded_artifact_sha}"
            )

    # 6. Verify actual raw dataset bytes if dataset_path is provided
    actual_ds_sha256: Optional[str] = None
    if dataset_path is not None:
        ds_p = Path(dataset_path)
        if not ds_p.is_file():
            errors.append(f"Referenced raw dataset file not found: {ds_p}")
        else:
            try:
                actual_ds_sha256 = _sha256_file(ds_p)
                if actual_ds_sha256 != expected_dataset_sha256:
                    errors.append(
                        f"Raw dataset file SHA-256 mismatch: "
                        f"expected {expected_dataset_sha256}, got {actual_ds_sha256}"
                    )
                if manifest_json and manifest_json.get("dataset_sha256") != actual_ds_sha256:
                    errors.append(
                        f"Raw dataset SHA-256 ({actual_ds_sha256}) does not match "
                        f"companion manifest dataset_sha256 ({manifest_json.get('dataset_sha256')})"
                    )
            except Exception as e:
                errors.append(f"Error computing raw dataset SHA-256: {e}")

    # 7. Verify split manifest if provided
    actual_sm_sha256: Optional[str] = None
    sm_json: Dict[str, Any] = {}
    if split_manifest_path is not None:
        split_p = Path(split_manifest_path)
        if not split_p.is_file():
            errors.append(f"Referenced split manifest not found: {split_p}")
        else:
            try:
                parsed_sm = json.loads(split_p.read_text(encoding="utf-8"))
                if not isinstance(parsed_sm, dict) or len(parsed_sm) == 0:
                    errors.append(f"Split manifest is empty or not a valid JSON object: {split_p}")
                else:
                    sm_json = parsed_sm
                    actual_sm_sha256 = _sha256_file(split_p)
                    if (
                        manifest_json
                        and manifest_json.get("split_manifest_sha256") != actual_sm_sha256
                    ):
                        man_sm = manifest_json.get("split_manifest_sha256")
                        errors.append(
                            f"Companion manifest split_manifest_sha256 ({man_sm}) "
                            f"does not match current split manifest hash ({actual_sm_sha256})"
                        )
                    if sm_json.get("dataset_sha256") != expected_dataset_sha256:
                        errors.append(
                            f"Split manifest dataset_sha256 mismatch: "
                            f"expected {expected_dataset_sha256}, "
                            f"got {sm_json.get('dataset_sha256')}"
                        )
                    if (
                        actual_ds_sha256 is not None
                        and sm_json.get("dataset_sha256") != actual_ds_sha256
                    ):
                        errors.append(
                            f"Raw dataset file SHA-256 ({actual_ds_sha256}) does not match "
                            f"split manifest dataset_sha256 ({sm_json.get('dataset_sha256')})"
                        )
                    if sm_json.get("split_protocol_version") != SPLIT_PROTOCOL_VERSION:
                        errors.append(
                            f"Split manifest protocol version mismatch: "
                            f"expected {SPLIT_PROTOCOL_VERSION}, "
                            f"got {sm_json.get('split_protocol_version')}"
                        )
            except Exception as e:
                errors.append(f"Error reading split manifest JSON: {e}")

    # CRITICAL: Fail closed BEFORE deserialization if any integrity check failed!
    if errors:
        return {
            "status": "FAIL",
            "errors": errors,
            "artifact_path": str(artifact_path),
            "manifest_path": str(manifest_path),
            "metadata": {},
        }

    # 8. Load and validate artifact .joblib (SAFE: all pre-deserialization integrity checks passed)
    preprocessor = None
    meta: Dict[str, Any] = {}
    try:
        preprocessor = TrainOnlyPreprocessor.load(
            artifact_path=artifact_path,
            expected_dataset_sha256=expected_dataset_sha256,
        )
        meta = preprocessor.get_metadata()
    except Exception as e:
        errors.append(f"Error loading/validating preprocessor artifact: {e}")

    # 9. Cross-verify hashes and contract metadata between artifact and companion manifest
    if preprocessor is not None and manifest_json:
        # Check dataset SHA-256
        if manifest_json.get("dataset_sha256") != meta.get("dataset_sha256"):
            errors.append(
                f"Dataset SHA-256 mismatch between artifact ({meta.get('dataset_sha256')}) "
                f"and companion manifest ({manifest_json.get('dataset_sha256')})"
            )
        if actual_ds_sha256 is not None and meta.get("dataset_sha256") != actual_ds_sha256:
            errors.append(
                f"Raw dataset SHA-256 ({actual_ds_sha256}) does not match "
                f"artifact recorded dataset_sha256 ({meta.get('dataset_sha256')})"
            )

        # Check split manifest SHA-256
        if manifest_json.get("split_manifest_sha256") != meta.get("split_manifest_sha256"):
            errors.append(
                f"Split manifest SHA-256 mismatch between artifact "
                f"({meta.get('split_manifest_sha256')}) and companion manifest "
                f"({manifest_json.get('split_manifest_sha256')})"
            )
        if actual_sm_sha256 is not None and meta.get("split_manifest_sha256") != actual_sm_sha256:
            errors.append(
                f"Artifact was not fit on current split manifest: "
                f"artifact recorded {meta.get('split_manifest_sha256')}, "
                f"current split manifest has {actual_sm_sha256}"
            )

        # Check split protocol version
        if manifest_json.get("split_protocol_version") != meta.get("split_protocol_version"):
            errors.append(
                f"Split protocol version mismatch: artifact has "
                f"'{meta.get('split_protocol_version')}', companion manifest has "
                f"'{manifest_json.get('split_protocol_version')}'"
            )

        # Check feature contract version
        if manifest_json.get("feature_contract_version") != meta.get("feature_contract_version"):
            errors.append(
                f"Feature contract version mismatch: artifact has "
                f"'{meta.get('feature_contract_version')}', companion manifest has "
                f"'{manifest_json.get('feature_contract_version')}'"
            )

        # Check preprocessing policy version
        if manifest_json.get("preprocessing_policy_version") != meta.get(
            "preprocessing_policy_version"
        ):
            errors.append(
                f"Preprocessing policy version mismatch: artifact has "
                f"'{meta.get('preprocessing_policy_version')}', companion manifest has "
                f"'{manifest_json.get('preprocessing_policy_version')}'"
            )

        # Check output feature count and order
        if manifest_json.get("output_features_count") != meta.get("output_features_count"):
            errors.append(
                f"Output features count mismatch: artifact has "
                f"{meta.get('output_features_count')}, companion manifest has "
                f"{manifest_json.get('output_features_count')}"
            )
        if manifest_json.get("output_features_in_order") != meta.get("output_features_in_order"):
            errors.append(
                "Output features in order mismatch between artifact and companion manifest"
            )

        # Check train row count
        if manifest_json.get("train_row_count") != meta.get("train_row_count"):
            errors.append(
                f"Train row count mismatch: artifact has {meta.get('train_row_count')}, "
                f"companion manifest has {manifest_json.get('train_row_count')}"
            )

        # Check config
        if manifest_json.get("config") != meta.get("config"):
            errors.append("Config mismatch between artifact and companion manifest")

    status = "PASS" if not errors else "FAIL"
    return {
        "status": status,
        "errors": errors,
        "artifact_path": str(artifact_path),
        "manifest_path": str(manifest_path),
        "metadata": meta,
    }
