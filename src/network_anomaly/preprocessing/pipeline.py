"""NF-UNSW-NB15-v3 train-only preprocessing pipeline.

This module implements a reusable, leak-free preprocessing pipeline for NF-UNSW-NB15-v3:
1. Validates the 47-feature baseline ML contract and strict exclusion of targets and trace metadata.
2. Fits imputers, vocabularies, and optional scalers EXCLUSIVELY on the training partition.
3. Freezes all learned state so Validation and Test receive only immutable transforms.
4. Audits missing, NaN, positive infinity, negative infinity, and rejects invalid numeric tokens.
5. Saves versioned, verifiable preprocessing artifacts with complete provenance metadata.
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


@dataclass(frozen=True)
class PreprocessingConfig:
    """Configuration for train-only preprocessing."""

    scaler_type: str = "none"
    imputer_strategy_quantitative: str = "median"
    imputer_strategy_categorical: str = "mode"
    add_missing_indicators: bool = False
    handle_unknown_categories: str = "passthrough"

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


def audit_column_tokens(series: pd.Series, column_name: str) -> Tuple[Dict[str, int], np.ndarray]:
    """Audit values in a column for missingness, non-finite states, and invalid numeric tokens.

    Returns
    -------
    audit_counts : dict
        Detailed counts of missing, nan, pos/neg infinity, invalid numeric, finite.
    cleaned_float_array : np.ndarray
        Float64 array where non-finite tokens (missing, nan, +inf, -inf) are represented as np.nan.

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

    if pd.api.types.is_numeric_dtype(series.dtype):
        vals = series.to_numpy(dtype=np.float64, copy=True)
        pos_inf_mask = np.isposinf(vals)
        neg_inf_mask = np.isneginf(vals)
        nan_mask = np.isnan(vals)

        pos_inf_count = int(pos_inf_mask.sum())
        neg_inf_count = int(neg_inf_mask.sum())
        nan_count = int(nan_mask.sum())
        finite_count = total - (pos_inf_count + neg_inf_count + nan_count)

        # In numeric pandas series, both empty strings and NaNs parse as NaN,
        # but infinities are distinct float objects.
        # Map infinities to np.nan sentinel for downstream imputation
        vals[pos_inf_mask | neg_inf_mask] = np.nan
        cleaned_array = vals
    else:
        # Object / string dtype: inspect individual elements
        cleaned_array = np.empty(total, dtype=np.float64)
        for i, val in enumerate(series):
            if val is None or val == "" or pd.isna(val):
                missing_count += 1
                cleaned_array[i] = np.nan
                continue

            val_str = str(val).strip()
            val_lower = val_str.lower()

            if val_lower in {"nan", "null", "none"}:
                nan_count += 1
                cleaned_array[i] = np.nan
            elif val_lower in {"inf", "+inf", "infinity", "+infinity"}:
                pos_inf_count += 1
                cleaned_array[i] = np.nan
            elif val_lower in {"-inf", "-infinity"}:
                neg_inf_count += 1
                cleaned_array[i] = np.nan
            else:
                try:
                    num = float(val_str)
                    if math.isnan(num):
                        nan_count += 1
                        cleaned_array[i] = np.nan
                    elif math.isinf(num):
                        if num > 0:
                            pos_inf_count += 1
                        else:
                            neg_inf_count += 1
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
        self.audit_counts_train_ = {}

        # 2. Audit and learn imputers and vocabularies on Train
        cleaned_train_arrays: Dict[str, np.ndarray] = {}

        for col in ML_FEATURE_COLUMNS:
            series = X[col]
            col_audit, cleaned_arr = audit_column_tokens(series, col)
            self.audit_counts_train_[col] = col_audit
            cleaned_train_arrays[col] = cleaned_arr

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
            Cleaned and transformed DataFrame with exactly 47 finite feature columns
            in exact contract order.
        """
        if not self.is_fitted_:
            raise RuntimeError("Preprocessor has not been fitted. Call fit(X_train) first.")

        if not isinstance(X, pd.DataFrame):
            raise TypeError(f"X must be a pandas DataFrame, got {type(X)}")

        # 1. Enforce feature contract on transform input
        validate_feature_selection(X.columns, require_complete=True)

        transformed_cols: Dict[str, np.ndarray] = {}

        # 2. Audit and transform each column using frozen train parameters
        for col in ML_FEATURE_COLUMNS:
            series = X[col]
            _, cleaned_arr = audit_column_tokens(series, col)

            # Impute non-finite values (missing, nan, inf) using train fitted value
            nan_mask = np.isnan(cleaned_arr)
            cleaned_arr[nan_mask] = self.imputed_values_[col]

            # Scale quantitative columns if scaler was fitted
            if self.config.scaler_type != "none" and col in self.scaler_params_:
                params = self.scaler_params_[col]
                center = params["center"]
                scale = params["scale"]
                cleaned_arr = (cleaned_arr - center) / scale

            # If categorical-coded, cast to int64 or float representation
            if col in CATEGORICAL_CODED_COLUMNS:
                # Keep discrete codes as float64 or int64
                cleaned_arr = np.round(cleaned_arr)

            transformed_cols[col] = cleaned_arr

        # Construct result DataFrame preserving exact column order and index
        df_out = pd.DataFrame(transformed_cols, index=X.index, columns=list(ML_FEATURE_COLUMNS))

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
            "categorical_coded_columns": list(CATEGORICAL_CODED_COLUMNS),
            "quantitative_ml_columns": list(QUANTITATIVE_ML_COLUMNS),
            "preprocessing_policy_version": PREPROCESSING_POLICY_VERSION,
            "config": asdict(self.config),
            "train_row_count": self.train_row_count_,
            "fitted_at_utc": self.fitted_at_utc_,
            "constant_features": list(self.constant_features_),
            "all_missing_columns": list(self.all_missing_columns_),
            "environment": {
                "python": sys.version,
                "numpy": np.__version__,
                "pandas": pd.__version__,
                "joblib": joblib.__version__,
            },
        }

    def save(self, artifact_path: Path, manifest_path: Optional[Path] = None) -> str:
        """Save fitted preprocessor artifact and optional companion manifest.

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
                },
            }
            manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

        return artifact_sha256

    @classmethod
    def load(
        cls,
        artifact_path: Union[str, Path],
        expected_dataset_sha256: Optional[str] = None,
        expected_manifest_sha256: Optional[str] = None,
    ) -> "TrainOnlyPreprocessor":
        """Load and verify a saved preprocessor artifact.

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

        features_in_order = metadata.get("baseline_ml_features_in_order")
        if features_in_order != list(ML_FEATURE_COLUMNS):
            raise ValueError("Artifact baseline feature columns or order do not match contract")

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
        preprocessor.audit_counts_train_ = fitted_state.get("audit_counts_train", {})
        preprocessor.train_row_count_ = fitted_state.get("train_row_count", 0)
        preprocessor.fitted_at_utc_ = fitted_state.get("fitted_at_utc")
        preprocessor.is_fitted_ = True

        return preprocessor


def load_and_preprocess_split(
    manifest_path: Union[str, Path],
    dataset_path: Union[str, Path],
    indices_dir: Union[str, Path],
    scaler_type: str = "none",
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
    - Features strictly match the 47 baseline ML features contract.
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

    # 3. Read dataset columns (47 ML features + 2 targets)
    cols_to_read = list(ML_FEATURE_COLUMNS) + list(TARGET_COLUMNS)
    df_raw = pd.read_csv(dataset_path, usecols=cols_to_read)

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
    config = PreprocessingConfig(scaler_type=scaler_type)
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
        "scaler_type": scaler_type,
        "row_counts": {
            "train": len(X_train),
            "validation": len(X_val),
            "test": len(X_test),
        },
        "constant_features": preprocessor.constant_features_,
        "all_missing_columns": preprocessor.all_missing_columns_,
        "train_audit_counts": preprocessor.audit_counts_train_,
    }

    train_data = (X_train, y_train_label, y_train_attack)
    val_data = (X_val, y_val_label, y_val_attack)
    test_data = (X_test, y_test_label, y_test_attack)

    return train_data, val_data, test_data, preprocessor, audit_report


def verify_preprocessing_artifact(
    artifact_path: Union[str, Path],
    manifest_path: Optional[Union[str, Path]] = None,
    expected_dataset_sha256: str = EXPECTED_DATASET_SHA256,
) -> Dict[str, Any]:
    """Inspect and verify an existing preprocessor artifact and companion manifest.

    Parameters
    ----------
    artifact_path : Path or str
        Path to the saved .joblib artifact.
    manifest_path : Path or str, optional
        Path to companion .json manifest.
    expected_dataset_sha256 : str
        Expected dataset SHA-256 hash.

    Returns
    -------
    dict
        Verification findings with PASS/FAIL status.
    """
    errors: List[str] = []
    artifact_path = Path(artifact_path)

    if not artifact_path.is_file():
        return {
            "status": "FAIL",
            "errors": [f"Artifact file not found: {artifact_path}"],
            "artifact_path": str(artifact_path),
        }

    try:
        preprocessor = TrainOnlyPreprocessor.load(
            artifact_path=artifact_path,
            expected_dataset_sha256=expected_dataset_sha256,
        )
    except Exception as e:
        return {
            "status": "FAIL",
            "errors": [f"Error loading/validating preprocessor artifact: {e}"],
            "artifact_path": str(artifact_path),
        }

    meta = preprocessor.get_metadata()

    # Check companion manifest if provided
    if manifest_path is not None:
        manifest_path = Path(manifest_path)
        if not manifest_path.is_file():
            errors.append(f"Companion manifest file not found: {manifest_path}")
        else:
            try:
                manifest_json = json.loads(manifest_path.read_text(encoding="utf-8"))
                actual_artifact_sha256 = _sha256_file(artifact_path)
                recorded_sha256 = manifest_json.get("artifact_sha256")
                if recorded_sha256 != actual_artifact_sha256:
                    errors.append(
                        f"Artifact SHA-256 mismatch in manifest: "
                        f"expected {actual_artifact_sha256}, recorded {recorded_sha256}"
                    )
            except Exception as e:
                errors.append(f"Error reading companion manifest: {e}")

    status = "PASS" if not errors else "FAIL"
    return {
        "status": status,
        "errors": errors,
        "artifact_path": str(artifact_path),
        "metadata": meta,
    }
