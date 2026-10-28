# NF-UNSW-NB15-v3 quality-handling contract

**Status:** policy and train-only fitted preprocessing artifact `IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED` on verified NF-UNSW-NB15-v3 bytes (SHA-256 `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`).
Fitted preprocessor artifact generated at `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib` with companion manifest at `reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json`.
Issue #8 is complete; downstream model training (Issue #9+) consumes this verified train-only preprocessed representation while keeping `ML_READY: BLOCKED` until model training is authorized.

## Immutable source boundary

The verified raw CSV is never rewritten. Missing and non-finite tokens remain evidence about the
published bytes. Any transformed dataset must be a derived artifact with the source manifest hash,
split identifier, policy version and fitted-transform hash.

## Fit boundary

Partition/group assignment happens before any learned preprocessing. Imputer statistics, encoder
vocabularies, scaling parameters, clipping thresholds, selectors and missingness-indicator choices
are fit using the training partition only (1,655,797 rows). Validation (345,371 rows) and Test
(345,953 rows) receive only frozen transforms. Test labels never select this policy or its parameters.

## Implemented numeric missing and non-finite policy

The transformer in `src/network_anomaly/preprocessing/pipeline.py` strictly adheres to the contract:

1. **Pre-transform token audit:** preserves separate audit counts (`missing`, `nan`,
   `positive_infinity`, `negative_infinity`, `invalid_numeric`) before transformation across all
   47 features. Uses `keep_default_na=False` on CSV loading to distinguish literal empty cells (`""`)
   from literal `NaN` strings and non-finite values.
2. **Fail-closed invalid numeric tokens:** rejects unparseable string tokens with a hard `ValueError`
   unless an explicit schema correction is provided.
3. **Internal missing mapping:** maps missing tokens (`""`, `None`, `pd.NA`), `NaN`, positive infinity
   and negative infinity to an internal missing sentinel (`np.nan`) strictly after chronological
   split partitioning.
4. **Train-only finite imputation:**
   - Quantitative features (37 fields): fits finite-value median computed strictly on the training
     partition (`train_indices`). Empirical medians learned from Train:
     - `SRC_TO_DST_SECOND_BYTES`: 162.0
     - `DST_TO_SRC_SECOND_BYTES`: 78.28151260504201
   - Categorical-coded features (10 fields): fits finite-value mode computed strictly on Train
     (e.g., `PROTOCOL`: 6.0 [TCP], `L7_PROTO`: 0.0).
5. **Frozen transformation:** applies the stored training medians and modes to validation and test
   without recomputation or adjustment.
6. **No silent zeroing:** never replaces infinity values with zero; all non-finite values receive
   training-derived medians/modes.
7. **Robust handling of edge cases:** features with zero variance (constants) or all-missing values
   on Train are identified, logged in artifact metadata, and handled deterministically without
   division-by-zero or NaNs.
8. **Missingness indicators:** optionally generates binary indicator columns (`add_missing_indicators=True`)
   learned strictly from Train and applied to Validation and Test without modifying the feature schema dynamically.
9. **Unknown discrete categories handling:** configurable via `handle_unknown_categories`:
   - `"passthrough"` (default): retains unseen category integer codes;
   - `"sentinel"`: maps unseen categories to training-derived mode;
   - `"error"`: fails closed with `ValueError` if an unseen category appears during transform.
10. **Strict companion manifest verification:** enforces fail-closed verification of the `.joblib`
    artifact alongside its companion `.json` manifest, cross-checking `artifact_sha256`, `split_manifest_sha256`,
    `dataset_sha256`, `feature_contract_version`, and `preprocessing_policy_version`.

## Numeric-coded semantics

The baseline 47 columns are not semantically interchangeable:

- byte, packet, duration, throughput, IAT and length fields (37 columns) are quantitative;
- `PROTOCOL`, `L7_PROTO`, TCP flags, ICMP/DNS types and FTP return codes (10 columns) are
  numeric-coded categorical/bit-mask fields and are NEVER treated as continuous continuous variables
  or scaled with continuous standardizers/normalizers;
- Any continuous scaler (such as `RobustScaler`, `StandardScaler`, or `MinMaxScaler`) fits and applies
  strictly to `QUANTITATIVE_ML_COLUMNS`. `CATEGORICAL_CODED_COLUMNS` retain their discrete integer
  codes in the exact contract order.

## Outliers and row retention

No row is removed solely because it has missing/infinite values, and the 1,134,553 behavioral-
fingerprint repeats are not automatically deduplicated. The baseline does not clip/winsorize
outliers. When scaling is requested, statistics are fit on train only; the baseline default is
passthrough (`scaler_type="none"`) for tree-based models (Random Forest, XGBoost, Isolation Forest).

## Executable interface for downstream models

Downstream model implementations consume:
```python
from network_anomaly.preprocessing import load_and_preprocess_split, TrainOnlyPreprocessor

# Load and preprocess all three partitions in one leak-free call:
train_data, val_data, test_data, preprocessor, audit = load_and_preprocess_split(
    manifest_path="data/processed/nf_unsw_nb15_v3_split_manifest.json",
    dataset_path="data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv",
    indices_dir="data/processed/splits",
    scaler_type="none",
)
X_train, y_train_label, y_train_attack = train_data
X_val, y_val_label, y_val_attack = val_data
X_test, y_test_label, y_test_attack = test_data
```

Or for standalone inference:
```python
preprocessor = TrainOnlyPreprocessor.load("artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib")
X_clean = preprocessor.transform(X_new)
```

## Acceptance gate

The train-only preprocessing pipeline is **IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED** (Audit status: PASS).
Reproducibility check confirms 100% parameter and output identity across independent runs.
Dataset readiness remains `ML_READY: BLOCKED` until supervised/unsupervised model training is authorized in Issue #9+.
