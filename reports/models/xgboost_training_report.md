# XGBoost Baseline Training Report — NF-UNSW-NB15-v3 (Issue #31 / C3)

- **Run ID:** `xgb-baseline-1794755807`
- **Trained at (UTC):** `2026-11-15T15:16:31.093690+00:00`
- **Git commit:** `7f51390bfe4cea76a413733ac1882d8579fc4a34`
- **Dataset:** `NF-UNSW-NB15-v3` (SHA-256 `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`)
- **Split protocol:** `nf-unsw-nb15-v3-chronological-group-purged-v1` (manifest SHA-256 `bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88`)
- **Preprocessing artifact:** `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib` (SHA-256 `12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19`)

## Configuration (canonical, locked)
- model: XGBClassifier, objective `binary:logistic`
- n_estimators=200, max_depth=6, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8, tree_method=`hist`
- random_state=42
- Training rows: 1,655,797, Validation rows: 345,371, features: 47
- Training duration: 13.92 s, peak memory: 3871.07 MB
- Environment: Python 3.14.10, xgboost 3.4.1, scikit-learn 1.9.1, pandas 3.1.1, numpy 2.5.4

## Label policy
- Positive class: `Attack` = label **1**; Negative class: `Benign` = label **0**.
- Task: binary classification on `Label`. Attack-category multiclass column is excluded.

## Validation metrics
- Precision: **0.999967**
- Recall: **1.000000**
- F1: **0.999984**
- Macro-F1: **0.999991**
- FPR: **0.000003**
- Confusion matrix (label order [0, 1]): `[[314870, 1], [0, 30500]]`
  - TN=314,870, FP=1, FN=0, TP=30,500

## Test-partition lock & held-out evaluation
- `test_partition_accessed`: `True`
- `test_rows_loaded`: `345953`
- `test_evaluated_post_fit`: `True`

- Artifact: `artifacts/models/xgboost/xgboost_baseline.joblib` (SHA-256 `3098b75acdd79c39605d724880f8f2ed48af6d68a0651292e27804b42a1f493e`)
- Reload verification: `PASSED`

## Held-out Test metrics (post-fit one-shot evaluation)
- Rows evaluated: **345,953**
- Precision: **0.999967**
- Recall: **1.000000**
- F1: **0.999984**
- Macro-F1: **0.999991**
- FPR: **0.000003**
- Confusion matrix (label order [0, 1]): `[[315356, 1], [0, 30596]]`
  - TN=315,356, FP=1, FN=0, TP=30,596

## Comparison with Random Forest reference (same protocol, Validation)
| Metric | Random Forest | XGBoost |
|---|---|---|
| Precision | 0.999836 | 0.999967 |
| Recall | 0.999902 | 1.000000 |
| F1 | 0.999869 | 0.999984 |
| Macro-F1 | 0.999928 | 0.999991 |
| FPR | 0.000016 | 0.000003 |

## Dataset Contract Clarification (55 Raw Columns, 47 ML Features)
- **Raw CSV canonical schema (55 columns):** Defined in `src/network_anomaly/data/nf_unsw_nb15_v3.py` (`ALL_COLUMNS`):
  - **47 ML feature columns (`ML_FEATURE_COLUMNS`):** NetFlow statistical and engineered flow attributes.
  - **6 trace metadata columns (`TRACE_METADATA_COLUMNS`):** Timestamps (`FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`), IP addresses (`IPV4_SRC_ADDR`, `IPV4_DST_ADDR`), and Layer-4 ports (`L4_SRC_PORT`, `L4_DST_PORT`). Excluded from training features to prevent identity/shortcut leakage.
  - **2 ground-truth target columns (`TARGET_COLUMNS`):** `Label` (binary classification target: 0=Benign, 1=Attack) and `Attack` (multiclass attack category string: Benign, Fuzzers, Analysis, Backdoor, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms).
- **Target & metadata leakage prevention:** The fitted train-only preprocessor and data ingestion stream strictly exclude all 6 trace metadata columns and both 2 target columns (`Label`, `Attack`) from model input features.
- **Model input contract:** The model is fitted strictly on the canonical 47 features (`n_features_in_ = 47`), matching `ML_FEATURE_COLUMNS` and `feature_contract_version = "nf-unsw-nb15-v3-baseline-47"`.

## Generalization & Shortcut Limitations
- **Evaluation context:** Near-perfect validation metrics (Recall = 1.000000, Precision = 0.999967, FPR = 0.000003) must be interpreted with extreme caution in benchmark NIDS environments.
- **Flow fingerprint overlap:** Despite chronological and purged gap partitioning, approximately 49.98% of flow fingerprints (protocol, ports, flow size profiles) overlap between partitions due to synthetic traffic generator configurations in the IXIA PerfectStorm testbed.
- **Shortcut learning risks:** Decision tree ensembles (XGBoost, Random Forest) can exploit testbed-specific artifacts (e.g., deterministic TTL values, static port distributions, synthetic packet sizing) rather than generalized malicious behaviors.
- **Out-of-Distribution (OOD) degradation:** True zero-day variants, evasive malware, and production enterprise networks will experience higher false alarm rates and degraded recall compared to benchmark test partitions.
- **Operational disclaimer:** Benchmark performance does not equate to production readiness; continuous drift monitoring, feature ablation, and out-of-distribution evaluation are required before live deployment.
