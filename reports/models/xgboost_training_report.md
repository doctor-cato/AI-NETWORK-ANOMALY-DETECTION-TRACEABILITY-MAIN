# XGBoost Baseline Training Report — NF-UNSW-NB15-v3 (Issue #31 / C3)

- **Run ID:** `xgb-baseline-1794151507`
- **Trained at (UTC):** `2026-11-08T15:24:43.195015+00:00`
- **Git commit:** `7d760e0ca3b43e1ed48108978922bf8638168dde`
- **Dataset:** `NF-UNSW-NB15-v3` (SHA-256 `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`)
- **Split protocol:** `nf-unsw-nb15-v3-chronological-group-purged-v1` (manifest SHA-256 `845d8863deeae84d2f7ce29758366d8e8146d0484faadc3b2721cdcc2fc92b2f`)
- **Preprocessing artifact:** `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib` (SHA-256 `e1e89bde7c6504cc26bc48a5ef41fc151f762dc61fe8f053252fb32035fb25e6`)

## Configuration (canonical, locked)
- model: XGBClassifier, objective `binary:logistic`
- n_estimators=200, max_depth=6, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8, tree_method=`hist`
- random_state=42
- Training rows: 1,655,797, Validation rows: 345,371, features: 47
- Training duration: 19.66 s, peak memory: 4422.59 MB
- Environment: Python 3.13.9, xgboost 3.4.1, scikit-learn 1.9.1, pandas 3.0.6, numpy 2.5.3

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

## Test-partition lock
- `test_partition_accessed`: `False`
- `test_rows_loaded`: `0`

- Artifact: `artifacts/models/xgboost/xgboost_baseline.joblib` (SHA-256 `c70ec52fb3229ccca680f70356e0a8c44e0b16ff7988c5e6fb91da3383eabd6e`)
- Reload verification: `PASSED`

## Comparison with Random Forest reference (same protocol, Validation)
| Metric | Random Forest | XGBoost |
|---|---|---|
| Precision | 0.999836 | 0.999967 |
| Recall | 0.999902 | 1.000000 |
| F1 | 0.999869 | 0.999984 |
| Macro-F1 | 0.999928 | 0.999991 |
| FPR | 0.000016 | 0.000003 |
