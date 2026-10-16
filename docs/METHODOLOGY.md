# Methodology — Baseline, Random Forest, Isolation Forest

## Overall pipeline

1. Data loading (after download to `data/raw/`)
2. Schema / label verification (`scripts/validate_data.py`)
3. Exploration (EDA notebook) — class distribution, missing values, duplicates, leakage audit
4. Train/val/test split (stratified if supervised; time/session-aware if needed; documented in `REPRODUCIBILITY.md`)
5. Preprocessing (fit on train only): encoding, scaling, feature selection; save pipeline
6. Model training (Random Forest or Isolation Forest with documented config)
7. Evaluation (protocol differs by model; see below)
8. Error analysis (false positives / false negatives; document limitations)
9. Inference (load pipeline + model; apply to new input)

## Random Forest (supervised baseline)

- Type: supervised classification (binary or multi-class depending on defined objective)
- Training: labeled training set; hyperparameters documented (`n_estimators`, `max_depth`, `random_state`)
- Evaluation: standard supervised metrics — Precision, Recall, F1-score (per class), Macro-F1, confusion matrix, False Positive Rate (FPR) when meaningful
- Confusion matrix interpretation: true negatives / false positives (normal misclassified as anomaly) / false negatives (anomaly missed) / true positives
- Data leakage prevention: no feature derived from target; split before any fit; identity columns audited and either excluded or handled with care

## Isolation Forest (unsupervised anomaly detection — if implemented)

- Type: unsupervised; learns normal data distribution; scores deviation
- Training: training set (labeled data used only to provide context; model does not use labels during fit)
- Evaluation protocol (must be documented separately from supervised evaluation):
  - Produce anomaly scores for validation/test sets
  - Select threshold on validation set (e.g., based on contamination estimate or score quantile)
  - Apply threshold to test set to obtain predicted labels
  - Compare predictions to ground-truth labels using Precision, Recall, F1, Macro-F1, FPR
  - Document threshold selection method and its impact on metrics
- Important: direct comparison with Random Forest requires explicit explanation because Random Forest uses labels during training and evaluates with standard supervised protocol, while Isolation Forest uses score-based thresholding and evaluates after threshold selection. Metrics are comparable numerically only after both protocols are clearly described.

## Preprocessing rules (to avoid leakage)

- Split train / val / test before any preprocessing fit.
- Fit scaler/encoder/selector on train only.
- Transform val/test with fitted objects.
- Save fitted objects with model artifacts.
- Document which columns are included/excluded and why (leakage audit result).

## Metrics definitions

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * Precision * Recall / (Precision + Recall)
- Macro-F1 = average of per-class F1 scores
- Confusion matrix: rows/columns must be clearly labeled (normal / anomaly)
- FPR = FP / (FP + TN) — only reported when meaningful for the use case

Updated: 2026-10-16
