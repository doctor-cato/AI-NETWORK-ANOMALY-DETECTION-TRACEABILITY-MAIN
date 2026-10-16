# Evaluation — Metrics, Interpretation, Error Analysis

## Evaluation protocol per model

### Random Forest (supervised)

- Train on labeled train set.
- Predict on validation and test sets using fitted pipeline.
- Compute: Precision, Recall, F1 (binary or per-class), Macro-F1, confusion matrix, FPR.
- Confusion matrix interpreted with clear axis labels.

### Isolation Forest (unsupervised — if implemented)

- Train on unlabeled (or labeled-ignored) train set.
- Produce anomaly scores on validation set.
- Select threshold (document method: e.g., contamination estimate = expected anomaly ratio, or score quantile).
- Predict on test with selected threshold.
- Compute same metrics; clearly state threshold selection process.
- Note: metrics are comparable only after both protocols documented.

## Metrics definitions (repeated from METHODOLOGY for clarity)

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * P * R / (P + R)
- Macro-F1 = mean(per-class F1)
- Confusion matrix: clearly labeled axes
- FPR = FP / (FP + TN) — report when meaningful

## Error analysis

- False positives: normal connections flagged; describe possible causes (similar features to anomalies; feature encoding issues; class overlap).
- False negatives: anomalies missed; describe possible causes (anomaly types underrepresented; feature not captured; threshold too conservative).
- Data limitations: imbalance, missing values, duplicates, identity leakage.
- Model limitations: Random Forest may overfit if depth unbounded; Isolation Forest assumes normal data clusters differently from anomalies; neither claims zero-day detection without proof.

## No unverified benchmark claims

- This repository does not claim specific accuracy, F1-score, or benchmark results until real experiments complete and results are recorded with seed/version.
- All results labeled: planned / implemented / verified.

Updated: 2026-10-16
