# Experiment Plan

## Hypotheses

- H1: Random Forest achieves usable supervised detection on UNSW-NB15 after proper preprocessing and split.
- H2: Isolation Forest can detect anomalies without labels, but evaluation requires threshold selection and yields different metric profiles than supervised evaluation.

## Variables

- Independent: model type (RF vs IF), preprocessing choices (encoding, selected features), split strategy, random seed.
- Dependent: Precision, Recall, F1, Macro-F1, confusion matrix, FPR.

## Baseline

- Random Forest with default/limited hyperparameters as baseline.
- Comparison point: documented metrics with seed and version.

## Metrics recording

- Each run saves: seed, dataset version, feature list, model config, metrics per class and macro, confusion matrix as CSV/PNG, time, environment info.
- Results stored in `reports/figures/` and `artifacts/` (not committed if large; config saved).

## Protocol

- Split first, then preprocess; save pipeline.
- Random seed fixed (e.g., 42) for reproducible splits and model init.
- Run multiple seeds if time permits; report mean/std if performed.
- Document any deviation (e.g., if Isolation Forest not implemented due to time).

Updated: 2026-10-16
