# Recovered held-out Test evidence

This directory contains small evidence for the existing `rf-heldout-ea330b9` run. The original predictions, chart PNG, source CSV, partition index files, and joblib artifacts remain outside Git. `verified_summary.json` records their SHA-256 values and the per-sample analysis. `metrics.json`, `confusion_matrix.csv`, and `evaluation_metadata.json` preserve the stored content with LF line endings for Git; their original byte hashes are recorded in the summary.

`split_manifest.json` and `preprocessing_manifest.json` are byte-for-byte snapshots from commit `9da4e50`. They identify the October artifact set used by the Random Forest model and this evaluation run. The currently tracked split and preprocessing manifests identify a later November artifact set with different hashes. Do not silently substitute those files, even though the row counts and split protocol match.

The verifier checked the UQ dataset record, raw CSV SHA-256, all three partition index file hashes, row counts, bounds and pairwise disjointness, model and preprocessor artifact hashes, locked configuration, threshold, feature order, stored artifact hashes, Test row order, source labels and Attack families, metrics and confusion matrix. No model inference or Test tuning was repeated. The historical runtime declaration that no training or threshold selection used Test is corroborated by the training manifest and code path; independent reconstruction of the original run process is not available.

To repeat the reconciliation with locally held binary artifacts, use the command in `docs/REPRODUCIBILITY.md`. A missing or inconsistent evidence link causes the command to fail before it writes a verified report.
