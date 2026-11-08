# Reproducibility

## Environment

- Python: 3.11/3.12 in CI; local code declares `>=3.11`.
- Supported CI OS: Ubuntu and Windows.
- Raw dataset and large model artifacts are not committed.
- `pytest` prepends this checkout's `src/`, avoiding an editable install from another worktree.

```text
python scripts/check_environment.py
python -m pytest tests -q
python -m ruff check .
python -m black --check .
git diff --check
```

Detailed unit, integration, and failure-path testing guidelines are documented in [docs/TESTING.md](TESTING.md).

## Reproduce official bytes

```text
python scripts/fetch_nf_unsw_nb15_v3.py
python scripts/dataset_manifest.py verify
```

The manifest pins DOI, UQRDM UUID, package identifier, byte sizes, project-computed SHA-256,
publisher BagIt SHA-1 for payload files, schema order and verified distributions. The download API
returns a rotating signed URL, so the stable identity is the UQRDM record plus pinned content bytes,
not the temporary URL.

Fetcher safety includes bounded streaming, HTML/ZIP/member checks, safe extraction, cache
verification, destination lock, staging, transaction marker, backup, rollback and recovery. A
successful cache hit still rehashes all package members.

## Reproduce real-data audit

```text
python scripts/validate_data.py
```

Expected current status is `SOURCE_INTEGRITY: PASS`, `RAW_QUALITY: FINDINGS_RECORDED`,
`ML_READY: BLOCKED`. The version-controlled report records the verified dataset SHA-256,
row/label/category counts, missing/non-finite counts and disk-backed duplicate audit. The validator
removes its temporary SQLite database after success or failure.

When the default CSV is absent, validation prints `SOURCE_INTEGRITY: SKIPPED` and exits `0`. A
source-valid but ML-blocked audit exits `1`; integrity/corruption errors exit `2`. The SKIPPED
behavior permits CI without a 577 MB raw CSV, but it is not real-data evidence. Synthetic test PASS
only demonstrates validator behavior.

## Reproduce the exploratory analysis

```text
python scripts/eda_nf_unsw_nb15_v3.py
```

The EDA reuses the manifest contract and the byte verification of `scripts/validate_data.py`, so
`scripts/validate_data.py` has to run first. The run streams the population in bounded memory and
writes the machine-readable summary `reports/eda/nf_unsw_nb15_v3_eda_summary.json`, the generated
report `docs/dataset/NF_UNSW_NB15_V3_EDA.md` and the labelled figures under
`reports/figures/nf_unsw_nb15_v3/` (excluded from Git, regenerated locally).

Reproducibility properties of the recorded run:

- Source identity: SHA-256 of the raw CSV is re-verified against the manifest before the analysis.
- Sampling: figures and shape statistics use a reservoir sample of 200,000 rows with seed `42` and
  the method is recorded in the summary. Counts, means, extremes, exact population quantiles and
  complete-case correlations are computed over every row.
- Float aggregation: means and standard deviations are accumulated per streaming chunk, so their
  last decimal digits depend on the chunk size. The recorded run uses the default chunk size of
  100,000 rows; counts and quantiles are unaffected.
- Stability: two runs of the same command on the same bytes produce identical counts and
  quantiles. Re-running the command regenerates the report and the summary; the summary records
  the run timestamp, the report records the dataset SHA-256.
- Absent raw bytes: the command prints `EDA: SKIPPED` and exits `0`. A skip is not a result and
  writes no artifact.

The analysis is descriptive only. It does not fit a transformer, does not select features, does not
remove a row and does not create a split, so `ML_READY` stays `BLOCKED`.

## Reproduce the EDA twice and compare the two runs

```text
python scripts/verify_eda_reproducibility.py
```

The command executes `scripts/eda_nf_unsw_nb15_v3.py` twice on the same verified source file and
writes one retrievable evidence bundle per run:

| Artifact | Path | Content |
|---|---|---|
| Run metadata | `reports/eda/evidence/run-{1,2}/run_metadata.json` | git HEAD, branch, commit date, interpreter, OS, dependency versions, dataset identity, manifest and schema verification, key aggregates, command, exit code, start/end timestamps, SHA-256 of the summary and report |
| Captured output | `reports/eda/evidence/run-{1,2}/stdout.log`, `stderr.log` | the real stdout and stderr of that run |
| Summary of that run | `reports/eda/evidence/run-{1,2}/eda_summary.json` | the exact machine-readable summary the run produced |
| Report of that run | `reports/eda/evidence/run-{1,2}/eda_report.md` | the exact generated report of that run |
| Comparison | `reports/eda/evidence/reproducibility_comparison.md`, `.json` | PASS/FAIL per metric and the list of differences |

The comparison walks both summaries and both evidence bundles. Only the metadata that is allowed to
differ between two runs of the same command is excluded: the run timestamp and the environment
description. The two summary artifacts have different file hashes because each artifact embeds its
own run timestamp; the deterministic content comparison is the authoritative check.

Exit codes: `0` when both runs succeeded and the deterministic content is identical, or when the raw
package is absent and the check was skipped, `1` when a run failed or the two runs disagree. A
skipped check prints `SKIPPED`, never `PASS`, and writes no artifact.

## Reproduce the train-only preprocessing pipeline

```text
python scripts/preprocess_nf_unsw_nb15_v3.py
python scripts/preprocess_nf_unsw_nb15_v3.py --check-reproducibility
python scripts/preprocess_nf_unsw_nb15_v3.py --verify-only
```

The script consumes the verified split manifest (`data/processed/nf_unsw_nb15_v3_split_manifest.json`)
and partition indices (`data/processed/splits/*.csv.gz`). It extracts the 47 baseline ML features,
fits imputers and vocabularies strictly on the Train partition (1,655,797 rows), and transforms Train,
Validation, and Test partitions with the frozen state.

Artifacts produced:
- Preprocessor binary: `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib`
- Companion manifest: `reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json`

Reproducibility properties:
- Independent dual-pass check (`--check-reproducibility`) verifies 100% parameter and numeric output identity.
- Verify-only mode (`--verify-only`) validates artifact schema, companion manifest integrity, and dataset/split checksums without retraining (fails closed if companion manifest is missing or hashes mismatch).
- Absent raw bytes: prints `PREPROCESSING: SKIPPED (raw dataset absent)` and exits `0`.

## Reproduce Random Forest baseline training (Issue #10)

```text
python scripts/train_random_forest.py --verify-only
python scripts/train_random_forest.py
python scripts/run_experiments.py --step baseline
```

The script trains the baseline Random Forest model strictly following the protocol `rf-baseline-nf-unsw-nb15-v3-v1`
locked in Issue #9:
- Uses verified raw dataset `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv` (SHA-256 `4ebb97...`).
- Reads partition indices from `data/processed/splits/` (`train`: 1,655,797 rows; `validation`: 345,371 rows).
- Reuses the existing fitted preprocessor artifact `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib` without refitting.
- Preserves the 47 baseline ML feature ordering and excludes all metadata and target columns.
- Locks canonical baseline hyperparameters in `CANONICAL_BASELINE_PARAMS` (including `n_jobs=-1`, `n_estimators=200`, `max_depth=16`, `random_state=42`, `configuration_id="rf-baseline-canonical-v1"`).
- Strict Test Lock: Enforces Contract A (no test data in fitting, tuning, selection, or reporting) and Contract B (test rows are strictly filtered at the raw line stream boundary and never materialized into DataFrames).
- Memory Architecture (Option B): `chunksize` (default 100,000) limits the raw text buffer during CSV parsing; full Train (1,655,797 rows) and Validation (345,371 rows) partitions are materialized into in-memory DataFrames as required for fitting standard scikit-learn `RandomForestClassifier`. Peak memory occurs during DataFrame concatenation and tree fitting (~4-8 GB RAM recommended).
- Produces model binary `artifacts/models/random_forest/random_forest_baseline.joblib` and execution manifest `artifacts/models/random_forest/random_forest_manifest.json` (also saved to `reports/models/random_forest_manifest.json`).
- Verifies model reload consistency using `RandomForestModel.load_verified()` with bitwise identical predictions and probability tolerance `atol=1e-7, rtol=0` (along with finite value and shape checks).
- Preprocessor companion manifest verification strictly enforces canonical `artifact_sha256` schema and `prep_audit["status"] == "PASS"`.
- `RandomForestModel.load_verified()` enforces top-level and nested provenance consistency and rejects missing or malformed hashes fail-closed.
- Experiment runner integration: `python scripts/run_experiments.py --step baseline` delegates directly to `scripts/train_random_forest.py` and forwards exit codes.
- Fail-closed prerequisite audit: If the raw dataset or preprocessor artifact is missing or altered, training stops immediately with exit code 1. Mock/synthetic data is strictly prohibited for benchmark results.

## Reproduce CSV inference on new network flows (Issue #15)

```text
python scripts/predict.py --input data/new_flows.csv --output results/predictions.csv
python scripts/predict.py --input data/new_flows.csv --output results/predictions.csv --model random_forest
```

The script executes the verified inference pipeline (Issue #15):
- Validates the 47-feature baseline schema and contract ordering without data leakage.
- Loads the verified train-only preprocessor (`artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib`) from Issue #8 (fails closed if artifact or companion manifest is missing or altered).
- Loads the trained model artifact and validates provenance.
- Executes transform and prediction without refitting.
- Emits prediction results (`results/predictions.csv`) preserving row identity, plus companion traceability metadata (`results/predictions.metadata.json`).
- When the model artifact binary is absent (e.g. if the local environment has not yet trained or restored the `.joblib` binary under `.gitignore`), the CLI reports fail-closed error with exit code `1` and does not fake execution.

See `docs/INFERENCE_PIPELINE.md` for complete contract and schema details.

## What runs where

| Check | Environment | Result |
|---|---|---|
| `scripts/validate_data.py` | local, raw package present | real-data audit, exit `1` while `ML_READY: BLOCKED` |
| `scripts/eda_nf_unsw_nb15_v3.py` | local, raw package present | EDA executed on the verified population |
| `scripts/verify_eda_reproducibility.py` | local, raw package present | two runs compared per metric |
| `scripts/split_and_audit_nf_unsw_nb15_v3.py` | local, raw package present | split manifest and leakage audit executed |
| `scripts/preprocess_nf_unsw_nb15_v3.py` | local, raw package present | train-only preprocessing executed and verified |
| `scripts/train_random_forest.py` | local, raw package & artifacts present | trains baseline RF on 1,655,797 train rows; exits `1` if raw dataset or preprocessor artifact is missing |
| `scripts/run_experiments.py --step baseline` | local, delegates to `train_random_forest.py` | fail-closed prerequisite check or baseline training |
| `scripts/predict.py` | local / production with trained artifacts | real model inference and metadata; fail-closed if model absent |
| `python -m pytest tests -q` | CI and local, synthetic fixtures | proves code behaviour only |
| `scripts/validate_data.py` in CI | CI runner without the raw CSV | `SKIPPED` |
| `scripts/eda_nf_unsw_nb15_v3.py` in CI | CI runner without the raw CSV | `SKIPPED` |
| `scripts/preprocess_nf_unsw_nb15_v3.py` in CI | CI runner without the raw CSV | `SKIPPED` |

A skipped CI step is never reported as evidence that the validator or the EDA ran on real data.

## Lint scope

| Scope | Ruff 0.17.1 | Black 26.10.1 | Tracking |
|---|---|---|---|
| Files owned by the current change set | PASS | PASS | — |
| Whole repository | 5 findings, exit `1` | 11 files, exit `1` | Issue #37 |

The repository-wide result is a FAIL while the findings remain. The Linux and CI-compatible
re-check is the manual or pull-request workflow `.github/workflows/lint-audit.yml`.

## Split and experiment identity

The official NF-UNSW-NB15-v3 chronological group-purged split (`reports/splits/nf_unsw_nb15_v3_split_manifest.json`, PR #41), train-only preprocessing contract (`reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json`, PR #42), and Random Forest baseline training run (`reports/models/random_forest_manifest.json`, `reports/models/rf_baseline_training_report.md`, Issue #10 / PR #43, model artifact SHA-256 `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`) are recorded and verified on real `NF-UNSW-NB15-v3` bytes. Held-out Test partition benchmark evaluation remains `PLANNED` under Issue #12 (`test_partition_accessed: false`, `test_rows_loaded: 0`). Every accepted model run must record:

- Git commit and dependency snapshot;
- dataset SHA-256 and split identifier;
- temporal boundaries, group rule, excluded-row ledger and row-index hashes;
- ordered feature list and trace-only metadata list;
- train-only fitted preprocessing artifact and its hash;
- model family, seed/config, artifact hash and environment;
- validation-selected threshold/hyperparameters;
- test metrics, confusion matrix, per-category errors and limitations.

Random seed `42` is the default where randomness is required. It does not replace recording the
actual seed or deterministic split algorithm.

## Leakage and transform rules

- Split/group/deduplicate before fitting preprocessing.
- Default `X` is the ordered 47-feature contract. Never put `Label`, `Attack`, IP identifiers,
  L4 ports or absolute timestamps in it.
- Fit imputer, non-finite policy, encoder, scaler, selector and resampler only on train.
- Validation selects configuration and thresholds; test is not reused for tuning.
- Enforce zero `exact_full_row_overlap`, zero `source_feature_overlap`, zero `canonical_flow_group_overlap`, and zero `temporal_boundary_violations` across partitions (`status: PASS`), with a 300,000 ms purge gap. Audited `ml_feature_overlap` across partitions (`61,007` train/val, `59,966` train/test, `24,143` val/test; `binary_label_conflicts: 0`) is recorded as `REVIEWED_AND_JUSTIFIED` and must be documented as a non-i.i.d. feature-space limitation during evaluation.
- Treat the five-minute bidirectional 5-tuple group as a documented heuristic, not a proven session.

See `docs/NF_UNSW_NB15_V3_SPLIT_PROTOCOL.md`.
The policy boundary is specified in `docs/NF_UNSW_NB15_V3_PREPROCESSING_POLICY.md`; it is not a
fitted preprocessing artifact.

## Historical snapshot boundary

UNSW-NB15 (2015) scripts, manifest and quality report are retained under `historical/`. Their old
PASS state describes different bytes/schema/split and cannot validate NF-UNSW-NB15-v3.
