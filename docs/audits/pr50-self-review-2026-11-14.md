# PR #50 — Self-review findings

- Audit date: 2026-11-14
- PR: https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/pull/50
- Base: `97456893f5c9f3f53755dd943b63169f5222ca10` (`origin/main`)
- Head: `4977f12ea1598b35864ade8ab55e9b04d3399766`
- Scope: 46 changed files, +6,445 / −746 lines, compared with `origin/main...HEAD`.
- Mode: self-review of the implementation by the same reviewer; not an independent review. No source, PR, issue, or milestone changes were made during the audit.
- Verdict: **CHANGES REQUIRED**. CI is green, but findings F1–F4 affect inference safety, experiment isolation, or API readiness.

## Findings

### F1 — BLOCKER — Isolation Forest verified loader can be bypassed by an inconsistent manifest

- Issue/AC: #53 fail-closed deserialization; #54 calibrated threshold and binary label invariant.
- Location: `src/network_anomaly/inference/predict.py:378-405`.
- Condition: A valid Isolation Forest payload and its byte hash remain unchanged, while the companion manifest's `model_type` is changed to `RandomForestClassifier`. The manifest is used to choose the loader, but its model type is not checked against the deserialized payload.
- Observed synthetic reproducer: `load_verified_model()` returned a raw `sklearn.ensemble.IsolationForest` with manifest type `RandomForestClassifier`; `predict()` returned labels `[-1, 1]`.
- Impact: The IF wrapper's stored threshold and 0/1 mapping are skipped. A mismatched manifest can produce incorrect predictions or fail API inference after health reported the artifact loaded.
- Required change: Verify payload model type against the manifest and enforce the model-specific verified loader based on a validated payload contract. Reject conflicting types before exposing a predictor.
- Evidence: Read-only synthetic artifact/manifest reproduction during this audit; output: `IsolationForest RandomForestClassifier [-1, 1]`.

### F2 — HIGH — Cross-dataset ablations can fit on Validation

- Issue/AC: #57 zero Train/Validation contamination.
- Location: `scripts/run_cross_dataset_experiments.py:140-180`; misleading provenance at lines 292, 327, 380, and 460.
- Condition: `unsw_train_csv` is only required to exist. Passing the same file as `unsw_val_csv` satisfies this condition. The runner then calls `prep_unsw.fit()` and E1/E2/E5 `fit()` on Validation data before evaluating those models on Validation.
- Impact: In-domain ablation metrics can be optimistically biased while output claims a Train partition. Several `train_provenance` fields also record `unsw_val_csv.name` instead of the actual Train file.
- Required change: Verify the Train sample's source/content binding and index membership against canonical Train indices; reject any overlap with Validation; record the actual Train file and hashes.
- Evidence: Direct caller/data-flow review. No real-data experiment was run in this audit.

### F3 — HIGH — E0 sample membership is based on self-reported offset

- Issue/AC: #57 zero overlap of E0 in-domain rows with canonical Train.
- Location: `scripts/fetch_external_dataset.py:224-250`; `tests/unit/test_cross_dataset_isolation.py:59-76`.
- Condition: The verifier hashes a sample and reads its offset/count from a companion manifest, then checks whether the *declared* offset falls in Validation indices. It never compares the sample's rows with the canonical source CSV or a trusted source-row digest.
- Observed test evidence: The existing synthetic test passes an arbitrary `Label\n0\n1\n` CSV with a manifest declaring Validation offset 5. The sample is accepted without access to a source CSV.
- Impact: A mislabeled, replaced, or manually edited sample can be accepted as a Validation holdout. E0's no-Train-overlap claim is not established for actual sample content.
- Required change: Bind sample rows to a canonical raw source checksum and source row content/identifiers, then verify those rows before E0 evaluation.

### F4 — HIGH — Health can be healthy while default analysis returns 503

- Issue/AC: #59 truthful health and verified API readiness.
- Location: `src/network_anomaly/api/service.py:85-97, 263-296`.
- Condition: `check_health()` accepts the first successfully loaded model. If only Isolation Forest loads, it reports `healthy`, but the default `/api/v1/analyze` requests Random Forest and fails.
- Observed synthetic reproducer: Mocked IF as loadable and RF as missing; output was `health healthy True` followed by `default_analysis 503`.
- Impact: Monitoring reports readiness for the default route even when that route cannot serve verified inference.
- Required change: Make health readiness reflect the default required model or report per-model readiness and mark default analysis unavailable.

### F5 — MEDIUM — Single-label confusion matrix conflicts with returned counts

- Issue/AC: #12 metric contract and traceable confusion matrix.
- Location: `src/network_anomaly/evaluation/metrics.py:143-175, 200-253`.
- Condition: `labels=[1]` or `labels=[0]` is accepted when both classes occur in `y_true/y_pred`. `sklearn.confusion_matrix` drops the other class, while the function calculates TN/FP/FN/TP from all rows.
- Observed synthetic reproducer: `compute_metrics([0,1], [1,1], labels=[1])` returned matrix `[[1]]` and counts `{tn:0, fp:1, fn:0, tp:1}`; matrix sum 1, count sum 2.
- Impact: Consumers can persist a confusion matrix that contradicts the reported sample count and FPR.
- Required change: Return a consistent canonical 2×2 matrix for binary data or reject a one-label request when the other class appears.

### F6 — MEDIUM — API repeatedly deserializes artifacts

- Issue/AC: #59 API operational readiness.
- Location: `src/network_anomaly/api/service.py:85-88, 263-280, 367-375`.
- Condition: Every health check loads verified artifacts; every analysis call invokes health and then loads them again for prediction.
- Impact: Repeated disk reads and deserialization can increase latency and memory pressure for large model artifacts. No load benchmark was run, so magnitude is **NOT VERIFIED**.
- Suggested change: Cache a verified pipeline per artifact identity with explicit invalidation, and avoid a second load within one request.

## Acceptance-criteria traceability

| Scope | Requirements → implementation/tests → verification | Status |
| --- | --- | --- |
| #12/#13 | Held-out Test run `rf-heldout-ea330b9`; stored predictions, metrics, confusion matrix, metadata and FP/FN report; external original-output hashes match committed summary on this machine. Independent model probability rerun was not performed. | **PASS** for stored evidence consistency; independent inference **NOT VERIFIED**. |
| #53/#54 | Manifest/hash checks, IF wrapper and synthetic parity tests exist. F1 bypasses the wrapper when manifest type conflicts with payload. | **FAIL** fail-closed/model-label AC in the F1 case. |
| #55 | RF script compares runtime artifact with companion digest instead of a hardcoded digest. Current local tracked November manifests do not form the historical October artifact chain. | Implementation **TESTED**; current-asset `--verify-only` **NOT VERIFIED** in this audit. |
| #56 | Required `index_sha256`, three-index disjointness checks and evidence-driven reports are present. Historical stored run checksums matched local files. | **PASS** for inspected code/stored evidence; original model inference not rerun. |
| #57 | Validation sample and E0 labels are guarded, but F2/F3 permit unproved or contaminated source membership. E0/E4 real results are absent from the PR. | **FAIL** isolation AC; real experiments **NOT VERIFIED**. |
| #58 | Pipeline and CLI can activate `InferenceEligibilityGate`; PR #47 remains draft/conflicting. | **PARTIAL**; rebase AC **NOT MET**. |
| #59 | Verified API loading and default fail-closed behavior are tested, but F4 gives a false healthy state. PR #52 remains draft/conflicting. | **FAIL** health AC in the F4 case. |
| #37/#60 | Ruff/Black checks pass; dedicated lint PR and master-issue completion conditions are outstanding. | **PARTIAL / NOT MET**. |

## Verification evidence and limits

- **PASS**: GitHub checks at `4977f12`: audit, lint, Ubuntu/Windows tests on Python 3.11/3.12 (6/6).
- **PASS**: `python -m pytest tests/unit/test_cross_dataset_isolation.py tests/unit/test_inference_pipeline.py tests/unit/test_isolation_forest_parity.py tests/unit/test_api_service.py -q` → 66 passed.
- **PASS**: `python scripts/check_environment.py`; `python -m ruff check .`; `python -m black --check .` (121 files); `git diff --check origin/main...HEAD`; working tree clean.
- **PASS**: SHA-256 of the five local original run outputs (`predictions.csv`, `metrics.json`, `evaluation_metadata.json`, `confusion_matrix.csv`, PNG) matches `verified_summary.json`. Historical Train/Validation/Test index and preprocessor/model artifact hashes also matched their historical manifests in this audit.
- **NOT VERIFIED**: Full local suite at current HEAD, independent probability reproduction, E0/E4 real runs, artifact-load performance, and independent reviewer acceptance. The review state on GitHub is `CHANGES_REQUESTED`.
- No dataset download, training, new model evaluation, source edit, stage, commit, push, or GitHub write was performed as part of this audit.