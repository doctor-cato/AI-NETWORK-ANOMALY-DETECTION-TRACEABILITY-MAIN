# NF-UNSW-NB15-v3 split and leakage protocol

**Status:** IMPLEMENTED, TESTED, and EXPERIMENTALLY VALIDATED on verified NF-UNSW-NB15-v3 bytes (SHA-256 `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`).
Cross-partition leakage audit status is **PASS**; split manifest generated at `reports/splits/nf_unsw_nb15_v3_split_manifest.json` and `data/processed/nf_unsw_nb15_v3_split_manifest.json`.
Issue #7 is complete; Issue #8 consumes this verified train/val/test split.

## Purpose

NF-UNSW-NB15-v3 is one CSV and does not inherit the published train/test files of UNSW-NB15
(2015). A new split must be produced from the verified v3 bytes. The test partition is held out
from feature selection, imputation policy selection, threshold selection and hyperparameter
tuning.

## Column roles

- Targets: `Label` for binary evaluation and `Attack` for stratified reporting. Neither enters
  `X`.
- Trace/grouping metadata: `FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`,
  `IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, `L4_SRC_PORT` and `L4_DST_PORT`. They remain available to
  flow grouping and Trace Engine correlation but are excluded from the default ML matrix.
- Baseline ML input: the other 47 ordered NetFlow v3 fields: protocol/application-protocol,
  traffic counters, flags, duration, throughput and IAT fields.
- A port-augmented 49-feature configuration is reserved for a future controlled experiment. It is
  not the default contract and has not been implemented or evaluated in this migration.
- API, authentication and application-session events are separate sources. This dataset does not
  supply them.

The executable column contract is
`src/network_anomaly/data/nf_unsw_nb15_v3.py`. It fails closed when a target, trace/grouping
metadata field, unknown field or ordering mismatch is supplied.

## Implemented deterministic split protocol

1. **Verified source baseline:** Start only from a package that passes `scripts/dataset_manifest.py verify` (SHA-256 `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`).
2. **Column preservation:** Attach the 0-based source-row index as the stable record identifier; exclude targets (`Label`, `Attack`) and trace metadata (`FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`, `IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, `L4_SRC_PORT`, `L4_DST_PORT`) from the default 47-feature ML matrix `X`.
3. **Chronological partition assignment with Purge Gap:**
   - Order all observations chronologically by `FLOW_START_MILLISECONDS` ascending, with source row index as a stable tie-breaker.
   - Establish initial cutpoints at approximately 70% Train, 15% Validation, and 15% Test.
   - Enforce a **5-minute (300,000 ms) Purge Gap** at the Train-to-Validation boundary and Validation-to-Test boundary. Records falling within these gaps are assigned to explicit purged partitions (`purged_train_val_gap` and `purged_val_test_gap`), guaranteeing full traceability (0 records dropped silently).
4. **Canonical flow-group protection:**
   - Construct bidirectional 5-tuples: `(min(IP), max(IP), min(Port), max(Port), Protocol)` within 5-minute time buckets (`FLOW_START_MILLISECONDS // 300_000`).
   - The 300,000 ms purge gap strictly isolates canonical flow groups: no flow group spans across partitions (0 canonical flow-group overlap).
   - *Limitation note:* Canonical flow groups are a heuristic proxy for sessions; NetFlow v3 contains no raw packet payload or TCP sequence tracking. Complex multi-connection application sessions or sessions spanning across buckets remain an inherent limitation of NetFlow datasets.
5. **Temporal end boundary protection (`FLOW_END_MILLISECONDS`):**
   - The maximum flow duration in NF-UNSW-NB15-v3 is 120,948 ms (2.02 minutes), which is strictly less than the 300,000 ms (5-minute) purge gap.
   - Empirical audit confirms that 0 flows originating in Train extend into the Validation time window (margin of 236,165 ms) and 0 flows from Validation extend into Test (margin of 252,058 ms).
6. **Leakage audit and gate conditions:**
   - **Hard Build Failures (Strict Zero Overlap required):**
     - Exact full-row overlap (`ALL_COLUMNS`) > 0.
     - Source-feature overlap (`SOURCE_FEATURE_COLUMNS`) > 0.
     - Canonical flow-group overlap > 0.
     - Temporal ordering violations (`FLOW_START_MILLISECONDS` inversions) > 0.
     - Flow end boundary crossing (`FLOW_END_MILLISECONDS >= later_partition_min_start`) > 0.
     - Binary label conflicts in ML overlap (`Label=0` in one partition and `Label=1` in another for the same 47-feature vector) > 0.
     - Byte-level artifact reproducibility mismatch across independent runs.
   - **Reviewed and Justified Conditions (Retained in data with documented rationale):**
     - ML-feature overlap across partitions: approximately 53.21% of Test samples and 49.98% of Validation samples share ML feature vectors with Train. These represent recurring standardized protocol templates (TCP SYN probes, DNS queries, FIN-ACK teardowns) occurring between different IP endpoints and at different times without payload.
     - Multiclass attack category variations (different attack categories exhibiting identical coarse NetFlow traffic counters).
     - *Evaluation limitation:* Zero binary-label conflicts does NOT imply that repeated ML feature vectors are harmless. Evaluation samples sharing feature vectors with Train are non-i.i.d. in feature space; model evaluation on Test may reflect memorization of recurring traffic profiles rather than generalization to novel traffic. Impact must be evaluated during model training in subsequent issues (Issue #8+).
7. **Downstream pipeline gate:**
   - Preprocessing transformers (imputer, scaler, one-hot encoder, feature selector) must fit EXCLUSIVELY on Train (`train_indices`).
   - Model training remains locked at `ML_READY: BLOCKED` until Issue #8 completes and verifies train-only preprocessing.

## Required split artifact

The future split manifest must record dataset SHA-256, algorithm/version, seed (use `42` where a
stable tie-break requires one), group rule, duplicate policy, temporal boundaries, row/group
counts, binary and attack-category distributions, excluded-row ledger, feature list and hashes of
the three row-index files. Changing any of these fields creates a new split identifier.

## Current limitations and gate

- Real validation found missing and positive-infinity values in throughput-like fields. The
  handling rule must be selected on train only and tested before a real split is accepted.
- Exact full-row, source-feature, canonical flow-group, and temporal boundary overlaps are 0 (zero)
  across all partitions. FLOW_END temporal boundary crossings into subsequent partitions are 0 (zero).
- ML-feature duplicate patterns affect 53.21% of Test samples and 49.98% of Validation samples
  relative to Train. These represent recurring standard network protocol patterns (TCP handshake,
  DNS queries) across different hosts and dates. Zero binary-label conflicts exist.
- Crucial evaluation limitation: zero binary-label conflicts does not mean duplicate patterns have
  no effect. Test samples sharing feature vectors with Train are not purely independent in feature
  space, and model evaluation may reflect pattern memorization rather than generalization to
  novel traffic. Impact must be evaluated during model training in future issues.
- Artifact generation is verified to be 100% byte-for-byte deterministic on disk using fixed
  gzip timestamp (`mtime=0.0`) and independent dual-pass verification (`--check-reproducibility`).
  The verification strictly compares all 10 generated artifacts on disk:
  1. `data/processed/splits/train_indices.csv.gz`
  2. `data/processed/splits/purged_train_val_gap_indices.csv.gz`
  3. `data/processed/splits/validation_indices.csv.gz`
  4. `data/processed/splits/purged_val_test_gap_indices.csv.gz`
  5. `data/processed/splits/test_indices.csv.gz`
  6. `data/processed/nf_unsw_nb15_v3_split_manifest.json` (primary manifest)
  7. `data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json` (root manifest)
  8. `reports/splits/nf_unsw_nb15_v3_split_manifest.json` (secondary manifest)
  9. `reports/splits/nf_unsw_nb15_v3_leakage_audit_report.md` (reports audit report)
  10. `docs/dataset/NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md` (docs audit report)
  A fixed ISO timestamp is passed during reproducibility checks so that all JSON manifests and
  Markdown reports achieve byte-identical SHA-256 hashes without variable metadata drift. If any
  artifact is missing or any hash differs, verification fails with exit code 2 and diagnostic logs.
- A five-minute bidirectional 5-tuple group is a heuristic proxy for flow sessions; NetFlow v3 contains
  no raw packet payload or TCP sequence tracking. 0 group overlap confirms isolation of groups under
  this definition, but does not guarantee complete elimination of all real-world session leakage (e.g.
  sessions spanning across buckets or complex multi-flow application relations).
- The source period is January-February 2015 even though the v3 release is from 2025. Temporal
  holdout tests chronology within this capture; it does not demonstrate contemporary traffic
  generalization.

The deterministic split with 5-minute canonical group purge gap is **IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED** (Audit status: PASS). Full leakage audit report is recorded in `docs/dataset/NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md` and `reports/splits/nf_unsw_nb15_v3_leakage_audit_report.md`. Model training remains blocked pending train-only fitted preprocessing in Issue #8 (`ML_READY: BLOCKED`).
