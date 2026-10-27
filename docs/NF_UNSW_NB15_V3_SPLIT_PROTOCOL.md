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

## Proposed deterministic split

1. Start only from a package that passes `scripts/dataset_manifest.py verify` and a quality report
   whose blocking findings have an approved handling policy.
2. Attach the source-row identifier and preserve the two targets plus trace metadata outside `X`.
3. Form a direction-independent group from source/destination IP and port, protocol, and a
   five-minute start-time bucket. Because the dataset has no trusted session identifier, this is a
   heuristic rather than proof of session separation.
4. Compute the versioned exact, source-feature, ML-feature, behavioral-v1 and canonical-group keys
   before assigning partitions. Do not automatically remove behavioral/ML-equivalent rows. If a
   future policy applies exact keep-first deduplication, record every excluded source row and the
   class-distribution impact; otherwise assign each equivalence/group wholly to one partition.
5. Order groups by their earliest `FLOW_START_MILLISECONDS`, with stable fingerprint tie-breaking.
   Assign whole groups approximately 70%/15%/15% to train/validation/test. Record actual temporal
   boundaries and class/category distributions; proportions are targets, not guarantees.
6. Fail the build if an exact, source-feature or ML-feature fingerprint, or a canonical group,
   occurs in more than one partition. Reject temporal-order inversions. Review boundary-adjacent
   flows and use a documented purge gap if the group heuristic still creates adjacency risk.
7. Fit imputer, finite-value replacement, scaler, encoder, feature selector and resampling only on
   train. Apply frozen transforms to validation and test. Fit supervised and unsupervised models
   only after the transform artifact records its train split identifier.
8. Use validation for hyperparameters and thresholds. Open test once for final reporting; never
   feed test metrics back into feature, threshold or policy choices.

## Required split artifact

The future split manifest must record dataset SHA-256, algorithm/version, seed (use `42` where a
stable tie-break requires one), group rule, duplicate policy, temporal boundaries, row/group
counts, binary and attack-category distributions, excluded-row ledger, feature list and hashes of
the three row-index files. Changing any of these fields creates a new split identifier.

## Current limitations and gate

- Real validation found missing and positive-infinity values in throughput-like fields. The
  handling rule must be selected on train only and tested before a real split is accepted.
- Exact full-row, source-feature, canonical flow-group, and temporal boundary overlaps are 0 (zero)
  across all partitions.
- ML-feature duplicate patterns affect 53.21% of Test samples and 49.98% of Validation samples
  relative to Train. These represent recurring standard network protocol patterns (TCP handshake,
  DNS queries) across different hosts and dates. Zero binary-label conflicts exist.
- Crucial evaluation limitation: zero binary-label conflicts does not mean duplicate patterns have
  no effect. Test samples sharing feature vectors with Train are not purely independent in feature
  space, and model evaluation may reflect pattern memorization rather than generalization to
  novel traffic. Impact must be evaluated during model training in future issues.
- Artifact generation is verified to be 100% byte-for-byte deterministic on disk using fixed
  gzip timestamp (`mtime=0.0`) and independent dual-pass verification (`--check-reproducibility`).
- A five-minute bidirectional 5-tuple group is only a proxy for a session; no trustworthy session
  ID is available in the verified schema.
- The source period is January-February 2015 even though the v3 release is from 2025. Temporal
  holdout tests chronology within this capture; it does not demonstrate contemporary traffic
  generalization.

The deterministic split with 5-minute canonical group purge gap is **IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED** (Audit status: PASS). Full leakage audit report is recorded in `docs/dataset/NF_UNSW_NB15_V3_LEAKAGE_AUDIT.md` and `reports/splits/nf_unsw_nb15_v3_leakage_audit_report.md`. Model training remains blocked pending train-only fitted preprocessing in Issue #8 (`ML_READY: BLOCKED`).
