# NF-UNSW-NB15-v3 split and leakage protocol

**Status:** IMPLEMENTED contract and TESTED safeguards; real train/validation/test split **NOT
VERIFIED**. The raw quality audit currently fails, so this document does not authorize model
training.

## Purpose

NF-UNSW-NB15-v3 is one CSV and does not inherit the published train/test files of UNSW-NB15
(2015). A new split must be produced from the verified v3 bytes. The test partition is held out
from feature selection, imputation policy selection, threshold selection and hyperparameter
tuning.

## Column roles

- Targets: `Label` for binary evaluation and `Attack` for stratified reporting. Neither enters
  `X`.
- Trace metadata: `FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`, `IPV4_SRC_ADDR` and
  `IPV4_DST_ADDR`. They remain available to Trace Engine correlation but are excluded from the
  default ML matrix.
- Candidate ML input: the other 49 ordered NetFlow v3 fields, including ports, protocol, traffic
  counters, duration, throughput and IAT fields.
- API, authentication and application-session events are separate sources. This dataset does not
  supply them.

The executable column contract is
`src/network_anomaly/data/nf_unsw_nb15_v3.py`. It fails closed when a target, absolute timestamp,
IP identifier, unknown field or ordering mismatch is supplied.

## Proposed deterministic split

1. Start only from a package that passes `scripts/dataset_manifest.py verify` and a quality report
   whose blocking findings have an approved handling policy.
2. Attach the source-row identifier and preserve the two targets plus trace metadata outside `X`.
3. Form a direction-independent group from source/destination IP and port, protocol, and a
   five-minute start-time bucket. Because the dataset has no trusted session identifier, this is a
   heuristic rather than proof of session separation.
4. Consolidate exact duplicates and the documented behavior-equivalent fingerprints before
   assigning partitions. Keep the earliest observation as the canonical observation and record
   every excluded row; do not silently drop it.
5. Order groups by their earliest `FLOW_START_MILLISECONDS`, with stable fingerprint tie-breaking.
   Assign whole groups approximately 70%/15%/15% to train/validation/test. Record actual temporal
   boundaries and class/category distributions; proportions are targets, not guarantees.
6. Fail the build if an exact fingerprint or group identifier occurs in more than one partition.
   Review boundary-adjacent flows and use a documented purge gap if the group heuristic still
   creates temporal adjacency risk.
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
- Exact and behavior-equivalent duplicates are present. The impact of consolidation on rare
  attack categories must be reported.
- A five-minute bidirectional 5-tuple group is only a proxy for a session; no trustworthy session
  ID is available in the verified schema.
- The source period is January-February 2015 even though the v3 release is from 2025. Temporal
  holdout tests chronology within this capture; it does not demonstrate contemporary traffic
  generalization.

Therefore the split is **PLANNED / NOT VERIFIED**, while feature exclusion and bounded overlap
guards are **IMPLEMENTED / TESTED** using synthetic fixtures only.
