# NF-UNSW-NB15-v3 duplicate and label-conflict audit

**Evidence:** verified CSV SHA-256
`4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`;
disk-backed report `reports/data_quality/nf_unsw_nb15_v3_validation.json`;
fingerprint schema `nf-unsw-nb15-v3-fingerprint-v1`.

No duplicate row was removed. Counts called “duplicate rows” are repeated occurrences after the
first occurrence of a fingerprint.

## Versioned definitions

| Name | Ordered columns | Purpose |
|---|---|---|
| Exact/full-row | all 55, including `Label` and `Attack` | identical raw-row audit and hypothetical exact-dedup impact |
| Source-feature | all 53 NetFlow fields, excluding both targets | detect the same published observation across splits even if targets differ |
| ML-feature-equivalent | the 47 baseline ML features | detect memorization risk and label/category conflicts when metadata differs |
| Behavioral-v1 | the same 47 columns, under a separate fingerprint namespace | correlation-oriented equivalence; never an automatic deduplication key |
| Canonical flow group | direction-independent IP/port endpoints + protocol + five-minute start bucket | group proxy when no authoritative session ID exists |

`split_row_fingerprint()` remains a compatibility alias for the source-feature fingerprint. The ML
and behavioral-v1 column sets are equal in schema v1, but their digests and purposes are namespaced;
a future behavioral schema must increment the version rather than silently changing meaning.

## Exact duplicates

There are 14,815 repeated exact rows across 14,815 fingerprints. Repeated rows by binary label:
14,801 benign and 14 attack. By `Attack`: Benign 14,801; Backdoor 1; DoS 9; Exploits 4; all other
categories 0.

A hypothetical keep-first exact deduplication—**not applied**—would retain 2,222,930 benign and
127,679 attack rows. Category counts would become: Analysis 1,226; Backdoor 4,658; Benign
2,222,930; DoS 5,971; Exploits 42,744; Fuzzers 33,816; Generic 19,651; Reconnaissance 17,074;
Shellcode 2,381; Worms 158.

## ML-feature equivalence and label conflicts

- 1,134,553 repeated rows across 189,788 ML-feature fingerprints.
- Binary-label conflict fingerprints: **0**; rows in such fingerprints: **0**.
- Benign-versus-attack conflict fingerprints: **0**.
- Fingerprints with multiple `Attack` values: **1,270**, covering 20,058 rows.
- All 1,270 conflicts are between multiple malicious categories; none mixes Benign with Attack.
- Analysis participates in 0 multi-category fingerprints.
- Worms participates in 2 multi-category fingerprints covering 34 rows: one
  `Backdoor | Generic | Worms` group (28 rows) and one `Exploits | Fuzzers | Worms` group
  (6 rows).

Therefore the 47-feature equivalence does not expose a binary target conflict in these bytes, but
it is not a safe multiclass deduplication key. Removing one row per fingerprint would discard
category evidence and materially alter class support. No such policy is approved.

## Split leakage status

The bounded synthetic guard now distinguishes exact, source-feature, ML-feature and canonical
group overlap. It also rejects temporal-order inversions and an unsatisfied configured purge gap.
Unit tests cover same-features/different-targets, metadata-only differences, group overlap and
boundary cases.

No real train/validation/test row-index artifact exists. Consequently cross-split exact overlap,
ML-feature-equivalent overlap, group overlap, temporal adjacency and purge-gap sufficiency are
**NOT VERIFIED** on real partitions. Label-dependent filtering is prohibited; a future split
artifact must start from all source rows, record every exclusion and assign equivalence/groups
before any label-aware sampling or preprocessing.

## Decision

Retain all source rows for now. A future split policy may keep exact duplicates grouped, or propose
keep-first exact deduplication using the impact table above, but it must be versioned and evaluated
without test feedback. Behavioral-v1 and ML-feature-equivalent rows are not automatically removed.
