# NF-UNSW-NB15-v3 numeric quality analysis

**Evidence:** verified CSV SHA-256
`4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`, streamed by
`scripts/validate_data.py`. Aggregate output is versioned in
`reports/data_quality/nf_unsw_nb15_v3_validation.json`.

## Scope and status

Source bytes, schema, row count and labels pass their integrity checks. This analysis concerns raw
numeric quality only; it does not mutate the CSV and does not make the dataset ML-ready.

Across 2,365,424 rows, exactly 122,493 unique rows contain at least one blank/non-finite/invalid
numeric token. Every affected row contains two findings; there are no single-finding rows.

| Finding | Rows |
|---|---:|
| blank `SRC_TO_DST_SECOND_BYTES` | 63,425 |
| `+Inf` `SRC_TO_DST_SECOND_BYTES` | 59,068 |
| `+Inf` `DST_TO_SRC_SECOND_BYTES` | 122,493 |
| `NaN`, `-Inf`, other invalid numeric token | 0 |

The two observed overlap patterns are mutually exclusive:

- 63,425 rows: blank source-to-destination rate plus `+Inf` destination-to-source rate;
- 59,068 rows: `+Inf` in both rate fields.

## Label and attack-category distribution

All 122,493 affected rows split into 86,704 `Label=0` and 35,789 `Label=1`. The first overlap
pattern contains 27,636 benign and 35,789 attack rows. The second contains 59,068 benign rows and
no attack rows.

Affected attack rows by `Attack`: Backdoor 1,208; DoS 930; Exploits 3,932; Fuzzers 8,228;
Generic 14,891; Reconnaissance 5,783; Shellcode 795; Worms 22. Analysis has zero affected rows.
These counts describe association with the token findings; they do not justify label-dependent
filtering or row removal.

## Duration, packet, byte and protocol associations

All affected rows have zero `FLOW_DURATION_MILLISECONDS`, `DURATION_IN` and `DURATION_OUT` in the
published CSV. All have positive `IN_PKTS` and `IN_BYTES`.

- For the 63,425 blank-source-rate rows, `OUT_PKTS` and `OUT_BYTES` are zero.
- For the 59,068 dual-`+Inf` rows, `OUT_PKTS` and `OUT_BYTES` are positive.
- The dual-`+Inf` rows use protocol 17 (54,163 rows) or protocol 6 (4,905 rows).
- The blank-source-rate group spans many protocol codes; the complete distribution remains in the
  machine-readable report rather than being collapsed to a selected subset.

The zero-duration association is exact for the observed affected rows, but neither the CSV nor the
published feature dictionary exposes the producer's arithmetic. Therefore this audit does **not**
claim that division by zero caused the infinities.

## Handling decision

The approved handling boundary is documented in
`docs/NF_UNSW_NB15_V3_PREPROCESSING_POLICY.md`: preserve raw bytes and finding types, split before
fitting, fit finite-value imputation on train only, apply frozen transforms to validation/test,
retain zero-duration rows pending impact analysis, and never replace infinity with zero silently.
No fitted preprocessing artifact or real split exists yet; `ML_READY` remains `BLOCKED`.
