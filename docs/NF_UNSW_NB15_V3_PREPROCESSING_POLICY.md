# NF-UNSW-NB15-v3 quality-handling contract

**Status:** policy `IMPLEMENTED` as a contract and validator tests; fitted preprocessing artifact
`PLANNED / NOT VERIFIED`.

## Immutable source boundary

The verified raw CSV is never rewritten. Missing and non-finite tokens remain evidence about the
published bytes. Any transformed dataset must be a derived artifact with the source manifest hash,
split identifier, policy version and fitted-transform hash.

## Fit boundary

Partition/group assignment happens before any learned preprocessing. Imputer statistics, encoder
vocabularies, scaling parameters, clipping thresholds, selectors and missingness-indicator choices
are fit using the training partition only. Validation and test receive only frozen transforms. Test
labels never select this policy or its parameters.

## Numeric missing and non-finite policy

The validator keeps these states distinct: blank/missing, `NaN`, positive infinity, negative
infinity and an invalid numeric token. A future C2 transformer must:

1. preserve separate audit counts before transformation;
2. reject invalid numeric tokens unless an explicit schema correction has been approved;
3. map missing/`NaN`/infinity to an internal missing sentinel only after split assignment;
4. fit a robust finite-value imputer (baseline: median) on training values only;
5. apply the stored training median to validation/test without recomputation;
6. evaluate optional per-column indicators using training/validation only—at minimum distinguish
   source missing from positive/negative infinity when indicators are enabled;
7. never replace all infinity values with zero silently.

This contract does not preselect final imputation values because a real split does not yet exist.

## Zero and short-duration flows

Zero-duration and `<=1 ms` flows are retained as separate observed conditions. They are not
automatically dropped and duration is not replaced merely because a throughput-like value is
infinite. The aggregate validator report records association with `FLOW_DURATION_MILLISECONDS`,
`DURATION_IN` and `DURATION_OUT`; association alone is not proof of how the publisher computed a
feature.

## Numeric-coded semantics

The baseline 47 columns are not semantically interchangeable:

- byte, packet, duration, throughput, IAT and length fields are quantitative;
- `PROTOCOL`, `L7_PROTO`, TCP flags, ICMP/DNS types and FTP return codes are numeric-coded
  categorical/bit-mask fields and must not be treated as continuous merely because CSV parsing
  yields numbers;
- encoder/scaler decisions belong to C2 and must be fit on train only.

## Outliers and row retention

No row is removed solely because it has missing/infinite values, and the 1,134,553 behavioral-
fingerprint repeats are not automatically deduplicated. The baseline does not clip/winsorize
outliers. A future transformation may propose training-derived robust scaling or quantile bounds,
but validation—not test—must justify the choice and the derived artifact must record affected row
counts.

## Acceptance gate

The dataset remains `ML_READY: BLOCKED` until a real split exists, this policy is implemented as a
train-only fitted artifact, and duplicate/group leakage audits pass for that split. Unit tests or a
synthetic fixture prove behavior only; they do not establish real-data readiness.
