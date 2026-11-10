# Split Membership Parity & Provenance Audit Report (NF-UNSW-NB15-v3)

## 1. Summary of Equivalence Status

- **Protocol Equivalence:** `VERIFIED`
- **Artifact Byte Equivalence:** `DIFFERENT`
- **Membership Equivalence:** `NOT_VERIFIED`

## 2. Provenance Chain Comparison

| Partition | Row Count (Canonical) | Row Count (Nov Runtime) | Counts Match | Canonical Oct SHA-256 | Regenerated Nov SHA-256 | Byte Match |
|---|---|---|---|---|---|---|
| `train` | 1,655,797 | 1,655,797 | `True` | `a09ba1757484c655...` | `30ed493e2b8ecadf...` | `False` |
| `purged_train_val_gap` | 9,443 | 9,443 | `True` | `3bdf9ef3ee6f6296...` | `94d4eb9de7eeed87...` | `False` |
| `validation` | 345,371 | 345,371 | `True` | `7d41a71a2a154a46...` | `a3e4470c2731870d...` | `False` |
| `purged_val_test_gap` | 8,860 | 8,860 | `True` | `ac7f1de36b7bf1e2...` | `244f4831907dda7e...` | `False` |
| `test` | 345,953 | 345,953 | `True` | `63e2e081300955fe...` | `90219f75a680705f...` | `False` |

## 3. Analysis & Evidentiary Limitations of Hash Divergence

- **Hypothesis Status:** `UNPROVEN_HYPOTHESIS`
- **Hypothesis:** Compression implementation differences (e.g., zlib version, OS gzip header timestamps, or deflate implementation details between Linux Ubuntu and Windows) have been proposed as a plausible hypothesis for divergent archive SHA-256 hashes.
- **Empirical Limitation:** Because original October compressed index files are absent from Git, this hypothesis has NOT been empirically proven. The root cause of archive hash divergence remains unverified.

> [!IMPORTANT]
> **Membership Equivalence Assessment:** `NOT_VERIFIED`.
> Canonical October compressed index files (.csv.gz) were excluded by .gitignore and are absent from Git. While Protocol Equivalence is VERIFIED across dataset identity, split policy, temporal boundaries, purge gaps, label distributions, and attack categories, exact row-by-row index identity and ordering cannot be proven without raw canonical index artifacts. Matching row counts and distributions do NOT constitute proof of membership equivalence.

## 4. Test Partition Isolation

### 4.1 Declared Policy Contract
- `test_partition_accessed`: `False`
- `test_rows_loaded`: `0`
- `test_indices_loaded`: `False`
- Policy: Contractual requirement: Test partition row indices and data must remain strictly isolated and never accessed during training, tuning, or validation.

### 4.2 Measured Runtime Evidence
- **Runtime Evidence Status:** `VERIFIED_FROM_RUN_MANIFEST`
- **Training Run ID:** `xgb-baseline-1794151507`
- **Recorded test_partition_accessed:** `False`
- **Recorded test_rows_loaded:** `0`
- **Recorded test_indices_loaded:** `False`

## 5. Model Comparison Impact

Comparisons between Random Forest (trained under canonical Oct split reference) and XGBoost (trained under regenerated Nov runtime split) constitute **same-protocol, same-data-definition comparisons**, not byte-identical artifact comparisons. All metric tables must explicitly declare this distinction.
