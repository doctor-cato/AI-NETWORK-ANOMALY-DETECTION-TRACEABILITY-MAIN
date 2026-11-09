# Split Membership Parity & Provenance Audit Report (NF-UNSW-NB15-v3)

## 1. Summary of Equivalence Status

- **Protocol Equivalence:** `VERIFIED`
- **Artifact Byte Equivalence:** `DIFFERENT`
- **Membership Equivalence:** `NOT_VERIFIED`

## 2. Provenance Chain Comparison

| Partition | Row Count (Canonical) | Row Count (Nov Runtime) | Counts Match | Canonical Oct SHA-256 | Regenerated Nov SHA-256 |
|---|---|---|---|---|---|
| `train` | 1,655,797 | 1,655,797 | `True` | `a09ba1757484c655...` | `30ed493e2b8ecadf...` |
| `purged_train_val_gap` | 9,443 | 9,443 | `True` | `3bdf9ef3ee6f6296...` | `94d4eb9de7eeed87...` |
| `validation` | 345,371 | 345,371 | `True` | `7d41a71a2a154a46...` | `a3e4470c2731870d...` |
| `purged_val_test_gap` | 8,860 | 8,860 | `True` | `ac7f1de36b7bf1e2...` | `244f4831907dda7e...` |
| `test` | 345,953 | 345,953 | `True` | `63e2e081300955fe...` | `90219f75a680705f...` |

## 3. Analysis & Root Cause of Hash Divergence

Gzip byte determinism differs between OS environments and Python builds (Ubuntu 3.12 vs Windows 3.13) due to zlib compression implementation details, even when uncompressed row indices are deterministic.

> [!IMPORTANT]
> **Membership Equivalence Assessment:** `NOT_VERIFIED`.
> Canonical Oct index files (.csv.gz) are excluded by .gitignore and not tracked in Git. While protocol equivalence (dataset SHA, seed, partition row counts, time boundaries, and attack category counts) is VERIFIED, bitwise membership equivalence cannot be proven without raw canonical row index sequences.

## 4. Test Partition Isolation

- `test_partition_accessed`: `False`
- `test_rows_loaded`: `0`
- `test_indices_loaded`: `False`
- Evaluation on held-out Test partition is strictly reserved for Issue #12 one-shot.

## 5. Model Comparison Impact

Comparisons between Random Forest (trained under canonical Oct split reference) and XGBoost (trained under regenerated Nov runtime split) constitute **same-protocol, same-data-definition comparisons**, not byte-identical artifact comparisons. All metric tables must explicitly declare this distinction.