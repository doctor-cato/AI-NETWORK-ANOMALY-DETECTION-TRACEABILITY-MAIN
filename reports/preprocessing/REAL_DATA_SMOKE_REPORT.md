# NF-UNSW-NB15-v3 Real-Data Preprocessing Smoke Evidence Report

**Status:** `PASS`
**Date:** 2026-10-28
**Scope:** Issue #8 — Train-Only Preprocessing Pipeline
**Dataset Readiness:** `ML_READY: BLOCKED` (model training unauthorized until Issue #9+)

---

## 1. Provenance and Input Artifacts

| Item | Value |
|---|---|
| Raw Dataset Path | `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv` |
| Raw Dataset Size | 577,360,958 bytes (2,365,424 rows) |
| Raw Dataset SHA-256 | `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5` |
| Split Protocol Version | `nf-unsw-nb15-v3-chronological-group-purged-v1` |
| Split Manifest Path | `data/processed/nf_unsw_nb15_v3_split_manifest.json` |
| Split Manifest SHA-256 | `69b1df1649f807eaecff29b9f3032d1645e9f8541a0dbfc41cf1a5806c55d0a6` |
| Partition Indices Dir | `data/processed/splits` |
| Preprocessing Policy Version | `v1-fit-train-only-median-mode` |
| Feature Contract Version | `v1-baseline-47-features` |

---

## 2. Generated Preprocessing Artifacts

| Artifact | Path | SHA-256 |
|---|---|---|
| Fitted Preprocessor Joblib | `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib` | `1de9448b3dc66bc9860ddf159f3f2b74f0ce667cea4e11265a29e8708a3d6611` |
| Companion Manifest JSON | `reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json` | Verified schema and hashes |

---

## 3. Partition Transformation Evidence

All partitions strictly adhere to the train-only preprocessing boundary. Statistics (finite medians and modes) are fit strictly on the Training partition and applied frozen to Validation and Test.

| Partition | Input Rows | Output Matrix Shape | Finite Status | Zero Duration Retained |
|---|---|---|---|---|
| Train | 1,655,797 | `(1655797, 47)` | 100% Finite (`True`) | Yes (exact duration preserved) |
| Validation | 345,371 | `(345371, 47)` | 100% Finite (`True`) | Yes (exact duration preserved) |
| Test | 345,953 | `(345953, 47)` | 100% Finite (`True`) | Yes (exact duration preserved) |
| Purged Gaps | 18,303 | N/A (held out) | N/A | Excluded from training/val/test |
| **Total** | **2,365,424** | — | — | — |

- **Exact Schema:** exactly 47 baseline ML features in contract order (`QUANTITATIVE_ML_COLUMNS` [37] + `CATEGORICAL_CODED_COLUMNS` [10]).
- **No Data Leakage:** zero test or validation observations contribute to imputer statistics or scalers.
- **No Silent Zeroing:** non-finite throughput tokens imputed with training-derived finite medians; zero-duration rows retained.

---

## 4. Execution and Verification Evidence

### 4.1. Real-Data Pipeline Fit and Transform

```bash
python scripts/preprocess_nf_unsw_nb15_v3.py
```

**Output:**
```
[preprocess] Loading and fitting train-only preprocessor on NF-UNSW-NB15-v3...
[preprocess] Success in 21.20s:
  Train shape:      (1655797, 47) (finite: True)
  Validation shape: (345371, 47) (finite: True)
  Test shape:       (345953, 47) (finite: True)
  Features count:   47 in exact contract order
  Scaler type:      none
  Artifact saved:   artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib (SHA-256: 1de9448b3dc66bc9860ddf159f3f2b74f0ce667cea4e11265a29e8708a3d6611)
  Manifest saved:   reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json
```
**Result:** `PASS` (21.20s execution time).

### 4.2. Fail-Closed Artifact and Raw Dataset Byte Verification

```bash
python scripts/preprocess_nf_unsw_nb15_v3.py --verify-only
```

**Output:**
```
[preprocess] Verifying existing preprocessor artifact: artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib...
[preprocess] PASS: artifact integrity and schema verified.
```
**Result:** `PASS` (Raw 577MB CSV SHA-256, companion manifest schema, and artifact bytes match without loading joblib).

### 4.3. Deterministic Dual-Pass Reproducibility Verification

```bash
python scripts/preprocess_nf_unsw_nb15_v3.py --check-reproducibility
```

**Output:**
```
[preprocess] ========================================================
[preprocess] Running independent dual-pass preprocessor reproducibility check...
[preprocess] ========================================================
[preprocess] Pass 1: fitting preprocessor...
[preprocess] Pass 2: fitting preprocessor independently...
[preprocess] PASS: preprocessor reproducibility verified (100% parameter and output identity)
```
**Result:** `PASS` (exact bitwise parameter match and zero matrix difference across two independent executions).

---

## 5. Traceability and Conclusion

- Requirement: C2 (Preprocessing không leakage)
- Issue: #8
- Gate: `IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED`
- Model Readiness: `ML_READY: BLOCKED` until supervised model experiment issue is authorized.
