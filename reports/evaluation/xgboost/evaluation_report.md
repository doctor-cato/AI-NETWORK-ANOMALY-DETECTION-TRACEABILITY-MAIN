# XGBoost Held-Out Test Evaluation Report (Issue #31 / C3)

- **Run ID:** `xgb-baseline-1794755807`
- **Evaluated at (UTC):** `2026-11-15T15:16:52.950502+00:00`
- **Decision threshold:** `0.5` (canonical fixed 0.5; zero test tuning)
- **Model SHA-256:** `3098b75acdd79c39605d724880f8f2ed48af6d68a0651292e27804b42a1f493e`
- **Test Indices SHA-256:** `63e2e081300955fe06835b0cf7405e07e53985ca3d84164e768be09116269d03`
- **Rows evaluated:** 345,953

## Metrics Summary
| Metric | Value |
|---|---|
| Accuracy | 0.999997 |
| Precision | 0.999967 |
| Recall | 1.000000 |
| F1-Score | 0.999984 |
| Macro-F1 | 0.999991 |
| FPR | 0.000003 |
| ROC-AUC | 1.000000 |
| PR-AUC | 1.000000 |

## Confusion Matrix (label order [0=Benign, 1=Attack])
- TN=315,356, FP=1, FN=0, TP=30,596

## Per-Category Breakdown
| Category | Total | Detected / True Neg | Missed / False Pos | Rate |
|---|---:|---:|---:|---:|
| Analysis | 294 | TP=294 | FN=0 | DR=1.000000 |
| Backdoor | 1,260 | TP=1,260 | FN=0 | DR=1.000000 |
| Benign | 315,357 | TN=315,356 | FP=1 | FPR=0.000003 |
| DoS | 1,193 | TP=1,193 | FN=0 | DR=1.000000 |
| Exploits | 10,520 | TP=10,520 | FN=0 | DR=1.000000 |
| Fuzzers | 7,322 | TP=7,322 | FN=0 | DR=1.000000 |
| Generic | 5,111 | TP=5,111 | FN=0 | DR=1.000000 |
| Reconnaissance | 4,464 | TP=4,464 | FN=0 | DR=1.000000 |
| Shellcode | 396 | TP=396 | FN=0 | DR=1.000000 |
| Worms | 36 | TP=36 | FN=0 | DR=1.000000 |
