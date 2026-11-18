# RQ4 — Unknown Attack Family Holdout Evaluation (Empirical AIT-NDS-v2)

- **Status:** `COMPLETED`
- **Timestamp (UTC):** `2026-11-18T02:16:57.724063+00:00`
- **Held-out Families:** `Exploitation_And_C2, Post_Exploitation_Discovery` (0 rows in Train & Validation)
- **Dataset:** `AIT-NetFlow-v2-Suite` (`cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf`)
- **Test Counts:** Benign=`812,980`, Known Attack=`175,781`, Unknown Holdout=`44`

| Model | Paradigm | Known Recall | Holdout Recall | Delta | Holdout Precision | Holdout F1 | Benign FPR |
|---|---|---:|---:|---:|---:|---:|---:|
| random_forest | Supervised Decision Forest (Holdout-Trained) | 0.9973 | 0.9091 | -8.84% | 0.1212 | 0.2139 | 0.0004 |
| xgboost | Gradient Boosted Trees (Holdout-Trained) | 0.8216 | 0.7500 | -8.71% | 0.1304 | 0.2222 | 0.0003 |
| isolation_forest | Unsupervised Isolation Forest (Benign-Only) | 0.4677 | 0.9091 | +94.36% | 0.0017 | 0.0034 | 0.0290 |
| autoencoder | Unsupervised Autoencoder MSE (Benign-Only) | 0.4693 | 0.2045 | -56.42% | 0.0004 | 0.0008 | 0.0276 |

## Limitations
- Holdout evaluation on AIT-NDS-v2 simulates unseen attack categories within the simulation testbed suite and does NOT guarantee detection of real-world zero-day or adversarial evasion attacks.
- Supervised models trained on AIT-NDS-v2 still exhibit cross-domain sensitivity when transferred zero-shot to real captured traffic such as CTU-SME-11.
