# RQ4 — Unknown Attack Family Holdout Evaluation (Empirical AIT-NDS-v2)

- **Status:** `COMPLETED`
- **Timestamp (UTC):** `2026-11-17T19:01:02.786323+00:00`
- **Held-out Families:** `Exploitation_And_C2, Post_Exploitation_Discovery` (0 rows in Train & Validation)
- **Dataset:** `AIT-NetFlow-v2-Suite` (`cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf`)
- **Test Counts:** Benign=`747,610`, Known Attack=`175,640`, Unknown Holdout=`42`

| Model | Paradigm | Known Recall | Holdout Recall | Delta | Holdout Precision | Holdout F1 | Benign FPR |
|---|---|---:|---:|---:|---:|---:|---:|
| random_forest | Supervised Decision Forest (Holdout-Trained) | 0.9974 | 0.8333 | -16.45% | 0.1129 | 0.1989 | 0.0004 |
| xgboost | Gradient Boosted Trees (Holdout-Trained) | 0.8227 | 0.8333 | +1.30% | 0.0916 | 0.1651 | 0.0005 |
| isolation_forest | Unsupervised Isolation Forest (Benign-Only) | 0.4697 | 0.9524 | +102.75% | 0.0014 | 0.0028 | 0.0376 |
| autoencoder | Unsupervised Autoencoder MSE (Benign-Only) | 0.4682 | 0.2143 | -54.23% | 0.0003 | 0.0007 | 0.0351 |

## Limitations
- Holdout evaluation on AIT-NDS-v2 simulates unseen attack categories within the simulation testbed suite and does NOT guarantee detection of real-world zero-day or adversarial evasion attacks.
- Supervised models trained on AIT-NDS-v2 still exhibit cross-domain sensitivity when transferred zero-shot to real captured traffic such as CTU-SME-11.
