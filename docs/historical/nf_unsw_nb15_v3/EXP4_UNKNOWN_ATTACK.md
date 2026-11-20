# RQ4 — Unknown Attack Family Holdout Evaluation (Empirical NF-UNSW-NB15-v3)

- **Status:** `COMPLETED`
- **Timestamp (UTC):** `2026-11-17T15:57:04.802877+00:00`
- **Held-out Families:** `Backdoor, Worms` (0 rows in Train & Validation)
- **Dataset:** `NF-UNSW-NB15-v3` (`None`)
- **Test Counts:** Benign=`315,357`, Known Attack=`29,300`, Unknown Holdout=`1,296`

| Model | Paradigm | Known Recall | Holdout Recall | Delta | Holdout Precision | Holdout F1 | Benign FPR |
|---|---|---:|---:|---:|---:|---:|---:|
| random_forest | Supervised Decision Forest (Holdout-Trained) | 0.9999 | 1.0000 | +0.01% | 0.9969 | 0.9985 | 0.0000 |
| xgboost | Gradient Boosted Trees (Holdout-Trained) | 1.0000 | 1.0000 | +0.00% | 0.9985 | 0.9992 | 0.0000 |
| isolation_forest | Unsupervised Isolation Forest (Benign-Only) | 0.9012 | 0.8657 | -3.94% | 0.0217 | 0.0423 | 0.1605 |
| autoencoder | Unsupervised Autoencoder MSE (Benign-Only) | 0.1113 | 0.0625 | -43.86% | 0.0053 | 0.0098 | 0.0482 |

## Limitations
- Holdout evaluation on NF-UNSW-NB15-v3 simulates unseen attack categories within the same testbed distribution and does NOT guarantee detection of real-world zero-day or adversarial evasion attacks.
- Supervised models trained on NF-UNSW-NB15-v3 may still exploit shared testbed artifacts (such as MIN_TTL) that correlate across both known and held-out attack categories.
