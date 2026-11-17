# RQ2 — Class Imbalance & Rare Attack Evaluation (Empirical AIT-NDS-v2)

- **Status:** `COMPLETED`
- **Timestamp (UTC):** `2026-11-17T18:58:27.405613+00:00`
- **Dataset:** `AIT-NetFlow-v2-Suite` (`cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf`)
- **Train Rows:** `1,930,219` (`scale_pos_weight=6.11`) | **Test Rows:** `923,292`
- **Rare Categories (Test < 0.5%):** `Credential_Attack, Exploitation_And_C2, Post_Exploitation_Discovery`

## Rare Attack Category Results

| Category | Test Count | Prevalence | Model | Detection Rate (Recall) | One-vs-Benign F1 | Benign FPR |
|---|---:|---:|---|---:|---:|---:|
| Credential_Attack | 78 | 0.0084% | RandomForest_Unweighted | 0.1410 | 0.0849 | 0.000227 |
| Credential_Attack | 78 | 0.0084% | RandomForest_CostSensitive | 0.1410 | 0.0772 | 0.000262 |
| Credential_Attack | 78 | 0.0084% | XGBoost_ScalePosWeight | 0.1410 | 0.0604 | 0.000368 |
| Credential_Attack | 78 | 0.0084% | IsolationForest | 0.1667 | 0.0009 | 0.037569 |
| Credential_Attack | 78 | 0.0084% | Autoencoder_Reconstruction | 0.0641 | 0.0004 | 0.035104 |
| Exploitation_And_C2 | 5 | 0.0005% | RandomForest_Unweighted | 1.0000 | 0.0556 | 0.000227 |
| Exploitation_And_C2 | 5 | 0.0005% | RandomForest_CostSensitive | 1.0000 | 0.0485 | 0.000262 |
| Exploitation_And_C2 | 5 | 0.0005% | XGBoost_ScalePosWeight | 1.0000 | 0.0351 | 0.000368 |
| Exploitation_And_C2 | 5 | 0.0005% | IsolationForest | 1.0000 | 0.0004 | 0.037569 |
| Exploitation_And_C2 | 5 | 0.0005% | Autoencoder_Reconstruction | 1.0000 | 0.0004 | 0.035104 |
| Post_Exploitation_Discovery | 37 | 0.0040% | RandomForest_Unweighted | 0.9459 | 0.2893 | 0.000227 |
| Post_Exploitation_Discovery | 37 | 0.0040% | RandomForest_CostSensitive | 0.9459 | 0.2612 | 0.000262 |
| Post_Exploitation_Discovery | 37 | 0.0040% | XGBoost_ScalePosWeight | 0.9459 | 0.2017 | 0.000368 |
| Post_Exploitation_Discovery | 37 | 0.0040% | IsolationForest | 0.9459 | 0.0025 | 0.037569 |
| Post_Exploitation_Discovery | 37 | 0.0040% | Autoencoder_Reconstruction | 0.1081 | 0.0003 | 0.035104 |

## Hypothesis Evaluation
- Cost-sensitive RF/XGB detection rate >= 0.70 across all rare classes: `False`
- Autoencoder one-vs-benign F1 >= 0.70 across all rare classes: `False`
- Full H2 confirmed: `False`

## Limitations
- One-vs-benign rare-class precision/F1 treats all Benign false positives as denominator against a single rare attack class, making F1 sensitive to benign FPR when category support is tiny (e.g., Worms).
- No SMOTE or synthetic oversampling was applied to Train, Validation, or Test.
