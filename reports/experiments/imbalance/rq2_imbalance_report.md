# RQ2 — Class Imbalance & Rare Attack Evaluation (Empirical AIT-NDS-v2)

- **Status:** `COMPLETED`
- **Timestamp (UTC):** `2026-11-18T02:12:08.319120+00:00`
- **Dataset:** `AIT-NetFlow-v2-Suite` (`cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf`)
- **Train Rows:** `2,097,891` (`scale_pos_weight=6.71`) | **Test Rows:** `988,805`
- **Rare Categories (Test < 0.5%):** `Credential_Attack, Exploitation_And_C2, Post_Exploitation_Discovery`

## Rare Attack Category Results

| Category | Test Count | Prevalence | Model | Detection Rate (Recall) | One-vs-Benign F1 | Benign FPR |
|---|---:|---:|---|---:|---:|---:|
| Credential_Attack | 78 | 0.0079% | RandomForest_Unweighted | 0.1410 | 0.0843 | 0.000212 |
| Credential_Attack | 78 | 0.0079% | RandomForest_CostSensitive | 0.1410 | 0.0767 | 0.000244 |
| Credential_Attack | 78 | 0.0079% | XGBoost_ScalePosWeight | 0.1410 | 0.0509 | 0.000422 |
| Credential_Attack | 78 | 0.0079% | IsolationForest | 0.1410 | 0.0009 | 0.028952 |
| Credential_Attack | 78 | 0.0079% | Autoencoder_Reconstruction | 0.0641 | 0.0004 | 0.027637 |
| Exploitation_And_C2 | 5 | 0.0005% | RandomForest_Unweighted | 1.0000 | 0.0549 | 0.000212 |
| Exploitation_And_C2 | 5 | 0.0005% | RandomForest_CostSensitive | 1.0000 | 0.0481 | 0.000244 |
| Exploitation_And_C2 | 5 | 0.0005% | XGBoost_ScalePosWeight | 1.0000 | 0.0283 | 0.000422 |
| Exploitation_And_C2 | 5 | 0.0005% | IsolationForest | 1.0000 | 0.0004 | 0.028952 |
| Exploitation_And_C2 | 5 | 0.0005% | Autoencoder_Reconstruction | 1.0000 | 0.0004 | 0.027637 |
| Post_Exploitation_Discovery | 39 | 0.0039% | RandomForest_Unweighted | 0.8974 | 0.2846 | 0.000212 |
| Post_Exploitation_Discovery | 39 | 0.0039% | RandomForest_CostSensitive | 0.8974 | 0.2574 | 0.000244 |
| Post_Exploitation_Discovery | 39 | 0.0039% | XGBoost_ScalePosWeight | 0.8974 | 0.1679 | 0.000422 |
| Post_Exploitation_Discovery | 39 | 0.0039% | IsolationForest | 0.8974 | 0.0030 | 0.028952 |
| Post_Exploitation_Discovery | 39 | 0.0039% | Autoencoder_Reconstruction | 0.1026 | 0.0004 | 0.027637 |

## Hypothesis Evaluation
- Cost-sensitive RF/XGB detection rate >= 0.70 across all rare classes: `False`
- Autoencoder one-vs-benign F1 >= 0.70 across all rare classes: `False`
- Full H2 confirmed: `False`

## Limitations
- One-vs-benign rare-class precision/F1 treats all Benign false positives as denominator against a single rare attack class, making F1 sensitive to benign FPR when category support is tiny (e.g., Worms).
- No SMOTE or synthetic oversampling was applied to Train, Validation, or Test.
