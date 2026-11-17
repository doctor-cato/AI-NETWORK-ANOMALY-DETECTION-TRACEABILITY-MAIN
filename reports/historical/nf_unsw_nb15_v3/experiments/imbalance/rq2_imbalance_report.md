# RQ2 — Class Imbalance & Rare Attack Evaluation (Empirical NF-UNSW-NB15-v3)

- **Status:** `COMPLETED`
- **Timestamp (UTC):** `2026-11-17T15:55:28.904002+00:00`
- **Dataset:** `NF-UNSW-NB15-v3` (`None`)
- **Train Rows:** `1,655,797` (`scale_pos_weight=24.40`) | **Test Rows:** `345,953`
- **Rare Categories (Test < 0.5%):** `Analysis, Backdoor, DoS, Shellcode, Worms`

## Rare Attack Category Results

| Category | Test Count | Prevalence | Model | Detection Rate (Recall) | One-vs-Benign F1 | Benign FPR |
|---|---:|---:|---|---:|---:|---:|
| Analysis | 294 | 0.0850% | RandomForest_Unweighted | 1.0000 | 0.9916 | 0.000016 |
| Analysis | 294 | 0.0850% | RandomForest_CostSensitive | 1.0000 | 0.9899 | 0.000019 |
| Analysis | 294 | 0.0850% | XGBoost_ScalePosWeight | 1.0000 | 0.9966 | 0.000006 |
| Analysis | 294 | 0.0850% | IsolationForest | 0.9320 | 0.0107 | 0.160459 |
| Analysis | 294 | 0.0850% | Autoencoder_Reconstruction | 0.0000 | 0.0000 | 0.048161 |
| Backdoor | 1260 | 0.3642% | RandomForest_Unweighted | 1.0000 | 0.9980 | 0.000016 |
| Backdoor | 1260 | 0.3642% | RandomForest_CostSensitive | 1.0000 | 0.9976 | 0.000019 |
| Backdoor | 1260 | 0.3642% | XGBoost_ScalePosWeight | 1.0000 | 0.9992 | 0.000006 |
| Backdoor | 1260 | 0.3642% | IsolationForest | 0.8675 | 0.0413 | 0.160459 |
| Backdoor | 1260 | 0.3642% | Autoencoder_Reconstruction | 0.0627 | 0.0096 | 0.048161 |
| DoS | 1193 | 0.3448% | RandomForest_Unweighted | 0.9983 | 0.9971 | 0.000016 |
| DoS | 1193 | 0.3448% | RandomForest_CostSensitive | 0.9983 | 0.9967 | 0.000019 |
| DoS | 1193 | 0.3448% | XGBoost_ScalePosWeight | 1.0000 | 0.9992 | 0.000006 |
| DoS | 1193 | 0.3448% | IsolationForest | 0.8156 | 0.0369 | 0.160459 |
| DoS | 1193 | 0.3448% | Autoencoder_Reconstruction | 0.1140 | 0.0165 | 0.048161 |
| Shellcode | 396 | 0.1145% | RandomForest_Unweighted | 1.0000 | 0.9937 | 0.000016 |
| Shellcode | 396 | 0.1145% | RandomForest_CostSensitive | 1.0000 | 0.9925 | 0.000019 |
| Shellcode | 396 | 0.1145% | XGBoost_ScalePosWeight | 1.0000 | 0.9975 | 0.000006 |
| Shellcode | 396 | 0.1145% | IsolationForest | 0.8864 | 0.0137 | 0.160459 |
| Shellcode | 396 | 0.1145% | Autoencoder_Reconstruction | 0.0025 | 0.0001 | 0.048161 |
| Worms | 36 | 0.0104% | RandomForest_Unweighted | 1.0000 | 0.9351 | 0.000016 |
| Worms | 36 | 0.0104% | RandomForest_CostSensitive | 1.0000 | 0.9231 | 0.000019 |
| Worms | 36 | 0.0104% | XGBoost_ScalePosWeight | 1.0000 | 0.9730 | 0.000006 |
| Worms | 36 | 0.0104% | IsolationForest | 0.8056 | 0.0011 | 0.160459 |
| Worms | 36 | 0.0104% | Autoencoder_Reconstruction | 0.0556 | 0.0003 | 0.048161 |

## Hypothesis Evaluation
- Cost-sensitive RF/XGB detection rate >= 0.70 across all rare classes: `True`
- Autoencoder one-vs-benign F1 >= 0.70 across all rare classes: `False`
- Full H2 confirmed: `False`

## Limitations
- One-vs-benign rare-class precision/F1 treats all Benign false positives as denominator against a single rare attack class, making F1 sensitive to benign FPR when category support is tiny (e.g., Worms).
- No SMOTE or synthetic oversampling was applied to Train, Validation, or Test.
