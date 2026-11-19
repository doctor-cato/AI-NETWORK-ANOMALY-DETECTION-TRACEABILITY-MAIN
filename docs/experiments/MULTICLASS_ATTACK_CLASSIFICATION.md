# Multi-Class Attack Classification Experiment (6 Classes, `AIT-NDS-v2`)

- **Executed At (UTC):** `2026-11-19T12:50:31.432910+00:00` | **Elapsed:** `172.76s`
- **Isolation Guarantee:** `separate_experimental_run = true`, `e0_artifacts_untouched = true`
- **Model Selected on Validation (`Macro-F1`):** `xgboost_multiclass`

## 1. Overall Summary (`AIT-Val` vs `AIT-Test`)

| Model | Val Macro-F1 | Val Weighted-F1 | Test Accuracy | Test Balanced Acc | Test Macro-F1 | Test Weighted-F1 |
|---|---:|---:|---:|---:|---:|---:|
| `random_forest_multiclass` | 0.8282 | 0.9910 | 0.9584 | 0.7791 | **0.7347** | **0.9778** |
| `xgboost_multiclass` | 0.9456 | 0.9996 | 0.9676 | 0.7618 | **0.6378** | **0.9644** |

## 2. Per-Class Test Breakdown (`xgboost_multiclass`)

| Attack Category | Support (`AIT-Test`) | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| `Benign` | 812,980 | 0.9628 | 0.9992 | 0.9807 |
| `Credential_Attack` | 78 | 0.0271 | 0.1410 | 0.0455 |
| `Data_Exfiltration` | 80,075 | 0.9997 | 0.6140 | 0.7608 |
| `Exploitation_And_C2` | 5 | 0.1316 | 1.0000 | 0.2326 |
| `Post_Exploitation_Discovery` | 39 | 0.8000 | 0.8205 | 0.8101 |
| `Reconnaissance` | 95,628 | 0.9981 | 0.9960 | 0.9971 |

## 3. Limitations
- Rare attack classes in AIT-NDS-v2 have extremely small evaluation counts (Exploitation_And_C2: N=2 val / N=5 test; Post_Exploitation_Discovery: N=56 val / N=39 test; Credential_Attack: N=11 val / N=78 test), so Macro-F1 variance on those classes is high.
- This experiment uses canonical-flow-v2-18 (network flow features only, without L7 HTTP/Auth log payloads) and does NOT alter frozen E0 binary production/research artifacts.
