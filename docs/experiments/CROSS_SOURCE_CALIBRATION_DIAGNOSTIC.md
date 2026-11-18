# Cross-Source Probability Shift & Threshold Calibration Diagnostic (Read-Only `E0`)

- **Executed At (UTC):** `2026-11-18T18:02:49.246785+00:00` | **Elapsed:** `10.69s`

| Model | Dataset | ROC-AUC | Attack Prob Median | F1 @ `0.50` (Zero-Shot) | F1 @ `AIT-Val Youden` (Zero-Shot) | F1 @ `Target Benign P95` (Diagnostic) |
|---|---|---:|---:|---:|---:|---:|
| `random_forest` | `ait_val` | 0.9999 | 0.9998 | 0.9997 | 0.9997 | 0.9413 |
| `random_forest` | `ait_test` | 0.9994 | 0.9997 | 0.9950 | 0.9951 | 0.8955 |
| `random_forest` | `ctu_echo` | 0.6137 | 0.0953 | 0.0474 | 0.1124 | 0.0181 |
| `random_forest` | `ctu_windows7ad` | 0.8392 | 0.8872 | 0.0712 | 0.0731 | 0.0735 |
| `random_forest` | `uwf_zeekdata24` | 0.9535 | 0.3884 | 0.0924 | 0.6596 | 0.9756 |
| `xgboost` | `ait_val` | 0.9999 | 0.9986 | 0.9996 | 0.9997 | 0.9707 |
| `xgboost` | `ait_test` | 0.9885 | 0.9986 | 0.9013 | 0.9725 | 0.8711 |
| `xgboost` | `ctu_echo` | 0.7015 | 0.0327 | 0.1436 | 0.1369 | 0.0169 |
| `xgboost` | `ctu_windows7ad` | 0.6961 | 0.9901 | 0.0738 | 0.0728 | 0.0710 |
| `xgboost` | `uwf_zeekdata24` | 0.9717 | 0.9424 | 0.9472 | 0.9572 | 0.9582 |

## Limitations
- target_benign_p95 uses unlabeled/benign quantile on the destination distribution purely as a diagnostic upper bound for threshold sensitivity; it MUST NOT be reported as zero-shot.
- E0 threshold manifests remain untouched.
