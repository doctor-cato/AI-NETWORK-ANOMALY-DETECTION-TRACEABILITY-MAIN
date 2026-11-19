# Multi-Domain E1 (`AIT + CTU-SME-11 + UWF-ZeekData24`) & Autoencoder E3b Experiment

- **Executed At (UTC):** `2026-11-19T12:53:40.421469+00:00` | **Elapsed:** `187.14s`
- **Isolation Guarantee:** `e0_artifacts_untouched = true`
- **E1 Train Rows:** `442,961` (`AIT=200,001`, `CTU=175,853`, `UWF=67,107`)

## Test Split Comparison (`E1` vs Frozen `E0` Zero-Shot)

| Test Split | Model | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---:|---:|---:|---:|---:|
| `AIT_Test` | `E0_RandomForest_ZeroShot` | 0.9991 | 0.9880 | **0.9935** | 0.000195 | 0.9984 |
| `AIT_Test` | `E1_RandomForest_Binary` | 0.9865 | 0.8316 | **0.9024** | 0.002484 | 0.9972 |
| `AIT_Test` | `E0_XGBoost_ZeroShot` | 0.9991 | 0.8201 | **0.9008** | 0.000158 | 0.9875 |
| `AIT_Test` | `E1_XGBoost_Binary` | 0.9884 | 0.6714 | **0.7996** | 0.001717 | 0.9439 |
| `AIT_Test` | `E0_Autoencoder_ZeroShot` | 0.7927 | 0.4687 | **0.5891** | 0.026666 | 0.5570 |
| `AIT_Test` | `Autoencoder_E3b_VarianceNormalized` | 0.9110 | 0.4668 | **0.6173** | 0.009924 | 0.6310 |
| `CTU_Test` | `E0_RandomForest_ZeroShot` | 0.0647 | 0.0409 | **0.0501** | 0.143493 | 0.7875 |
| `CTU_Test` | `E1_RandomForest_Binary` | 0.9804 | 0.9603 | **0.9703** | 0.004650 | 0.9979 |
| `CTU_Test` | `E0_XGBoost_ZeroShot` | 0.2269 | 0.1725 | **0.1960** | 0.142735 | 0.8096 |
| `CTU_Test` | `E1_XGBoost_Binary` | 0.9790 | 0.9607 | **0.9698** | 0.005013 | 0.9977 |
| `CTU_Test` | `E0_Autoencoder_ZeroShot` | 0.2560 | 0.9976 | **0.4075** | 0.703845 | 0.6302 |
| `CTU_Test` | `Autoencoder_E3b_VarianceNormalized` | 0.5202 | 0.1823 | **0.2699** | 0.040828 | 0.8156 |
| `CTU_Win7AD_Test` | `E0_RandomForest_ZeroShot` | 0.0000 | 0.0000 | **0.0000** | 0.145320 | N/A |
| `CTU_Win7AD_Test` | `E1_RandomForest_Binary` | 0.0000 | 0.0000 | **0.0000** | 0.004720 | N/A |
| `CTU_Win7AD_Test` | `E0_XGBoost_ZeroShot` | 0.0000 | 0.0000 | **0.0000** | 0.143265 | N/A |
| `CTU_Win7AD_Test` | `E1_XGBoost_Binary` | 0.0000 | 0.0000 | **0.0000** | 0.005138 | N/A |
| `CTU_Win7AD_Test` | `E0_Autoencoder_ZeroShot` | 0.0000 | 0.0000 | **0.0000** | 0.720930 | N/A |
| `CTU_Win7AD_Test` | `Autoencoder_E3b_VarianceNormalized` | 0.0000 | 0.0000 | **0.0000** | 0.044190 | N/A |
| `UWF_Test` | `E0_RandomForest_ZeroShot` | 0.5464 | 0.0515 | **0.0942** | 0.042855 | 0.9577 |
| `UWF_Test` | `E1_RandomForest_Binary` | 0.9985 | 1.0000 | **0.9992** | 0.001531 | 1.0000 |
| `UWF_Test` | `E0_XGBoost_ZeroShot` | 0.9565 | 0.9406 | **0.9485** | 0.042855 | 0.9745 |
| `UWF_Test` | `E1_XGBoost_Binary` | 0.9971 | 1.0000 | **0.9985** | 0.002922 | 1.0000 |
| `UWF_Test` | `E0_Autoencoder_ZeroShot` | 0.3730 | 0.2722 | **0.3147** | 0.458328 | 0.3869 |
| `UWF_Test` | `Autoencoder_E3b_VarianceNormalized` | 1.0000 | 0.0911 | **0.1670** | 0.000000 | 0.6901 |
