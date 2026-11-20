# Multi-Domain E1 (`AIT + CTU-SME-11 + UWF-ZeekData24`) & Autoencoder E3b Experiment

- **Executed At (UTC):** `2026-11-19T14:24:25.988900+00:00` | **Elapsed:** `50.63s`
- **Isolation Guarantee:** `e0_artifacts_untouched = true`
- **E1 Train Rows:** `442,960` (`AIT=200,001`, `CTU=175,852`, `UWF=67,107`)

## Test Split Comparison (`E1` vs Frozen `E0` Zero-Shot)

| Test Split | Model | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---:|---:|---:|---:|---:|
| `AIT_Test` | `E0_RandomForest_ZeroShot` | 0.9991 | 0.9880 | **0.9935** | 0.000195 | 0.9984 |
| `AIT_Test` | `E1_RandomForest_Binary` | 0.9864 | 0.8620 | **0.9200** | 0.002581 | 0.9974 |
| `AIT_Test` | `E0_XGBoost_ZeroShot` | 0.9991 | 0.8201 | **0.9008** | 0.000158 | 0.9875 |
| `AIT_Test` | `E1_XGBoost_Binary` | 0.9984 | 0.8016 | **0.8892** | 0.000280 | 0.9643 |
| `AIT_Test` | `E0_Autoencoder_ZeroShot` | 0.7927 | 0.4687 | **0.5891** | 0.026666 | 0.5570 |
| `AIT_Test` | `Autoencoder_E3b_VarianceNormalized` | 0.7939 | 0.4691 | **0.5898** | 0.026507 | 0.5447 |
| `CTU_Test` | `E0_RandomForest_ZeroShot` | 0.0808 | 0.0493 | **0.0612** | 0.143224 | 0.7901 |
| `CTU_Test` | `E1_RandomForest_Binary` | 0.9807 | 0.9332 | **0.9564** | 0.004697 | 0.9977 |
| `CTU_Test` | `E0_XGBoost_ZeroShot` | 0.2420 | 0.1780 | **0.2051** | 0.142457 | 0.8111 |
| `CTU_Test` | `E1_XGBoost_Binary` | 0.9965 | 0.9172 | **0.9552** | 0.000833 | 0.9973 |
| `CTU_Test` | `E0_Autoencoder_ZeroShot` | 0.2655 | 0.9957 | **0.4192** | 0.704058 | 0.6292 |
| `CTU_Test` | `Autoencoder_E3b_VarianceNormalized` | 0.6525 | 0.9389 | **0.7699** | 0.127765 | 0.8878 |
| `CTU_Win7AD_Test` | `E0_RandomForest_ZeroShot` | 0.0200 | 0.2508 | **0.0371** | 0.145030 | 0.8639 |
| `CTU_Win7AD_Test` | `E1_RandomForest_Binary` | 0.4123 | 0.2834 | **0.3359** | 0.004775 | 0.9883 |
| `CTU_Win7AD_Test` | `E0_XGBoost_ZeroShot` | 0.0250 | 0.3094 | **0.0462** | 0.142951 | 0.8592 |
| `CTU_Win7AD_Test` | `E1_XGBoost_Binary` | 0.7059 | 0.1564 | **0.2560** | 0.000770 | 0.9849 |
| `CTU_Win7AD_Test` | `E0_Autoencoder_ZeroShot` | 0.0153 | 0.9511 | **0.0302** | 0.721377 | 0.5872 |
| `CTU_Win7AD_Test` | `Autoencoder_E3b_VarianceNormalized` | 0.0749 | 0.9446 | **0.1388** | 0.137944 | 0.9706 |
| `UWF_Test` | `E0_RandomForest_ZeroShot` | 0.5464 | 0.0515 | **0.0942** | 0.042855 | 0.9577 |
| `UWF_Test` | `E1_RandomForest_Binary` | 0.9983 | 1.0000 | **0.9992** | 0.001670 | 1.0000 |
| `UWF_Test` | `E0_XGBoost_ZeroShot` | 0.9565 | 0.9406 | **0.9485** | 0.042855 | 0.9745 |
| `UWF_Test` | `E1_XGBoost_Binary` | 0.9983 | 1.0000 | **0.9992** | 0.001670 | 1.0000 |
| `UWF_Test` | `E0_Autoencoder_ZeroShot` | 0.3730 | 0.2722 | **0.3147** | 0.458328 | 0.3869 |
| `UWF_Test` | `Autoencoder_E3b_VarianceNormalized` | 0.9828 | 0.0953 | **0.1737** | 0.001670 | 0.3102 |

## Limitations & Governance Disclosure

- **UWF-ZeekData24 Governance (`evaluation_only = true` for frozen `E0`):** `data/UWF_ZEEKDATA24_MANIFEST.json` designates `UWF-ZeekData24` as `evaluation_only = true` for the frozen `E0` baseline models. In this separate `E1` multi-domain experiment, `UWF_Train` is included in `E1_Train`, so `E1`'s `UWF_Test` evaluation is an **in-domain multi-source split** (NOT zero-shot generalization), whereas `E0_*_ZeroShot` rows remain true zero-shot evaluations.
- **Frozen `E0` Isolation:** All four frozen `E0` `.joblib` artifacts and `E0` thresholds remain **100% untouched** (`e0_artifacts_untouched = true`); `E1` and `Autoencoder_E3b` are trained and evaluated strictly in-memory as experimental models.
- **CTU-Win7AD Stratified Chronological Block Split:** Because raw `ctu_windows7ad.csv.gz` places all `Exploitation_And_C2` attack flows in the first 85% of the chronological stream, `CTU-Win7AD` uses a deterministic stratified 70/15/15 chronological block split per `attack_category` so `CTU_Win7AD_Test` contains both Benign and Attack rows.
