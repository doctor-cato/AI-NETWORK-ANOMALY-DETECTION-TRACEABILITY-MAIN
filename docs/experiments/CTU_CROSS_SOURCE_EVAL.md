# Cross-Source & Real-Capture CTU-SME-11 Evaluation

Real captured evaluation on **CTU-SME-11** (`Honeypot-Assistant-Amazon-Echo1stGen-1`: 76,073 flows; `Experiment-VM-Microsoft-Windows7AD-1`: 175,146 labeled flows; plus 9,394 `unknown`/`Unmapped` Windows7AD flows excluded from supervised binary metrics). **UGR'16** remains `BLOCKED` (official NESG portal returned HTTP 403 / Portal en Mantenimiento).

## 1. Zero-Shot Transfer: AIT-NDS-v2 Models -> Real CTU-SME-11

| Model | AIT-Test F1 | CTU-Echo F1 | CTU-Echo Recall | CTU-Echo FPR | CTU-Win7AD F1 | CTU-Win7AD Recall | CTU-Win7AD FPR |
|---|---|---|---|---|---|---|---|
| `random_forest` | 0.8997 | 0.0000 | 0.0000 | 0.0008 | 0.0000 | 0.0000 | 0.0131 |
| `xgboost` | 0.8910 | 0.0000 | 0.0000 | 0.0468 | 0.0007 | 0.0005 | 0.0039 |
| `isolation_forest` | 0.5766 | 0.8527 | 0.9108 | 0.2086 | 0.0002 | 0.0034 | 0.4334 |
| `autoencoder` | 0.5788 | 0.7000 | 0.9176 | 0.6520 | 0.0246 | 0.9146 | 0.8545 |

## 2. Device-Disjoint Cross-Source Transfer (`AIT-Train + CTU-Echo` -> Unseen `CTU-Windows7AD` & `AIT-Test`)

| Model | AIT-Test F1 | Unseen CTU-Win7AD F1 | Unseen CTU-Win7AD Recall | Unseen CTU-Win7AD FPR | Unseen Win7AD ROC-AUC |
|---|---|---|---|---|---|
| `random_forest` | 0.7998 | 0.0636 | 0.5074 | 0.1700 | 0.7880 |
| `xgboost` | 0.9010 | 0.0561 | 0.5039 | 0.1938 | 0.8305 |
| `isolation_forest` | 0.5789 | 0.0002 | 0.0044 | 0.4573 | 0.4344 |

## 3. Within-CTU Temporal Split (`2023-02-20..24` -> Held-out `2023-02-25..26`)

| Model | Late CTU-Echo F1 | Late CTU-Echo Recall | Late CTU-Echo FPR | Late CTU-Win7AD F1 | Late CTU-Win7AD Recall | Late CTU-Win7AD FPR |
|---|---|---|---|---|---|---|
| `random_forest` | 0.9600 | 0.9245 | 0.0020 | 0.0000 | 0.0000 | 0.0002 |
| `xgboost` | 0.9521 | 0.9098 | 0.0018 | 0.0000 | 0.0000 | 0.0002 |
| `isolation_forest` | 0.7965 | 0.6894 | 0.0562 | 0.0000 | 0.0000 | 0.0371 |

## 4. Empirical Feature-Shift Failure Analysis

Median feature shifts explain why AIT-trained supervised classifiers degrade zero-shot on CTU-SME-11:

| Feature | AIT-Test Attack | AIT-Test Benign | CTU-Echo Attack | CTU-Echo Benign | CTU-Win7AD Attack | CTU-Win7AD Benign |
|---|---|---|---|---|---|---|
| `duration_ms` | 0.0 | 5088.19 | 0.0 | 91.727 | 2.641 | 2.417 |
| `bytes_in` | 231.0 | 1278.0 | 88.0 | 840.0 | 178.0 | 164.0 |
| `bytes_out` | 250.0 | 1676.0 | 0.0 | 396.0 | 100.0 | 93.0 |
| `pkts_in` | 1.0 | 10.0 | 2.0 | 10.0 | 3.0 | 2.0 |
| `pkts_out` | 1.0 | 9.0 | 0.0 | 2.0 | 2.0 | 1.0 |
