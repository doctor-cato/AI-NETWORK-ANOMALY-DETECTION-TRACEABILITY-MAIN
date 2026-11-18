# RQ1 — 4-Model Empirical Comparison Report (NetFlow Sentinel v2 / AIT-NDS-v2)

- **Status:** `COMPLETED`
- **Generated At (UTC):** `2026-11-18T02:07:40.325399+00:00`
- **Dataset:** `AIT-NetFlow-v2-Suite` (SHA-256: `cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf`)
- **Split Protocol:** `v2-scenario-group-purged-v1` (`test`, N=988,805)
- **Random Seed:** `42`

## 1. Empirical Test Metrics (Same Preprocessing & Split)

| Model | Precision | Recall | F1 | Macro-F1 | FPR | ROC-AUC | PR-AUC | Avg Latency | Throughput |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Random Forest | 0.9989 | 0.9911 | 0.9950 | 0.9969 | 0.000246 | 0.9994 | 0.9977 | 2.06 us | 486,239.1 flow/s |
| XGBoost | 0.9989 | 0.8211 | 0.9013 | 0.9411 | 0.000198 | 0.9885 | 0.9728 | 0.65 us | 1,547,693.1 flow/s |
| Isolation Forest | 0.7775 | 0.4678 | 0.5842 | 0.7576 | 0.028952 | 0.8330 | 0.6587 | 8.67 us | 115,364.4 flow/s |
| Autoencoder | 0.7860 | 0.4693 | 0.5877 | 0.7597 | 0.027637 | 0.5544 | 0.5664 | 0.48 us | 2,066,235.4 flow/s |

## 2. Evaluation Protocols & Artifact Hashes

- **Random Forest**: `supervised_binary_classification (trained on Train Ben+Attack; threshold on probability)`, threshold=`0.5`, sha256=`b2e42f85f2625f5bf04902a032a4db734f4c4e744d45f4fef3ddffd05a694f2f`
- **XGBoost**: `supervised_binary_classification (trained on Train Ben+Attack; threshold on probability)`, threshold=`0.5`, sha256=`33d201f8f3d842c0b71547532c74f3d107bd402d8a65e20241ff5f407723aa48`
- **Isolation Forest**: `unsupervised_anomaly_detection (trained on Train Benign-only; threshold_source=manifest.threshold)`, threshold=`0.03126839775265744`, sha256=`11b1690088bca1984df9280b3c5662fbb13a76ca31e55258b9de43d6a10a6885`
- **Autoencoder**: `unsupervised_anomaly_detection (trained on Train Benign-only; threshold_source=manifest.threshold)`, threshold=`0.0004672738606371692`, sha256=`e6afecefdc939a09e3c7fedd3e994a10c404f74e9b52c9ab95dfd984aae0cd4f`

## 3. Limitations

- Supervised and unsupervised models follow different training and threshold calibration protocols and must be compared with protocol awareness.
- In-domain evaluation uses AIT-NDS-v2 scenario-disjoint held-out testbeds (shaw, wheeler); cross-source domain-shift evaluation is separately measured on CTU-SME-11.
- Batch throughput reflects offline vectorized inference on this host and does not directly measure live network line-rate capacity.
