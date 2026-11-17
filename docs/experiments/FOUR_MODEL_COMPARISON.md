# RQ1 — 4-Model Empirical Comparison Report (NetFlow Sentinel v2 / AIT-NDS-v2)

- **Status:** `COMPLETED`
- **Generated At (UTC):** `2026-11-17T18:54:50.951138+00:00`
- **Dataset:** `AIT-NetFlow-v2-Suite` (SHA-256: `cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf`)
- **Split Protocol:** `v2-scenario-group-purged-v1` (`test`, N=923,292)
- **Random Seed:** `42`

## 1. Empirical Test Metrics (Same Preprocessing & Split)

| Model | Precision | Recall | F1 | Macro-F1 | FPR | ROC-AUC | PR-AUC | Avg Latency | Throughput |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Random Forest | 0.9988 | 0.8185 | 0.8997 | 0.9394 | 0.000227 | 0.9996 | 0.9981 | 1.74 us | 576,169.1 flow/s |
| XGBoost | 0.9988 | 0.8042 | 0.8910 | 0.9342 | 0.000225 | 0.9786 | 0.9385 | 0.49 us | 2,021,728.8 flow/s |
| Isolation Forest | 0.7461 | 0.4698 | 0.5766 | 0.7495 | 0.037569 | 0.7753 | 0.6353 | 6.57 us | 152,117.2 flow/s |
| Autoencoder | 0.7581 | 0.4681 | 0.5788 | 0.7511 | 0.035104 | 0.7886 | 0.6411 | 0.39 us | 2,569,121.0 flow/s |

## 2. Evaluation Protocols & Artifact Hashes

- **Random Forest**: `supervised_binary_classification (trained on Train Ben+Attack; threshold on probability)`, threshold=`0.5`, sha256=`0dd7aaafa40f351986d7f977e81d9517a3c25083e6cd4525ecdb23abac38dbf0`
- **XGBoost**: `supervised_binary_classification (trained on Train Ben+Attack; threshold on probability)`, threshold=`0.5`, sha256=`6bb5a6f2ac6f16fc76138c6f22c3e80cc8664d2db1ddc039819c845a97a26732`
- **Isolation Forest**: `unsupervised_anomaly_detection (trained on Train Benign-only; threshold_source=manifest.threshold)`, threshold=`0.002736309694079453`, sha256=`aca66915e0f57433c18ebbb819f2438c75e3840a183d2e379c986f0952e1aa1c`
- **Autoencoder**: `unsupervised_anomaly_detection (trained on Train Benign-only; threshold_source=manifest.threshold)`, threshold=`0.0002279976895622908`, sha256=`2032f8caf37be27f12a91ca1348e85d32a718f332e151cd900dedcf082b71a1f`

## 3. Limitations

- Supervised and unsupervised models follow different training and threshold calibration protocols and must be compared with protocol awareness.
- In-domain evaluation uses AIT-NDS-v2 scenario-disjoint held-out testbeds (shaw, wheeler); cross-source domain-shift evaluation is separately measured on CTU-SME-11.
- Batch throughput reflects offline vectorized inference on this host and does not directly measure live network line-rate capacity.
