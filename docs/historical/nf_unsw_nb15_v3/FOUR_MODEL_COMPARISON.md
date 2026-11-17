# RQ1 — 4-Model Empirical Comparison Report (NF-UNSW-NB15-v3)

- **Status:** `COMPLETED`
- **Generated At (UTC):** `2026-11-17T16:00:46.778876+00:00`
- **Dataset:** `NF-UNSW-NB15-v3` (SHA-256: `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`)
- **Split Protocol:** `nf-unsw-nb15-v3-chronological-group-purged-v1` (`test`, N=345,953)
- **Random Seed:** `42`

## 1. Empirical Test Metrics (Same Preprocessing & Split)

| Model | Precision | Recall | F1 | Macro-F1 | FPR | ROC-AUC | PR-AUC | Avg Latency | Throughput |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Random Forest | 0.9998 | 0.9999 | 0.9999 | 0.9999 | 0.000022 | 1.0000 | 1.0000 | 2.01 us | 497,907.9 flow/s |
| XGBoost | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.000003 | 1.0000 | 1.0000 | 0.59 us | 1,691,308.0 flow/s |
| Isolation Forest | 0.3523 | 0.8997 | 0.5064 | 0.7072 | 0.160459 | 0.8937 | 0.2888 | 5.46 us | 183,081.3 flow/s |
| Autoencoder | 0.1804 | 0.1093 | 0.1361 | 0.5350 | 0.048161 | 0.6303 | 0.1615 | 1.11 us | 903,376.5 flow/s |

## 2. Evaluation Protocols & Artifact Hashes

- **Random Forest**: `supervised_binary_classification (trained on Train Ben+Attack; threshold on probability)`, threshold=`0.5`, sha256=`801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`
- **XGBoost**: `supervised_binary_classification (trained on Train Ben+Attack; threshold on probability)`, threshold=`0.5`, sha256=`3098b75acdd79c39605d724880f8f2ed48af6d68a0651292e27804b42a1f493e`
- **Isolation Forest**: `unsupervised_anomaly_detection (trained on Train Benign-only; threshold_source=manifest.threshold)`, threshold=`-0.033526858092757406`, sha256=`15a69cc491ce8903fd2dfd3ee12e7283bd3d9c0ceba51c9a2c04b2188a5fddf9`
- **Autoencoder**: `unsupervised_anomaly_detection (trained on Train Benign-only; threshold_source=manifest.threshold)`, threshold=`17234985.792475585`, sha256=`df24752b8eca0b111c6a7efa0700217bac3eabe8aaa194fcf82590c13b9d3b86`

## 3. Limitations

- NF-UNSW-NB15-v3 contains strong MIN_TTL separation between benign and attack traffic; high supervised F1 partially reflects testbed topology.
- Supervised and unsupervised models follow different training and threshold calibration protocols and must be compared with protocol awareness.
- Batch throughput reflects offline vectorized inference on this host and does not directly measure live network line-rate capacity.
