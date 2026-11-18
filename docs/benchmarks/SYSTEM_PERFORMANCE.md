# System Performance Benchmark Report (Dynamic Measurement)

- **Executed At (UTC):** `2026-11-18T16:38:30.131998+00:00`
- **Host OS / CPU / RAM:** `Windows-11-10.0.26200-SP0` / `12 vCPU` / `15.27 GB`
- **Python:** `3.12.10` | **AI Readiness:** `4/4 (UNAVAILABLE)`
- **Repeatability Runs:** `3`

## 1. End-to-End Orchestrator Measurement
- **Events Processed:** `200` (latest run)
- **Throughput (Latest / Mean ± Std / CV%):** `5,861.68 flow/s` / `7,643.89 ± 3,340.15` (`CV=43.7%`)
- **E2E Latency (Med / P95 / P99):** `133.95 / 275.8 / 577.7 us` (Med CV=`37.07%`)
- **Replay Throughput (Mean ± Std / CV%):** `6,508.33 ± 129.38 flow/s` (`CV=1.99%`)
- **Ring Buffer Peak Utilization:** `10.0%` (`dropped=0`)

## 2. Isolated Component Microbenchmarks (Separate from E2E)

| Component | Median (us) | P95 (us) | P99 (us) | Repeat Mean ± Std (us) | CV (%) |
|---|---:|---:|---:|---:|---:|
| collector_decoding | 0.4 | 0.4 | 0.6 | 0.467 ± 0.115 | 24.74% |
| feature_contract_validation | 1.6 | 2.9 | 3.7 | 1.6 ± 0.0 | 0.0% |
| multi_model_ai_inference | 2.45 | 3.5 | 16.0 | 2.15 ± 0.26 | 12.08% |
| behavioral_vector_build | 17.45 | 33.7 | 100.5 | 17.317 ± 0.465 | 2.68% |
| aes_256_gcm_encrypt | 1.9 | 2.2 | 3.5 | 1.95 ± 0.087 | 4.44% |
| risk_scoring_dedup | 1.6 | 1.8 | 3.2 | 1.867 ± 0.462 | 24.74% |

## 3. Limitations
- Measurements reflect in-process synthetic event workloads on this specific host and do not constitute 1-10 Gbps physical NIC line-rate certification.
- Component microbenchmarks and full end-to-end event processing latency are reported separately because Python loop/dispatch and SQLite/sessionizer overhead are not additive across isolated microbenchmarks.
