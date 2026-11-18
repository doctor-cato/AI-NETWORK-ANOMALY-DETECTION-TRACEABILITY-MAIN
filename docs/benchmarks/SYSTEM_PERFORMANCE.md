# System Performance Benchmark Report (Dynamic Measurement)

- **Executed At (UTC):** `2026-11-17T23:30:15.877435+00:00`
- **Host OS / CPU / RAM:** `Windows-11-10.0.26200-SP0` / `12 vCPU` / `15.27 GB`
- **Python:** `3.12.10` | **AI Readiness:** `4/4 (REAL_MODELS)`

## 1. End-to-End Orchestrator Measurement
- **Events Processed:** `200`
- **Throughput:** `16.38 flow/s`
- **E2E Latency (Med / P95 / P99):** `61750.4 / 73575.7 / 82525.6 us`
- **Ring Buffer Peak Utilization:** `10.0%` (`dropped=0`)

## 2. Isolated Component Microbenchmarks (Separate from E2E)

| Component | Median (us) | P95 (us) | P99 (us) |
|---|---:|---:|---:|
| collector_decoding | 1.0 | 1.4 | 2.8 |
| feature_contract_validation | 3.7 | 3.8 | 4.6 |
| multi_model_ai_inference | 57635.75 | 66242.0 | 73633.1 |
| behavioral_vector_build | 35.65 | 42.9 | 54.2 |
| aes_256_gcm_encrypt | 4.7 | 25.9 | 28.4 |
| risk_scoring_dedup | 20.8 | 24.3 | 55.6 |

## 3. Limitations
- Measurements reflect in-process synthetic event workloads on this specific host and do not constitute 1-10 Gbps physical NIC line-rate certification.
- Component microbenchmarks and full end-to-end event processing latency are reported separately because Python loop/dispatch and SQLite/sessionizer overhead are not additive across isolated microbenchmarks.
