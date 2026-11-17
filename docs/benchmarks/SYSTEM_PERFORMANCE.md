# System Performance Benchmark Report (Dynamic Measurement)

- **Executed At (UTC):** `2026-11-17T15:52:01.441243+00:00`
- **Host OS / CPU / RAM:** `Windows-11-10.0.26200-SP0` / `12 vCPU` / `15.27 GB`
- **Python:** `3.12.10` | **AI Readiness:** `4/4 (REAL_MODELS)`

## 1. End-to-End Orchestrator Measurement
- **Events Processed:** `200`
- **Throughput:** `12.30 flow/s`
- **E2E Latency (Med / P95 / P99):** `78423.3 / 99766.7 / 175674.9 us`
- **Ring Buffer Peak Utilization:** `10.0%` (`dropped=0`)

## 2. Isolated Component Microbenchmarks (Separate from E2E)

| Component | Median (us) | P95 (us) | P99 (us) |
|---|---:|---:|---:|
| collector_decoding | 1.0 | 1.2 | 2.0 |
| feature_contract_validation | 8.7 | 9.6 | 12.3 |
| multi_model_ai_inference | 79346.35 | 159022.0 | 244357.6 |
| behavioral_vector_build | 41.45 | 87.1 | 149.1 |
| aes_256_gcm_encrypt | 4.5 | 13.2 | 71.6 |
| risk_scoring_dedup | 4.1 | 7.8 | 9.4 |

## 3. Limitations
- Measurements reflect in-process synthetic event workloads on this specific host and do not constitute 1-10 Gbps physical NIC line-rate certification.
- Component microbenchmarks and full end-to-end event processing latency are reported separately because Python loop/dispatch and SQLite/sessionizer overhead are not additive across isolated microbenchmarks.
