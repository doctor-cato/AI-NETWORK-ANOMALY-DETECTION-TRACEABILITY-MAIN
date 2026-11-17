# System Performance Benchmark Report (Dynamic Measurement)

- **Executed At (UTC):** `2026-11-17T19:01:50.739167+00:00`
- **Host OS / CPU / RAM:** `Windows-11-10.0.26200-SP0` / `12 vCPU` / `15.27 GB`
- **Python:** `3.12.10` | **AI Readiness:** `4/4 (REAL_MODELS)`

## 1. End-to-End Orchestrator Measurement
- **Events Processed:** `200`
- **Throughput:** `10.78 flow/s`
- **E2E Latency (Med / P95 / P99):** `90432.9 / 131399.4 / 180361.7 us`
- **Ring Buffer Peak Utilization:** `10.0%` (`dropped=0`)

## 2. Isolated Component Microbenchmarks (Separate from E2E)

| Component | Median (us) | P95 (us) | P99 (us) |
|---|---:|---:|---:|
| collector_decoding | 1.1 | 1.5 | 2.0 |
| feature_contract_validation | 3.8 | 4.2 | 11.4 |
| multi_model_ai_inference | 86594.2 | 127555.9 | 159956.6 |
| behavioral_vector_build | 44.35 | 78.2 | 113.9 |
| aes_256_gcm_encrypt | 4.8 | 8.8 | 47.7 |
| risk_scoring_dedup | 4.25 | 5.6 | 11.6 |

## 3. Limitations
- Measurements reflect in-process synthetic event workloads on this specific host and do not constitute 1-10 Gbps physical NIC line-rate certification.
- Component microbenchmarks and full end-to-end event processing latency are reported separately because Python loop/dispatch and SQLite/sessionizer overhead are not additive across isolated microbenchmarks.
