# System Performance Benchmark Report (Dynamic Measurement)

- **Executed At (UTC):** `2026-11-19T10:41:49.915464+00:00`
- **Host OS / CPU / RAM:** `Windows-11-10.0.26200-SP0` / `12 vCPU` / `15.27 GB`
- **Python:** `3.12.10` | **AI Readiness:** `4/4 (REAL_MODELS)` | **Runtime Mode:** `deployment` | **OOD Gate:** `FITTED` (`explicit_expected_sha256`)
- **Repeatability Runs:** `3`

## 1. End-to-End Orchestrator Measurement
- **Events Processed:** `200` (latest run)
- **Throughput (Latest / Mean ± Std / CV%):** `20.19 flow/s` / `18.81 ± 1.86` (`CV=9.88%`)
- **E2E Latency (Med / P95 / P99):** `46745.5 / 61919.6 / 67205.7 us` (Med CV=`15.7%`)
- **Replay Throughput (Mean ± Std / CV%):** `19.09 ± 0.84 flow/s` (`CV=4.41%`)
- **Ring Buffer Peak Utilization:** `10.0%` (`dropped=0`)

## 2. Isolated Component Microbenchmarks (Separate from E2E)

| Component | Median (us) | P95 (us) | P99 (us) | Repeat Mean ± Std (us) | CV (%) |
|---|---:|---:|---:|---:|---:|
| collector_decoding | 1.0 | 1.1 | 1.2 | 0.833 ± 0.208 | 24.98% |
| feature_contract_validation | 3.7 | 3.8 | 4.4 | 3.3 ± 0.693 | 20.99% |
| multi_model_ai_inference | 61458.1 | 90122.5 | 143819.5 | 51451.5 ± 8666.666 | 16.84% |
| behavioral_vector_build | 26.45 | 47.3 | 105.9 | 33.383 ± 6.03 | 18.06% |
| aes_256_gcm_encrypt | 3.1 | 3.5 | 4.5 | 3.933 ± 0.764 | 19.42% |
| risk_scoring_dedup | 2.9 | 3.1 | 5.2 | 3.667 ± 0.681 | 18.56% |

## 3. Limitations
- Measurements reflect in-process synthetic event workloads on this specific host and do not constitute 1-10 Gbps physical NIC line-rate certification.
- Component microbenchmarks and full end-to-end event processing latency are reported separately because Python loop/dispatch and SQLite/sessionizer overhead are not additive across isolated microbenchmarks.
