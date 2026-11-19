# System Performance Benchmark Report (Dynamic Measurement)

- **Executed At (UTC):** `2026-11-19T13:06:01.802232+00:00`
- **Host OS / CPU / RAM:** `Windows-11-10.0.26200-SP0` / `12 vCPU` / `15.27 GB`
- **Python:** `3.12.10` | **AI Readiness:** `4/4 (REAL_MODELS)` | **Runtime Mode:** `deployment` | **OOD Gate:** `FITTED` (`explicit_expected_sha256`)
- **Repeatability Runs:** `3`

## 1. End-to-End Orchestrator Measurement
- **Events Processed:** `200` (latest run)
- **Throughput (Latest / Mean ± Std / CV%):** `16.78 flow/s` / `16.75 ± 0.11` (`CV=0.68%`)
- **E2E Latency (Med / P95 / P99):** `60873.45 / 66623.1 / 71772.4 us` (Med CV=`1.1%`)
- **Vectorized Micro-Batch (`process_batch`, `batch_size=32`) Throughput (Latest / Mean ± Std / CV%):** `389.91 flow/s` / `386.37 ± 12.88` (`CV=3.33%`, amortized Med=`2369.28 us/event`)
- **Replay Throughput (Mean ± Std / CV%):** `399.44 ± 15.47 flow/s` (`CV=3.87%`)
- **Ring Buffer Peak Utilization:** `10.0%` (`dropped=0`)

## 2. Isolated Component Microbenchmarks (Separate from E2E)

| Component | Median (us) | P95 (us) | P99 (us) | Repeat Mean ± Std (us) | CV (%) |
|---|---:|---:|---:|---:|---:|
| collector_decoding | 1.0 | 1.1 | 1.3 | 0.767 ± 0.208 | 27.15% |
| feature_contract_validation | 3.8 | 4.0 | 4.3 | 2.967 ± 0.723 | 24.38% |
| multi_model_ai_inference | 62227.85 | 72913.3 | 87865.2 | 61263.783 ± 856.732 | 1.4% |
| behavioral_vector_build | 24.4 | 30.9 | 40.0 | 31.4 ± 8.888 | 28.31% |
| aes_256_gcm_encrypt | 2.7 | 3.3 | 4.3 | 3.467 ± 1.159 | 33.43% |
| risk_scoring_dedup | 2.7 | 2.9 | 4.0 | 3.367 ± 0.987 | 29.3% |

## 3. Limitations
- Measurements reflect in-process synthetic event workloads on this specific host and do not constitute 1-10 Gbps physical NIC line-rate certification.
- Component microbenchmarks and full end-to-end event processing latency are reported separately because Python loop/dispatch and SQLite/sessionizer overhead are not additive across isolated microbenchmarks.
