# Cryptographic Performance & Overhead Benchmark (RQ6 / Exp 7)

- **Timestamp (UTC):** `2026-11-18T18:04:37.017637+00:00`
- **Host OS / CPU / RAM:** `Windows-11-10.0.26200-SP0` / `12 vCPU` / `15.27 GB`
- **Python / cryptography:** `3.12.10` / `50.0.2`
- **Warm-up:** `200` | **Iterations/size:** `2000`
- **Hypothesis Confirmed:** `True`

## 1. Payload-Level AES-256-GCM Microbenchmark

| Payload | Plaintext Median | Encrypt (Med / P95 / P99) | Decrypt (Med / P95 / P99) | Encrypt Throughput | Peak Traced RAM |
|---:|---:|---:|---:|---:|---:|
| 256 B | 6.10 us | 8.80 / 13.30 / 66.80 us | 2.90 / 4.70 / 6.40 us | 72,177.2 ops/s | 1.458 MB |
| 1024 B | 8.00 us | 10.00 / 11.40 / 26.20 us | 3.70 / 5.50 / 33.70 us | 74,807.5 ops/s | 3.412 MB |
| 4096 B | 14.80 us | 19.00 / 38.40 / 117.30 us | 8.60 / 16.10 / 17.60 us | 36,351.0 ops/s | 11.234 MB |

## 2. System-Level A/B Overhead (Encryption ON vs OFF, `N=500` events x `3` trials)

| Mode | Throughput (flow/s) | Latency Med / P95 (us) | Process CPU Time (s) | Peak Traced RAM (MB) | RSS Delta (MB) |
|---|---:|---:|---:|---:|---:|
| **Encryption OFF (Plaintext Vault)** | 181.2 | 5314.7 / 7490.6 | 5.0469 | 0.05 | None |
| **Encryption ON (AES-256-GCM)** | 121.7 | 7997.3 / 10672.1 | 7.75 | 0.134 | None |

- **Relative Overhead (ON vs OFF):** Throughput delta `-32.85%`, CPU time delta `53.56%`, Median latency delta `+2682.60 us`.
