# Cryptographic Performance & Overhead Benchmark (RQ6)

- **Timestamp (UTC):** `2026-11-17T19:02:37.925762+00:00`
- **Host OS / CPU / RAM:** `Windows-11-10.0.26200-SP0` / `12 vCPU` / `15.27 GB`
- **Python / cryptography:** `3.12.10` / `50.0.2`
- **Warm-up:** `200` | **Iterations/size:** `2000`
- **Hypothesis Confirmed:** `True`

| Payload | Plaintext Median | Encrypt (Med / P95 / P99) | Decrypt (Med / P95 / P99) | Encrypt Throughput | Peak Traced RAM |
|---:|---:|---:|---:|---:|---:|
| 256 B | 10.20 us | 11.90 / 38.80 / 107.50 us | 2.30 / 3.90 / 6.40 us | 43,806.2 ops/s | 1.458 MB |
| 1024 B | 8.50 us | 11.50 / 28.00 / 59.60 us | 3.80 / 6.20 / 8.10 us | 52,903.8 ops/s | 3.412 MB |
| 4096 B | 18.35 us | 27.40 / 54.30 / 115.90 us | 15.00 / 24.80 / 38.70 us | 26,661.0 ops/s | 11.234 MB |
