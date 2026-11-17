# Cryptographic Performance & Overhead Benchmark (RQ6)

- **Timestamp (UTC):** `2026-11-17T15:51:20.899985+00:00`
- **Host OS / CPU / RAM:** `Windows-11-10.0.26200-SP0` / `12 vCPU` / `15.27 GB`
- **Python / cryptography:** `3.12.10` / `50.0.2`
- **Warm-up:** `200` | **Iterations/size:** `2000`
- **Hypothesis Confirmed:** `True`

| Payload | Plaintext Median | Encrypt (Med / P95 / P99) | Decrypt (Med / P95 / P99) | Encrypt Throughput | Peak Traced RAM |
|---:|---:|---:|---:|---:|---:|
| 256 B | 6.10 us | 8.10 / 9.90 / 30.60 us | 2.10 / 2.30 / 3.10 us | 85,065.5 ops/s | 1.458 MB |
| 1024 B | 7.80 us | 10.70 / 23.00 / 92.90 us | 4.65 / 6.20 / 9.00 us | 56,106.5 ops/s | 3.412 MB |
| 4096 B | 14.80 us | 19.00 / 31.80 / 85.10 us | 8.50 / 16.20 / 19.40 us | 40,028.7 ops/s | 11.234 MB |
