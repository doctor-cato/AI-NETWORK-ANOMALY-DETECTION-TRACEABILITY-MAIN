# Cryptographic Performance & Overhead Benchmark (RQ6)

- **Timestamp (UTC):** `2026-11-17T23:04:56.436285+00:00`
- **Host OS / CPU / RAM:** `Windows-11-10.0.26200-SP0` / `12 vCPU` / `15.27 GB`
- **Python / cryptography:** `3.12.10` / `50.0.2`
- **Warm-up:** `200` | **Iterations/size:** `2000`
- **Hypothesis Confirmed:** `True`

| Payload | Plaintext Median | Encrypt (Med / P95 / P99) | Decrypt (Med / P95 / P99) | Encrypt Throughput | Peak Traced RAM |
|---:|---:|---:|---:|---:|---:|
| 256 B | 6.10 us | 9.20 / 13.30 / 33.20 us | 2.20 / 2.60 / 3.10 us | 75,851.2 ops/s | 1.458 MB |
| 1024 B | 8.30 us | 12.20 / 17.30 / 52.00 us | 4.00 / 5.90 / 6.50 us | 59,259.3 ops/s | 3.412 MB |
| 4096 B | 14.60 us | 19.70 / 29.60 / 78.20 us | 8.30 / 15.80 / 16.50 us | 38,617.1 ops/s | 11.234 MB |
