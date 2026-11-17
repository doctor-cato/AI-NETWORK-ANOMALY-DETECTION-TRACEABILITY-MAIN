# Research Experiment RQ5: Fixed vs Adaptive Key Rotation (SIMULATION)

- **Execution Mode:** `SIMULATION`
- **Timestamp (UTC):** `2026-11-17T15:56:56.059535+00:00`
- **Hypothesis Confirmed (>= 70% exposure reduction):** `True`

## Computed Metrics from Recorded Timeline

| Metric | Fixed 30m Schedule | Adaptive Risk (>= 85) | Delta / Reduction |
|---|---:|---:|---:|
| Total Key Rotations | 1 | 10 | - |
| Max Attack-Key Exposure (min) | 20.0000 | 2.5002 | 87.50% |
| Blast Radius (max attack records / key) | 40 | 6 | 85.00% |
| Detection-to-Rotation (s) | 1200.0 | 0.01 | - |

## Limitations
- Results come from a deterministic 60-minute discrete-time lab simulation using real KeyManager/KeyRotationPolicy objects, not long-duration production traffic.
