# Experiment 5 (RQ3): IP-Independent Session Correlation Benchmark

- **Execution Mode:** `SIMULATION` (Synthetic IP-rotation simulation)
- **Empirical AIT Dataset Status:** `BLOCKED` — Official AIT campaign-linkage ground truth absent or not verified in data\raw\ait; empirical real-dataset validation cannot be claimed from simulation alone.
- **Timestamp (UTC):** `2026-11-17T19:04:42.720488+00:00`

## Simulation Ablation: IP Exact Match vs 16-D Behavioral Vector

| Strategy | Pairwise Precision | Pairwise Recall | Pairwise F1 | False Link Rate | Match Accuracy |
|---|---:|---:|---:|---:|---:|
| Strategy A: IP Exact Match | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.8421 |
| Strategy B: 16-D Behavioral Vector (cos >= 0.85) | 0.1899 | 1.0000 | 0.3191 | 0.8000 | 0.3263 |
| Strategy B (Strict cos >= 0.95) | 0.3846 | 1.0000 | 0.5556 | 0.3000 | 0.7474 |

## Limitations
- Synthetic IP-rotation simulation tests algorithmic behavior only and MUST NOT be treated as empirical validation on real enterprise datasets.
- Official AIT campaign-linkage ground truth absent or not verified in data\raw\ait; empirical real-dataset validation cannot be claimed from simulation alone.
