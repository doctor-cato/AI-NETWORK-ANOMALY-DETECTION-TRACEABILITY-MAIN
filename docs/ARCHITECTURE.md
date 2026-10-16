# Architecture — Data Flow and Modules

```mermaid
graph LR
    A[Raw UNSW-NB15<br/>data/raw/] --> B[Validate & Inspect]
    B --> C[EDA / Leakage Audit]
    C --> D[Split train/val/test]
    D --> E[Preprocessing Pipeline<br/>fit on train]
    E --> F[Model Training<br/>Random Forest / Isolation Forest]
    F --> G[Evaluation<br/>metrics + confusion matrix]
    G --> H[Error Analysis
    H --> I[Inference Pipeline<br/>new input -> prediction]
    I --> J[Demo / Report]
```

## Module description

| Module | Path | Role |
|---|---|---|
| Config | `src/network_anomaly/config.py` | Paths, seeds, hyperparameter defaults |
| Data validation | `scripts/validate_data.py` | Load, schema check, summary |
| Preprocessing | `src/network_anomaly/preprocessing/` | Pipeline objects; encoding; scaling |
| Features | `src/network_anomaly/features/` | Feature selection / engineering rules (documented, not over-engineered) |
| Models — Random Forest | `src/network_anomaly/models/random_forest.py` | Supervised classifier |
| Models — Isolation Forest | `src/network_anomaly/models/isolation_forest.py` | Unsupervised detector (if implemented) |
| Evaluation | `src/network_anomaly/evaluation/` | Metrics, confusion matrix, error analysis |
| Inference | `src/network_anomaly/inference/` | Load artifacts; predict new data |
| Visualization | `src/network_anomaly/visualization/` | Plots for EDA, metrics, error analysis |

Updated: 2026-10-16
