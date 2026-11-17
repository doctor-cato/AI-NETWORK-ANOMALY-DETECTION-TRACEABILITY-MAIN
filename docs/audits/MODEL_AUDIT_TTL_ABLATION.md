# Audit & Ablation: MIN_TTL Shortcut on NF-UNSW-NB15-v3 (#94, #97)

- **Status:** `COMPLETED_IN_DISTRIBUTION_PARTIAL_CROSS_DATASET`
- **Timestamp (UTC):** `2026-11-17T16:00:01.582836+00:00`
- **Dataset:** `NF-UNSW-NB15-v3` (`4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`)

## In-Distribution Ablation Results (47 vs 46 Features)

| Model | MIN_TTL Importance | 47-Feat F1 | 46-Feat F1 (No MIN_TTL) | F1 Delta |
|---|---:|---:|---:|---:|
| RandomForest | 0.240573 | 0.999886 | 0.999804 | -0.000082 |
| XGBoost | 0.829272 | 0.999984 | 0.999984 | +0.000000 |

## Cross-Dataset Status (NF-CSE-CIC-IDS2018-v3)
- Recorded v1.0.0 baseline RF (with MIN_TTL, 100k sample): `{'accuracy': 0.43399, 'precision': 0.0, 'recall': 0.0, 'f1': 0.0, 'macro_f1': 0.30264506725988327, 'false_positive_rate': 0.38019137389317337, 'confusion_matrix': {'labels': ['Benign (0)', 'Attack (1)'], 'tn': 43399, 'fp': 26621, 'fn': 29980, 'tp': 0, 'matrix': [[43399, 26621], [29980, 0]]}}`
- Ablated 46-feature cross-dataset run: **`BLOCKED`** — Raw NF-CSE-CIC-IDS2018-v3 dataset absent at data\raw\NF-CSE-CIC-IDS2018-v3; 46-feature cross-dataset ablation cannot be run without raw dataset.

## Limitations
- Cross-dataset 46-feature ablation on NF-CSE-CIC-IDS2018-v3 is BLOCKED locally because the raw NF-CSE-CIC-IDS2018-v3 file is not present.
- In-distribution NF-UNSW-NB15-v3 remains accurate after removing MIN_TTL because MAX_TTL and other flow features still reflect testbed structure.
