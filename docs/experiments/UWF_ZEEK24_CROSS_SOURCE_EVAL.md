# UWF-ZeekData24 Supplemental Zero-Shot Evaluation (CC BY 4.0)

- **Role:** Independent Cyber Range Zeek L4-payload cross-source check (`evaluation_only = true`). Does **not** replace `UGR'16` ISP benchmark (`BLOCKED`).
- **Rows:** Total labeled (Zeek unset `''`→`0.0`): **95,871** | Strict complete only (no unset fields): **93,000** | Unmapped excluded: **0**.
- **SYN-only Probe Check (L4 vs L3):** `6,417` unanswered TCP probes, `median(bytes_in) = 0.0`, `zero_rate = 1.0000` → `L4_PAYLOAD_COMPATIBLE_WITH_AIT`.

## Zero-Shot Results on Full Labeled Set (`AIT-Train E0` frozen models)

| Model | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|
| `random_forest` | 0.5213 | 0.0507 | **0.0924** | 0.0466 | 0.9535 | 0.8692 |
| `xgboost` | 0.9529 | 0.9416 | **0.9472** | 0.0466 | 0.9717 | 0.9580 |
| `isolation_forest` | 0.2668 | 0.0897 | **0.1342** | 0.2467 | 0.6788 | 0.6023 |
| `autoencoder` | 0.3666 | 0.2694 | **0.3106** | 0.4660 | 0.3749 | 0.4276 |

## Zero-Shot Results on Strict Complete Subset Only

| Model | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|
| `random_forest` | 0.9844 | 0.0373 | **0.0719** | 0.0006 | 0.9987 | 0.9969 |
| `xgboost` | 0.9993 | 0.9408 | **0.9692** | 0.0006 | 0.9993 | 0.9991 |
| `isolation_forest` | 0.2743 | 0.0768 | **0.1200** | 0.2104 | 0.7042 | 0.6286 |
| `autoencoder` | 0.3785 | 0.2591 | **0.3076** | 0.4402 | 0.3844 | 0.4696 |
