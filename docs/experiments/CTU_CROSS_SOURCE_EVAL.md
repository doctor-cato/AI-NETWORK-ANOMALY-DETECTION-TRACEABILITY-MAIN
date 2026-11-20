# Cross-Source & Real-Capture CTU-SME-11 Evaluation (Experiments A–E)

> **Quan hệ kế thừa (#97 AC4 vs #25 / #48):** Tài liệu này đại diện cho phạm vi v2 (`canonical-flow-v2-18`, `AIT-NDS-v2` + `CTU-SME-11`, script `scripts/run_ctu_cross_source_eval.py` và `scripts/run_wp3_controlled_ablation.py`). Các thực nghiệm v1 (`NF-UNSW-NB15-v3`, `PR #49`, `MIN_TTL` ablation trên `ToN-IoT` thuộc `#25` và `#48`) đã được đóng băng chỉ đọc tại [`docs/historical/nf_unsw_nb15_v3/MODEL_AUDIT_TTL_ABLATION.md`](../historical/nf_unsw_nb15_v3/MODEL_AUDIT_TTL_ABLATION.md); `#97` thay thế `#25/#48` trong pipeline v2 mà không trùng lặp dữ liệu hay số liệu.

Real captured evaluation on **CTU-SME-11** (`Honeypot-Assistant-Amazon-Echo1stGen-1`: 76,073 flows; `Experiment-VM-Microsoft-Windows7AD-1`: 175,146 labeled flows (175,101 after deduplicating 45 5-tuple/300s-bucket overlaps with Echo); plus 9,394 `unknown`/`Unmapped` Windows7AD flows excluded from supervised binary metrics). **UGR'16** (Exp E) remains `BLOCKED` (official NESG portal returned HTTP 403 / Portal en Mantenimiento).

## Exp A — In-Domain AIT-NDS-v2 Reference

| Model | AIT-Val F1 | AIT-Val FPR | AIT-Test F1 | AIT-Test FPR | AIT-Test ROC-AUC |
|---|---|---|---|---|---|
| `random_forest` | 0.9997 | 0.0002 | 0.9950 | 0.0002 | 0.9994 |
| `xgboost` | 0.9996 | 0.0002 | 0.9013 | 0.0002 | 0.9884 |
| `isolation_forest` | 0.9213 | 0.0500 | 0.5842 | 0.0290 | 0.8330 |
| `autoencoder` | 0.9215 | 0.0500 | 0.5877 | 0.0276 | 0.5544 |

## Exp B — Zero-Shot Transfer: AIT-NDS-v2 Models -> Real CTU-SME-11

| Model | AIT-Test F1 | CTU-Echo F1 | CTU-Echo Recall | CTU-Echo FPR | CTU-Win7AD F1 | CTU-Win7AD Recall | CTU-Win7AD FPR |
|---|---|---|---|---|---|---|---|
| `random_forest` | 0.9950 | 0.0474 | 0.0264 | 0.0811 | 0.0712 | 0.5412 | 0.1608 |
| `xgboost` | 0.9013 | 0.1436 | 0.0832 | 0.0700 | 0.0738 | 0.5623 | 0.1611 |
| `isolation_forest` | 0.5842 | 0.8853 | 0.9908 | 0.2292 | 0.0464 | 0.9760 | 0.4722 |
| `autoencoder` | 0.5877 | 0.7325 | 0.9990 | 0.6746 | 0.0326 | 0.9921 | 0.6925 |

## Exp C — Reverse Zero-Shot Transfer (`CTU-SME-11` -> `AIT-Test`)

| Model | AIT-Test F1 | AIT-Test Recall | AIT-Test FPR | AIT-Test ROC-AUC |
|---|---|---|---|---|
| `random_forest` | 0.6114 | 0.4465 | 0.0030 | 0.9160 |
| `xgboost` | 0.6254 | 0.4648 | 0.0047 | 0.6427 |
| `isolation_forest` | 0.3196 | 0.5429 | 0.4011 | 0.5796 |
| `autoencoder` | 0.2835 | 0.4952 | 0.4321 | 0.5100 |

## Exp D — Device-Disjoint Cross-Source Transfer (`AIT-Train + CTU-Echo` -> Unseen `CTU-Windows7AD` & `AIT-Test`)

| Model | AIT-Test F1 | Unseen CTU-Win7AD F1 | Unseen CTU-Win7AD Recall | Unseen CTU-Win7AD FPR | Unseen Win7AD ROC-AUC |
|---|---|---|---|---|---|
| `random_forest` | 0.7904 | 0.0928 | 0.6428 | 0.1438 | 0.8280 |
| `xgboost` | 0.7931 | 0.0923 | 0.6340 | 0.1425 | 0.8465 |
| `isolation_forest` | 0.5851 | 0.0403 | 0.8557 | 0.4782 | 0.7359 |
| `autoencoder` | 0.5958 | 0.0474 | 0.9907 | 0.4688 | 0.9520 |

## Within-CTU Temporal Split (`2023-02-20..24` -> Held-out `2023-02-25..26`)

| Model | Late CTU-Echo F1 | Late CTU-Echo Recall | Late CTU-Echo FPR | Late CTU-Win7AD F1 | Late CTU-Win7AD Recall | Late CTU-Win7AD FPR |
|---|---|---|---|---|---|---|
| `random_forest` | 0.9634 | 0.9302 | 0.0011 | 0.0000 | 0.0000 | 0.0005 |
| `xgboost` | 0.9589 | 0.9214 | 0.0006 | 0.0000 | 0.0000 | 0.0010 |
| `isolation_forest` | 0.9132 | 0.8792 | 0.0625 | 0.0000 | 0.0000 | 0.0779 |
| `autoencoder` | 0.2875 | 0.1767 | 0.0709 | 0.0000 | 0.0000 | 0.0413 |

## Exp E — UGR'16 External Generalization

- **Status:** `BLOCKED` (official NESG portal returned HTTP 403 / Portal en Mantenimiento; no synthetic proxy substituted).

## Empirical Feature-Shift Failure Analysis

Median feature shifts explain domain shift behavior between AIT-NDS-v2 and real CTU-SME-11:

| Feature | AIT-Test Attack | AIT-Test Benign | CTU-Echo Attack | CTU-Echo Benign | CTU-Win7AD Attack | CTU-Win7AD Benign |
|---|---|---|---|---|---|---|
| `duration_ms` | 0.0 | 5131.001 | 0.0 | 91.727 | 2.641 | 2.418 |
| `bytes_in` | 231.0 | 1383.0 | 0.0 | 179.0 | 4.0 | 96.0 |
| `bytes_out` | 250.0 | 2492.0 | 0.0 | 222.0 | 0.0 | 61.0 |
| `pkts_in` | 1.0 | 10.0 | 2.0 | 10.0 | 3.0 | 2.0 |
| `pkts_out` | 1.0 | 9.0 | 0.0 | 2.0 | 2.0 | 1.0 |
