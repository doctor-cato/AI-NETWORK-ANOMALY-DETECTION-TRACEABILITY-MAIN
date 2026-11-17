# Đánh giá — Metric, Kết quả v2 & Phân tích Lỗi

> Tài liệu ghi nhận kết quả đánh giá thực nghiệm trên **NetFlow Sentinel v2** (`canonical-flow-v2-18`). Báo cáo v1 trên `NF-UNSW-NB15-v3` đã chuyển sang [`docs/historical/nf_unsw_nb15_v3/`](historical/nf_unsw_nb15_v3/).

---

## 1. Bảng kết quả 4 Mô hình v2 (In-Domain & Real Capture CTU-SME-11)

Nguồn số liệu: `reports/models/*_manifest.json`, [`reports/experiments/ml/model_comparison_report.json`](../reports/experiments/ml/model_comparison_report.json) và [`reports/experiments/ml/ctu_cross_source_eval.json`](../reports/experiments/ml/ctu_cross_source_eval.json).

| Mô hình | Protocol & Threshold | AIT-Val (`377,704`) | AIT-Test (`923,292`) | CTU-Echo Real (`76,073`) | CTU-Win7AD Real (`175,146`) |
|---|---|---|---|---|---|
| **Random Forest** (`0dd7aaaf...`) | Supervised (`th = 0.50`) | `F1 = 0.9995`, `P = 0.9998`, `R = 0.9992`, `FPR = 0.000184`, `ROC = 0.9999` | `F1 = 0.8997`, `P = 0.9988`, `R = 0.8185`, `FPR = 0.000227`, `ROC = 0.9996`, `PR = 0.9981`, `CM = [[747440, 170], [31891, 143791]]` | `F1 = 0.0000`, `R = 0.0000`, `FPR = 0.000836`, `ROC = 0.7996`, `PR = 0.7637` | `F1 = 0.0000`, `R = 0.0000`, `FPR = 0.013148`, `ROC = 0.6888`, `PR = 0.1199` |
| **XGBoost** (`6bb5a6f2...`) | Supervised (`th = 0.50`) | `F1 = 0.9996`, `P = 0.9998`, `R = 0.9994`, `FPR = 0.000165`, `ROC = 0.9999` | `F1 = 0.8910`, `P = 0.9988`, `R = 0.8042`, `FPR = 0.000225`, `ROC = 0.9786`, `PR = 0.9385`, `CM = [[747442, 168], [34405, 141277]]` | `F1 = 0.0000`, `R = 0.0000`, `FPR = 0.046763`, `ROC = 0.0373`, `PR = 0.3931` | `F1 = 0.0007`, `R = 0.0005`, `FPR = 0.003934`, `ROC = 0.1599`, `PR = 0.0079` |
| **Isolation Forest** (`aca66915...`) | Benign-only (`th = 0.002736`) | `F1 = 0.9213`, `P = 0.9374`, `R = 0.9057`, `FPR = 0.050011` (`empirical_val_fpr = 0.049986`), `ROC = 0.9659` | `F1 = 0.5766`, `P = 0.7461`, `R = 0.4698`, `FPR = 0.037569`, `ROC = 0.7753`, `PR = 0.6353`, `CM = [[719523, 28087], [93138, 82544]]` | `F1 = 0.8527`, `P = 0.8017`, `R = 0.9108`, `FPR = 0.208649`, `ROC = 0.7845`, `PR = 0.6782` | `F1 = 0.0002`, `R = 0.0034`, `FPR = 0.433417`, `ROC = 0.3067`, `PR = 0.0093` |
| **Autoencoder** (`2032f8ca...`) | Benign-only (`th = 0.000228`) | `F1 = 0.9212`, `P = 0.9374`, `R = 0.9054`, `FPR = 0.050001` (`empirical_val_fpr = 0.049996`), `ROC = 0.9615` | `F1 = 0.5788`, `P = 0.7581`, `R = 0.4681`, `FPR = 0.035104`, `ROC = 0.7886`, `PR = 0.6411`, `CM = [[721366, 26244], [93440, 82242]]` | `F1 = 0.7000`, `P = 0.5658`, `R = 0.9176`, `FPR = 0.652024`, `ROC = 0.7588`, `PR = 0.6547` | `F1 = 0.0246`, `R = 0.9146`, `FPR = 0.854472`, `ROC = 0.7813`, `PR = 0.0320` |

*Lưu ý về CTU-Windows7AD:* `9,394` dòng có nhãn `unknown` (`Unmapped` theo `taxonomy-v2`) được tách riêng và loại khỏi các metric nhị phân có nhãn.

---

## 2. Phân tích Domain Shift & Cross-Source trên CTU-SME-11 (`CTU_CROSS_SOURCE_EVAL.md`)

1. **Zero-shot Synthetic → Real failure:** Cả `RF` và `XGBoost` huấn luyện trên `AIT-NDS-v2` bị suy giảm Recall xuống `~0.00` khi áp trực tiếp sang `CTU-Echo` và `CTU-Windows7AD` dù `AIT-Test F1 ~ 0.89–0.90`. Nguyên nhân đo được từ phân phối trung vị (`feature_shift_medians`): `bytes_out` Benign trên `AIT-Test` có median `1676.0`, nhưng trên `CTU-Echo` chỉ là `396.0` (Attack `0.0`) và `CTU-Win7AD` là `93.0` (`duration_ms` Benign tụt từ `5088.19 ms` trên `AIT-Test` xuống `91.727 ms` và `2.417 ms` trên CTU).
2. **Device-Disjoint Adaptation (`AIT-Train + CTU-Echo` → unseen `CTU-Win7AD`):** Thêm thiết bị `CTU-Echo` khi huấn luyện giúp `RF` và `XGB` nâng unseen `CTU-Win7AD ROC-AUC` lên `0.7880` (`R = 0.5074, FPR = 0.1700`) và `0.8305` (`R = 0.5039, FPR = 0.1938`).
3. **Within-CTU Temporal Split (`2023-02-20..24` → `2023-02-25..26`):** `RF` đạt `F1 = 0.9600` (`R = 0.9245, FPR = 0.0020`) trên `CTU-Echo`, nhưng tiếp tục đạt `0.0000` Recall trên `CTU-Win7AD` vì trong 2 ngày cuối của bản capture `Win7AD` không có mẫu Attack có nhãn (`2023-02-25`: 0 attack, `2023-02-26`: 0 attack).
4. **UGR'16 External Validation:** `BLOCKED` (HTTP 403 / Portal en Mantenimiento). Không có dữ liệu giả thay thế.

---

## 3. Phân tích Mất cân bằng Lớp (RQ2) & Unknown Holdout (RQ4)

- **RQ2 (`reports/experiments/imbalance/rq2_imbalance_report.json`):** Ba lớp hiếm trên `AIT-Test` (`Credential_Attack`: 78, `Post_Exploitation_Discovery`: 37, `Exploitation_And_C2`: 5):
  - `Credential_Attack` có Recall thấp trên cả 5 biến thể (`0.1410` ở `RF`/`RF_CostSensitive`/`XGB_ScalePosWeight`, `0.1667` ở `IF`, `0.0641` ở `AE`).
  - `Post_Exploitation_Discovery` đạt Recall `0.9459` ở `RF`, `XGB`, `IF` và `0.1081` ở `AE`.
  - `Exploitation_And_C2` đạt `5/5 = 1.0000` (support quá nhỏ N=5), nên `h2_full_confirmed = false`.
- **RQ4 (`reports/experiments/ml/rq4_unknown_attack_report.json`):** Holdout `Exploitation_And_C2` + `Post_Exploitation_Discovery` (loại `209` dòng Train, `58` dòng Val; đánh giá trên `42` dòng holdout Test):
  - `Isolation Forest`: Unknown Recall `0.9524` (`40/42`, FPR `0.0376`).
  - `Random Forest` & `XGBoost`: Unknown Recall `0.8333` (`35/42`, FPR `0.0004`).
  - `Autoencoder`: Unknown Recall `0.2143` (`9/42`, FPR `0.0351`).
  - `unsupervised_ge_0_75_both = false`: Không coi kết quả holdout trên một simulation testbed là bằng chứng phát hiện zero-day tổng quát.
