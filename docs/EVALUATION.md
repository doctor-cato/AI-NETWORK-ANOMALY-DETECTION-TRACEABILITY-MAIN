# Đánh giá — Metric, Kết quả v2 & Phân tích Lỗi

> Tài liệu ghi nhận kết quả đánh giá thực nghiệm trên **NetFlow Sentinel v2** (`canonical-flow-v2-18`). Báo cáo v1 trên `NF-UNSW-NB15-v3` đã chuyển sang [`docs/historical/nf_unsw_nb15_v3/`](historical/nf_unsw_nb15_v3/).

---

## 1. Bảng kết quả 4 Mô hình v2 (In-Domain & Real Capture CTU-SME-11)

Nguồn số liệu: `reports/models/*_manifest.json`, [`reports/experiments/ml/model_comparison_report.json`](../reports/experiments/ml/model_comparison_report.json) và [`reports/experiments/ml/ctu_cross_source_eval.json`](../reports/experiments/ml/ctu_cross_source_eval.json).

| Mô hình | Protocol & Threshold | AIT-Val (`377,704`) | AIT-Test (`988,805`) | CTU-Echo Real (`76,073`) | CTU-Win7AD Real (`175,146`) |
|---|---|---|---|---|---|
| **Random Forest** (`b2e42f85...`) | Supervised (`balanced_subsample, leaf=5`, `th = 0.50`) | `F1 = 0.9997`, `P = 0.9998`, `R = 0.9996`, `FPR = 0.000198`, `ROC = 0.9999` | `F1 = 0.9950`, `P = 0.9989`, `R = 0.9911`, `FPR = 0.000246`, `ROC = 0.9994`, `PR = 0.9977`, `CM = [[812780, 200], [1563, 174262]]` | `F1 = 0.0474`, `R = 0.0264`, `FPR = 0.081069`, `ROC = 0.6137`, `PR = 0.6180` | `F1 = 0.0712`, `R = 0.5412`, `FPR = 0.160755`, `ROC = 0.8392`, `PR = 0.4948` |
| **XGBoost** (`33d201f8...`) | Supervised (`th = 0.50`) | `F1 = 0.9996`, `P = 0.9998`, `R = 0.9993`, `FPR = 0.000160`, `ROC = 0.9999` | `F1 = 0.9013`, `P = 0.9989`, `R = 0.8211`, `FPR = 0.000198`, `ROC = 0.9884`, `PR = 0.9728`, `CM = [[812819, 161], [31461, 144364]]` | `F1 = 0.1436`, `R = 0.0832`, `FPR = 0.069980`, `ROC = 0.7017`, `PR = 0.6747` | `F1 = 0.0738`, `R = 0.5623`, `FPR = 0.161131`, `ROC = 0.6978`, `PR = 0.4774` |
| **Isolation Forest** (`11b16900...`) | Benign-only (`th = 0.031268`) | `F1 = 0.9213`, `P = 0.9375`, `R = 0.9057`, `FPR = 0.049991`, `ROC = 0.9705` | `F1 = 0.5842`, `P = 0.7775`, `R = 0.4678`, `FPR = 0.028952`, `ROC = 0.8330`, `PR = 0.6587`, `CM = [[789443, 23537], [93566, 82259]]` | `F1 = 0.8853`, `P = 0.8001`, `R = 0.9908`, `FPR = 0.229182`, `ROC = 0.9571`, `PR = 0.9237` | `F1 = 0.0464`, `R = 0.9760`, `FPR = 0.472185`, `ROC = 0.7649`, `PR = 0.1002` |
| **Autoencoder** (`e6afecef...`) | Benign-only std (`th = 0.000467`) | `F1 = 0.9215`, `P = 0.9375`, `R = 0.9061`, `FPR = 0.049996`, `ROC = 0.9192` | `F1 = 0.5877`, `P = 0.7860`, `R = 0.4693`, `FPR = 0.027637`, `ROC = 0.5544`, `PR = 0.5664`, `CM = [[790512, 22468], [93317, 82508]]` | `F1 = 0.7325`, `P = 0.5783`, `R = 0.9990`, `FPR = 0.674634`, `ROC = 0.7810`, `PR = 0.7146` | `F1 = 0.0326`, `R = 0.9921`, `FPR = 0.692521`, `ROC = 0.7280`, `PR = 0.0204` |

*Lưu ý về CTU-Windows7AD:* `9,394` dòng có nhãn `unknown` (`Unmapped` theo `taxonomy-v2`) được tách riêng và loại khỏi các metric nhị phân có nhãn (riêng Exp C/D/Temporal trong `ctu_cross_source_eval.json` còn loại thêm `45` dòng trùng khóa 5-tuple/300s với `CTU-Echo`, còn `175,101` dòng).

---

## 2. Phân tích Domain Shift & Cross-Source trên CTU-SME-11 (`CTU_CROSS_SOURCE_EVAL.md`)

1. **Zero-shot Synthetic → Real:** Sau khi đồng bộ Zeek L4 payload (`orig_bytes`/`resp_bytes`), sửa `udp_complete * 1000.0 ms` và nới scale floor biến bounded `0.25`, ranking zero-shot cải thiện rõ (`RF Win7AD ROC-AUC = 0.8392`, `XGB Echo ROC-AUC = 0.7017` hết bị đảo dấu, `IF Echo F1 = 0.8853`), nhưng `F1` tuyệt đối của mô hình cây tại ngưỡng `0.50` vẫn thấp (`0.0474` / `0.1436`) do dịch chuyển phân phối nền (`bytes_out` Benign `AIT-Test` median `2492.0` vs `CTU-Echo` `222.0` và `CTU-Win7AD` `61.0`; `duration_ms` Benign tụt từ `5131.001 ms` xuống `91.727 ms` và `2.418 ms`).
2. **Device-Disjoint Adaptation (`Exp D: AIT-Train + CTU-Echo` → unseen `CTU-Win7AD`):** Thêm thiết bị `CTU-Echo` giúp `RF` và `XGB` nâng unseen `CTU-Win7AD ROC-AUC` lên `0.8280` (`R = 0.6428, FPR = 0.1438`) và `0.8465` (`R = 0.6340, FPR = 0.1425`), đồng thời `AE` đạt `ROC-AUC = 0.9520` (`R = 0.9907`).
3. **Reverse Zero-Shot (`Exp C: CTU-SME-11` → `AIT-Test`):** `RF` đạt `F1 = 0.6114` (`ROC-AUC = 0.9160`, `FPR = 0.0030`), `XGB` đạt `F1 = 0.6254`.
4. **Within-CTU Temporal Split (`2023-02-20..24` → `2023-02-25..26`):** `RF` đạt `F1 = 0.9634` (`R = 0.9302, FPR = 0.0011`) trên `CTU-Echo`, nhưng tiếp tục đạt `0.0000` Recall trên `CTU-Win7AD` vì trong 2 ngày cuối của bản capture `Win7AD` không có mẫu Attack có nhãn (`2023-02-25`: 0 attack, `2023-02-26`: 0 attack).
5. **UGR'16 External Validation (`Exp E`):** `BLOCKED` (HTTP 403 / Portal en Mantenimiento). Không có dữ liệu giả thay thế.

---

## 3. Phân tích Mất cân bằng Lớp (RQ2) & Unknown Holdout (RQ4)

- **RQ2 (`reports/experiments/imbalance/rq2_imbalance_report.json`):** Ba lớp hiếm trên `AIT-Test` (`Credential_Attack`: 78, `Post_Exploitation_Discovery`: 39, `Exploitation_And_C2`: 5):
  - `Credential_Attack` có Recall thấp trên cả 5 biến thể (`0.1410` ở `RF`/`RF_CostSensitive`/`XGB_ScalePosWeight`/`IF`, `0.0641` ở `AE`).
  - `Post_Exploitation_Discovery` đạt Recall `0.8974` ở `RF`, `XGB`, `IF` và `0.1026` ở `AE`.
  - `Exploitation_And_C2` đạt `5/5 = 1.0000` (support quá nhỏ N=5), nên `h2_full_confirmed = false`.
- **RQ4 (`reports/experiments/ml/rq4_unknown_attack_report.json`):** Holdout `Exploitation_And_C2` + `Post_Exploitation_Discovery` (loại 100% khỏi Train & Validation, đánh giá trên `44` dòng holdout Test):
  - `Isolation Forest`: Unknown Recall `0.9091` (FPR `0.0290`, calibrated on holdout-filtered Val).
  - `Random Forest`: Unknown Recall `0.9091` (FPR `0.0004`); `XGBoost`: `0.7500` (FPR `0.0003`).
  - `Autoencoder`: Unknown Recall `0.2045` (FPR `0.0276`).
  - `unsupervised_ge_0_75_both = false`: Không coi kết quả holdout trên một simulation testbed là bằng chứng phát hiện zero-day tổng quát.
