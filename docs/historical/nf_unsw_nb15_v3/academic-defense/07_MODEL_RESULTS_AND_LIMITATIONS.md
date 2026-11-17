# 07 — Tổng hợp Kết quả Thực nghiệm, OOD & Giới hạn Khoa học

> **Quy tắc bắt buộc:** Tuyệt đối **không** gộp chung kết quả của **Validation**, **Held-out Test**, **Demo CSV 200 dòng** và **Cross-Dataset** vào một bảng mập mờ. Mỗi tập đánh giá có mục đích, phân bố và ý nghĩa khác nhau.

---

## 1. Kết quả trên Validation (`345.371` dòng: `314.871` Benign / `30.500` Attack)

| Mô hình | Nguồn manifest | Accuracy | Precision | Recall | F1 (Attack) | FPR | Ghi chú ngưỡng / giao thức |
|---|---|---:|---:|---:|---:|---:|---|
| **Random Forest** | [random_forest_manifest.json](../../reports/models/random_forest_manifest.json) | 0,999977 | 0,999836 | 0,999902 | 0,999869 | 0,000016 | `CM=[[314866, 5], [3, 30497]]`, ngưỡng `0.5` |
| **XGBoost** | [xgboost_manifest.json](../../reports/models/xgboost_manifest.json) | 0,999997 | 0,999967 | 1,000000 | 0,999984 | 0,000003 | `CM=[[314870, 1], [0, 30500]]`, ngưỡng `0.5` |
| **Isolation Forest** | [evaluation_report.md](../../reports/experiments/isolation_forest/evaluation_report.md) | — | 0,327973 | 0,887892 | 0,479008 | 0,175183 | Hiệu chuẩn trên `314.871` Benign + `30.319` Known (`181` Unknown tách riêng), chọn `-0,033527` |
| **Autoencoder (Active)** | [metrics.json](../../reports/evaluation/autoencoder/metrics.json) | 0,876417 | 0,184470 | 0,116754 | 0,143001 | 0,049998 | `ae_fpr_constrained_20261115T163000Z`, `Val FPR <= 0.05`, ngưỡng `17.234.985,79` |

---

## 2. Kết quả trên Held-out Test (`345.953` dòng: `315.357` Benign / `30.596` Attack)

Tập Test được mở khóa **một lần sau khi đóng băng mô hình và ngưỡng**:

| Mô hình | Run ID | TN | FP | FN | TP | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Random Forest** (`MODEL_VALIDATED`) | `rf-heldout-ea330b9` | 315.350 | 7 | 2 | 30.594 | 0,999974 | 0,999771 | 0,999935 | 0,999853 | 0,000022 | — | — |
| **XGBoost** (`RESEARCH_ONLY`) | `xgb-baseline-1794755807` | 315.356 | 1 | 0 | 30.596 | 0,999997 | 0,999967 | 1,000000 | 0,999984 | 0,000003 | 1,000000 | 1,000000 |
| **Isolation Forest** (`RESEARCH_ONLY`) | `if-c4-20261115T055359Z` | 264.755 | 50.602 | 3.068 | 27.528 | 0,844863 | 0,352336 | 0,899725 | 0,506374 | 0,160459 | 0,893730 | 0,288753 |
| **Autoencoder** (`RESEARCH_ONLY`) | `ae_fpr_constrained_20261115T163000Z` | 300.169 | 15.188 | 27.253 | 3.343 | 0,877321 | 0,180400 | 0,109263 | 0,136096 | 0,048161 | 0,630310 | 0,161465 |

### Ý nghĩa của TN, FP, FN, TP trong bối cảnh An ninh mạng (NIDS)
- **TN (True Negative):** Lưu lượng Benign được dự đoán đúng là Benign (không làm phiền vận hành).
- **FP (False Positive — Báo động giả):** Lưu lượng Benign bị gắn nhầm là Attack. Với Isolation Forest (`50.602` FP, `FPR = 16,05%`) hay Autoencoder (`15.188` FP, `FPR = 4,82%`), số cảnh báo giả quá lớn sẽ gây quá tải cho đội ngũ SOC nếu chạy tự động.
- **FN (False Negative — Bỏ lọt tấn công):** Lưu lượng Attack bị đoán nhầm là Benign. Autoencoder để lọt `27.253 / 30.596` tấn công (`Recall = 10,93%`) do nhiều dòng tấn công có biên độ đặc trưng nằm trong dải tái tạo MSE thấp hơn ngưỡng `17.234.985,79`.
- **TP (True Positive):** Lưu lượng Attack được phát hiện đúng.

### Đánh giá Known vs Unknown Attacks (chỉ áp dụng cho Unsupervised IF & AE trên Test)
Trong tập Test có `29.300` Known Attacks (7 họ) và `1.296` Unknown Attacks (`1.260` `Backdoor` + `36` `Worms`, bị loại hoàn toàn khỏi bước chọn ngưỡng Validation):

| Mô hình Unsupervised | Known Attack Recall (`29.300`) | Unknown Attack Recall (`1.296`) | Backdoor (`1.260`) | Worms (`36`) |
|---|---:|---:|---:|---:|
| **Isolation Forest** (`if-c4-20261115T055359Z`) | **0,9012** (`26.406/29.300`) | **0,8657** (`1.122/1.296`) | `0,8675` (`1.093/1.260`) | `0,8056` (`29/36`) |
| **Autoencoder** (`ae_fpr_constrained_20261115T163000Z`) | **0,1113** (`3.262/29.300`) | **0,0625** (`81/1.296`) | `0,0627` (`79/1.260`) | `0,0556` (`2/36`) |

> **Cảnh báo:** Tỷ lệ phát hiện `86,57%` của Isolation Forest trên `{Backdoor, Worms}` là trong cùng testbed IXIA PerfectStorm năm 2015 (nơi các cuộc tấn công có phân bố TTL/gói khác hẳn nền Benign của testbed), **không** phải bằng chứng phát hiện zero-day trên mạng thực tế.

---

## 3. Kết quả Cross-Dataset (`NF-CSE-CIC-IDS2018-v3` — 100.000 dòng)

Kiểm chứng ngoài miền tại [cross_dataset_evaluation_results.json](../../reports/evaluation/cross_dataset_evaluation_results.json) (dùng mô hình Random Forest `rf-baseline-1794068628` trên `70.020` Benign + `29.980` `FTP-BruteForce`):
- `TN = 43.399`, `FP = 26.621`, `FN = 29.980`, `TP = 0`
- `Accuracy = 0,43399`, `Precision = 0,0`, **`Recall = 0,0`**, `F1 = 0,0`, **`FPR = 0,380191`**
- **OOD / Drift quan sát:** **`99.990 / 100.000` (`99,99%`) dòng** có `MIN_TTL` nằm ngoài bộ giá trị đường tắt `{31, 62, 254, 255}` của `NF-UNSW-NB15-v3`. Điều này chứng minh trực tiếp mô hình cây supervised đã học phụ thuộc vào đặc trưng riêng của testbed 2015.

---

## 4. Khác biệt giữa Metrics Thực nghiệm và Demo CSV 200 dòng

- Tệp demo `data/demo/demo_flows.csv` được tạo bằng `scripts/prepare_demo_dataset.py` từ **Validation partition** (`0` overlap với Train và Test), gồm **`200` dòng cân bằng `100` Benign / `100` Attack** (`seed=42`).
- **Không được coi đây là phân bố thực tế:** Tỷ lệ Attack trong demo là `50%`, khác hoàn toàn tỷ lệ `5,40%` của dataset gốc.
- **Cơ chế OOD Abstention (`ABSTAINED_OOD`) khi chạy Demo trên Desktop App (`v1.0.0`):**
  - Trong 200 dòng của `demo_flows.csv`, có **2 dòng (`row_id = 92156` và `1020383`) có `MIN_TTL == 0`** (TTL ban đầu không quan sát được).
  - Cổng `OODValidator` trong `desktop_csv.py` từ chối suy luận 2 dòng này (`predicted_label = null`, `predicted_class = "ABSTAINED_OOD"`, `risk_level = "ABSTAINED_OOD"`), và **chỉ chấm Confusion Matrix trên `198` dòng hợp lệ** (`prediction_coverage = 0,9900`, `abstained_rows = 2`).
  - Trong kiểm thử E2E của PR #72 trên bộ cài `v1.0.0`, cả 4 mô hình đều chạy thành công qua 200 dòng demo (`198` dòng đánh giá + `2` dòng `ABSTAINED_OOD`).

---

## 5. Hạn chế và Lý do KHÔNG công bố là Production IDS

1. **Dữ liệu cũ & đường tắt testbed:** Capture từ 2015, phụ thuộc mạnh vào `MIN_TTL` và trùng lặp vector `49,98%–53,21%`.
2. **Suy giảm ngoài miền:** Cross-dataset trên `NF-CSE-CIC-IDS2018-v3` cho `Recall = 0,0`.
3. **Hiệu năng Autoencoder thấp dưới ngưỡng bảo thủ:** Khi siết `Val FPR <= 0,05` mà không scale 47 đặc trưng, Autoencoder chỉ đạt `Recall = 10,93%` (`F1 = 0,1361`) trên Test.
4. **Isolation Forest FPR cao:** `FPR = 16,05%` trên Test không phù hợp cảnh báo tự động trong vận hành.
5. **Thiếu bắt gói trực tiếp và bảo vệ chủ động thật:** Hệ thống chỉ phân tích tệp CSV NetFlow offline; Issue #27 Security Response chỉ là **Dry-Run (`executed = false`)**; không đọc PCAP trực tiếp, không có EDR/payload inspection.
6. **Phân phối công khai & Windows VM sạch còn chờ nghiệm thu (`Issue #73`):** Quyền tái phân phối công khai `.joblib` dẫn xuất UQ `454104` đang `BLOCKED` (`approved=false`), và kiểm thử trên máy ảo Windows 10/11 sạch độc lập đang chuyển theo dõi tại #73.
