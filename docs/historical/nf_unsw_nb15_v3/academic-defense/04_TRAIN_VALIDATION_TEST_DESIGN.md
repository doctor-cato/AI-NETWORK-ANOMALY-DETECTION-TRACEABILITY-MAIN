# 04 — Thiết kế Chia Tập Train / Validation / Test và Chống Rò rỉ Dữ liệu

> **Trạng thái kiểm chứng:** `IMPLEMENTED`, `TESTED` (`tests/unit/test_nf_unsw_nb15_v3_split.py`, `tests/unit/test_split_protocol.py`) và `EXPERIMENTALLY VALIDATED` trên `NF-UNSW-NB15-v3.csv` (`reports/splits/nf_unsw_nb15_v3_split_manifest.json`, SHA-256 `bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88`).

---

## 1. Nguồn phân chia dữ liệu và chiến lược chia

- `NF-UNSW-NB15-v3.csv` là **một tệp CSV duy nhất (`2.365.424` dòng)**, không có official train/test CSV tách sẵn như bộ UNSW-NB15 (2015) cũ.
- Dự án **không** dùng `train_test_split` ngẫu nhiên (random split) vì random split trên dữ liệu lưu lượng mạng theo thời gian sẽ đưa các luồng cùng một phiên tấn công hoặc cùng cửa sổ thời gian vào cả Train lẫn Test (temporal/session leakage).
- Thay vào đó, `scripts/split_and_audit_nf_unsw_nb15_v3.py` và `src/network_anomaly/data/split.py` áp dụng giao thức **`nf-unsw-nb15-v3-chronological-group-purged-v1`**:
  1. Sắp xếp toàn bộ `2.365.424` dòng theo **`FLOW_START_MILLISECONDS` tăng dần**, lấy chỉ số dòng gốc 0-based (`source_row_index`) làm tie-breaker tất định (`RANDOM_SEED = 42`).
  2. Đặt điểm cắt mục tiêu theo tỷ lệ **70% Train / 15% Validation / 15% Test**.
  3. Chèn **Purge Gap 5 phút (`300.000 ms`)** tại hai ranh giới Train→Validation và Validation→Test để tách biệt hoàn toàn các `canonical_flow_group` (5-tuple hai chiều + bucket 5 phút) và ngăn flow kéo dài vượt biên (`FLOW_END_MILLISECONDS`). Các dòng rơi vào khoảng đệm không bị xóa âm thầm mà được ghi vào hai tệp chỉ số purged riêng.

---

## 2. Bảng đối chiếu số dòng, thời gian và phân bố nhãn thực tế

Số liệu trích xuất trực tiếp từ [nf_unsw_nb15_v3_split_manifest.json](../../reports/splits/nf_unsw_nb15_v3_split_manifest.json):

| Phân vùng | Số dòng | Tỷ lệ (%) | Khoảng thời gian UTC (`FLOW_START_MILLISECONDS`) | Benign (`Label=0`) | Attack (`Label=1`) | Tỷ lệ Attack | Index SHA-256 (tiền tố) |
|---|---:|---:|---|---:|---:|---:|---|
| **Train** | 1.655.797 | 70,00% | `2015-01-22 11:49:36` → `2015-02-18 05:42:13` | 1.590.608 | 65.189 | 3,94% | `a09ba175...` |
| *Purged (Train–Val)* | *9.443* | *0,40%* | `2015-02-18 05:42:13` → `2015-02-18 05:47:13` | *8.546* | *897* | *9,50%* | `3bdf9ef3...` |
| **Validation** | 345.371 | 14,60% | `2015-02-18 05:47:13` → `2015-02-18 09:08:16` | 314.871 | 30.500 | 8,83% | `7d41a71a...` |
| *Purged (Val–Test)* | *8.860* | *0,37%* | `2015-02-18 09:08:16` → `2015-02-18 09:13:16` | *8.349* | *511* | *5,77%* | `ac7f1de3...` |
| **Test (Held-out)** | 345.953 | 14,63% | `2015-02-18 09:13:16` → `2015-02-18 12:29:24` | 315.357 | 30.596 | 8,84% | `63e2e081...` |
| **Tổng cộng CSV** | **2.365.424** | **100,00%** | `2015-01-22` → `2015-02-18` | **2.237.731** | **127.693** | **5,40%** | `4ebb97bd...` |

### Phân bố chi tiết 9 họ `Attack` trên từng phân vùng:

| Họ `Attack` | Train | Purged (T–V) | Validation | Purged (V–T) | Test | Ghi chú vai trò |
|---|---:|---:|---:|---:|---:|---|
| `Benign` | 1.590.608 | 8.546 | 314.871 | 8.349 | 315.357 | Lớp âm tính (`Label=0`) |
| `Exploits` | 21.416 | 223 | 10.294 | 295 | 10.520 | Known attack |
| `Fuzzers` | 17.599 | 335 | 8.495 | 65 | 7.322 | Known attack |
| `Generic` | 9.243 | 145 | 5.137 | 15 | 5.111 | Known attack |
| `Reconnaissance` | 8.304 | 115 | 4.107 | 84 | 4.464 | Known attack |
| `DoS` | 3.238 | 63 | 1.445 | 41 | 1.193 | Known attack |
| `Shellcode` | 1.407 | 12 | 556 | 10 | 396 | Known attack |
| `Analysis` | 646 | 1 | 285 | 0 | 294 | Known attack |
| `Backdoor` | 3.253 | 2 | 144 | 0 | 1.260 | **Unknown holdout ở C4 (IF/AE)** |
| `Worms` | 83 | 1 | 37 | 1 | 36 | **Unknown holdout ở C4 (IF/AE)** |

---

## 3. Vai trò riêng biệt của Train, Validation và Held-out Test

| Tập dữ liệu | Mục đích hợp lệ | Hoạt động bị CẤM tuyệt đối |
|---|---|---|
| **Train** (`1.655.797`) | Fit `TrainOnlyPreprocessor` (median/mode/vocabulary); fit cây **RF** & **XGBoost** (dùng `Label`); fit **Isolation Forest** & **Autoencoder** (chỉ lọc `Label==0` benign-only, không dùng nhãn khi tối ưu). | Không dùng để báo cáo kết quả tổng quát hóa cuối. |
| **Validation** (`345.371`) | Kiểm tra hiệu năng ngoài Train; hiệu chuẩn ngưỡng $\tau$ cho **Isolation Forest** (`-0,033527`) và **Autoencoder** (`17.234.985,79`) *chỉ trên Benign + Known Attacks* (tách `{Backdoor, Worms}`); phân tích lỗi & kiểm toán chẩn đoán (`rf_baseline_validation_audit.json`); trích **200 dòng demo** (`scripts/prepare_demo_dataset.py`). | Không được fit lại `TrainOnlyPreprocessor`; không dùng Unknown `{Backdoor, Worms}` để chọn ngưỡng $\tau$. |
| **Test (Held-out)** (`345.953`) | **Chỉ dùng để đánh giá một lần cuối sau khi mô hình và ngưỡng đã đóng băng** (`--evaluate-test` / `evaluate_random_forest.py`). | **Cấm tuyệt đối** dùng Test để chọn đặc trưng, chỉnh hyperparameter, fit scaler/imputer hay chọn ngưỡng $\tau$. |

---

## 4. Mất cân bằng lớp, Dữ liệu trùng lặp và Rủi ro Shortcut Learning

### 4.1. Mất cân bằng lớp (`Class Imbalance`)
- Trong toàn bộ dataset, Attack chỉ chiếm **5,40%** (Train **3,94%**, Validation **8,83%**, Test **8,84%**); họ `Worms` chỉ có `83` dòng Train, `37` Validation và `36` Test.
- **Cách xử lý trong codebase:** Không dùng SMOTE hay oversampling/undersampling nhân tạo; giữ nguyên phân bố tự nhiên theo thời gian, dùng `class_weight=None` ở RF (`random_forest_manifest.json`), đánh giá bằng **Precision, Recall, F1, Macro-F1, FPR, ROC-AUC, PR-AUC và breakdown từng họ Attack** thay vì chỉ nhìn Accuracy (vì đoán toàn bộ là Benign vẫn đạt ~91,16% Accuracy trên Test).

### 4.2. Kiểm toán trùng lặp & Rò rỉ (`Leakage Audit`)
Kết quả tại [nf_unsw_nb15_v3_split_manifest.json](../../reports/splits/nf_unsw_nb15_v3_split_manifest.json):
- `exact_full_row_overlap`: **0**
- `source_feature_overlap` (53 cột): **0**
- `canonical_flow_group_overlap` (5-tuple + bucket 5 phút): **0**
- `temporal_boundary_violations` & `flow_end_crossings`: **0** (khoảng đệm thực tế `train→val = 236.165 ms`, `val→test = 252.058 ms`; mọi flow dài tối đa `120.948 ms < 300.000 ms`).
- `binary_label_conflicts`: **0**
- **Tuy nhiên**, có tỷ lệ trùng lặp vector 47 đặc trưng ML (`ml_feature_overlap`) rất lớn giữa các phân vùng:
  - Train vs Validation: `61.007` vector trùng → ảnh hưởng **`49,98%` dòng Validation** (`172.621 / 345.371`).
  - Train vs Test: `59.966` vector trùng → ảnh hưởng **`53,21%` dòng Test** (`184.067 / 345.953`).
  - Lý do: các mẫu giao thức chuẩn (TCP handshake, DNS query lặp lại giữa các endpoint khác nhau tại thời điểm khác nhau) tạo ra cùng vector 47 thông số thống kê dù khác IP/timestamp.

### 4.3. Tại sao Accuracy / F1 gần 100% không chứng minh model chạy tốt ngoài thực tế?

Bằng chứng thực nghiệm tại [rf_baseline_validation_audit.json](../../reports/models/rf_baseline_validation_audit.json) và [cross_dataset_evaluation_results.json](../../reports/evaluation/cross_dataset_evaluation_results.json) trả lời rõ câu hỏi này:

1. **Đường tắt `MIN_TTL` của testbed IXIA PerfectStorm:** Một cây quyết định đơn **chỉ dùng đúng 1 cột `MIN_TTL`** đã đạt **Validation Accuracy = `0,999849`** (`MIN_TTL = 31` là `100%` Benign trên `308.033` dòng Validation; `MIN_TTL ∈ {62, 254, 255}` là `99,997%` Attack trên `30.450` dòng Validation).
2. **Không chỉ `MIN_TTL`, toàn bộ không gian 37 feature còn lại cũng phân tách mạnh trong cùng cửa sổ `2015-02-18`:** Khi bỏ `MIN_TTL`/`MAX_TTL` (probe C1) hoặc bỏ Top-10 feature (probe C5), mô hình chẩn đoán vẫn đạt `0,999902` trên Validation vì cùng nằm trong một môi trường lab tĩnh.
3. **Kiểm chứng chéo (Cross-Dataset Shift) sụp đổ:** Khi lấy đúng mô hình Random Forest đạt `F1 = 0,999853` trên Held-out Test đi đánh giá trên **`100.000` dòng `NF-CSE-CIC-IDS2018-v3`** (`70.020` Benign + `29.980` `FTP-BruteForce`), kết quả là **`TP = 0`, `FN = 29.980`, `Recall = 0,0`, `F1 = 0,0`, `FPR = 0,380191`** (`99,99%` dòng có `MIN_TTL` lệch khỏi `{31, 62, 254, 255}`).
4. **Hạn chế đối chiếu chỉ số nén lịch sử:** [split_membership_audit_report.md](../../reports/splits/split_membership_audit_report.md) ghi nhận `MEMBERSHIP_EQUIVALENCE: NOT_VERIFIED` ở mức SHA byte-level với file index của run RF rất cũ do index cũ không lưu trong Git, dù mọi ràng buộc row count và hash chain hiện tại đều khớp.
