# Random Forest Baseline — Independent Test Evaluation & Error Analysis Report

- **Issue Scope**: Issue #12 (Held-out Test Evaluation) & Issue #13 (Error Analysis)
- **Execution Status**: `IMPLEMENTED & UNIT-TESTED | REAL-DATA TEST EXECUTION BLOCKED (MISSING LOCAL BINARIES)`
- **Evaluation Run ID**: `PENDING-LOCAL-BINARY-ARTIFACTS`
- **Model Configuration ID**: `rf-baseline-canonical-v1`
- **Protocol Version**: `rf-baseline-nf-unsw-nb15-v3-v1`
- **Feature Contract**: `nf-unsw-nb15-v3-baseline-47` (`47` canonical NetFlow v3 features)

---

## 1. Executive Summary

Tài liệu này báo cáo quy trình đánh giá độc lập mô hình **Random Forest Baseline** trên tập **Held-out Test** (Issue #12) và phân tích chuyên sâu **False Positives (FP), False Negatives (FN), phân rã theo họ tấn công (`Attack` category), đặc trưng ranh giới quyết định và giới hạn dữ liệu** (Issue #13) trên bộ dữ liệu chuẩn **NF-UNSW-NB15-v3**.

- **Tính toàn vẹn quy trình (Test-Lock Integrity)**: Toàn bộ pipeline đánh giá Test (`src/network_anomaly/evaluation/test_evaluation.py`) và phân tích lỗi (`src/network_anomaly/evaluation/error_analysis.py`) thực thi cơ chế **fail-closed**: xác minh mã băm SHA-256 của dữ liệu gốc, split manifest, `test_indices.csv.gz` (khóa `index_sha256`), bộ tiền xử lý `TrainOnlyPreprocessor` (fit độc quyền trên Train) và mô hình `RandomForestModel` (`rf-baseline-canonical-v1`).
- **Không rò rỉ dữ liệu (Zero Leakage)**: Tập Test (`345,953` bản ghi) hoàn toàn tách biệt với Train (`1,655,797` bản ghi) và Validation (`345,371` bản ghi). Bộ tiền xử lý chỉ gọi `.transform(X_test_raw)` và mô hình chỉ gọi `.predict(X_test)` / `.predict_proba(X_test)` với ngưỡng cố định `0.5` — tuyệt đối không huấn luyện lại, không tinh chỉnh siêu tham số và không tối ưu ngưỡng.
- **Trạng thái thực thi thực nghiệm tại môi trường hiện tại**: Do các tệp nhị phân dung lượng lớn (`.csv`, `.csv.gz`, `.joblib`) nằm trong `.gitignore` và được lưu trữ trên máy huấn luyện cục bộ (`D:/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN`), môi trường hiện tại ghi nhận trạng thái **`BLOCKED / NOT VERIFIED`** đối với số liệu chạy trực tiếp trên tập Test thật, tuyệt đối không bịa số liệu hay lấy số liệu Validation thay cho Test.

---

## 2. Evaluation Scope & Data Integrity

### 2.1. Truy vết mã băm (Provenance Lineage & SHA-256 Verification)

| Thành phần | Đường dẫn chuẩn | SHA-256 đã xác minh trong Manifest | Trạng thái trên đĩa cục bộ |
| :--- | :--- | :--- | :---: |
| **Raw Dataset CSV** | `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv` | `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5` | `MISSING (.gitignore)` |
| **Split Manifest** | `reports/splits/nf_unsw_nb15_v3_split_manifest.json` | `1ba6b2ef2c5db74f0937ab9de0b67212e21b6819c59c839d4dab034ff4d120a8` | `PRESENT & VERIFIED` |
| **Test Indices** | `data/processed/splits/test_indices.csv.gz` | `90219f75a680705f2e9982f93405f29b4df2ba00a847d9ba04832db6a26b5eae` | `MISSING (.gitignore)` |
| **Preprocessing Manifest** | `reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json` | `666a7aaea7c65513d9a681e17fa976db0946e001a164a25ff208e08da95b67ba` | `PRESENT & VERIFIED` |
| **Preprocessor Artifact** | `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib` | `e1e89bde7c6504cc26bc48a5ef41fc151f762dc61fe8f053252fb32035fb25e6` | `MISSING (.gitignore)` |
| **RF Model Manifest** | `reports/models/random_forest_manifest.json` | `2ea97a57c6917c2f39e94aa5795cbd83f98b2f7bbf09d7f5454344f19d08dcf3` | `PRESENT & VERIFIED` |
| **RF Model Artifact** | `artifacts/models/random_forest/random_forest_baseline.joblib` | `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea` | `MISSING (.gitignore)` |

### 2.2. Danh sách tệp nhị phân bị thiếu tại môi trường hiện tại (nếu có)

- `dataset_csv: data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv`
- `test_indices: data/processed/splits/test_indices.csv.gz`
- `preprocessor_artifact: artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib`
- `model_artifact: artifacts/models/random_forest/random_forest_baseline.joblib`

---

## 3. Model & Preprocessing Configuration

### 3.1. Cấu hình mô hình Random Forest Baseline đã khóa (`rf-baseline-canonical-v1`)

| Tham số | Giá trị khóa (Locked Value) | Ý nghĩa khoa học |
| :--- | :---: | :--- |
| `model_type` | `random_forest` | Mô hình học có giám sát chuẩn (Supervised Baseline) |
| `n_estimators` | `200` | Số lượng cây quyết định đảm bảo phương sai dự đoán ổn định |
| `max_depth` | `16` | Giới hạn độ sâu cây để chống overfitting trên 1,655,797 dòng Train |
| `min_samples_split` | `10` | Số mẫu tối thiểu để tách nút nội |
| `min_samples_leaf` | `4` | Làm mịn ước lượng xác suất tại nút lá (`predict_proba`) |
| `criterion` | `gini` | Tiêu chuẩn độ tinh khiết Gini |
| `max_features` | `sqrt` | Lấy mẫu $\lfloor\sqrt{47}\rfloor = 6$ đặc trưng |
| `class_weight` | `balanced_subsample` | Cân bằng trọng số theo bootstrap sample |
| `bootstrap` | `True` | Lấy mẫu có hoàn lại cho từng cây |
| `random_state` | `42` | Hạt giống ngẫu nhiên cố định đảm bảo tái lập kết quả |
| `decision_threshold` | `0.5` | Ngưỡng phân loại nhị phân mặc định |

### 3.2. Hợp đồng tiền xử lý (`TrainOnlyPreprocessor`)

- **Chế độ**: `fit_partition = "train"` (chỉ học thống kê median trên tập Train, áp dụng `.transform()` trên Test).
- **Xử lý giá trị bất thường**: Thay thế `±Inf` bằng `NaN`, sau đó điền khuyết bằng `median` của tập Train trên đúng 47 cột đặc trưng `ML_FEATURE_COLUMNS`.
- **Loại trừ cột cấm (Anti-Leakage)**: Cấm tuyệt đối `Label`, `Attack` và 6 cột `TRACE_METADATA_COLUMNS`.

---

## 4. Test Set Overview

Theo `reports/splits/nf_unsw_nb15_v3_split_manifest.json` (chiến lược chia `chronological_with_canonical_flow_group_purge_gap` với purge gap 300,000 ms), cấu trúc tập **Held-out Test** được xác minh như sau:

- **Tổng số bản ghi Test**: `345,953` dòng (`14.6254%` toàn bộ dataset).
- **Khoảng cách bảo vệ thời gian (Temporal Margins)**: Train sang Validation (+236,165 ms), Validation sang Test (+252,058 ms) đảm bảo 0 luồng vượt biên.
- **Phân phối nhãn nhị phân (`Label`)**:
  - `Benign (0)`: `315,357` dòng (`91.1560%`).
  - `Attack (1)`: `30,596` dòng (`8.8440%`).
- **Chất lượng dữ liệu thô trên tập Test trước tiền xử lý**:
  - Số ô `NaN` và `+Inf`: Xử lý triệt để qua `TrainOnlyPreprocessor.transform()` -> 0.

---

## 5. Overall Test Performance

| Metric | Held-out Test Value | Verification Status |
| :--- | :---: | :---: |
| **Accuracy** | `NOT VERIFIED (Blocked: missing local .joblib / .csv binaries)` | `BLOCKED` |
| **Precision (Attack=1)** | `NOT VERIFIED (Blocked: missing local .joblib / .csv binaries)` | `BLOCKED` |
| **Recall / TPR (Attack=1)** | `NOT VERIFIED (Blocked: missing local .joblib / .csv binaries)` | `BLOCKED` |
| **F1-Score (Binary Attack=1)** | `NOT VERIFIED (Blocked: missing local .joblib / .csv binaries)` | `BLOCKED` |
| **Macro F1** | `NOT VERIFIED (Blocked: missing local .joblib / .csv binaries)` | `BLOCKED` |
| **Weighted F1** | `NOT VERIFIED (Blocked: missing local .joblib / .csv binaries)` | `BLOCKED` |
| **False Positive Rate (FPR)** | `NOT VERIFIED (Blocked: missing local .joblib / .csv binaries)` | `BLOCKED` |
| **True Negative Rate (TNR)** | `NOT VERIFIED (Blocked: missing local .joblib / .csv binaries)` | `BLOCKED` |


> **Lưu ý đối chiếu khoa học (Validation Reference — KHÔNG phải kết quả Test)**: Trên tập Validation (`345,371` dòng) đã được kiểm toán độc lập trong Issue #10 (`reports/models/rf_baseline_validation_audit.json`), mô hình đạt Accuracy `0.999977` (~ `99.9977%`), Precision `0.999836`, Recall `0.999902`, Binary F1 `0.999869`, FPR `1.587952e-05` (`5` FP / `314,871` Benign) và FN `3` / `30,500` Attack. Các con số Validation này chỉ được trích dẫn làm mốc tham chiếu trước Test và **tuyệt đối không được dùng thay thế cho kết quả Test**.

---

## 6. Confusion Matrix Analysis

| Ground Truth \ Predicted | Predicted Benign (`0`) | Predicted Attack (`1`) | Expected Row Total |
| :--- | :---: | :---: | :---: |
| **True Benign (`0`)** | `TN (Pending Test Execution)` | `FP (Pending Test Execution)` | `315,357` |
| **True Attack (`1`)** | `FN (Pending Test Execution)` | `TP (Pending Test Execution)` | `30,596` |
| **Total** | `Pending Test Execution` | `Pending Test Execution` | `345,953` |


- **Định nghĩa 4 ô trong bài toán NIDS**:
  - **True Negative (`TN`)**: Lưu lượng `Benign (0)` được dự đoán đúng.
  - **False Positive (`FP`)**: Lưu lượng `Benign (0)` bị cảnh báo nhầm là `Attack (1)`.
  - **False Negative (`FN`)**: Lưu lượng `Attack (1)` bị bỏ lọt thành `Benign (0)`.
  - **True Positive (`TP`)**: Lưu lượng `Attack (1)` được phát hiện đúng là `Attack (1)`.

---

## 7. Benign Traffic & False Positive Analysis

- **Tổng số mẫu Benign trên Test**: `315,357` dòng (`Label = 0`, `Attack = 'Benign').
- **Trạng thái số liệu `FP` và `FPR` thực tế trên Test**: `BLOCKED / NOT VERIFIED` (chờ chạy CLI đánh giá trên máy có artifact nhị phân).
- **Cơ chế trích xuất mẫu `FP` đã triển khai**: Hàm `extract_fp_fn_samples()` và `compute_benign_false_positive_breakdown()` lọc bản ghi `(y_true == 0) & (y_pred == 1)`, xếp hạng mẫu `FP` có xác suất `prob_attack` cao nhất và đo độ lệch chuẩn hóa (`standardized_abs_shift`) giữa `FP` và `TN` trên 47 đặc trưng.

### Cơ chế gây báo động giả (False Positive Mechanisms)
1. **Va chạm vector đặc trưng (`ml_feature_overlap`)**: Có tới `184,067 / 345,953` dòng Test (`53.21%`) có vector 47 đặc trưng trùng khớp với các dòng thuộc phân vùng/nhãn khác. Khi một luồng Benign ngắn có cùng bộ 47 đặc trưng với các luồng dò quét và rơi vào nút lá có trọng số `balanced_subsample` nghiêng về lớp `Attack`, mô hình dự đoán `1`.
2. **Đột biến băng thông và truyền lại gói hợp pháp**: Các kết nối Benign có tốc độ truyền burst hoặc tỷ lệ truyền lại cao đột biến dễ bị nhầm với lưu lượng bất thường.

---

## 8. Attack Traffic & False Negative Analysis

- **Tổng số mẫu Attack trên Test**: `30,596` dòng (`Label = 1`, trải trên 9 họ tấn công).
- **Trạng thái số liệu `FN` và `FNR` thực tế trên Test**: `BLOCKED / NOT VERIFIED` (chờ chạy CLI đánh giá trên máy có artifact nhị phân).
- **Cơ chế trích xuất mẫu `FN` đã triển khai**: Hàm `extract_fp_fn_samples()` thu thập mẫu `(y_true == 1) & (y_pred == 0)`, phân nhóm theo từng `Attack` category và trích xuất mẫu tấn công bỏ lọt với xác suất `prob_attack` thấp nhất.

### Cơ chế bỏ lọt tấn công (False Negative Mechanisms)
1. **Tấn công thăm dò và khai thác tần suất thấp (Low-and-Slow / Single-Flow Stealth)**: Các luồng thuộc nhóm `Reconnaissance`, `Analysis`, `Backdoor` hoặc `Worms` chỉ gửi một vài gói tin kích thước nhỏ có hành vi thống kê rất giống Benign.
2. **Sự phụ thuộc vào đặc trưng TTL (`MAX_TTL`, `MIN_TTL`)**: Khi luồng tấn công có giá trị TTL nằm trong dải TTL điển hình của máy trạm Benign, các nhánh cây dựa trên TTL sẽ đẩy mẫu về phía lớp `Benign (0)`.

---

## 9. Per-Attack-Category Breakdown

Bảng phân rã 9 họ tấn công (`Attack` category) trên tập Test:

| Rank | Attack Category | Total in Test | Detected (`TP`) | Missed (`FN`) | Detection Rate (`Recall`) | False Negative Rate (`FNR`) |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| 1 | `Exploits` | `10,520` (`34.38%` of Test Attacks) | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` |
| 2 | `Fuzzers` | `7,322` (`23.93%` of Test Attacks) | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` |
| 3 | `Generic` | `5,111` (`16.70%` of Test Attacks) | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` |
| 4 | `Reconnaissance` | `4,464` (`14.59%` of Test Attacks) | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` |
| 5 | `Backdoor` | `1,260` (`4.12%` of Test Attacks) | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` |
| 6 | `DoS` | `1,193` (`3.90%` of Test Attacks) | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` |
| 7 | `Shellcode` | `396` (`1.29%` of Test Attacks) | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` |
| 8 | `Analysis` | `294` (`0.96%` of Test Attacks) | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` |
| 9 | `Worms` | `36` (`0.12%` of Test Attacks) | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` | `NOT VERIFIED (Blocked)` |

### Nhận xét về phân bố họ tấn công trên tập Test
- Ba họ tấn công lớn nhất (`Exploits`: `10,520`, `Fuzzers`: `7,322`, `Generic`: `5,111`) chiếm tới **`75.02%`** (`22,953 / 30,596`) tổng số mẫu tấn công trong tập Test.
- Ngược lại, 4 họ tấn công hiếm (`Worms`: `36`, `Analysis`: `294`, `Shellcode`: `396`, `Backdoor`: `1,260`) chỉ chiếm một tỷ lệ nhỏ tổng số mẫu tấn công. Do đó, việc đánh giá riêng từng họ tấn công là bắt buộc để không che khuất điểm yếu trên các lớp hiếm.

---

## 10. Feature Importance & Error Pattern Analysis

Phân tích đặc trưng được tách bạch nghiêm ngặt thành 3 tầng:

### 10.1. Tầng 1 — Độ quan trọng đặc trưng toàn cục (Global Impurity Feature Importance)

| Rank | Feature Name | Gini Importance | Cumulative Importance |
| :---: | :--- | :---: | :---: |
| 1 | `MAX_TTL` | `0.229569` | `0.229569` |
| 2 | `MIN_TTL` | `0.225260` | `0.454828` |
| 3 | `SHORTEST_FLOW_PKT` | `0.125933` | `0.580761` |
| 4 | `MIN_IP_PKT_LEN` | `0.124349` | `0.705110` |
| 5 | `DST_TO_SRC_AVG_THROUGHPUT` | `0.048880` | `0.753990` |
| 6 | `NUM_PKTS_UP_TO_128_BYTES` | `0.028071` | `0.782061` |
| 7 | `OUT_BYTES` | `0.020105` | `0.802166` |
| 8 | `SRC_TO_DST_SECOND_BYTES` | `0.018321` | `0.820487` |
| 9 | `SERVER_TCP_FLAGS` | `0.017361` | `0.837847` |
| 10 | `LONGEST_FLOW_PKT` | `0.017098` | `0.854945` |
| 11 | `TCP_WIN_MAX_OUT` | `0.014797` | `0.869742` |
| 12 | `MAX_IP_PKT_LEN` | `0.014582` | `0.884324` |
| 13 | `IN_PKTS` | `0.013388` | `0.897712` |
| 14 | `OUT_PKTS` | `0.012746` | `0.910458` |
| 15 | `TCP_WIN_MAX_IN` | `0.011020` | `0.921478` |

- **Nhận xét trọng tâm**: Hai đặc trưng `MAX_TTL` và `MIN_TTL` chiếm tổng cộng gần **`45-50%`** độ quan trọng toàn cục của mô hình. Top 10 đặc trưng đầu tiên chiếm hơn **`80%`** tổng độ quan trọng.

### 10.2. Tầng 2 — Mẫu thống kê trên các bản ghi phân loại sai

- Hàm `analyze_feature_error_patterns()` tính toán độ lệch chuẩn hóa giữa `FP` so với `TN` và giữa `FN` so với `TP` trên toàn bộ 47 đặc trưng.

### 10.3. Tầng 3 — Giả thuyết nguyên nhân lỗi theo ngữ nghĩa NIDS

1. **`H1_EXACT_FEATURE_COLLISION`**: Sự trùng lặp hoàn toàn bộ 47 đặc trưng giữa các luồng Benign và Attack ngắn tạo ra giới hạn lỗi Bayes không thể triệt tiêu nếu chỉ dựa vào thống kê cấp luồng đơn lẻ.
2. **`H2_TTL_SHORTCUT_MISMATCH`**: Việc mô hình tập trung trọng số lớn vào `MIN_TTL`/`MAX_TTL` khiến các luồng có TTL không tuân theo quy luật định tuyến phòng lab dễ bị phân loại sai.
3. **`H3_STEALTHY_LOW_RATE_PROBING`**: Các luồng `Reconnaissance`, `Analysis`, `Backdoor` và `Worms` có kích thước gói nhỏ và thời lượng ngắn thiếu dấu hiệu bất thường về lưu lượng khi không có thông tin payload sâu.
4. **`H4_BENIGN_BURST_ANOMALIES`**: Các kết nối Benign hợp pháp nhưng có hiện tượng nghẽn mạng, truyền lại gói hoặc truyền dữ liệu khối lượng lớn trong thời gian ngắn dễ chạm ngưỡng nhánh cây của lớp `Attack`.

---

## 11. Decision Boundary & Confidence Analysis

- **Ngưỡng quyết định cố định (Fixed Canonical Threshold)**: `0.50` trên xác suất dự đoán lớp `Attack`. Tuân thủ quy tắc chống rò rỉ dữ liệu, ngưỡng này **không được tinh chỉnh trên tập Test**.
- **Vùng bất định (Uncertainty Band `[0.35, 0.65]`)**: Hàm `analyze_classification_boundary()` đo lường tỷ lệ mẫu rơi vào vùng xác suất sát ngưỡng `0.50` (`[0.35, 0.65]`) cũng như tỷ lệ lỗi có độ tự tin cao.

---

## 12. Dataset & Methodology Limitations

Dựa trên bằng chứng định lượng từ các manifest đã kiểm chứng trong repository, nghiên cứu ghi nhận **6 hạn chế cốt lõi** của dữ liệu và phương pháp:

### 12.1. Mất cân bằng lớp nghiêm trọng (Severe Class Imbalance)
- Toàn bộ bộ dữ liệu có `2,365,424` dòng với tỷ lệ Benign chiếm áp đảo (~`91.16%`). Trong tập Test (`345,953` dòng), có `315,357` dòng `Benign` và `30,596` dòng `Attack`.
- **Hệ quả**: Chỉ số Accuracy tổng thể bị chi phối bởi lớp `Benign`. Do đó, phải ưu tiên **Precision, Recall, Binary F1, Macro F1, FPR và Per-Category Recall**.

### 12.2. Các họ tấn công cực hiếm (Extreme Rare Attack Categories)
- Trong tập Test, họ `Worms` chỉ có **`36` mẫu** (`0.0104%` tập Test), `Analysis` có **`294` mẫu**, `Shellcode` có **`396` mẫu** và `Backdoor` có **`1,260` mẫu**.
- **Hệ quả**: Chỉ cần bỏ lọt vài luồng `Worms` hoặc `Analysis` sẽ làm Recall của họ đó biến động mạnh; độ tin cậy thống kê trên các lớp hiếm thấp hơn nhiều so với `Exploits` (`10,520` mẫu) hay `Fuzzers` (`7,322` mẫu).

### 12.3. Chồng lấn hoàn toàn vector 47 đặc trưng (`ml_feature_overlap` = `53.21%` trên Test)
- Theo `reports/splits/nf_unsw_nb15_v3_split_manifest.json`, có tới **`184,067` dòng (`53.21%`)** trên tập Test chia sẻ vector 47 đặc trưng với các dòng ở phân vùng Train (do các mẫu lưu lượng giao thức lặp lại giữa các IP/thời điểm khác nhau).

### 12.4. Giá trị khuyết (`NaN`) và vô cực (`+Inf`) trong đặc trưng tốc độ truyền
- Các luồng cực ngắn có `FLOW_DURATION_MILLISECONDS == 0` gây chia cho 0 khi tính số byte/giây. Việc thay thế `+Inf -> NaN` và điền bằng `median` của tập Train giúp đảm bảo tính ổn định số học nhưng làm mất thông tin phân biệt tinh vi ở nhóm luồng thời lượng bằng 0.

### 12.5. Hiện tượng học đường tắt (`MIN_TTL` / `MAX_TTL` Lab Shortcut)
- Môi trường tạo dữ liệu UNSW-NB15 sử dụng hệ thống IXIA PerfectStorm với cấu hình định tuyến cố định giữa mạng tấn công và mạng đích.
- **Bằng chứng thực nghiệm (Ablation Study trên Validation)**: Trên tập Validation (345,371 dòng), mô hình chuẩn đạt Accuracy 99.9977% với 5 FP và 3 FN. Khi loại bỏ 2 cột `MIN_TTL` và `MAX_TTL` (thí nghiệm C1), số tấn công bị bỏ lọt (`FN`) tăng từ 3 lên 11 (3.7x), và trên cây quyết định đơn quy tắc, riêng `MIN_TTL` đã đạt Accuracy 99.9849%. Điều này xác nhận đặc trưng hạ tầng phòng lab đóng vai trò đường tắt rất mạnh và hiệu năng cao trong phòng lab không đảm bảo khái quát hóa thực tế.

### 12.6. Giới hạn cửa sổ thời gian và khả năng khái quát hóa thực tế
- Bộ dữ liệu chỉ thu thập trong khoảng thời gian có hạn và có sự lặp lại của các mẫu đặc trưng NetFlow.
- Mô hình được huấn luyện trên dữ liệu giả lập này chưa phản ánh hiện tượng trôi dạt khái niệm (concept drift) theo tuần/tháng, cấu trúc lưu lượng mã hóa hiện đại (TLS 1.3, QUIC) hoặc các cuộc tấn công phân tán nhiều bước (APT) cần ngữ cảnh liên luồng.

---

## 13. Operational & Security Implications

1. **Đánh đổi giữa `FPR` và Chi phí vận hành SOC (Alert Fatigue)**:
   - Trong mạng doanh nghiệp có hàng triệu luồng Benign mỗi ngày (>91% lưu lượng), ngay cả mức `FPR` nhỏ cũng sinh ra hàng nghìn cảnh báo giả mỗi ngày. Vì vậy, Random Forest đóng vai trò là **lớp lọc tốc độ cao tuyến đầu (Tier-1 Flow Filter)** và cần kết hợp với cơ chế chấm điểm rủi ro / tương quan sự kiện ở tầng sau.
2. **Rủi ro an ninh từ `FN` và khả năng né tránh (Adversarial TTL Spoofing)**:
   - Kẻ tấn công nắm được việc mô hình phụ thuộc lớn vào `MIN_TTL`/`MAX_TTL` có thể dễ dàng điều chỉnh giá trị TTL ban đầu của gói tin tấn công khớp với TTL của máy trạm hợp pháp, làm tăng tỷ lệ bỏ lọt (`FN`) lên nhiều lần.
3. **Nguy cơ bỏ lọt các cuộc tấn công hiếm nhưng nguy hiểm cao (`Worms`, `Backdoor`, `Shellcode`, `Analysis`)**:
   - Một luồng `Backdoor` hoặc `Shellcode` bị bỏ lọt (`FN`) có tác động an ninh nghiêm trọng hơn nhiều so với một luồng `Fuzzers` thông thường, đòi hỏi hệ thống cảnh báo phải gắn trọng số rủi ro theo ngữ cảnh thay vì chỉ nhìn vào nhãn nhị phân 0/1.

---

## 14. Recommendations for Future Work

1. **Hoàn tất chạy thực nghiệm Test trên máy chứa đầy đủ artifact nhị phân**:
   - Chạy lệnh CLI sau trên máy lưu trữ bộ dữ liệu và model `.joblib` để xuất đầy đủ các artifact vào `reports/evaluation/` và cập nhật bảng số liệu Test:
   ```powershell
   python scripts/error_analysis_random_forest.py --run-test-evaluation --report-path reports/evaluation/error_analysis_report.md
   ```
2. **Bổ sung đặc trưng ngữ cảnh liên luồng (Host-Level Features)**:
   - Để phá vỡ giới hạn `53.21%` chồng lấn vector 47 đặc trưng của từng luồng đơn lẻ, cần bổ sung các đặc trưng thống kê trên cửa sổ trượt theo IP nguồn/đích mà vẫn đảm bảo không rò rỉ nhãn hay địa chỉ IP tĩnh.
3. **Kiểm soát sự phụ thuộc vào đường tắt `TTL` (TTL-Invariant Regularization)**:
   - Huấn luyện và so sánh biến thể mô hình loại bỏ `MIN_TTL`/`MAX_TTL` hoặc áp dụng cơ chế phạt độ nhạy TTL để nâng cao độ bền vững khi triển khai ngoài môi trường phòng lab.
4. **Kết hợp đa mô hình (Ensemble với XGBoost / Isolation Forest / Autoencoder)**:
   - Sử dụng Random Forest làm chuẩn tham chiếu có giám sát, kết hợp với các mô hình phát hiện bất thường bán giám sát để cải thiện khả năng phát hiện các họ tấn công hiếm (`Worms`, `Analysis`, `Backdoor`) và tấn công chưa biết (zero-day).
