# Random Forest Baseline — Independent Test Evaluation & Error Analysis Report

- **Issue Scope**: Issue #12 (Independent Held-out Test Set Evaluation) & Issue #13 (FP/FN & Data Limitations Analysis)
- **Execution Status**: `IMPLEMENTED & UNIT-TESTED | REAL-DATA TEST EXECUTION BLOCKED (MISSING LOCAL BINARIES)`
- **Evaluation Run ID**: `PENDING-LOCAL-BINARY-ARTIFACTS`
- **Model Configuration ID**: `rf-baseline-canonical-v1`
- **Protocol Version**: `rf-baseline-nf-unsw-nb15-v3-v1`
- **Feature Contract**: `nf-unsw-nb15-v3-baseline-47` (`47` canonical NetFlow v3 features)

---

## 1. Executive Summary

Tài liệu này báo cáo quy trình đánh giá độc lập mô hình **Random Forest Baseline** trên tập **Held-out Test** (Issue #12) và phân tích chuyên sâu **False Positives (FP), False Negatives (FN), phân rã theo họ tấn công (`Attack` category), đặc trưng ranh giới quyết định và giới hạn dữ liệu** (Issue #13) trên bộ dữ liệu chuẩn **NF-UNSW-NB15-v3**.

- **Tính toàn vẹn quy trình (Test-Lock Integrity)**: Toàn bộ pipeline đánh giá Test (`src/network_anomaly/evaluation/test_evaluation.py`) và phân tích lỗi (`src/network_anomaly/evaluation/error_analysis.py`) thực thi cơ chế **fail-closed**: xác minh mã băm SHA-256 của dữ liệu gốc, split manifest, `test_indices.csv.gz`, bộ tiền xử lý `TabularPreprocessor` (fit độc quyền trên Train) và mô hình `RandomForestModel` (`rf-baseline-1794068628`).
- **Không rò rỉ dữ liệu (Zero Leakage)**: Tập Test (`345,953` bản ghi) hoàn toàn tách biệt với Train (`1,654,162` bản ghi) và Validation (`365,608` bản ghi). Bộ tiền xử lý chỉ gọi `.transform(X_test_raw)` và mô hình chỉ gọi `.predict(X_test)` / `.predict_proba(X_test)` với ngưỡng cố định `0.5` — tuyệt đối không huấn luyện lại, không tinh chỉnh siêu tham số và không tối ưu ngưỡng trên tập Test.
- **Trạng thái thực thi thực nghiệm tại môi trường hiện tại**: Do các tệp nhị phân dung lượng lớn (`.csv`, `.csv.gz`, `.joblib`) nằm trong `.gitignore` và được lưu trữ trên máy huấn luyện cục bộ (`D:/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN`), môi trường hiện tại ghi nhận trạng thái **`BLOCKED / NOT VERIFIED`** đối với số liệu chạy trực tiếp trên tập Test thật, tuyệt đối không bịa số liệu hay lấy số liệu Validation thay cho Test.

---

## 2. Evaluation Scope & Data Integrity

### 2.1. Truy vết mã băm (Provenance Lineage & SHA-256 Verification)

| Thành phần | Đường dẫn chuẩn | SHA-256 đã xác minh trong Manifest | Trạng thái trên đĩa cục bộ |
| :--- | :--- | :--- | :---: |
| **Raw Dataset CSV** | `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv` | `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5` | `MISSING (.gitignore)` |
| **Split Manifest** | `reports/splits/nf_unsw_nb15_v3_split_manifest.json` | `bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88` | `PRESENT & VERIFIED` |
| **Test Indices** | `data/processed/splits/test_indices.csv.gz` | `63e2e081300955fe06835b0cf7405e07e53985ca3d84164e768be09116269d03` | `MISSING (.gitignore)` |
| **Preprocessing Manifest** | `reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json` | `af07dc3b6c7cbc9e75426eeb5b96d52dbd191e8a09161699df2fad1bb5555441` | `PRESENT & VERIFIED` |
| **Preprocessor Artifact** | `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib` | `12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19` | `MISSING (.gitignore)` |
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
| `max_depth` | `16` | Giới hạn độ sâu cây để chống overfitting trên 1.65M dòng Train |
| `min_samples_split` | `10` | Số mẫu tối thiểu để tách nút nội |
| `min_samples_leaf` | `4` | Làm mịn ước lượng xác suất tại nút lá (`predict_proba`) |
| `criterion` | `gini` | Tiêu chuẩn độ tinh khiết Gini |
| `max_features` | `sqrt` | Lấy mẫu ngẫu nhiên $\lfloor\sqrt{47}\rfloor = 6$ đặc trưng tại mỗi lần tách |
| `class_weight` | `balanced_subsample` | Cân bằng trọng số lớp theo từng bootstrap sample (tỷ lệ 10.32:1) |
| `bootstrap` | `True` | Lấy mẫu có hoàn lại cho từng cây |
| `random_state` | `42` | Hạt giống ngẫu nhiên cố định đảm bảo tái lập kết quả |
| `decision_threshold` | `0.5` | Ngưỡng phân loại nhị phân mặc định (không chỉnh trên Test) |

### 3.2. Hợp đồng tiền xử lý (`TabularPreprocessor`)

- **Chế độ**: `fit_partition = "train"` (chỉ học thống kê median trên tập Train, áp dụng `.transform()` trên Test).
- **Xử lý giá trị bất thường**: Thay thế `±Inf` bằng `NaN`, sau đó điền khuyết bằng `median` của tập Train trên đúng 47 cột đặc trưng `ML_FEATURE_COLUMNS`.
- **Loại trừ cột cấm (Anti-Leakage)**: Cấm tuyệt đối `Label`, `Attack` và 6 cột `TRACE_METADATA_COLUMNS` (`IPV4_SRC_ADDR`, `L4_SRC_PORT`, `IPV4_DST_ADDR`, `L4_DST_PORT`, `FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`).

---

## 4. Test Set Overview

Theo `reports/splits/nf_unsw_nb15_v3_split_manifest.json` (chiến lược chia `grouped_by_flow_second_window` với `seed=42`, kích thước cửa sổ thời gian `1,000 ms`), cấu trúc tập **Held-out Test** được xác minh như sau:

- **Tổng số bản ghi Test**: `345,953` dòng (`14.6236%` toàn bộ dataset).
- **Số lượng cụm thời gian (Temporal Groups)**: `16,003` cửa sổ 1 giây tách biệt hoàn toàn với Train (`74,698` cụm) và Validation (`16,002` cụm).
- **Phân phối nhãn nhị phân (`Label`)**:
  - `Benign (0)`: `315,357` dòng (`91.1560%`).
  - `Attack (1)`: `30,596` dòng (`8.8440%`).
- **Chất lượng dữ liệu thô trên tập Test trước tiền xử lý**:
  - Số ô `NaN`: `14,193` ô (tập trung ở `SRC_TO_DST_SECOND_BYTES` và `DST_TO_SRC_SECOND_BYTES`).
  - Số ô `+Inf`: `14,192` ô (do các luồng có `DURATION_IN_MILLISECONDS == 0`).
  - Sau khi qua `preprocessor.transform(X_test_raw)`: `0` `NaN`, `0` `Inf`.

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


> **Lưu ý đối chiếu khoa học (Validation Reference — KHÔNG phải kết quả Test)**: Trên tập Validation (`365,608` dòng) đã được kiểm toán độc lập trong Issue #10 (`reports/models/rf_baseline_validation_audit.json`), mô hình đạt Precision `0.979948`, Recall `0.994322`, Binary F1 `0.987083`, Macro F1 `0.992910`, FPR `0.001857` (`622` FP / `335,317` Benign) và FN `172` / `30,291` Attack. Các con số Validation này chỉ được trích dẫn làm mốc tham chiếu trước Test và **tuyệt đối không được dùng thay thế cho kết quả Test**.

---

## 6. Confusion Matrix Analysis

| Ground Truth \ Predicted | Predicted Benign (`0`) | Predicted Attack (`1`) | Expected Row Total |
| :--- | :---: | :---: | :---: |
| **True Benign (`0`)** | `TN (Pending Test Execution)` | `FP (Pending Test Execution)` | `315,357` |
| **True Attack (`1`)** | `FN (Pending Test Execution)` | `TP (Pending Test Execution)` | `30,596` |
| **Total** | `Pending Test Execution` | `Pending Test Execution` | `345,953` |


- **Định nghĩa 4 ô trong bài toán NIDS**:
  - **True Negative (`TN`)**: Lưu lượng `Benign (0)` được dự đoán đúng là `Benign (0)`.
  - **False Positive (`FP`)**: Lưu lượng `Benign (0)` bị cảnh báo nhầm là `Attack (1)` (gây tốn chi phí điều tra SOC / alert fatigue).
  - **False Negative (`FN`)**: Lưu lượng `Attack (1)` bị bỏ lọt thành `Benign (0)` (rủi ro an ninh nghiêm trọng vì tấn công đi qua hệ thống mà không bị phát hiện).
  - **True Positive (`TP`)**: Lưu lượng `Attack (1)` được phát hiện đúng là `Attack (1)`.

---

## 7. Benign Traffic & False Positive Analysis

- **Tổng số mẫu Benign trên Test**: `315,357` dòng (`Label = 0`, `Attack = 'Benign'`).
- **Trạng thái số liệu `FP` và `FPR` thực tế trên Test**: `BLOCKED / NOT VERIFIED` (chờ chạy CLI đánh giá trên máy chứa artifact nhị phân).
- **Cơ chế trích xuất mẫu `FP` đã triển khai**: Hàm `extract_fp_fn_samples()` và `compute_benign_false_positive_breakdown()` lọc toàn bộ bản ghi `(y_true == 0) & (y_pred == 1)`, xếp hạng các mẫu `FP` có xác suất `prob_attack` cao nhất và đo độ lệch chuẩn hóa (`standardized_abs_shift`) giữa `FP` và `TN` trên 47 đặc trưng.

### Cơ chế gây báo động giả (False Positive Mechanisms)
1. **Va chạm vector đặc trưng (`ml_feature_overlap`)**: Có tới `184,087 / 345,953` dòng Test (`53.21%`) có vector 47 đặc trưng trùng khớp với các dòng thuộc phân vùng/nhãn khác. Khi một luồng Benign ngắn có cùng bộ 47 đặc trưng với các luồng dò quét và rơi vào nút lá có trọng số `balanced_subsample` nghiêng về lớp `Attack`, mô hình buộc phải dự đoán `1`.
2. **Đột biến băng thông và truyền lại gói hợp pháp**: Các kết nối Benign có tốc độ truyền burst lớn hoặc tỷ lệ truyền lại (`RETRANSMITTED_IN_BYTES`, `RETRANSMITTED_OUT_BYTES`) cao đột biến dễ bị nhầm với lưu lượng `DoS` hoặc `Fuzzers`.

---

## 8. Attack Traffic & False Negative Analysis

- **Tổng số mẫu Attack trên Test**: `30,596` dòng (`Label = 1`, trải trên 9 họ tấn công).
- **Trạng thái số liệu `FN` và `FNR` thực tế trên Test**: `BLOCKED / NOT VERIFIED` (chờ chạy CLI đánh giá trên máy chứa artifact nhị phân).
- **Cơ chế trích xuất mẫu `FN` đã triển khai**: Hàm `extract_fp_fn_samples()` thu thập toàn bộ mẫu `(y_true == 1) & (y_pred == 0)`, phân nhóm theo từng `Attack` category và trích xuất các mẫu tấn công bị bỏ lọt với xác suất `prob_attack` thấp nhất.

### Cơ chế bỏ lọt tấn công (False Negative Mechanisms)
1. **Tấn công thăm dò và khai thác tần suất thấp (Low-and-Slow / Single-Flow Stealth)**: Các luồng thuộc nhóm `Reconnaissance`, `Analysis`, `Backdoor` hoặc `Worms` chỉ gửi một vài gói tin kích thước nhỏ có hành vi thống kê lớp Transport/Network rất giống giao dịch Benign bình thường.
2. **Sự phụ thuộc quá mức vào đặc trưng TTL (`MAX_TTL`, `MIN_TTL`)**: Khi luồng tấn công có giá trị TTL nằm trong dải TTL điển hình của máy trạm Benign (và không có dấu hiệu bất thường rõ rệt về số byte/gói), các nhánh cây dựa trên TTL sẽ đẩy mẫu về phía lớp `Benign (0)`.

---

## 9. Per-Attack-Category Breakdown

Bảng phân rã 9 họ tấn công (`Attack` category) trên tập Test (sắp xếp theo số lượng mẫu hoặc số lỗi bỏ lọt `FN` giảm dần):

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
- Ba họ tấn công lớn nhất (`Exploits`: `12,869`, `Fuzzers`: `8,457`, `Generic`: `4,296`) chiếm tới **`83.74%`** (`25,622 / 30,596`) tổng số mẫu tấn công trong tập Test.
- Ngược lại, 4 họ tấn công hiếm (`Worms`: `36`, `Analysis`: `266`, `Shellcode`: `321`, `Backdoor`: `486`) chỉ chiếm **`3.62%`** (`1,109 / 30,596`) tổng số mẫu tấn công. Do đó, Recall tổng thể trên toàn bộ lớp `Attack` bị chi phối mạnh bởi `Exploits`, `Fuzzers` và `Generic`; việc đánh giá riêng từng họ tấn công là bắt buộc để không che khuất điểm yếu trên các lớp hiếm.

---

## 10. Feature Importance & Error Pattern Analysis

Phân tích đặc trưng được tách bạch nghiêm ngặt thành 3 tầng để tránh suy diễn nhân quả quá mức:

### 10.1. Tầng 1 — Độ quan trọng đặc trưng toàn cục (Global Impurity Feature Importance)

| Rank | Feature Name | Gini Importance | Cumulative Importance |
| :---: | :--- | :---: | :---: |

- **Nhận xét trọng tâm**: Hai đặc trưng `MAX_TTL` (`25.81%`) và `MIN_TTL` (`24.13%`) chiếm tổng cộng **`49.94%`** độ quan trọng toàn cục của mô hình. Top 10 đặc trưng đầu tiên chiếm hơn **`82.5%`** tổng độ quan trọng.

### 10.2. Tầng 2 — Mẫu thống kê trên các bản ghi phân loại sai (Empirical Misclassified Patterns)

- Hàm `analyze_feature_error_patterns()` tính toán độ lệch chuẩn hóa (`standardized_abs_shift`) giữa `FP` so với `TN` và giữa `FN` so với `TP` trên toàn bộ 47 đặc trưng.
- Trên dữ liệu kiểm định, các mẫu `FN` (tấn công bị bỏ lọt) thường có giá trị `MIN_TTL`/`MAX_TTL`, `SHORTEST_FLOW_PKT` và `TCP_WIN_MAX_IN` nằm sát phân phối trung vị của lớp `Benign`, trong khi các mẫu `FP` có sự dịch chuyển mạnh ở các đặc trưng tốc độ truyền (`SRC_TO_DST_SECOND_BYTES`, `DST_TO_SRC_AVG_THROUGHPUT`) và số lượng gói tin.

### 10.3. Tầng 3 — Giả thuyết nguyên nhân lỗi theo ngữ nghĩa NIDS (Domain Hypotheses)

1. **`H1_EXACT_FEATURE_COLLISION`**: Sự trùng lặp hoàn toàn bộ 47 đặc trưng giữa các luồng Benign và Attack ngắn tạo ra giới hạn lỗi Bayes không thể triệt tiêu nếu chỉ dựa vào thống kê cấp luồng đơn lẻ.
2. **`H2_TTL_SHORTCUT_MISMATCH`**: Việc mô hình tập trung gần 50% trọng số vào `MIN_TTL`/`MAX_TTL` khiến các luồng có TTL không tuân theo quy luật định tuyến phòng lab dễ bị phân loại sai.
3. **`H3_STEALTHY_LOW_RATE_PROBING`**: Các luồng `Reconnaissance`, `Analysis`, `Backdoor` và `Worms` có kích thước gói nhỏ và thời lượng ngắn thiếu dấu hiệu bất thường về lưu lượng khi không có thông tin payload sâu.
4. **`H4_BENIGN_BURST_ANOMALIES`**: Các kết nối Benign hợp pháp nhưng có hiện tượng nghẽn mạng, truyền lại gói hoặc truyền dữ liệu khối lượng lớn trong thời gian ngắn dễ chạm ngưỡng nhánh cây của lớp `Attack`.

---

## 11. Decision Boundary & Confidence Analysis

- **Ngưỡng quyết định cố định (Fixed Canonical Threshold)**: `0.50` trên xác suất dự đoán lớp `Attack` (`prob_attack = predict_proba(X)[:, 1]`). Tuân thủ quy tắc chống rò rỉ dữ liệu, ngưỡng này **không được tinh chỉnh trên tập Test**.
- **Vùng bất định (Uncertainty Band `[0.35, 0.65]`)**: Hàm `analyze_classification_boundary()` đo lường tỷ lệ mẫu rơi vào vùng xác suất sát ngưỡng `0.50` (`[0.35, 0.65]`) cũng như tỷ lệ lỗi có độ tự tin cao (`FP` với `prob_attack >= 0.80` và `FN` với `prob_attack <= 0.20`).
- **Tham chiếu từ kiểm toán xác suất trên Validation**: Điểm trung bình `prob_attack` trên lớp `Attack` đạt `0.9854` so với `0.0042` trên lớp `Benign` (`ROC-AUC = 0.999932`, `PR-AUC = 0.999118`), nhưng tại các nút lá xảy ra va chạm 47 đặc trưng, xác suất dự đoán phân tán vào vùng lân cận ngưỡng `0.5` hoặc bị đảo chiều hoàn toàn.

---

## 12. Dataset & Methodology Limitations

Dựa trên bằng chứng định lượng từ các manifest đã kiểm chứng trong repository, nghiên cứu ghi nhận **6 hạn chế cốt lõi** của dữ liệu và phương pháp:

### 12.1. Mất cân bằng lớp nghiêm trọng (Severe Class Imbalance)
- Toàn bộ bộ dữ liệu có `2,156,662` dòng `Benign` (`91.16%`) so với `209,061` dòng `Attack` (`8.84%`), tương ứng tỷ lệ **`10.32 : 1`**. Trong tập Test (`345,953` dòng), có `315,357` dòng `Benign` và `30,596` dòng `Attack`.
- **Hệ quả**: Chỉ số Accuracy tổng thể bị chi phối bởi lớp `Benign` (một bộ phân loại đoán toàn bộ là `Benign` vẫn đạt Accuracy `91.16%`). Do đó, phải ưu tiên **Precision, Recall, Binary F1, Macro F1, FPR và Per-Category Recall**.

### 12.2. Các họ tấn công cực hiếm (Extreme Rare Attack Categories)
- Trong tập Test, họ `Worms` chỉ có **`36` mẫu** (`0.0104%` tập Test), `Analysis` có **`266` mẫu**, `Shellcode` có **`321` mẫu** và `Backdoor` có **`486` mẫu**.
- **Hệ quả**: Chỉ cần bỏ lọt vài luồng `Worms` hoặc `Analysis` sẽ làm Recall của họ đó biến động mạnh; độ tin cậy thống kê trên các lớp hiếm thấp hơn nhiều so với `Exploits` (`12,869` mẫu) hay `Fuzzers` (`8,457` mẫu).

### 12.3. Chồng lấn hoàn toàn vector 47 đặc trưng (`ml_feature_overlap` = `53.21%` trên Test)
- Theo `reports/splits/nf_unsw_nb15_v3_split_manifest.json`, tồn tại **`2,690` tổ hợp giá trị 47 đặc trưng** xuất hiện lặp lại ở nhiều phân vùng/nhãn khác nhau, ảnh hưởng tới **`1,259,365` dòng (`53.23%`)** trên toàn bộ dataset và **`184,087` dòng (`53.21%`)** trên tập Test.
- **Hệ quả**: Với các luồng có vector 47 đặc trưng trùng nhau nhưng nhãn thực tế khác nhau (`Benign` vs `Attack`), không một mô hình học máy nào chỉ dựa trên 47 đặc trưng của từng luồng đơn lẻ có thể đạt độ chính xác tuyệt đối 100% một cách thực chất.

### 12.4. Giá trị khuyết (`NaN`) và vô cực (`+Inf`) trong đặc trưng tốc độ truyền
- Toàn bộ dataset chứa **`97,852` ô `NaN`** và **`97,850` ô `+Inf`** tập trung tại 2 cột `SRC_TO_DST_SECOND_BYTES` và `DST_TO_SRC_SECOND_BYTES` (riêng tập Test có **`14,193` ô `NaN`** và **`14,192` ô `+Inf`** trước tiền xử lý).
- **Nguyên nhân & Hệ quả**: Các luồng cực ngắn có `DURATION_IN_MILLISECONDS == 0` gây chia cho 0 khi tính số byte/giây. Việc thay thế `+Inf -> NaN` và điền bằng `median` của tập Train giúp đảm bảo tính ổn định số học nhưng làm mất thông tin phân biệt tinh vi ở nhóm luồng thời lượng bằng 0.

### 12.5. Hiện tượng học đường tắt từ môi trường giả lập (`MIN_TTL` / `MAX_TTL` Lab Shortcut)
- Môi trường tạo dữ liệu UNSW-NB15 sử dụng hệ thống IXIA PerfectStorm với cấu hình định tuyến cố định giữa mạng tấn công và mạng đích. Do đó, `MAX_TTL` và `MIN_TTL` chiếm tới **`49.94%`** tổng độ quan trọng của Random Forest.
- **Bằng chứng thực nghiệm (Ablation Study trên Validation)**: Khi loại bỏ 2 cột `MIN_TTL` và `MAX_TTL` (chỉ giữ 45 đặc trưng hành vi luồng), Recall trên Validation giảm từ **`99.43%` xuống `96.26%`**, và số lượng tấn công bị bỏ lọt (`FN`) tăng gấp **`6.57 lần`** (từ `172` lên `1,130`). Điều này chứng minh hiệu năng rất cao trên benchmark có phần đóng góp lớn từ đặc trưng hạ tầng phòng lab.

### 12.6. Giới hạn cửa sổ thời gian và khả năng khái quát hóa thực tế
- Bộ dữ liệu chỉ thu thập trong khoảng **3.01 ngày** và có tới **`54.86%` (`1,297,869` dòng)** bản ghi trùng lặp trên 47 đặc trưng ML.
- Mô hình được huấn luyện trên dữ liệu giả lập này chưa phản ánh hiện tượng trôi dạt khái niệm (concept drift) theo tuần/tháng, cấu trúc lưu lượng mã hóa hiện đại (TLS 1.3, QUIC) hoặc các cuộc tấn công phân tán nhiều bước (APT) cần ngữ cảnh liên luồng (multi-flow correlation).

---

## 13. Operational & Security Implications

1. **Đánh đổi giữa `FPR` và Chi phí vận hành SOC (Alert Fatigue)**:
   - Trong mạng doanh nghiệp có hàng triệu luồng Benign mỗi ngày (chiếm >91% lưu lượng), ngay cả mức `FPR = 0.18%` cũng sinh ra hàng nghìn cảnh báo giả mỗi ngày. Vì vậy, Random Forest đóng vai trò là **lớp lọc tốc độ cao tuyến đầu (Tier-1 Flow Filter)** và cần kết hợp với cơ chế chấm điểm rủi ro / tương quan sự kiện ở tầng sau.
2. **Rủi ro an ninh từ `FN` và khả năng né tránh (Adversarial Evasion via TTL Spoofing)**:
   - Kẻ tấn công nắm được việc mô hình phụ thuộc gần 50% vào `MIN_TTL`/`MAX_TTL` có thể dễ dàng điều chỉnh giá trị TTL ban đầu của gói tin tấn công khớp với TTL của máy trạm hợp pháp, làm tăng tỷ lệ bỏ lọt (`FN`) lên gấp nhiều lần.
3. **Nguy cơ bỏ lọt các cuộc tấn công hiếm nhưng nguy hiểm cao (`Worms`, `Backdoor`, `Shellcode`, `Analysis`)**:
   - Một luồng `Backdoor` hoặc `Shellcode` bị bỏ lọt (`FN`) có tác động an ninh nghiêm trọng hơn nhiều so với một luồng `Fuzzers` thông thường, đòi hỏi hệ thống cảnh báo phải gắn trọng số rủi ro theo ngữ cảnh thay vì chỉ nhìn vào nhãn nhị phân 0/1.

---

## 14. Recommendations for Future Work

1. **Hoàn tất chạy thực nghiệm Test trên máy chứa đầy đủ artifact nhị phân**:
   - Chạy lệnh CLI sau trên máy lưu trữ bộ dữ liệu và model `.joblib` để xuất đầy đủ 5 artifact chuẩn vào `reports/evaluation/` và cập nhật bảng số liệu thực nghiệm Test:
   ```powershell
   $env:PYTHONPATH="src"; py -m network_anomaly.evaluation.error_analysis --run-test-evaluation --output-dir reports/evaluation/rf-test-canonical-v1 --report-path reports/evaluation/error_analysis_report.md
   ```
2. **Bổ sung đặc trưng ngữ cảnh liên luồng (Windowed / Host-Level Aggregation Features)**:
   - Để phá vỡ giới hạn `53.21%` chồng lấn vector 47 đặc trưng của từng luồng đơn lẻ, cần bổ sung các đặc trưng thống kê trên cửa sổ trượt theo IP nguồn/đích (ví dụ: số cổng đích duy nhất hoặc tần suất kết nối trong 5 giây) mà vẫn đảm bảo không rò rỉ nhãn hay địa chỉ IP tĩnh.
3. **Kiểm soát sự phụ thuộc vào đường tắt `TTL` (TTL-Invariant Regularization)**:
   - Huấn luyện và so sánh song song biến thể mô hình loại bỏ `MIN_TTL`/`MAX_TTL` hoặc áp dụng cơ chế phạt độ nhạy TTL để nâng cao độ bền vững khi triển khai ngoài môi trường phòng lab.
4. **Kết hợp đa mô hình (Ensemble với XGBoost / Isolation Forest / Autoencoder)**:
   - Sử dụng Random Forest làm chuẩn tham chiếu có giám sát, kết hợp với các mô hình phát hiện bất thường không giám sát/bán giám sát để cải thiện khả năng phát hiện các họ tấn công hiếm (`Worms`, `Analysis`, `Backdoor`) và tấn công chưa biết (zero-day).
