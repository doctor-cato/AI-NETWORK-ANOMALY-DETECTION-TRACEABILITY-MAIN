# 08 — Bộ 20 Câu hỏi Phản biện của Giảng viên & Đáp án Chuyên sâu

> Mọi câu trả lời dưới đây đều có cấu trúc: **Trả lời ngắn** (để nói trực tiếp trong 20–30 giây) → **Giải thích kỹ thuật** → **Ví dụ thực tế** → **Dẫn chứng từ repository** → **Giới hạn / Điều chưa kiểm chứng**.

---

### Câu 1: Dữ liệu lấy từ đâu?
- **Trả lời ngắn:** Từ bộ dữ liệu chuẩn công bố **NF-UNSW-NB15-v3** của Đại học Queensland (The University of Queensland, DOI `10.48610/6E0EDA1`, công bố 2025, bài báo Luay et al. `arXiv:2503.04404`).
- **Giải thích kỹ thuật:** Tệp CSV gốc `NF-UNSW-NB15-v3.csv` (577.360.958 bytes) được tải qua API UQRDM chính thức bằng `scripts/fetch_nf_unsw_nb15_v3.py`, giải nén từ gói BagIt và đối chiếu SHA-256 (`4ebb97bd...`) cùng publisher SHA-1 (`2cba4879...`). Điều khoản sử dụng là *Permitted Re-Use with Commercial Use Restriction* (UQ License ID `454104`).
- **Ví dụ thực tế:** Khi chạy `python scripts/dataset_manifest.py verify`, hệ thống kiểm tra kích thước 577 MB và SHA-256 của CSV khớp với `data/NF_UNSW_NB15_V3_MANIFEST.json`.
- **Dẫn chứng:** `data/NF_UNSW_NB15_V3_MANIFEST.json`, `scripts/fetch_nf_unsw_nb15_v3.py`, `docs/dataset/NF_UNSW_NB15_V3_PROVENANCE.md`.
- **Giới hạn / Chưa kiểm chứng:** Raw CSV và `.joblib` không đưa lên Git; quyền phân phối công khai nhị phân dẫn xuất đang `BLOCKED` tại `reports/governance/DISTRIBUTION_AUTHORIZATION.json`.

### Câu 2: Một dòng NetFlow mô tả điều gì?
- **Trả lời ngắn:** Một dòng mô tả **một luồng mạng hai chiều (bidirectional network flow)** giữa hai cặp IP/port theo một giao thức trong một khoảng thời gian, được tổng hợp thành các thống kê gói, byte, cờ TCP, TTL và thời gian giữa các gói (IAT).
- **Giải thích kỹ thuật:** Khác với PCAP (từng gói rời rạc) hay Application log (yêu cầu HTTP/Auth), một dòng NetFlow v3 gom toàn bộ giao tiếp của phiên kết nối đó thành 53 trường tổng hợp do bộ thu thập nProbe xuất ra (kèm 2 nhãn `Label`, `Attack`).
- **Ví dụ thực tế:** Dòng `row_id=7946` trong `demo_flows.csv` mô tả 1 flow TCP (`PROTOCOL=6`) từ `175.45.176.3:33878` tới `149.171.126.10:80` kéo dài `615 ms`, gửi `10` gói (`818` bytes) và nhận `6` gói (`256` bytes), gán nhãn `Reconnaissance`.
- **Dẫn chứng:** `docs/dataset/NF_UNSW_NB15_V3_SCHEMA.md`, `src/network_anomaly/data/nf_unsw_nb15_v3.py`.
- **Giới hạn / Chưa kiểm chứng:** Không có payload gói tin, không có thứ tự từng gói hay log người dùng/phiên ứng dụng.

### Câu 3: Dataset có bao nhiêu cột? Ý nghĩa từng nhóm?
- **Trả lời ngắn:** Có đúng **55 cột**, tách làm 3 nhóm: **6 cột Trace Metadata** (loại khỏi model), **47 cột ML Features** (đưa vào model) và **2 cột Targets** (`Label`, `Attack` — loại khỏi `X`).
- **Giải thích kỹ thuật:** `ALL_COLUMNS` trong `nf_unsw_nb15_v3.py` cố định thứ tự 55 cột: 6 metadata (`FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`, `IPV4_SRC_ADDR`, `L4_SRC_PORT`, `IPV4_DST_ADDR`, `L4_DST_PORT`), 47 ML features (10 categorical-coded + 37 quantitative), và 2 targets (`Label`, `Attack`).
- **Ví dụ thực tế:** Hàm `validate_feature_selection()` sẽ ném `ValueError` ngay nếu phát hiện bất kỳ cột nào trong 6 metadata hoặc 2 target lọt vào `X`.
- **Dẫn chứng:** `src/network_anomaly/data/nf_unsw_nb15_v3.py:17-123`, `scripts/export_academic_schema_summary.py`.
- **Giới hạn / Chưa kiểm chứng:** Một cấu hình 49 features (thêm 2 cổng L4) được nhắc như hướng mở rộng tương lai nhưng **chưa** triển khai hay đánh giá (`NOT VERIFIED`).

### Câu 4: Trường text là gì? Có sử dụng để train không?
- **Trả lời ngắn:** Chỉ có **3 cột dạng chuỗi text** trong 55 cột: `IPV4_SRC_ADDR`, `IPV4_DST_ADDR` và `Attack`. **Không cột text nào được dùng để train làm feature đầu vào `X`.**
- **Giải thích kỹ thuật:** Hai địa chỉ IP là chuỗi định danh bị loại khỏi `X` để tránh mô hình học thuộc IP phòng lab (`175.45.176.x`), còn `Attack` là chuỗi tên họ tấn công (`"Exploits"`, `"Fuzzers"`, ...) chỉ dùng để phân tích lỗi và tách Unknown holdout `{Backdoor, Worms}`. Toàn bộ 47 cột đưa vào `X` đều là số/mã số trong CSV gốc.
- **Ví dụ thực tế:** Ở `train_random_forest.py:701`, script chỉ đọc `ML_FEATURE_COLUMNS` (47 cột) + `["Label", "Attack"]`, không nạp cả cột IPv4 và Timestamp vào ma trận `X`.
- **Dẫn chứng:** `src/network_anomaly/data/nf_unsw_nb15_v3.py:10-14`, `scripts/train_random_forest.py:701-715`.
- **Giới hạn / Chưa kiểm chứng:** Việc bỏ IP/port khiến mô hình không phân biệt được hành vi theo vai trò host/dịch vụ đích trong mạng nếu thông tin lưu lượng thuần túy giống nhau.

### Câu 5: Protocol, state và nhóm lưu lượng được xử lý thế nào?
- **Trả lời ngắn:** `PROTOCOL`, `TCP_FLAGS`, `CLIENT_TCP_FLAGS`, `SERVER_TCP_FLAGS` và `L7_PROTO` vốn đã được mã hóa số trong `NF-UNSW-NB15-v3`; chúng được xếp vào nhóm `CATEGORICAL_CODED_COLUMNS`, điền giá trị thiếu bằng **mode của Train** và làm tròn nguyên (`np.round`), **không** scale.
- **Giải thích kỹ thuật:** Khác với bản 2015 có chữ `"TCP"`, `"FIN"`, `"http"`, bản NetFlow v3 dùng mã số IANA (`6` = TCP, `17` = UDP), bitmask TCP (`27` = `0b11011`) và mã nProbe `L7_PROTO` (`5` = DNS, `7` = HTTP, `37` = nhóm phổ biến). Trong `TrainOnlyPreprocessor`, 10 cột này bị loại khỏi nhánh scaling liên tục (`pipeline.py:370-372`).
- **Ví dụ thực tế:** `L7_PROTO` trong CSV có giá trị thập phân `7.37` (HTTP sub-protocol); `fit()` ép `int64` để lập vocabulary `124` mã (mode `37.0`), còn `transform()` làm tròn `np.round(7.37) = 7.0`.
- **Dẫn chứng:** `src/network_anomaly/data/nf_unsw_nb15_v3.py:83-94`, `src/network_anomaly/preprocessing/pipeline.py:356-363, 451-470`.
- **Giới hạn / Chưa kiểm chứng:** Giá trị unknown ở tập mới dùng chính sách `"passthrough"` (giữ nguyên mã số) thay vì ánh xạ danh mục mới; với `L7_PROTO`, việc làm tròn có thể gộp các sub-protocol nProbe về cùng số nguyên.

### Câu 6: Categorical features được chuyển thành vector số như thế nào?
- **Trả lời ngắn:** **Không dùng One-Hot Encoding.** Cả 10 trường categorical-coded vốn đã là mã số nên được giữ nguyên thành **10 cột số thực `float64`** trong cùng vector 47 chiều `(N, 47)`.
- **Giải thích kỹ thuật:** Trong `CATEGORICAL_CODED_COLUMNS` có những trường cardinality cực lớn như `DNS_QUERY_ID` (`63.003` mã trong Train) và `ICMP_TYPE` (`910` mã). Nếu dùng One-Hot Encoding, ma trận sẽ phình lên hơn 64.000 cột thưa không thể train hiệu quả trên 1,65 triệu dòng. `TrainOnlyPreprocessor` giữ nguyên 10 cột số nguyên đã kiểm định kiểu và vocabulary (`output_features_count = 47`).
- **Ví dụ thực tế:** `PROTOCOL = 6` sau `transform()` vẫn nằm tại cột index 0 với giá trị `6.0` (`float64`), tổng số cột vẫn là `47`.
- **Dẫn chứng:** `reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json` (`baseline_ml_features_count = 47`, `output_features_count = 47`), `src/network_anomaly/preprocessing/pipeline.py:451-484`.
- **Giới hạn / Chưa kiểm chứng:** Các mô hình cây (RF, XGBoost) xử lý mã số khá tốt, nhưng với mạng nơ-ron `MLPRegressor` (Autoencoder), biểu diễn mã số nguyên (như `DNS_QUERY_ID` lên tới `65535`) dưới dạng giá trị số trực tiếp không mang ý nghĩa khoảng cách tuyến tính.

### Câu 7: Trường số có được chuẩn hóa không? Vì sao?
- **Trả lời ngắn:** **Không chuẩn hóa (No scaling — `scaler_type = "none"`)** trong pipeline baseline đã kiểm chứng đang đóng gói cho cả 4 mô hình.
- **Giải thích kỹ thuật:** `TrainOnlyPreprocessor` có viết sẵn 3 tùy chọn `robust`, `standard`, `minmax` (áp dụng riêng cho 37 cột `QUANTITATIVE_ML_COLUMNS`), nhưng `nf_unsw_nb15_v3_preprocessing_manifest.json` cấu hình `scaler_type: "none"` (`scaler_params_count: 0`) vì các mô hình cây (RF, XGBoost, Isolation Forest) bất biến với phép biến đổi đơn điệu và cần giữ nguyên giá trị gốc (như `FLOW_DURATION_MILLISECONDS = 0.0`, `MIN_TTL = 31.0`). Autoencoder dùng chung artifact preprocessor này nên cũng nhận đầu vào chưa scale (đó là lý do ngưỡng MSE của Autoencoder lên tới `17.234.985,79`).
- **Ví dụ thực tế:** `SRC_TO_DST_AVG_THROUGHPUT = 540222.0` đi thẳng vào mô hình là `540222.0`, không bị trừ mean hay chia std.
- **Dẫn chứng:** `reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json:161-187`, `docs/NF_UNSW_NB15_V3_PREPROCESSING_POLICY.md:73-74`.
- **Giới hạn / Chưa kiểm chứng:** Không scale làm MSE của Autoencoder bị chi phối bởi các cột có biên độ lớn (bytes/throughput), góp phần khiến Recall của Autoencoder thấp (`0,1093`); chưa chạy thí nghiệm đối chứng Autoencoder với `robust`/`standard` scaler trên real data.

### Câu 8: Model nhận đầu vào có kích thước bao nhiêu?
- **Trả lời ngắn:** Ma trận 2 chiều shape **`(N, 47)`**, kiểu `float64`, hoàn toàn hữu hạn (`0 NaN`, `0 Inf`), giống nhau cho **cả 4 mô hình**.
- **Giải thích kỹ thuật:** Cụ thể khi huấn luyện: RF & XGBoost nhận `X_train` shape `(1.655.797, 47)`; Isolation Forest & Autoencoder nhận `X_train_benign` shape `(1.590.608, 47)`; khi đánh giá Held-out Test: `(345.953, 47)`; khi chạy demo 200 dòng (trừ 2 dòng OOD): `(198, 47)`.
- **Ví dụ thực tế:** `train_random_forest.py:727` ép assertion `X_train_trans.shape == (len(train_indices), 47)` trước khi cho phép gọi `model.fit()`.
- **Dẫn chứng:** `reports/preprocessing/REAL_DATA_SMOKE_REPORT.md:39-43`, `scripts/train_random_forest.py:727-732`, `src/network_anomaly/models/autoencoder.py:27,234,302`.
- **Giới hạn / Chưa kiểm chứng:** Nếu một file CSV thiếu dù chỉ 1 trong 47 cột, pipeline từ chối fail-closed ngay trước tiền xử lý.

### Câu 9: `Label = 1` đại diện cho điều gì?
- **Trả lời ngắn:** Đại diện cho một luồng mạng được gắn nhãn thuộc một trong 9 kịch bản tấn công trong testbed UNSW-NB15 (`Analysis`, `Backdoor`, `DoS`, `Exploits`, `Fuzzers`, `Generic`, `Reconnaissance`, `Shellcode`, `Worms`).
- **Giải thích kỹ thuật:** Mô hình supervised học bài toán phân loại nhị phân (`0` = Benign, `1` = Attack), không phân biệt 9 lớp con khi `fit()`. Tuy nhiên `Label = 1` **không đồng nghĩa** máy đích đã bị xâm nhập thành công — ví dụ các flow quét thăm dò `Reconnaissance` hoặc gói thử nghiệm `Fuzzers` vẫn mang `Label = 1`.
- **Ví dụ thực tế:** Trong Held-out Test (`345.953` dòng), có `30.596` dòng `Label = 1`, gồm `10.520` Exploits, `7.322` Fuzzers, `5.111` Generic, `4.464` Reconnaissance, `1.260` Backdoor, `1.193` DoS, `396` Shellcode, `294` Analysis, `36` Worms.
- **Dẫn chứng:** `reports/evaluation/rf-heldout-ea330b9/metrics.json:54-114`, `src/network_anomaly/models/xgboost_model.py:239-243`.
- **Giới hạn / Chưa kiểm chứng:** Không thể dùng kết quả `Label = 1` để kết luận mức độ thiệt hại trên host hay thay thế công cụ giám sát endpoint (EDR).

### Câu 10: Train/Validation/Test được chia thế nào?
- **Trả lời ngắn:** Chia **theo thứ tự thời gian (`FLOW_START_MILLISECONDS`) với khoảng đệm Purge Gap 5 phút (`300.000 ms`)** ở hai ranh giới: Train `1.655.797` (70%), Purged `9.443`, Validation `345.371` (14,60%), Purged `8.860`, Test `345.953` (14,63%).
- **Giải thích kỹ thuật:** Khoảng đệm `300.000 ms` khớp với bucket 5 phút của `canonical_flow_group` và lớn hơn thời lượng tối đa của mọi flow trong dataset (`120.948 ms`), bảo đảm 0 flow cắt ngang ranh giới và 0 canonical flow-group lặp giữa Train/Val/Test.
- **Ví dụ thực tế:** Train kết thúc ở `2015-02-18 05:42:13.382Z`; Validation bắt đầu sau đó `300.004 ms` lúc `05:47:13.386Z`.
- **Dẫn chứng:** `reports/splits/nf_unsw_nb15_v3_split_manifest.json:126-309`, `docs/NF_UNSW_NB15_V3_SPLIT_PROTOCOL.md`.
- **Giới hạn / Chưa kiểm chứng:** Nhóm `canonical_flow_group` 5 phút chỉ là xấp xỉ cho phiên mạng vì NetFlow v3 không có session ID gốc từ PCAP; toàn bộ phần cắt Validation và Test đều nằm trong ngày `2015-02-18`.

### Câu 11: Có data leakage không? Kiểm tra bằng gì?
- **Trả lời ngắn:** **Không có code/pipeline leakage** (đã kiểm toán `0` overlap dòng gốc, `0` overlap flow-group, `0` vượt biên thời gian, preprocessor fit `train_only`, Test bị khóa khi train), nhưng **có lặp lại 47-feature vector (`49,98%–53,21%`) và `MIN_TTL` shortcut trong bản chất dữ liệu testbed**.
- **Giải thích kỹ thuật:** Dự án kiểm tra bằng: (1) disk-backed fingerprint audit (`split_and_audit_nf_unsw_nb15_v3.py`), (2) `TestLockPolicy` & `PartitionAccessTracker` trong script train, (3) 70+ test `test_preprocessing_pipeline.py` xác minh `fit` không dùng Val/Test, (4) `rf_baseline_validation_audit.json` kiểm tra label-shuffle control (C7), bỏ cột/loại trùng (C1–C6), và cây 1 biến `MIN_TTL`.
- **Ví dụ thực tế:** Ngay cả khi xóa toàn bộ `551.167` dòng Train có vector 47 chiều trùng với Validation (probe C6), RF vẫn đạt `0,999699` nhờ các đặc trưng testbed khác trong cùng ngày `2015-02-18` (như `MIN_TTL`).
- **Dẫn chứng:** `reports/splits/nf_unsw_nb15_v3_leakage_audit_report.md`, `reports/models/rf_baseline_validation_audit.json`, `tests/unit/test_anti_imputation_and_label_integrity.py`.
- **Giới hạn / Chưa kiểm chứng:** `split_membership_audit_report.md` ghi nhận `MEMBERSHIP_EQUIVALENCE: NOT_VERIFIED` ở mức SHA file index đối với bản RF đầu tiên vì tệp index cũ không lưu trong Git.

### Câu 12: Mô hình học gì từ dữ liệu?
- **Trả lời ngắn:** Học ranh giới phân tách giữa lưu lượng Benign và Attack trong không gian 47 thông số thống kê NetFlow của **testbed UNSW-NB15 2015** — trong đó các mô hình cây học rất mạnh các đặc điểm đặc thù của bộ sinh IXIA PerfectStorm (đặc biệt `MIN_TTL`, `MAX_TTL`, byte/pkt/throughput).
- **Giải thích kỹ thuật:** Cây RF/XGB phân hoạch không gian 47 chiều theo Gini/logloss; Isolation Forest và Autoencoder học phân phối/cấu trúc của `1.590.608` flow Benign để đánh dấu các flow nằm ở vùng thưa hoặc có sai số tái tạo MSE cao.
- **Ví dụ thực tế:** Trên `NF-UNSW-NB15-v3`, `MIN_TTL` của Benign có trung vị `31.0` còn Attack có trung vị `254.0` — chỉ 1 đặc trưng này đã phân tách `99,98%` Validation (`rf_baseline_validation_audit.json`).
- **Dẫn chứng:** `reports/models/rf_baseline_validation_audit.json:47-50`, `reports/evaluation/error_analysis_report.md:54-85`.
- **Giới hạn / Chưa kiểm chứng:** Không chứng minh được mô hình học bản chất hành vi tấn công tổng quát trên mạng thật (bằng chứng: cross-dataset trên CIC-IDS2018-v3 tụt Recall về `0,0`).

### Câu 13: Bốn model khác nhau ra sao?
- **Trả lời ngắn:** 2 supervised (`Random Forest` bagging cây sâu, `XGBoost` boosting cây nông) xuất xác suất tấn công `[0, 1]`; 2 unsupervised (`Isolation Forest` cô lập bằng độ sâu cây ngẫu nhiên, `Autoencoder` mạng `MLPRegressor 32-16-32` đo lỗi tái tạo MSE) chỉ học trên Benign-only và dùng ngưỡng hiệu chuẩn Validation.
- **Giải thích kỹ thuật:** Trên giao diện Desktop, chỉ **Random Forest** mang nhãn `MODEL_VALIDATED`; **XGBoost**, **Isolation Forest** và **Autoencoder** mang nhãn `RESEARCH_ONLY` để đối chiếu khoa học (không được phép đề xuất `ISOLATE_RECOMMENDED` trong Security Dry-Run `#27`).
- **Ví dụ thực tế:** Khi phân tích cùng một flow, RF/XGB trả `attack_probability` (ví dụ `0.985`), còn IF/AE trả `attack_probability = null` và `raw_anomaly_score` (ví dụ IF `-0.01`, AE `2.1e7`).
- **Dẫn chứng:** `src/network_anomaly/models/*.py`, `src/network_anomaly/api/desktop_csv.py`, `src/network_anomaly/ingestion/compatibility.py`.
- **Giới hạn / Chưa kiểm chứng:** Không có ensemble/voting kết hợp tự động cả 4 mô hình thành 1 quyết định duy nhất.

### Câu 14: Code training nằm ở đâu?
- **Trả lời ngắn:** Trong 4 script entrypoint ở `scripts/`: `train_random_forest.py`, `train_xgboost.py`, `train_isolation_forest.py`, `train_autoencoder.py`, gọi các lớp mô hình ở `src/network_anomaly/models/`.
- **Giải thích kỹ thuật:** Tiền xử lý fit tại `scripts/preprocess_nf_unsw_nb15_v3.py` (`TrainOnlyPreprocessor.fit`); chia tập tại `scripts/split_and_audit_nf_unsw_nb15_v3.py`; đánh giá Held-out Test RF riêng tại `scripts/evaluate_random_forest.py`.
- **Ví dụ thực tế:** `train_random_forest.py:802` gọi `model.fit(X_train_trans, y_train)`, `train_isolation_forest.py:1813` gọi `fit_model(model, X_train_benign)`.
- **Dẫn chứng:** `scripts/train_*.py`, `src/network_anomaly/models/*.py`.
- **Giới hạn / Chưa kiểm chứng:** Chạy lại đầy đủ cần raw CSV 577 MB và ~4 GB RAM, không chạy trên CI GitHub Actions (CI bỏ qua bước real-data nếu thiếu raw CSV).

### Câu 15: Dữ liệu đã biến đổi thế nào trước `model.fit()`?
- **Trả lời ngắn:** Đọc CSV với `keep_default_na=False` → chọn đúng 47 cột `ML_FEATURE_COLUMNS` (bỏ 6 metadata + 2 target) → `audit_column_tokens()` chuyển `""`/`inf` thành `np.nan` → điền median (37 cột số) hoặc mode + làm tròn (10 cột phân loại) đã fit **chỉ trên Train** → không OHE, không scale → xuất `(1.655.797, 47)` `float64` (với IF/AE lọc tiếp `Label==0` còn `(1.590.608, 47)`).
- **Giải thích kỹ thuật:** Trong Train, 69.717 ô thiếu/`+Inf` ở `SRC_TO_DST_SECOND_BYTES` được thay bằng `162.0`, 69.717 ô `+Inf` ở `DST_TO_SRC_SECOND_BYTES` được thay bằng `78.2815...`, 69.717 dòng `FLOW_DURATION_MILLISECONDS == 0` được giữ nguyên `0.0`.
- **Ví dụ thực tế:** Dòng `row_id=92156` từ `SRC_TO_DST_SECOND_BYTES=""` và `DST_TO_SRC_SECOND_BYTES=inf` biến thành `162.0` và `78.28151260504201`.
- **Dẫn chứng:** `src/network_anomaly/preprocessing/pipeline.py:108-492`, `reports/preprocessing/REAL_DATA_SMOKE_REPORT.md`.
- **Giới hạn / Chưa kiểm chứng:** Nếu CSV có chuỗi chữ lỗi không ép được float (ví dụ `"abc"`), pipeline từ chối bằng `ValueError` thay vì tự điền.

### Câu 16: Vì sao F1 rất cao hoặc rất thấp?
- **Trả lời ngắn:** RF (`0,999853`) và XGBoost (`0,999984`) rất cao vì bài toán trong miền testbed 2015 phân tách cực mạnh qua `MIN_TTL` và trùng vector 53,21%; ngược lại Autoencoder (`0,1361`) thấp vì không scale 47 đặc trưng khiến MSE bị chi phối bởi cột biên độ lớn dưới ngưỡng chặt `Val FPR <= 0,05`, còn IF (`0,5064`) có Recall cao (`0,8997`) nhưng nhiều False Positive (`FPR = 16,05%`).
- **Giải thích kỹ thuật:** Đây là sự tương phản có giá trị khoa học: supervised trees tận dụng triệt để tương quan đặc trưng-nhãn của testbed, còn unsupervised models không biết nhãn tấn công nên mọi flow Benign hiếm/lưu lượng lớn đều dễ bị đẩy qua ngưỡng lỗi tái tạo hoặc vùng cô lập thưa.
- **Ví dụ thực tế:** Cây 1 biến `MIN_TTL` đạt `0,999849` trên Validation, còn trên `NF-CSE-CIC-IDS2018-v3`, RF rớt xuống `F1 = 0,0`.
- **Dẫn chứng:** `reports/models/rf_baseline_validation_audit.json`, `reports/evaluation/autoencoder/metrics.json`, `reports/experiments/isolation_forest/metrics.json`, `reports/evaluation/cross_dataset_evaluation_results.json`.
- **Giới hạn / Chưa kiểm chứng:** Chưa đánh giá Autoencoder với scaler `standard`/`robust` trên real data để đo mức cải thiện khi chuẩn hóa biên độ.

### Câu 17: Khi chạy demo có huấn luyện lại không?
- **Trả lời ngắn:** **Tuyệt đối không.** Demo chỉ nạp các tệp `.joblib` và `.json` đã train/đóng băng trước, kiểm tra SHA-256 rồi chạy `.transform()` và `.predict()`.
- **Giải thích kỹ thuật:** Cả CLI (`scripts/predict.py`) lẫn Desktop Backend (`desktop_csv.py` → `service.py` → `InferencePipeline.from_artifacts()`) đều chỉ dùng `load_verified_preprocessor()` và `load_verified_model()`. Nếu thiếu `.joblib` hoặc sai hash, hệ thống fail-closed (`HTTP 503`).
- **Ví dụ thực tế:** Trong `src/network_anomaly/api/`, không có lệnh `.fit()` nào được gọi khi xử lý `/api/v1/csv/analyze`.
- **Dẫn chứng:** `src/network_anomaly/inference/predict.py:534-718`, `src/network_anomaly/api/service.py:387-480`, `src/network_anomaly/api/desktop_csv.py:1222-1440`.
- **Giới hạn / Chưa kiểm chứng:** Trong `service.py` vẫn còn helper `_analyze_with_heuristic()` cho endpoint `/api/v1/analyze` nếu caller bật `allow_heuristic_fallback=True`, nhưng **Desktop CSV (`/api/v1/csv/analyze`) khóa cứng `allow_heuristic_fallback=False`** (`desktop_csv.py:1310`).

### Câu 18: Nếu CSV thiếu feature thì chuyện gì xảy ra?
- **Trả lời ngắn:** Hệ thống **từ chối ngay lập tức (fail-closed)**, trả lỗi rõ ràng cho biết chính xác thiếu cột nào trong 47 `ML_FEATURE_COLUMNS` và không ép chạy mô hình.
- **Giải thích kỹ thuật:** Ở tầng kiểm tra (`validate_inference_input()` tại `predict.py:124-129`), nếu `missing_features` khác rỗng, hàm ném `ValueError("Input data is missing X required baseline ML feature(s): [...]")`. Trên Desktop UI (`desktop_csv.py`), API trả mã lỗi 4xx được `formatUserFriendlyError` dịch sang thông báo tiếng Việt dễ hiểu. Nếu đủ 47 cột nhưng khác thứ tự, pipeline tự sắp xếp lại đúng thứ tự canonical; nếu thừa cột IP/port/label, pipeline tự loại khỏi `X`.
- **Ví dụ thực tế:** Bỏ cột `MIN_TTL` khỏi CSV thử nghiệm → `/api/v1/csv/inspect` và `/api/v1/csv/analyze` từ chối ngay ở bước schema check.
- **Dẫn chứng:** `src/network_anomaly/inference/predict.py:124-132`, `tests/unit/test_inference_pipeline.py`, `tests/unit/test_desktop_csv_api.py`.
- **Giới hạn / Chưa kiểm chứng:** Không hỗ trợ suy luận một phần khi thiếu cột (anti-imputation policy cho thiếu cột schema).

### Câu 19: Hệ thống nhận diện tấn công chưa từng thấy được không?
- **Trả lời ngắn:** Trong giao thức **holdout nội bộ** (`Backdoor`, `Worms` bị giấu khỏi bước chọn ngưỡng Validation), Isolation Forest phát hiện được **`86,57%`** (`1.122/1.296`) và Autoencoder phát hiện được **`6,25%`** (`81/1.296`); nhưng **không thể khẳng định hệ thống phát hiện được tấn công zero-day trên mạng thực tế**.
- **Giải thích kỹ thuật:** `Backdoor` và `Worms` trong `NF-UNSW-NB15-v3` vẫn sinh ra từ cùng phòng lab IXIA PerfectStorm 2015. Khi gặp lưu lượng ngoài miền (`NF-CSE-CIC-IDS2018-v3`), phân phối thay đổi hoàn toàn. Ngoài ra cổng `OODValidator` của Desktop chủ động gắn `ABSTAINED_OOD` khi `MIN_TTL == 0` hoặc vi phạm vật lý để tránh phán đoán bừa.
- **Ví dụ thực tế:** `Isolation Forest` đạt Recall `0,8675` với `Backdoor` và `0,8056` với `Worms` trên Held-out Test (`if-c4-20261115T055359Z`), nhưng đi kèm `FPR = 16,05%` trên Benign.
- **Dẫn chứng:** `reports/experiments/isolation_forest/evaluation_report.md:85-103`, `reports/evaluation/autoencoder/evaluation_report.md:120-191`, `.agents/rules/project-scope.md:28`.
- **Giới hạn / Chưa kiểm chứng:** Chưa có bằng chứng thực nghiệm cross-dataset cho IF và AE (mới có cross-dataset cho RF trên `NF-CSE-CIC-IDS2018-v3`).

### Câu 20: Bằng chứng nào chứng minh model thật đã được train/test?
- **Trả lời ngắn:** Toàn bộ chuỗi SHA-256 và báo cáo JSON/Markdown lưu trong `reports/` (`random_forest_manifest.json`, `rf-heldout-ea330b9/`, `xgboost_manifest.json`, `evaluation/xgboost/`, `isolation_forest_manifest.json`, `experiments/isolation_forest/`, `autoencoder_manifest.json`, `evaluation/autoencoder/`) cùng bộ test `pytest` + kiểm chứng E2E trong PR #70 và PR #72.
- **Giải thích kỹ thuật:** Mỗi báo cáo ghi rõ `dataset_sha256`, `split_manifest_sha256`, `train/val/test_indices_sha256`, `preprocessor_artifact_sha256`, `model_artifact_sha256`, `git_commit`, phiên bản Python/thư viện, confusion matrix từng lớp và kết quả reload verification (`atol=1e-7`).
- **Ví dụ thực tế:** Trên máy cục bộ có `.joblib`, chạy `python scripts/verify_companion_artifacts.py --verify-e2e` kiểm chứng 4/4 model nạp đúng SHA-256 và chạy inference 200 dòng (`198` đánh giá + `2` OOD).
- **Dẫn chứng:** `reports/models/*.json`, `reports/evaluation/**`, `reports/experiments/isolation_forest/**`, `scripts/verify_companion_artifacts.py`, PR #72 (merge commit `e5a1f89`, gồm commit `e6be2ea`).
- **Giới hạn / Chưa kiểm chứng:** Các tệp `.joblib` và `demo_*.csv` không lưu trực tiếp trong public Git repo do kích thước lớn và giới hạn UQ `454104`; trên máy mới chưa có `.joblib` hoặc trên CI GitHub Actions, test real-data báo `SKIPPED` và API báo `BLOCKED / NOT READY` fail-closed.
