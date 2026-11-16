# 03 — Pipeline Tiền xử lý Dữ liệu (`DATA_PREPROCESSING_PIPELINE.md`)

> **Trạng thái kiểm chứng:** `IMPLEMENTED`, `TESTED` (70+ unit/integration tests trong `tests/unit/test_preprocessing_pipeline.py`) và `EXPERIMENTALLY VALIDATED` trên `NF-UNSW-NB15-v3.csv` (`reports/preprocessing/REAL_DATA_SMOKE_REPORT.md`, artifact SHA-256 `12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19`).

---

## 1. Trả lời trực tiếp câu hỏi của giảng viên

> *“Dữ liệu ban đầu có trường text, trạng thái và trường số. Sau tiền xử lý, dữ liệu thay đổi cụ thể thế nào trước khi đưa vào mô hình?”*

**Trả lời chính xác theo mã nguồn thực tế (`src/network_anomaly/preprocessing/pipeline.py`):**

1. **Ba cột text/định danh thật sự bị loại bỏ hoàn toàn trước khi vào `TrainOnlyPreprocessor`:**
   - Hai cột địa chỉ IP chuỗi (`IPV4_SRC_ADDR`, `IPV4_DST_ADDR`), hai cổng (`L4_SRC_PORT`, `L4_DST_PORT`), hai timestamp (`FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`) bị loại bỏ vì là trace metadata.
   - Hai cột nhãn (`Label`, `Attack` — trong đó `Attack` là chuỗi tên họ tấn công) bị loại bỏ khỏi `X`.
   - Sau bước lọc cột (`validate_inference_input()` / `ML_FEATURE_COLUMNS`), dữ liệu chỉ còn **47 cột số/mã số** theo đúng thứ tự canonical (`nf-unsw-nb15-v3-baseline-47`).
2. **Các trường trạng thái và giao thức (`TCP_FLAGS`, `PROTOCOL`, `L7_PROTO`, v.v.) không qua One-Hot Encoding:**
   - Trong `NF-UNSW-NB15-v3`, các trường này vốn đã được mã hóa số nguyên/thực (bitmask `TCP_FLAGS`, mã IANA `PROTOCOL`, mã `L7_PROTO`, mã `ICMP`, `DNS`, `FTP`).
   - `TrainOnlyPreprocessor` **không tạo vector One-Hot** (nếu One-Hot Encoding cả `DNS_QUERY_ID` có `63.003` giá trị phân biệt thì số chiều sẽ bùng nổ). Do đó ma trận đầu ra giữ nguyên đúng **47 cột**, mỗi cột là 1 chiều số thực `float64`.
   - Với 10 cột `CATEGORICAL_CODED_COLUMNS`, bộ tiền xử lý kiểm tra token, điền giá trị thiếu (nếu có) bằng **mode của Train**, rồi làm tròn về số nguyên gần nhất (`np.round()`).
3. **Các trường số định lượng (`37` cột) KHÔNG được chuẩn hóa (No Scaling) trong cấu hình baseline hiện hành:**
   - Trong artifact đang dùng cho cả 4 mô hình (`nf_unsw_nb15_v3_preprocessing_manifest.json`), cấu hình là **`scaler_type = "none"`** (`scaler_params_count = 0`). Code `TrainOnlyPreprocessor` có hỗ trợ tùy chọn `standard` (z-score), `robust` (median/IQR), `minmax`, nhưng **pipeline chính thức của dự án không bật scaler** để giữ nguyên đơn vị vật lý và phân phối cho các mô hình cây (RF, XGB, IF), đồng thời Autoencoder (`MLPRegressor`) cũng đọc trực tiếp cùng artifact tiền xử lý 47 cột này.
4. **Thay đổi cụ thể lớn nhất diễn ra ở hai cột tốc độ bị thiếu và `+Inf`:**
   - Trong CSV gốc, `SRC_TO_DST_SECOND_BYTES` có `63.425` ô trống `""` và `59.068` giá trị `inf`; `DST_TO_SRC_SECOND_BYTES` có `122.493` giá trị `inf` (trùng với các dòng `FLOW_DURATION_MILLISECONDS == 0`).
   - `audit_column_tokens()` chuyển `""`, `NaN`, `+Inf`, `-Inf` thành `np.nan`, sau đó `transform()` thay bằng **median tính chỉ trên tập Train** (`162.0` cho `SRC_TO_DST_SECOND_BYTES` và `78.28151260504201` cho `DST_TO_SRC_SECOND_BYTES`), giữ nguyên `FLOW_DURATION_MILLISECONDS = 0.0` (không xóa dòng).
5. **Hình dạng (Shape) và Kiểu dữ liệu (Dtype) cuối cùng trước `model.fit()` và `model.predict()`:**
   - Đầu vào sau chọn cột: DataFrame `(N, 47)` (lẫn chuỗi số/`""`/`inf`).
   - Đầu ra sau `TrainOnlyPreprocessor.transform()`: DataFrame `(N, 47)` toàn bộ **47 cột kiểu `float64`, 100% hữu hạn (0 NaN, 0 Inf)**.

---

## 2. Chi tiết từng bước trong `TrainOnlyPreprocessor`

### Bước 1 — Đọc CSV với `keep_default_na=False` và Kiểm tra Schema
- Hàm `load_and_preprocess_split()` (`src/network_anomaly/preprocessing/pipeline.py:895`) đọc CSV với `keep_default_na=False` để **không gộp ngầm ô trống `""` với chuỗi `"NaN"`**.
- Tại inference (`validate_inference_input()` tại `src/network_anomaly/inference/predict.py:83`), kiểm tra đủ 47 cột `ML_FEATURE_COLUMNS`, tự động sắp xếp lại theo đúng thứ tự canonical và tách riêng `row_id`, `TARGET_COLUMNS`, `TRACE_METADATA_COLUMNS`. Thiếu dù 1 cột sẽ ném `ValueError` fail-closed.

### Bước 2 — Phát hiện Missing, NaN, `±Infinity` và Token không hợp lệ
- Hàm `audit_column_tokens()` (`src/network_anomaly/preprocessing/pipeline.py:108`) quét từng cột:
  - Ô trống `""` → đếm vào `missing` → gán `np.nan`.
  - `"nan"`, `"null"`, `"none"`, `None`, `pd.NA` → đếm vào `nan` → gán `np.nan`.
  - `"inf"`, `"+inf"`, `"infinity"` → đếm vào `positive_infinity` → gán `np.nan`.
  - `"-inf"`, `"-infinity"` → đếm vào `negative_infinity` → gán `np.nan`.
  - Chuỗi chữ không ép kiểu float được (ví dụ `"malicious_packet"`) → đếm `invalid_numeric` và **ném `ValueError` fail-closed ngay lập tức**.
- Kiểm chứng trên `1.655.797` dòng **Train**:
  - `SRC_TO_DST_SECOND_BYTES`: `missing = 30.973`, `positive_infinity = 38.744` (tổng `69.717` non-finite).
  - `DST_TO_SRC_SECOND_BYTES`: `missing = 0`, `positive_infinity = 69.717` (tổng `69.717` non-finite).
  - 45 cột còn lại trên Train: `0` non-finite.

### Bước 3 — Xử lý trùng lặp và dòng `FLOW_DURATION_MILLISECONDS == 0`
- **Không xóa dòng trùng lặp (`14.815` exact duplicates / `1.134.553` repeated 47-feature vectors)** và **không xóa dòng zero-duration** (`69.717` dòng Train, `25.697` dòng Validation, `25.969` dòng Test).
- Hàm `verify_zero_duration_retention()` (`pipeline.py:779`) kiểm chứng 100% dòng có duration `0.0` được giữ nguyên giá trị `0.0` sau biến đổi.
- Không cắt ngoại lệ (no clipping / no winsorization).

### Bước 4 — Fit CHỈ trên Train (`TrainOnlyPreprocessor.fit`)
- Chạy tại `pipeline.py:282` sau khi đã tách `train_indices` (`1.655.797` dòng). Tham số `y` hoàn toàn bị bỏ qua (`y: Any = None`).
- **37 cột `QUANTITATIVE_ML_COLUMNS`:** tính **median** trên các giá trị hữu hạn của Train (`np.median(finite_values)`).
- **10 cột `CATEGORICAL_CODED_COLUMNS`:** ép `int64` trên các giá trị hữu hạn của Train, tính **mode** (`series_finite.mode().iloc[0]`) và lưu tập giá trị đã gặp `category_vocabularies_`.
- **Scaler:** `scaler_type == "none"` → không fit scaler (`scaler_params_ = {}`).

### Bước 5 — Biến đổi đóng băng (`TrainOnlyPreprocessor.transform`)
- Chạy tại `pipeline.py:401` cho Validation, Test và dữ liệu Inference mới:
  1. Điền mọi `np.nan` (bao gồm `""` và `±Inf` đã chuyển đổi) bằng `self.imputed_values_[col]` đã học từ Train.
  2. Với 10 cột `CATEGORICAL_CODED_COLUMNS`: làm tròn `np.round(cleaned_arr)` và đối chiếu `category_vocabularies_`. Với cấu hình baseline `handle_unknown_categories = "passthrough"`, mã danh mục chưa từng gặp ở Train vẫn được giữ nguyên (thay vì báo lỗi hoặc gán về mode như chế độ `"error"` / `"sentinel"`).
  3. Kiểm tra hậu kiểm `np.all(np.isfinite(df_out.to_numpy()))` — bảo đảm đầu ra không còn bất kỳ `NaN` hay `Inf`.

### Bước 6 — Lưu trữ, kiểm tra SHA-256 và tái sử dụng khi Inference
- Lưu thành `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib` (SHA-256 `12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19`) kèm manifest `reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json`.
- Khi huấn luyện hoặc chạy inference (`TrainOnlyPreprocessor.load_verified()` tại `pipeline.py:719`), hệ thống **băm SHA-256 tệp `.joblib` và kiểm tra contract TRƯỚC khi deserialize pickle/joblib**, đồng thời kiểm tra chéo `preprocessor_sha256` khớp với manifest của từng model. Không bao giờ `fit()` lại trên Validation, Test hay CSV người dùng nhập vào.

---

## 3. Ví dụ thực tế từng bước (Lấy từ `data/demo/demo_flows.csv`)

### Ví dụ A — Dòng tấn công hữu hạn hoàn chỉnh (`row_id = 7946`, `Label = 1`, `Attack = "Reconnaissance"`)

> **Lưu ý:** Đây là một **dòng tấn công (`Label = 1`, họ `Reconnaissance`)** có đầy đủ 47 giá trị hữu hạn (`0` ô trống, `0` `inf`), minh họa luồng đi chuẩn của một Attack flow qua `TrainOnlyPreprocessor.transform()` mà không cần bù giá trị thiếu (trái ngược với Ví dụ B bên dưới là dòng Benign bị thiếu/`+Inf` và `MIN_TTL = 0`).

| Giai đoạn | Dữ liệu cụ thể | Shape / Kiểu |
|---|---|---|
| **1. Raw CSV row** (54 cột trong `demo_flows.csv`, gồm `row_id` + 53 NetFlow) | `row_id=7946`, `FLOW_START=1424244898204`, `IPV4_SRC="175.45.176.3"`, `L4_SRC_PORT=33878`, `IPV4_DST="149.171.126.10"`, `L4_DST_PORT=80`, `PROTOCOL=6`, `L7_PROTO=7.0`, `IN_BYTES=818`, `OUT_BYTES=256`, `TCP_FLAGS=19`, `FLOW_DURATION=615`, `MIN_TTL=254`, `MAX_TTL=255`, `SRC_TO_DST_SECOND_BYTES=0.41626`, `DST_TO_SRC_SECOND_BYTES=1.33008`, ... | 1 dòng CSV text |
| **2. Selected Features** (`validate_inference_input`) | Loại `row_id`, 6 metadata (`FLOW_START`, `FLOW_END`, `IPV4_SRC`, `L4_SRC_PORT`, `IPV4_DST`, `L4_DST_PORT`), giữ đúng 47 cột `ML_FEATURE_COLUMNS` | DataFrame `(1, 47)` |
| **3. Missing-value Handling** (`audit_column_tokens` + impute) | Tất cả 47 ô đều hữu hạn → không có ô nào cần điền median/mode | DataFrame `(1, 47)` |
| **4. Encoding & Scaling** | Không OHE; `PROTOCOL=6→6.0`, `L7_PROTO=7.0→7.0`, `TCP_FLAGS=19→19.0`; `scaler_type="none"` giữ nguyên `IN_BYTES=818.0`, `MIN_TTL=254.0` | DataFrame `(1, 47)` |
| **5. Final Model Input** | `[6.0, 7.0, 818.0, 10.0, 256.0, 6.0, 19.0, 19.0, 19.0, 615.0, ..., 254.0, 255.0, ..., 0.41626, 1.33008, ...]` | `(1, 47)`, `float64`, finite=True |

### Ví dụ B — Dòng có thiếu/vô hạn và zero-duration (`row_id = 92156`, `Label = 0`, `Attack = "Benign"`)

> **Lưu ý:** Dòng này có `MIN_TTL = 0` nên trong ứng dụng Desktop (`analyze_csv_file()`), tầng `OODValidator` sẽ chặn trước inference với nhãn `ABSTAINED_OOD`. Ví dụ dưới đây minh họa chính xác điều gì xảy ra bên trong `TrainOnlyPreprocessor.transform()` khi gặp ô trống `""` và `inf`.

| Giai đoạn | Giá trị biến đổi trên các cột trọng tâm | Shape / Kiểu |
|---|---|---|
| **1. Raw CSV row** | `IPV4_SRC="149.171.126.18"`, `L4_SRC_PORT=47439`, `PROTOCOL=17`, `L7_PROTO=5.0`, `IN_BYTES=132`, `OUT_BYTES=0`, `FLOW_DURATION_MILLISECONDS=0`, `MIN_TTL=0`, `SRC_TO_DST_SECOND_BYTES=""` *(trống)*, `DST_TO_SRC_SECOND_BYTES=inf` | 1 dòng CSV text |
| **2. Selected Features** | Loại `row_id`, IP, port, timestamp; giữ 47 cột | `(1, 47)` |
| **3. Token Audit → `np.nan`** | `SRC_TO_DST_SECOND_BYTES: "" → np.nan`; `DST_TO_SRC_SECOND_BYTES: inf → np.nan`; `FLOW_DURATION_MILLISECONDS: 0 → 0.0` | `(1, 47)` |
| **4. Train-only Imputation** | `SRC_TO_DST_SECOND_BYTES: np.nan → 162.0` *(Train median)*; `DST_TO_SRC_SECOND_BYTES: np.nan → 78.28151260504201` *(Train median)*; `FLOW_DURATION_MILLISECONDS` giữ `0.0` | `(1, 47)` |
| **5. Final Model Input** | `[17.0, 5.0, 132.0, ..., 0.0, ..., 162.0, 78.28151260504201, ...]` | `(1, 47)`, `float64`, finite=True |
