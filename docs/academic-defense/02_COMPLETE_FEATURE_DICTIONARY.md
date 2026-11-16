# 02 — Từ điển Đầy đủ 55 Cột Dữ liệu (`NF-UNSW-NB15-v3`)

> **Trạng thái kiểm chứng:** Toàn bộ danh sách 55 cột, phân nhóm vai trò và trạng thái sử dụng được trích xuất trực tiếp từ `src/network_anomaly/data/nf_unsw_nb15_v3.py`, từ điển gốc UQ (`NetFlow_v3_Features.csv`), báo cáo EDA (`reports/eda/nf_unsw_nb15_v3_eda_summary.json`), và đối chiếu qua script read-only [`scripts/export_academic_schema_summary.py`](../../scripts/export_academic_schema_summary.py).
> Các giá trị thống kê (`Min`, `Median`, `Max`, `Train Imputed`, `Vocab Size`) được lấy từ manifest và artifact `nf_unsw_nb15_v3_preprocessor.joblib` (`12d4360a...`) đã fit trên `1.655.797` dòng Train.

---

## 1. Tổng quan cấu trúc 55 cột (Contract HEAD)

Tệp `NF-UNSW-NB15-v3.csv` có đúng **55 cột** theo thứ tự cố định trong `ALL_COLUMNS`:

- **6 cột Trace Metadata (`TRACE_METADATA_COLUMNS`):** `FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`, `IPV4_SRC_ADDR`, `L4_SRC_PORT`, `IPV4_DST_ADDR`, `L4_DST_PORT` → **Bị loại khỏi `X`** (`Used in train = Không`).
- **2 cột Targets (`TARGET_COLUMNS`):** `Label` (nhị phân `0/1`), `Attack` (chuỗi 10 lớp) → **Bị loại khỏi `X`** (`Label` dùng làm `y` cho supervised RF/XGB và dùng để lọc `Label==0` cho IF/AE; `Attack` dùng đánh giá phân rã & tách unknown `{Backdoor, Worms}`).
- **47 cột Baseline ML Features (`ML_FEATURE_COLUMNS`, hợp đồng `nf-unsw-nb15-v3-baseline-47`):**
  - **10 cột phân loại mã hóa số (`CATEGORICAL_CODED_COLUMNS`):** `PROTOCOL`, `L7_PROTO`, `TCP_FLAGS`, `CLIENT_TCP_FLAGS`, `SERVER_TCP_FLAGS`, `ICMP_TYPE`, `ICMP_IPV4_TYPE`, `DNS_QUERY_ID`, `DNS_QUERY_TYPE`, `FTP_COMMAND_RET_CODE`.
  - **37 cột định lượng (`QUANTITATIVE_ML_COLUMNS`):** các trường đếm byte/packet, thời lượng, TTL, kích thước gói, tốc độ byte/s, thông lượng bps, histogram kích thước gói, TCP window, DNS TTL và thống kê Inter-Arrival Time (IAT).

> **Điểm then chốt cần trả lời trực tiếp với giảng viên:**
> 1. Trong 47 đặc trưng đầu vào mô hình **KHÔNG có trường chuỗi (string/text) tự do**. Cả 3 cột dạng text duy nhất trong 55 cột là `IPV4_SRC_ADDR`, `IPV4_DST_ADDR` (IPv4 string metadata → bị loại) và `Attack` (nhãn đa lớp string → bị loại).
> 2. 10 cột phân loại (`PROTOCOL`, `L7_PROTO`, `TCP_FLAGS`, v.v.) **được lưu sẵn dưới dạng mã số (numeric-coded)** trong CSV gốc.
> 3. Trong `TrainOnlyPreprocessor` (`src/network_anomaly/preprocessing/pipeline.py`), dự án **KHÔNG dùng One-Hot Encoding** (số chiều đầu ra giữ nguyên đúng **47 cột**, không phải hàng chục nghìn cột — riêng `DNS_QUERY_ID` có tới **63.003** giá trị phân biệt trong Train!).
> 4. Trong cấu hình baseline đã kiểm chứng (`scaler_type = "none"`), dự án **KHÔNG chuẩn hóa (no scaling / no standardization)** trên 37 cột định lượng; dữ liệu đi qua `audit_column_tokens()` → điền giá trị thiếu/vô hạn bằng **Train median** (37 cột số) hoặc **Train mode** + `np.round()` (10 cột phân loại mã hóa số) → xuất ma trận `(N, 47)` kiểu `float64`.

---

## 2. Phân tích chi tiết các nhóm trường đặc biệt

### 2.1. Trường dạng chuỗi (Text/String) và IP/Timestamp/Port

| Cột | Dạng gốc | Vì sao có hoặc bỏ? | Rủi ro Data Leakage nếu giữ? |
|---|---|---|---|
| `IPV4_SRC_ADDR`, `IPV4_DST_ADDR` | Chuỗi IPv4 (`"175.45.176.3"`) | **Bỏ khỏi `X`**, chỉ giữ cho Trace/Behavioral metadata trên UI | **Rất cao:** Trong testbed UNSW-NB15, các dải IP cố định gắn trực tiếp với máy tấn công (`175.45.176.x`) và nạn nhân (`149.171.126.x`). Giữ IP làm mô hình học thuộc địa chỉ lab. |
| `FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS` | Số nguyên Epoch ms (`1424244898204`) | **Bỏ khỏi `X`**, dùng để sắp xếp split thời gian & sắp thứ tự timeline | **Rất cao:** Mọi mô hình sẽ học thuộc khung thời gian tấn công diễn ra vào ngày/giờ nào trong capture 2015 thay vì đặc tính lưu lượng. |
| `L4_SRC_PORT`, `L4_DST_PORT` | Số nguyên `[0, 65535]` (`33878`, `80`) | **Bỏ khỏi `X`** ở baseline 47 đặc trưng; dùng cho `canonical_flow_group` & thống kê top port | **Trung bình/Cao:** Port đích cố định trong lab dễ gây shortcut; một cấu hình 49-feature được ghi là nghiên cứu tương lai nhưng **chưa triển khai** (`NOT VERIFIED`). |
| `Attack` | Chuỗi danh mục (`"Exploits"`, `"Benign"`, ...) | **Bỏ khỏi `X`**, chỉ dùng làm nhãn phân tích lỗi và tách Unknown `{Backdoor, Worms}` | **Leakage tuyệt đối** nếu đưa vào `X` vì tương ứng 1-1 với `Label`. |

### 2.2. Cách xử lý Protocol, Connection State (`TCP_FLAGS`) và Nhóm dịch vụ (`L7_PROTO`)

- **Protocol (`PROTOCOL`):** Mã số giao thức tầng IP theo chuẩn IANA (số nguyên `0–255`, ví dụ `6` = TCP chiếm 1.805.270 dòng, `17` = UDP chiếm 556.557 dòng, `1` = ICMP, `89` = OSPF). Được xếp vào `CATEGORICAL_CODED_COLUMNS` (255 mã trong Train, mode = `6.0`). Không scale, giữ nguyên mã số nguyên sau `np.round()`.
- **Connection State (`TCP_FLAGS`, `CLIENT_TCP_FLAGS`, `SERVER_TCP_FLAGS`):** Trong NetFlow v3 không có cột string kiểu `"FIN"`, `"CON"`, `"INT"` như bản UNSW-NB15 2015 cũ, mà lưu **tổ hợp bitmask các cờ TCP dưới dạng số nguyên `[0..31]`** (ví dụ `27` = `0b11011` gồm FIN+SYN+PSH+ACK; `19` = `0b10011` gồm FIN+SYN+ACK; `0` khi không phải TCP hoặc không thấy cờ). Cả 3 cột nằm trong `CATEGORICAL_CODED_COLUMNS` (mode trên Train = `27.0`), không scale, không One-Hot Encode.
- **Nhóm dịch vụ/ứng dụng (`L7_PROTO`):** Mã giao thức tầng ứng dụng do nProbe gán (ví dụ `0.0` = Unknown, `5.0` = DNS, `7.0` = HTTP, `36.0` / `37.0` = mã nhóm phổ biến trong dataset). Lưu ý từ code thực tế (`pipeline.py` dòng 358 & 452): trong CSV gốc có một số giá trị thập phân sub-protocol của nProbe (như `7.37`, `7.212`, `10.16`); khi `fit()`, code ép `int64` để tạo vocabulary (`124` mã) và tính mode (`37.0`); khi `transform()`, code dùng `np.round(cleaned_arr)` đưa về số nguyên gần nhất.

---

## 3. Bảng từ điển đầy đủ 100% (55/55 cột)

Quy ước ký hiệu trong bảng:
- **Vai trò:** `Metadata (Loại)`, `Target (Loại)`, `ML Cat (Dùng)`, `ML Quant (Dùng)`.
- **Kiểu dữ liệu gốc trong CSV:** CSV lưu văn bản UTF-8, Validator parse theo loại ngữ nghĩa: `Int (Discrete)`, `Float (Continuous)`, `Categorical-Coded (Int/Float)`, `IPv4 String`, `Binary Int`, `Category String`.
- **Tiền xử lý thực tế (`TrainOnlyPreprocessor`):**
  - *Mode + Round:* Audit token → điền missing/NaN/Inf bằng Train mode (nếu thiếu) → `np.round()` → kiểm tra vocabulary với `handle_unknown_categories="passthrough"` (không OHE, không scale).
  - *Median:* Audit token → chuyển `""`, `NaN`, `±Inf` thành `np.nan` → điền bằng Train median → giữ nguyên giá trị gốc (`scaler_type="none"`).
  - **Kết quả sau biến đổi:** Cả 47 cột ML đều xuất ra kiểu `float64` nằm trong DataFrame/ma trận shape `(N, 47)`.

| # | Tên cột | Ý nghĩa (theo UQ & schema) | Kiểu dữ liệu gốc | Ví dụ giá trị | Đơn vị | Vai trò | Dùng train? | Tiền xử lý | Kết quả sau biến đổi |
|---:|---|---|---|---|---|---|---|---|---|
| 1 | `FLOW_START_MILLISECONDS` | Thời điểm bắt đầu luồng | Int (Discrete, Epoch) | `1424244898204` | ms (UTC epoch) | Metadata (Loại) | Không (rò rỉ thời gian) | Loại khỏi `X` trước `fit()` | Không vào model |
| 2 | `FLOW_END_MILLISECONDS` | Thời điểm kết thúc luồng | Int (Discrete, Epoch) | `1424244898820` | ms (UTC epoch) | Metadata (Loại) | Không (rò rỉ thời gian) | Loại khỏi `X` trước `fit()` | Không vào model |
| 3 | `IPV4_SRC_ADDR` | Địa chỉ IPv4 nguồn | IPv4 String (Text) | `"175.45.176.3"` | IPv4 | Metadata (Loại) | Không (rò rỉ định danh lab) | Loại khỏi `X` trước `fit()` | Không vào model |
| 4 | `L4_SRC_PORT` | Cổng tầng giao vận nguồn | Int (Discrete `[0..65535]`) | `33878` | Port number | Metadata (Loại) | Không (theo contract 47) | Loại khỏi `X` trước `fit()` | Không vào model |
| 5 | `IPV4_DST_ADDR` | Địa chỉ IPv4 đích | IPv4 String (Text) | `"149.171.126.10"` | IPv4 | Metadata (Loại) | Không (rò rỉ định danh lab) | Loại khỏi `X` trước `fit()` | Không vào model |
| 6 | `L4_DST_PORT` | Cổng tầng giao vận đích | Int (Discrete `[0..65535]`) | `80` | Port number | Metadata (Loại) | Không (theo contract 47) | Loại khỏi `X` trước `fit()` | Không vào model |
| 7 | `PROTOCOL` | Mã giao thức IP (6=TCP, 17=UDP...) | Categorical-Coded (Int) | `6`, `17` | IANA proto ID | ML Cat (Dùng) | Có | Audit + Mode (`6.0`) + Round + Passthrough | `float64` (1 cột, không OHE) |
| 8 | `L7_PROTO` | Giao thức ứng dụng tầng 7 (nProbe) | Categorical-Coded (Float/Int) | `7.0`, `37.0`, `7.37` | nProbe L7 ID | ML Cat (Dùng) | Có | Audit + Mode (`37.0`) + Round + Passthrough | `float64` (1 cột, `7.37→7.0`) |
| 9 | `IN_BYTES` | Số byte chiều nguồn → đích | Int (Discrete `[1..27M]`) | `818` | Bytes | ML Quant (Dùng) | Có | Audit + Median (`1684.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 10 | `IN_PKTS` | Số gói tin chiều nguồn → đích | Int (Discrete `[1..20166]`) | `10` | Packets | ML Quant (Dùng) | Có | Audit + Median (`18.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 11 | `OUT_BYTES` | Số byte chiều đích → nguồn | Int (Discrete `[0..14.6M]`) | `256` | Bytes | ML Quant (Dùng) | Có | Audit + Median (`2456.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 12 | `OUT_PKTS` | Số gói tin chiều đích → nguồn | Int (Discrete `[0..11024]`) | `6` | Packets | ML Quant (Dùng) | Có | Audit + Median (`18.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 13 | `TCP_FLAGS` | Bitmask tích lũy mọi cờ TCP của flow | Categorical-Coded (Bitmask Int) | `19`, `27`, `0` | Bitmask `[0..31]` | ML Cat (Dùng) | Có | Audit + Mode (`27.0`) + Round + Passthrough | `float64` (1 cột, không OHE) |
| 14 | `CLIENT_TCP_FLAGS` | Bitmask cờ TCP phía client | Categorical-Coded (Bitmask Int) | `19`, `27`, `0` | Bitmask `[0..31]` | ML Cat (Dùng) | Có | Audit + Mode (`27.0`) + Round + Passthrough | `float64` (1 cột, không OHE) |
| 15 | `SERVER_TCP_FLAGS` | Bitmask cờ TCP phía server | Categorical-Coded (Bitmask Int) | `19`, `27`, `0` | Bitmask `[0..31]` | ML Cat (Dùng) | Có | Audit + Mode (`27.0`) + Round + Passthrough | `float64` (1 cột, không OHE) |
| 16 | `FLOW_DURATION_MILLISECONDS` | Tổng thời lượng luồng | Int (Continuous/Discrete `[0..120948]`) | `615`, `0` | ms | ML Quant (Dùng) | Có | Audit + Median (`31.0`); bảo toàn `0.0` | `float64` (`0.0` giữ nguyên) |
| 17 | `DURATION_IN` | Thời lượng luồng chiều src → dst | Int (Continuous/Discrete `[0..120948]`) | `615`, `0` | ms | ML Quant (Dùng) | Có | Audit + Median (`28.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 18 | `DURATION_OUT` | Thời lượng luồng chiều dst → src *(lưu ý UQ CSV ghi nhầm mô tả)* | Int (Continuous/Discrete `[0..120922]`) | `507`, `0` | ms | ML Quant (Dùng) | Có | Audit + Median (`28.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 19 | `MIN_TTL` | Giá trị IP Time-To-Live nhỏ nhất | Int (Discrete `[0..255]`) | `31`, `254`, `0` | Hops (TTL) | ML Quant (Dùng) | Có *(nhạy shortcut!)* | Audit + Median (`31.0`), `scaler=none` | `float64` (desktop gate chặn `0` thành OOD) |
| 20 | `MAX_TTL` | Giá trị IP Time-To-Live lớn nhất | Int (Discrete `[0..255]`) | `31`, `255`, `0` | Hops (TTL) | ML Quant (Dùng) | Có *(nhạy shortcut!)* | Audit + Median (`32.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 21 | `LONGEST_FLOW_PKT` | Kích thước gói dài nhất trong flow | Int (Discrete `[28..1508]`) | `233` | Bytes | ML Quant (Dùng) | Có | Audit + Median (`485.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 22 | `SHORTEST_FLOW_PKT` | Kích thước gói ngắn nhất trong flow | Int (Discrete `[28..1508]`) | `40` | Bytes | ML Quant (Dùng) | Có | Audit + Median (`52.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 23 | `MIN_IP_PKT_LEN` | Độ dài IP packet nhỏ nhất quan sát | Int (Discrete `[0..680]`) | `40` | Bytes | ML Quant (Dùng) | Có | Audit + Median (`52.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 24 | `MAX_IP_PKT_LEN` | Độ dài IP packet lớn nhất quan sát | Int (Discrete `[28..1508]`) | `233` | Bytes | ML Quant (Dùng) | Có | Audit + Median (`485.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 25 | `SRC_TO_DST_SECOND_BYTES` | Tốc độ byte/giây chiều src → dst | Float (Continuous, có `""` & `inf`) | `0.416`, `""`, `inf` | Bytes/sec | ML Quant (Dùng) | Có | `""`/`inf` → `NaN` → Train Median **`162.0`** | `float64` hữu hạn (`122.493` dòng CSV được điền `162.0`) |
| 26 | `DST_TO_SRC_SECOND_BYTES` | Tốc độ byte/giây chiều dst → src | Float (Continuous, có `inf`) | `1.330`, `inf` | Bytes/sec | ML Quant (Dùng) | Có | `inf` → `NaN` → Train Median **`78.2815...`** | `float64` hữu hạn (`122.493` dòng CSV được điền `78.2815...`) |
| 27 | `RETRANSMITTED_IN_BYTES` | Số byte TCP truyền lại chiều src → dst | Int (Discrete `[0..13.5M]`) | `281`, `0` | Bytes | ML Quant (Dùng) | Có | Audit + Median (`562.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 28 | `RETRANSMITTED_IN_PKTS` | Số gói TCP truyền lại chiều src → dst | Int (Discrete `[0..10081]`) | `2`, `0` | Packets | ML Quant (Dùng) | Có | Audit + Median (`4.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 29 | `RETRANSMITTED_OUT_BYTES` | Số byte TCP truyền lại chiều dst → src | Int (Discrete `[0..7.3M]`) | `0` | Bytes | ML Quant (Dùng) | Có | Audit + Median (`871.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 30 | `RETRANSMITTED_OUT_PKTS` | Số gói TCP truyền lại chiều dst → src | Int (Discrete `[0..5508]`) | `0` | Packets | ML Quant (Dùng) | Có | Audit + Median (`4.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 31 | `SRC_TO_DST_AVG_THROUGHPUT` | Thông lượng trung bình src → dst | Int/Float (Continuous `[11..36M]`) | `10623` | bps | ML Quant (Dùng) | Có | Audit + Median (`540222.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 32 | `DST_TO_SRC_AVG_THROUGHPUT` | Thông lượng trung bình dst → src | Int/Float (Continuous `[0..23.5M]`) | `3324` | bps | ML Quant (Dùng) | Có | Audit + Median (`712000.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 33 | `NUM_PKTS_UP_TO_128_BYTES` | Số gói kích thước IP ≤ 128 B | Int (Discrete `[0..3840]`) | `14` | Packets | ML Quant (Dùng) | Có | Audit + Median (`32.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 34 | `NUM_PKTS_128_TO_256_BYTES` | Số gói kích thước (128, 256] B | Int (Discrete `[0..298]`) | `2`, `0` | Packets | ML Quant (Dùng) | Có | Audit + Median (`0.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 35 | `NUM_PKTS_256_TO_512_BYTES` | Số gói kích thước (256, 512] B | Int (Discrete `[0..2564]`) | `0` | Packets | ML Quant (Dùng) | Có | Audit + Median (`0.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 36 | `NUM_PKTS_512_TO_1024_BYTES` | Số gói kích thước (512, 1024] B | Int (Discrete `[0..642]`) | `0` | Packets | ML Quant (Dùng) | Có | Audit + Median (`0.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 37 | `NUM_PKTS_1024_TO_1514_BYTES` | Số gói kích thước (1024, 1514] B | Int (Discrete `[0..17500]`) | `0` | Packets | ML Quant (Dùng) | Có | Audit + Median (`0.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 38 | `TCP_WIN_MAX_IN` | Kích thước TCP Window lớn nhất chiều src → dst | Int (Discrete `[0..65533]`) | `16383` | Bytes | ML Quant (Dùng) | Có | Audit + Median (`14480.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 39 | `TCP_WIN_MAX_OUT` | Kích thước TCP Window lớn nhất chiều dst → src | Int (Discrete `[0..65531]`) | `16383` | Bytes | ML Quant (Dùng) | Có | Audit + Median (`13032.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 40 | `ICMP_TYPE` | Mã gộp `ICMP Type * 256 + ICMP Code` | Categorical-Coded (Int) | `6400`, `0` | Encoded ID | ML Cat (Dùng) | Có | Audit + Mode (`0.0`) + Round + Passthrough | `float64` (910 mã trong Train) |
| 41 | `ICMP_IPV4_TYPE` | Mã ICMP Type IPv4 | Categorical-Coded (Int) | `25`, `0` | ICMP Type | ML Cat (Dùng) | Có | Audit + Mode (`0.0`) + Round + Passthrough | `float64` (256 mã trong Train) |
| 42 | `DNS_QUERY_ID` | ID phiên truy vấn DNS | Categorical-Coded (Int) | `11116`, `0` | Query ID | ML Cat (Dùng) | Có | Audit + Mode (`0.0`) + Round + Passthrough | `float64` (63.003 mã trong Train, không OHE) |
| 43 | `DNS_QUERY_TYPE` | Loại bản ghi truy vấn DNS (1=A, 2=NS...) | Categorical-Coded (Int) | `1`, `0` | DNS Type ID | ML Cat (Dùng) | Có | Audit + Mode (`0.0`) + Round + Passthrough | `float64` (18 mã trong Train) |
| 44 | `DNS_TTL_ANSWER` | TTL của bản ghi DNS A đầu tiên | Int (Continuous/Discrete `[0..4.28e9]`) | `60`, `0` | Seconds | ML Quant (Dùng) | Có | Audit + Median (`0.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 45 | `FTP_COMMAND_RET_CODE` | Mã trả về của lệnh FTP client | Categorical-Coded (Int) | `331`, `0` | FTP Code | ML Cat (Dùng) | Có | Audit + Mode (`0.0`) + Round + Passthrough | `float64` (16 mã trong Train) |
| 46 | `SRC_TO_DST_IAT_MIN` | Inter-Packet Arrival Time min (src → dst) | Int/Float (Continuous `[0..60598]`) | `0` | ms | ML Quant (Dùng) | Có | Audit + Median (`0.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 47 | `SRC_TO_DST_IAT_MAX` | Inter-Packet Arrival Time max (src → dst) | Int/Float (Continuous `[0..60598]`) | `203` | ms | ML Quant (Dùng) | Có | Audit + Median (`5.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 48 | `SRC_TO_DST_IAT_AVG` | Inter-Packet Arrival Time trung bình (src → dst) | Int/Float (Continuous `[0..30299]`) | `68` | ms | ML Quant (Dùng) | Có | Audit + Median (`0.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 49 | `SRC_TO_DST_IAT_STDDEV` | Độ lệch chuẩn IAT (src → dst) | Int/Float (Continuous `[0..30299]`) | `81` | ms | ML Quant (Dùng) | Có | Audit + Median (`1.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 50 | `DST_TO_SRC_IAT_MIN` | Inter-Packet Arrival Time min (dst → src) | Int/Float (Continuous `[0..1490]`) | `0` | ms | ML Quant (Dùng) | Có | Audit + Median (`0.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 51 | `DST_TO_SRC_IAT_MAX` | Inter-Packet Arrival Time max (dst → src) | Int/Float (Continuous `[0..60598]`) | `456` | ms | ML Quant (Dùng) | Có | Audit + Median (`5.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 52 | `DST_TO_SRC_IAT_AVG` | Inter-Packet Arrival Time trung bình (dst → src) | Int/Float (Continuous `[0..20199]`) | `101` | ms | ML Quant (Dùng) | Có | Audit + Median (`0.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 53 | `DST_TO_SRC_IAT_STDDEV` | Độ lệch chuẩn IAT (dst → src) | Int/Float (Continuous `[0..28566]`) | `178` | ms | ML Quant (Dùng) | Có | Audit + Median (`1.0`), `scaler=none` | `float64` giữ nguyên thang đo |
| 54 | `Label` | Nhãn nhị phân (0=Benign, 1=Attack) | Binary Int (`0` hoặc `1`) | `0`, `1` | Binary | Target (Loại khỏi `X`) | Chỉ làm `y` / lọc Benign | Loại tuyệt đối khỏi `X` | Không vào `X` |
| 55 | `Attack` | Tên họ tấn công hoặc `"Benign"` | Category String (Text, 10 lớp) | `"Benign"`, `"Fuzzers"` | Category | Target (Loại khỏi `X`) | Chỉ dùng phân tích lỗi & tách Unknown | Loại tuyệt đối khỏi `X` | Không vào `X` |

> **Lưu ý về derived features:** Ngoài 53 trường NetFlow v3 gốc, baseline contract **không tạo thêm feature dẫn xuất mới** (mô hình chỉ nhận đúng 47 cột gốc sau khi làm sạch và điền thiếu). Một cột phụ tùy chọn là `row_id` trong `demo_flows.csv` cũng chỉ dùng để giữ định danh dòng đầu vào và **bị loại khỏi `X`**.
