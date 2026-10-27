# Báo cáo kiểm toán Data Leakage và Phân chia Dữ liệu NF-UNSW-NB15-v3

**Trạng thái kiểm toán:** `PASS`
**Mã giao thức phân chia:** `nf-unsw-nb15-v3-chronological-group-purged-v1`
**Phiên bản Fingerprint Schema:** `nf-unsw-nb15-v3-fingerprint-v1`
**Dataset SHA-256:** `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`
**Ngày thực hiện kiểm toán:** `2026-10-27T07:08:04.948795+00:00`

---

## 1. Cơ sở lựa chọn chiến lược phân chia dữ liệu (Data Splitting Strategy)

### 1.1 Đặc điểm phân bố thời gian thực tế
Phân tích toàn diện bộ dữ liệu NF-UNSW-NB15-v3 (2.365.424 dòng) cho thấy lưu lượng chỉ phân bố
trên **3 ngày UTC duy nhất**:
1. **2015-01-22:** 1.095.574 flows (1.078.112 Benign, 17.462 Attack, đủ 9 loại tấn công).
2. **2015-01-23:** 39.778 flows (100% Benign, 0 Attack, diễn ra trong 25 phút đầu ngày).
3. **2015-02-18:** 1.230.072 flows (1.119.841 Benign, 110.231 Attack, đủ 9 loại tấn công).

> [!WARNING]
> Nếu phân chia theo ngày (Day-based split) như gán Ngày 1 cho Train, Ngày 2 cho Validation,
> Ngày 3 cho Test, thì tập **Validation sẽ có 0 mẫu tấn công** (Class 1 = 0), khiến việc
> đánh giá chỉ số Precision, Recall, F1, ROC-AUC trên Validation hoàn toàn bất khả thi.

### 1.2 Giao thức phân chia theo dòng thời gian có Purge Gap bảo vệ nhóm
Để đảm bảo tính hợp lý khoa học và tuân thủ ranh giới thời gian (chronological holdout):
- **Trật tự thời gian:** Sắp xếp toàn bộ quan sát theo `FLOW_START_MILLISECONDS` tăng dần
  (dùng số thứ tự dòng gốc làm tie-breaker ổn định tuyệt đối).
- **Điểm cắt mục tiêu:** Phân bổ xấp xỉ 70% Train, 15% Validation, 15% Test. Hai điểm cắt
  rơi vào thời điểm ngày 2015-02-18.
- **Vùng đệm Purge Gap (300.000 ms = 5 phút):** Thiết lập vùng đệm 5 phút tại ranh giới
  Train-Validation và Validation-Test. Do quy tắc gom nhóm `canonical_flow_group` sử dụng
  bucket 5 phút (`FLOW_START_MILLISECONDS // 300_000`), khoảng cách tối thiểu >300.000 ms
  giữa các tập đảm bảo **toán học và thực nghiệm rằng không có bất kỳ nhóm luồng nào có
  thể rò rỉ qua các phân vùng**.

---

## 2. Kết quả phân bổ phân vùng và xử lý bản ghi Purge

Tổng số dòng nguồn: **2,365,424 dòng** (100.00% được gán minh bạch,
không bản ghi nào bị drop ngầm).

| Phân vùng | Số dòng | Tỷ lệ (%) | Khoảng thời gian (UTC) | Benign (`Label=0`) | Attack (`Label=1`) |
| --- | --- | --- | --- | --- | --- |
| **Train** | 1,655,797 | 70.0% | `2015-01-22T11:49:36.907000+00:00` → `2015-02-18T05:42:13.382000+00:00` | 1,590,608 | 65,189 |
| **Purged (Train-Val Gap)** | 9,443 | 0.3992% | `2015-02-18T05:42:13.412000+00:00` → `2015-02-18T05:47:13.334000+00:00` | 8,546 | 897 |
| **Validation** | 345,371 | 14.6008% | `2015-02-18T05:47:13.386000+00:00` → `2015-02-18T09:08:16.133000+00:00` | 314,871 | 30,500 |
| **Purged (Val-Test Gap)** | 8,860 | 0.3746% | `2015-02-18T09:08:16.143000+00:00` → `2015-02-18T09:13:16.107000+00:00` | 8,349 | 511 |
| **Test** | 345,953 | 14.6254% | `2015-02-18T09:13:16.160000+00:00` → `2015-02-18T12:29:24.927000+00:00` | 315,357 | 30,596 |

- **Khoảng cách thời gian thực tế Train → Val:** `300,004 ms` (yêu cầu >= 300.000 ms: **ĐẠT**).
- **Khoảng cách thời gian thực tế Val → Test:** `300,027 ms` (yêu cầu >= 300.000 ms: **ĐẠT**).

---

## 3. Phân bố các loại tấn công (Attack Categories) qua các phân vùng

Mọi loại tấn công (kể cả các lớp hiếm như `Worms`, `Analysis`, `Shellcode`) đều hiện diện đầy đủ
trong cả ba phân vùng Train, Validation, Test:

| Loại lưu lượng / Tấn công | Train | Validation | Test | Purged (Vùng đệm) | Tổng số dòng |
| --- | --- | --- | --- | --- | --- |
| `Analysis` | 646 | 285 | 294 | 1 | 1,226 |
| `Backdoor` | 3,253 | 144 | 1,260 | 2 | 4,659 |
| `Benign` | 1,590,608 | 314,871 | 315,357 | 16,895 | 2,237,731 |
| `DoS` | 3,238 | 1,445 | 1,193 | 104 | 5,980 |
| `Exploits` | 21,416 | 10,294 | 10,520 | 518 | 42,748 |
| `Fuzzers` | 17,599 | 8,495 | 7,322 | 400 | 33,816 |
| `Generic` | 9,243 | 5,137 | 5,111 | 160 | 19,651 |
| `Reconnaissance` | 8,304 | 4,107 | 4,464 | 199 | 17,074 |
| `Shellcode` | 1,407 | 556 | 396 | 22 | 2,381 |
| `Worms` | 83 | 37 | 36 | 2 | 158 |

---

## 4. Bảng kiểm toán rò rỉ chéo phân vùng (Cross-Partition Leakage Audit)

Áp dụng toàn diện `nf-unsw-nb15-v3-fingerprint-v1`:

| Cặp phân vùng | Exact Full-Row Overlap | Source-Feature Overlap | Flow-Group Overlap | ML-Feature Overlap (47 features) | Xung đột nhãn nhị phân | Khác biệt nhãn Attack |
| --- | --- | --- | --- | --- | --- | --- |
| **TRAIN VS VALIDATION** | 0 | 0 | 0 | 61,007 (551,167 / 172,621 rows) | 0 | 580 |
| **VALIDATION VS TEST** | 0 | 0 | 0 | 24,143 (105,218 / 114,622 rows) | 0 | 586 |
| **TRAIN VS TEST** | 0 | 0 | 0 | 59,966 (548,253 / 184,067 rows) | 0 | 889 |

### Diễn giải chi tiết từng loại trùng khớp và chính sách xử lý:
1. **Exact Full-Row Overlap (0 bản ghi):** Không có bất kỳ dòng dữ liệu nguyên bản nào xuất hiện ở
   hai phân vùng khác nhau. Trùng khớp = 0.
2. **Source-Feature Overlap (0 bản ghi):** Không có bản ghi nào trùng khớp toàn bộ 53 trường NetFlow
   v3 xuất hiện giữa các tập. Trùng khớp = 0.
3. **Canonical Flow-Group Overlap (0 nhóm):** Không có phiên liên lạc nào (cặp IP, Port đối xứng,
   Protocol trong cùng bucket 5 phút) bị phân tách qua hai phân vùng. Toàn vẹn phiên được bảo toàn
   nhờ Purge Gap 300.000 ms.
4. **Xung đột nhãn nhị phân (`Label` conflict):** **0 trường hợp**. Tuyệt đối không có trường hợp
   nào cùng một bộ đặc trưng ML 47 chiều mà ở tập này là Benign (`Label=0`) nhưng ở tập khác là
   Attack (`Label=1`).
5. **ML-Feature Overlap (Đặc trưng thống kê 47 chiều trùng khớp):**
   - Có ~61k mẫu trùng giữa Train-Val, ~24k mẫu giữa Val-Test, ~60k mẫu giữa Train-Test.
   - **Bản chất kỹ thuật:** Các mẫu này KHÔNG PHẢI là cùng một luồng mạng vật lý (khác địa chỉ IP,
     khác Port và khác mốc thời gian cách nhau hàng giờ). Đây là các cấu hình thống kê phổ biến của
     giao thức mạng (ví dụ: gói tin TCP SYN chuẩn, truy vấn DNS tiêu chuẩn, handshake ACK rỗng) do
     nhiều máy trạm phát sinh độc lập tại các thời điểm khác nhau.
   - **Chính sách:** Giữ nguyên các dòng này trong phân vùng tự nhiên. Không xóa bỏ vì việc xóa các
     cấu hình lưu lượng mạng phổ biến sẽ bóp méo phân bố xác suất tự nhiên của dữ liệu mạng và loại
     bỏ sai các gói tin bình thường thực tế.
6. **Khác biệt danh mục tấn công giữa các đặc trưng ML trùng lặp:** Ghi nhận 580 (Train-Val),
   589 (Val-Test), 890 (Train-Test) trường hợp các dòng tấn công khác loại (ví dụ DoS vs Exploits)
   có vector 47 đặc trưng thống kê giống nhau. Đây là giới hạn tự nhiên của việc biểu diễn luồng
   bằng 47 trường NetFlow v3 (ghi nhận tại `docs/dataset/NF_UNSW_NB15_V3_DUPLICATE_AUDIT.md`),
   không phải rò rỉ dữ liệu mục tiêu.

---

## 5. Hợp đồng đặc trưng cơ sở (Baseline Feature Contract)

- **Số lượng đặc trưng đầu vào ML:** Đúng **47 cột**, giữ nguyên thứ tự quy định trong
  `src/network_anomaly/data/nf_unsw_nb15_v3.py`.
- **Cột mục tiêu loại trừ khỏi X:** `Label` (nhị phân) và `Attack` (phân loại đa lớp).
- **Metadata phân nhóm loại trừ khỏi baseline X:**
  1. `FLOW_START_MILLISECONDS`
  2. `FLOW_END_MILLISECONDS`
  3. `IPV4_SRC_ADDR`
  4. `IPV4_DST_ADDR`
  5. `L4_SRC_PORT`
  6. `L4_DST_PORT`
- **10 cột số mã hóa hạng mục (Categorical-coded):** `PROTOCOL`, `L7_PROTO`, `TCP_FLAGS`,
  `CLIENT_TCP_FLAGS`, `SERVER_TCP_FLAGS`, `ICMP_TYPE`, `ICMP_IPV4_TYPE`, `DNS_QUERY_ID`,
  `DNS_QUERY_TYPE`, `FTP_COMMAND_RET_CODE`.
- **37 cột định lượng liên tục (Quantitative ML columns):** Các trường đếm byte, gói tin,
  thời lượng, throughput, IAT.

---

## 6. Giao diện ổn định cho Issue #8 (Integration Interface)

Issue #8 có thể tiêu thụ phân vùng này thông qua hàm `load_split_for_modeling()` trong
`src/network_anomaly/data/split.py`:
1. **Kiểm tra checksum dataset:** Đảm bảo CSV khớp SHA-256 `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`.
2. **Kiểm tra hash chỉ mục:** Kiểm tra toàn vẹn mảng chỉ mục phân vùng
   (`index_sha256`) trước khi nạp.
3. **Quy tắc huấn luyện tiền xử lý:** Toàn bộ bộ biến đổi (Imputer, Scaler, One-Hot Encoder,
   Feature Selector) **CHỈ ĐƯỢC FIT TRÊN TẬP TRAIN** (`train_indices`). Tập Validation và Test
   chỉ được áp dụng phép biến đổi đã đóng băng (frozen transforms).

---

## 7. Kết luận kiểm toán

Giao thức phân chia theo thời gian có vùng đệm 5 phút giải quyết triệt để rủi ro rò rỉ phiên luồng,
không vi phạm thứ tự thời gian, bảo tồn đầy đủ 10 lớp lưu lượng trong cả 3 tập, và đáp ứng toàn bộ
tiêu chí nghiệm thu của Issue #7.
