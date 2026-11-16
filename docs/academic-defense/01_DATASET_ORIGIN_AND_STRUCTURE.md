# 01 — Nguồn gốc, Bản chất và Cấu trúc Dữ liệu NF-UNSW-NB15-v3

> **Trạng thái bằng chứng:** `EXPERIMENTALLY VALIDATED` đối với tính toàn vẹn nguồn, phân bố nhãn và schema của tệp CSV đã tải và kiểm băm (`data/NF_UNSW_NB15_V3_MANIFEST.json`, `reports/data_quality/nf_unsw_nb15_v3_validation.json`). Bộ dữ liệu raw (`577.360.958` bytes) nằm ngoài Git theo `.gitignore` và điều khoản UQ.

---

## 1. Nguồn gốc, tác giả, DOI và điều khoản sử dụng

Dự án **NetFlow Sentinel v1.0.0** sử dụng bộ dữ liệu **NF-UNSW-NB15-v3**, **không** sử dụng bộ `UNSW-NB15` bản CSV 2015 cũ (các tệp cũ chỉ được lưu tại `data/historical/` để đối chiếu lịch sử migration).

| Thuộc tính | Giá trị đã xác minh trong repository | Nguồn kiểm chứng |
|---|---|---|
| **Tên dataset** | `NF-UNSW-NB15-v3` | [NF_UNSW_NB15_V3_MANIFEST.json](../../data/NF_UNSW_NB15_V3_MANIFEST.json) |
| **Đơn vị công bố** | The University of Queensland (UQ) | [NF_UNSW_NB15_V3_PROVENANCE.md](../dataset/NF_UNSW_NB15_V3_PROVENANCE.md) |
| **DOI chính thức** | `10.48610/6E0EDA1` (<https://doi.org/10.48610/6E0EDA1>) | [NF_UNSW_NB15_V3_MANIFEST.json](../../data/NF_UNSW_NB15_V3_MANIFEST.json) |
| **UQ RDM UUID** | `abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f` | [NF_UNSW_NB15_V3_PROVENANCE.md](../dataset/NF_UNSW_NB15_V3_PROVENANCE.md) |
| **Công trình trích dẫn** | Majed Luay, Siamak Layeghy, Seyedehfaezeh Hosseininoorbin, Mohanad Sarhan, Nour Moustafa, Marius Portmann (2025), *"Temporal Analysis of NetFlow Datasets for Network Intrusion Detection Systems"*, `arXiv:2503.04404` | [NOTICE](../../NOTICE) |
| **Ngày phát hành gói UQRDM** | Năm 2025 (tạo package `2025-02-28`, công bố `2025-03-05`) | [NF_UNSW_NB15_V3_PROVENANCE.md](../dataset/NF_UNSW_NB15_V3_PROVENANCE.md) |
| **Khoảng thời gian bắt gói gốc** | `2015-01-22T11:49:36.907Z` đến `2015-02-18T12:29:25.011Z` (tập trung trong 3 ngày UTC) | [NF_UNSW_NB15_V3_SCHEMA.md](../dataset/NF_UNSW_NB15_V3_SCHEMA.md), [nf_unsw_nb15_v3_split_manifest.json](../../reports/splits/nf_unsw_nb15_v3_split_manifest.json) |
| **Điều khoản sử dụng** | *Permitted Re-Use with Commercial Use Restriction* (UQ License ID `454104`) — yêu cầu trích dẫn đầy đủ và **chỉ dùng phi thương mại** | [DISTRIBUTION_AUTHORIZATION.json](../../reports/governance/DISTRIBUTION_AUTHORIZATION.json) |
| **Checksum CSV cục bộ** | SHA-256 `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5` (`577.360.958` bytes); BagIt SHA-1 `2cba4879ead17c51e3268a01c06af41186cd90e4` | [NF_UNSW_NB15_V3_MANIFEST.json](../../data/NF_UNSW_NB15_V3_MANIFEST.json) |

**Ranh giới pháp lý:** Mã nguồn phần mềm của dự án dùng giấy phép `Apache-2.0` ([LICENSE](../../LICENSE)), nhưng giấy phép này **không** cấp lại quyền sử dụng hay miễn trừ hạn chế phi thương mại của `NF-UNSW-NB15-v3`. Hiện tại quyền phân phối công khai các model `.joblib` dẫn xuất và `demo_*.csv` vẫn ở trạng thái **`BLOCKED_PENDING_VERIFIABLE_EVIDENCE`** (`approved: false` trong [DISTRIBUTION_AUTHORIZATION.json](../../reports/governance/DISTRIBUTION_AUTHORIZATION.json)).

---

## 2. Môi trường thu thập và bản chất dữ liệu NetFlow

### 2.1. Dữ liệu được thu thập trong môi trường nào?

- Lưu lượng gốc của họ UNSW-NB15 được tạo trong **phòng thí nghiệm testbed (Australian Centre for Cyber Security — ACCS)** sử dụng công cụ sinh lưu lượng **IXIA PerfectStorm** kết hợp lưu lượng bình thường mô phỏng và các kịch bản tấn công tổng hợp trong 3 ngày UTC năm 2015 (`2015-01-22`, `2015-01-23`, `2015-02-18`).
- Nhóm nghiên cứu tại **The University of Queensland** sau đó trích xuất lại từ các tệp PCAP gốc sang định dạng **NetFlow v9 / nProbe (53 trường NetFlow v3)** — bổ sung thêm 10 đặc trưng thời gian (như `SRC_TO_DST_IAT_*`, `DST_TO_SRC_IAT_*`, `FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`) trong phiên bản v3 công bố năm 2025.

### 2.2. Dữ liệu NetFlow là gì? Khác gì PCAP thô và Application Logs?

| Khía cạnh | NetFlow v3 (`NF-UNSW-NB15-v3`) | Packet Capture (PCAP / Raw Packets) | Application / Auth / API Logs |
|---|---|---|---|
| **Đơn vị quan sát** | 1 dòng = 1 **luồng mạng tổng hợp** (flow summary giữa cặp IP/port/protocol trong một khoảng thời gian) | Từng gói tin (packet) riêng lẻ trên dây mạng | Từng sự kiện ứng dụng (HTTP request, đăng nhập, SQL query) |
| **Nội dung có sẵn** | Thống kê gói, byte, thời lượng, TCP flags, TTL, độ dài gói, IAT, mã giao thức L4/L7 | Toàn bộ header từng gói + **payload ứng dụng** | Username, session token, URI, HTTP status, câu lệnh |
| **Có payload gói tin không?** | **Không** | Có (nếu không mã hóa) | Có ngữ cảnh ứng dụng |
| **Có danh tính người dùng/phiên Auth không?** | **Không** | Không trực tiếp | Có |

> **Hệ quả cho kiến trúc NetFlow Sentinel:** Vì dataset chỉ có NetFlow fields, các module thống kê hành vi (`#28` trong `src/network_anomaly/api/desktop_csv.py`) chỉ tổng hợp thống kê trên metadata NetFlow (`IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, `L4_SRC_PORT`, `L4_DST_PORT`, `FLOW_START_MILLISECONDS`) kèm thông báo không quy kết danh tính (`_NON_ATTRIBUTION_NOTICE`), **không** giả lập Auth/API logs.

---

## 3. Một dòng dữ liệu đại diện cho đối tượng nào? Nhóm cột khác nhau ra sao?

- **Một dòng dữ liệu (1 row)** trong `NF-UNSW-NB15-v3.csv` biểu diễn **một luồng mạng (network flow)** hai chiều được bộ thu thập nProbe tổng hợp từ lúc bắt đầu (`FLOW_START_MILLISECONDS`) đến lúc kết thúc (`FLOW_END_MILLISECONDS`) giữa nguồn `(IPV4_SRC_ADDR, L4_SRC_PORT)` và đích `(IPV4_DST_ADDR, L4_DST_PORT)` theo giao thức `PROTOCOL`.
- Tổng cộng tệp CSV có **55 cột** (`src/network_anomaly/data/nf_unsw_nb15_v3.py`), chia làm **3 vai trò tách biệt tuyệt đối**:

1. **Trace Metadata (6 cột — BẮT BUỘC LOẠI khỏi ma trận đặc trưng `X`):**
   - Thời gian tuyệt đối: `FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`
   - Định danh IP: `IPV4_SRC_ADDR`, `IPV4_DST_ADDR`
   - Cổng tầng giao vận: `L4_SRC_PORT`, `L4_DST_PORT`
   - *Lý do loại:* Dùng để chia tập theo thời gian, nhóm luồng (`canonical_flow_group`), hiển thị timeline/thống kê metadata trên UI; nếu đưa vào `X`, mô hình có thể học thuộc IP máy attacker trong lab (`175.45.176.x`) hoặc mốc thời gian thay vì hành vi lưu lượng.
2. **Baseline ML Features (47 cột — ĐẦU VÀO MÔ HÌNH):**
   - Gồm **10 trường phân loại mã hóa số (`CATEGORICAL_CODED_COLUMNS`)** như `PROTOCOL`, `L7_PROTO`, `TCP_FLAGS`, `ICMP_TYPE`, `DNS_QUERY_TYPE`, `FTP_COMMAND_RET_CODE` và **37 trường định lượng (`QUANTITATIVE_ML_COLUMNS`)** như byte, packet, thời lượng, TTL, throughput, phân bố kích thước gói và IAT.
3. **Target Labels (2 cột — TUYỆT ĐỐI LOẠI khỏi `X`):**
   - `Label` (nhị phân `0` = Benign, `1` = Attack)
   - `Attack` (đa lớp gồm `Benign` và 9 họ tấn công)

---

## 4. Ý nghĩa nhãn `Label` và `Attack`

### 4.1. `Label = 0/1` mang ý nghĩa gì?

- `Label = 0` (`Benign`): luồng mạng được gán nhãn là lưu lượng bình thường trong kịch bản testbed.
- `Label = 1` (`Attack`): luồng mạng thuộc một trong 9 kịch bản tấn công được sinh ra trong testbed.
- **Trả lời phản biện quan trọng:** **Một dòng bị gán `Label = 1` (`Attack`) KHÔNG đồng nghĩa chắc chắn một thiết bị đã bị xâm nhập thành công.** Nó chỉ phản ánh rằng *luồng mạng đó được gắn nhãn thuộc một hoạt động tấn công trong kịch bản benchmark* (ví dụ quét cổng `Reconnaissance`, gửi gói fuzzing `Fuzzers`, hoặc nỗ lực khai thác `Exploits` chưa chắc thành công trên host đích). Hơn nữa, dữ liệu NetFlow không có log hệ điều hành hay payload để xác nhận mức độ xâm nhập trên endpoint.

### 4.2. Nguồn gốc và ý nghĩa 9 họ tấn công (`Attack`)

Trong `NF-UNSW-NB15-v3.csv` (`2.365.424` dòng), cột `Attack` mang 10 giá trị (1 Benign + 9 Attack), phân bố được kiểm chứng trực tiếp từ bytes CSV như sau ([NF_UNSW_NB15_V3_MANIFEST.json](../../data/NF_UNSW_NB15_V3_MANIFEST.json)):

| Giá trị `Attack` | `Label` | Số dòng trong CSV thật | Tỷ lệ (%) | Ý nghĩa nhóm lưu lượng trong UNSW-NB15 |
|---|---:|---:|---:|---|
| `Benign` | `0` | 2.237.731 | 94,60% | Lưu lượng nền bình thường mô phỏng |
| `Exploits` | `1` | 42.748 | 1,81% | Khai thác lỗ hổng phần mềm/dịch vụ |
| `Fuzzers` | `1` | 33.816 | 1,43% | Gửi dữ liệu ngẫu nhiên/biến dạng nhằm gây lỗi hoặc treo dịch vụ |
| `Generic` | `1` | 19.651 | 0,83% | Kỹ thuật tấn công chung lên mật mã khối/giao thức (không phụ thuộc cấu trúc cụ thể) |
| `Reconnaissance` | `1` | 17.074 | 0,72% | Thăm dò, quét cổng, thu thập thông tin hệ thống |
| `DoS` | `1` | 5.980 | 0,25% | Tấn công từ chối dịch vụ làm cạn kiệt tài nguyên |
| `Backdoor` | `1` | 4.659 | 0,20% | Duy trì truy cập lén lút vượt qua cơ chế xác thực *(giữ làm Unknown holdout ở C4)* |
| `Shellcode` | `1` | 2.381 | 0,10% | Truyền tải đoạn mã nhỏ nhằm chiếm quyền điều khiển |
| `Analysis` | `1` | 1.226 | 0,05% | Quét cổng sâu, spam hoặc thâm nhập qua tệp HTML/web |
| `Worms` | `1` | 158 | 0,007% | Mã độc tự nhân bản và lan truyền qua mạng *(giữ làm Unknown holdout ở C4)* |
| **Tổng cộng** | **0 / 1** | **2.365.424** | **100,00%** | `2.237.731` Benign (`94,60%`) + `127.693` Attack (`5,40%`), tỷ lệ `17,52 : 1` |

> **Ghi nhận sai khác nguồn UQ (đã kiểm chứng):** Landing page của UQ ghi tổng `127.639` Attack và hoán đổi bộ đếm cho `Analysis / Backdoor / Shellcode` (`2381 / 1226 / 4659`). Kiểm tra trực tiếp trên bytes CSV tải từ UQRDM xác nhận có **`127.693` Attack** và phân bố đúng là `Analysis = 1.226`, `Backdoor = 4.659`, `Shellcode = 2.381` ([NF_UNSW_NB15_V3_PROVENANCE.md](../dataset/NF_UNSW_NB15_V3_PROVENANCE.md)).

---

## 5. Giới hạn của bộ dữ liệu khi áp dụng vào mạng thực tế

1. **Dữ liệu testbed 2015, không phải mạng doanh nghiệp hiện đại:** Dù được phát hành định dạng NetFlow v3 năm 2025, lưu lượng gốc được bắt từ năm 2015 trong phòng lab IXIA PerfectStorm. Các giao thức hiện đại (QUIC/HTTP3, TLS 1.3 phổ biến, traffic cloud/SaaS) không có trong capture này.
2. **Đường tắt tổng hợp của trình sinh lưu lượng (`MIN_TTL` shortcut):** Kiểm toán ([rf_baseline_validation_audit.json](../../reports/models/rf_baseline_validation_audit.json)) cho thấy một cây quyết định đơn chỉ dùng `MIN_TTL` đạt `0,999849` Accuracy trên Validation (`MIN_TTL=31` chủ yếu là Benign, `MIN_TTL∈{62, 254, 255}` chủ yếu là Attack). Trong mạng thật, hệ điều hành Linux (TTL 64) hay Windows (TTL 128) hoàn toàn bình thường nhưng có thể gây báo động giả nếu mô hình dựa vào shortcut này.
3. **Lặp vector hành vi (`ml_feature_overlap`):** Toàn bộ CSV có `14.815` dòng trùng hệt cả 55 cột và `1.134.553` dòng lặp lại trên vector 47 đặc trưng ML (`reports/data_quality/nf_unsw_nb15_v3_validation.json`).
4. **Không có file train/test chính thức từ tác giả:** `NF-UNSW-NB15-v3.csv` là **một tệp CSV duy nhất**, buộc dự án phải tự thiết kế giao thức chia theo thời gian kèm purge gap 5 phút thay vì dùng partition 2015 cũ.
5. **Mất cân bằng lớp mạnh (`5,40%` Attack, `Worms` chỉ `158` dòng):** Do đó Accuracy tổng thể không đủ để kết luận, bắt buộc báo Precision, Recall, F1, FPR và breakdown theo 9 họ tấn công.
6. **Chứng cứ sụp đổ ngoài miền:** Khi đưa mô hình Random Forest đã train trên `NF-UNSW-NB15-v3` đi đánh giá trên `100.000` dòng của `NF-CSE-CIC-IDS2018-v3`, Recall tụt xuống `0,0` và FPR tăng lên `0,3802` ([cross_dataset_evaluation_results.json](../../reports/evaluation/cross_dataset_evaluation_results.json)).
