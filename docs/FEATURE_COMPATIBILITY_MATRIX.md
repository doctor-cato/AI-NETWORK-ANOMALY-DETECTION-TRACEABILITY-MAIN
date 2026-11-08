# Source & Feature Compatibility Matrix (Issue #46)

Tài liệu kiểm toán tính tương thích nguồn dữ liệu mạng và ánh xạ 47 đặc trưng ML phục vụ:
1. Multi-Source Ingestion & Adapter Architecture (Milestone M6).
2. Out-of-Distribution & Prediction Abstention Policy.
3. Hợp đồng định tuyến dữ liệu sang Trace Engine (#24) và Risk Engine (#32).

---

## 1. Hệ thống 4 Tầng Kiểm chứng Dữ liệu (4-Tier Data States)

Hệ thống bắt buộc phải phân định và báo cáo độc lập 4 tầng trạng thái cho từng nguồn dữ liệu nạp vào:

| Tầng Kiểm chứng | Mã Trạng thái | Điều kiện Kỹ thuật | Hành vi Hệ thống |
|---|---|---|---|
| **Tầng 1** | `PARSEABLE` | Định dạng tệp vật lý (CSV, JSON, TSV, PCAP) được giải mã thành công; không bị hỏng định dạng hoặc lỗi cú pháp. | Cho phép chuyển bản ghi sang bộ chuyển đổi (Adapter). |
| **Tầng 2** | `SCHEMA_COMPATIBLE` | Tệp chứa đầy đủ các trường bắt buộc và đúng kiểu dữ liệu theo lược đồ nguồn đã đăng ký trong `SourceRegistry`. | Bản ghi được chuẩn hóa thành `CanonicalNetworkEvent`. |
| **Tầng 3** | `SEMANTICALLY_COMPATIBLE` | Các trường trong `CanonicalNetworkEvent` có cùng bản chất ngữ nghĩa, đơn vị đo, hướng luồng và phương thức tính toán với hợp đồng 47 đặc trưng ML. | Đủ điều kiện kỹ thuật để nạp vào pipeline tiền xử lý và mô hình ML. |
| **Tầng 4** | `MODEL_VALIDATED` | Cặp (mô hình, nguồn dữ liệu) cụ thể đã được kiểm nghiệm thực nghiệm, có báo cáo benchmark đo lường FPR, F1 và phân tích lỗi trên phân phối thực tế. | Kết quả suy luận được xác thực độ tin cậy; không gắn cờ `VALIDATION_NOT_VERIFIED`. |

---

## 2. Phân loại Mức độ Tương thích 47 Đặc trưng ML

Mỗi đặc trưng trong số 47 đặc trưng ML chuẩn hóa (`nf-unsw-nb15-v3-baseline-47`) được đánh giá theo 5 cấp độ tương thích khi ánh xạ từ nguồn ngoại vi:

- **`EXACT`:** Đặc trưng có cùng tên, kiểu dữ liệu, đơn vị đo và thuật toán trích xuất nProbe v3.
- **`DERIVABLE`:** Đặc trưng không có sẵn trực tiếp nhưng có thể tính toán chính xác 100% bằng công thức xác định từ các trường khác (ví dụ: `FLOW_DURATION_MILLISECONDS = FLOW_END - FLOW_START`).
- **`APPROXIMATE`:** Đặc trưng có thể ước tính xấp xỉ qua phân tích thống kê (CẢNH BÁO: Không được sử dụng cho mô hình baseline 47 features fail-closed).
- **`MISSING`:** Đặc trưng hoàn toàn không tồn tại trong nguồn dữ liệu và không thể suy diễn.
- **`SEMANTIC_MISMATCH`:** Trường có tên tương tự nhưng sai khác về bản chất (lấy mẫu sFlow 1-in-N, cửa sổ tích lũy đám mây 10 phút, luồng đơn chiều thay vì hai chiều).

---

## 3. Ma trận Khảo sát Nguồn Dữ liệu Ngoại vi (Source Compatibility Matrix)

| Source ID | Tên Nguồn | Định dạng Vật lý | Số đặc trưng ML khả dụng (trên 47) | Tầng Đạt Được | Trạng thái ML | Hướng Xử lý trong Hệ thống M6 |
|---|---|---|:---:|---|---|---|
| `source:nf-v3-canonical` | NetFlow v3 Nội bộ (`NF-UNSW-NB15-v3`) | CSV | **47/47 (100%)** | `MODEL_VALIDATED` | `PREDICTION_AVAILABLE` | **Cho phép Inference trực tiếp.** Đã kiểm nghiệm đạt Recall 99.98%, FPR 0.0016%. |
| `source:nf-v3-external` | NetFlow v3 Ngoại vi (`NF-CSE-CIC-IDS2018-v3`, AWS) | CSV | **47/47 (100%)** | `BENCHMARK_FAILED` | `BENCHMARK_UNSATISFACTORY` | **Chặn Inference fail-closed.** Benchmark thực nghiệm thất bại (Recall 0.0, FPR 38.02%) do sụp đổ phím tắt và lệch miền. |
| `source:netflow-v5` | Cisco NetFlow v5 | Binary / Flow-tools | **6/47 (12.8%)** | `SCHEMA_COMPATIBLE` | `FEATURE_INCOMPATIBLE` | **Từ chối Inference (Abstain).** Trích xuất 5-tuple, byte, packet cho Trace Engine (#24). |
| `source:netflow-v9-ipfix` | Enterprise NetFlow v9 / IPFIX (Cisco, Juniper) | Binary / JSON | **9/47 (19.1%)** | `SCHEMA_COMPATIBLE` | `FEATURE_INCOMPATIBLE` | **Từ chối Inference.** Thiếu IAT vi mô và histogram; chuyển sang Risk Engine để tính Volume Anomaly. |
| `source:pcap` | Packet Capture (PCAP / PCAPNG) | Binary (libpcap) | **47/47 (nếu có Flow Exporter)** | `DERIVABLE` | `PENDING_EXPORTER` | Cần Flow Exporter Engine (nProbe/ipfixprobe) trích xuất luồng hai chiều trước khi suy luận. |
| `source:zeek-conn` | Zeek Security Log (`conn.log`) | TSV / JSON | **7/47 (14.9%)** | `SCHEMA_COMPATIBLE` | `FEATURE_INCOMPATIBLE` | **Không chạy model 47 features.** Dùng `uid`, 5-tuple, duration, proto làm chứng cứ liên kết cho Trace Engine (#24). |
| `source:suricata-eve` | Suricata EVE Log (`eve.json`) | JSON / JSONL | **7/47 (14.9%)** | `SCHEMA_COMPATIBLE` | `FEATURE_INCOMPATIBLE` | **Không chạy model 47 features.** Kết hợp metadata luồng và signature alert cho tương quan sự cố Risk Engine (#32). |
| `source:aws-vpc-flow` | AWS VPC Flow Logs (Custom/Standard) | TSV / Space-delimited | **4/47 (8.5%)** | `SCHEMA_COMPATIBLE` | `FEATURE_INCOMPATIBLE` | **Từ chối Inference.** Dữ liệu tổng hợp theo cửa sổ 1–10 phút, thiếu đặc trưng gói vi mô. |
| `source:sflow` | sFlow (RFC 3176) | Binary UDP datagram | **0/47 (0%)** | `PARSEABLE` | `SEMANTIC_MISMATCH` | **Tuyệt đối cấm Inference.** Lấy mẫu 1-in-N phá vỡ hoàn toàn định nghĩa luồng trạng thái (stateful flow). |

---

## 4. Chi tiết Ánh xạ 47 Đặc trưng ML theo Từng Nguồn

| # | Tên Đặc trưng ML | NetFlow v3 | NetFlow v5 | NetFlow v9/IPFIX | Zeek `conn.log` | AWS VPC Flow | Suricata `eve` |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | `PROTOCOL` | `EXACT` | `EXACT` | `EXACT` | `DERIVABLE` (proto) | `EXACT` | `EXACT` |
| 2 | `L7_PROTO` | `EXACT` | `MISSING` | `MISSING` | `APPROXIMATE` (service) | `MISSING` | `APPROXIMATE` (app_proto) |
| 3 | `IN_BYTES` | `EXACT` | `EXACT` (dOctets) | `EXACT` (octetDeltaCount) | `EXACT` (orig_bytes) | `APPROXIMATE` (bytes) | `EXACT` (src_bytes) |
| 4 | `IN_PKTS` | `EXACT` | `EXACT` (dPkts) | `EXACT` (packetDeltaCount) | `EXACT` (orig_pkts) | `APPROXIMATE` (packets) | `EXACT` (src_pkts) |
| 5 | `OUT_BYTES` | `EXACT` | `MISSING` | `APPROXIMATE` | `EXACT` (resp_bytes) | `MISSING` | `EXACT` (dst_bytes) |
| 6 | `OUT_PKTS` | `EXACT` | `MISSING` | `APPROXIMATE` | `EXACT` (resp_pkts) | `MISSING` | `EXACT` (dst_pkts) |
| 7 | `TCP_FLAGS` | `EXACT` | `EXACT` (tcp_flags) | `EXACT` (tcpControlBits) | `APPROXIMATE` (history) | `APPROXIMATE` (tcp_flags) | `EXACT` (tcp.tcp_flags) |
| 8 | `CLIENT_TCP_FLAGS` | `EXACT` | `MISSING` | `MISSING` | `APPROXIMATE` | `MISSING` | `APPROXIMATE` |
| 9 | `SERVER_TCP_FLAGS` | `EXACT` | `MISSING` | `MISSING` | `APPROXIMATE` | `MISSING` | `APPROXIMATE` |
| 10 | `FLOW_DURATION_MILLISECONDS` | `EXACT` | `DERIVABLE` | `DERIVABLE` | `DERIVABLE` (duration*1000) | `SEMANTIC_MISMATCH` (60s win) | `DERIVABLE` |
| 11 | `DURATION_IN` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 12 | `DURATION_OUT` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 13 | `MIN_TTL` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 14 | `MAX_TTL` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 15 | `LONGEST_FLOW_PKT` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 16 | `SHORTEST_FLOW_PKT` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 17 | `MIN_IP_PKT_LEN` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 18 | `MAX_IP_PKT_LEN` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 19 | `SRC_TO_DST_SECOND_BYTES` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 20 | `DST_TO_SRC_SECOND_BYTES` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 21 | `RETRANSMITTED_IN_BYTES` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 22 | `RETRANSMITTED_IN_PKTS` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 23 | `RETRANSMITTED_OUT_BYTES` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 24 | `RETRANSMITTED_OUT_PKTS` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 25 | `SRC_TO_DST_AVG_THROUGHPUT` | `EXACT` | `DERIVABLE` | `DERIVABLE` | `DERIVABLE` | `SEMANTIC_MISMATCH` | `DERIVABLE` |
| 26 | `DST_TO_SRC_AVG_THROUGHPUT` | `EXACT` | `MISSING` | `MISSING` | `DERIVABLE` | `MISSING` | `DERIVABLE` |
| 27 | `NUM_PKTS_UP_TO_128_BYTES` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 28 | `NUM_PKTS_128_TO_256_BYTES` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 29 | `NUM_PKTS_256_TO_512_BYTES` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 30 | `NUM_PKTS_512_TO_1024_BYTES` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 31 | `NUM_PKTS_1024_TO_1514_BYTES`| `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 32 | `TCP_WIN_MAX_IN` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 33 | `TCP_WIN_MAX_OUT` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 34 | `ICMP_TYPE` | `EXACT` | `APPROXIMATE` | `EXACT` | `MISSING` | `MISSING` | `MISSING` |
| 35 | `ICMP_IPV4_TYPE` | `EXACT` | `APPROXIMATE` | `EXACT` | `MISSING` | `MISSING` | `MISSING` |
| 36 | `DNS_QUERY_ID` | `EXACT` | `MISSING` | `MISSING` | `MISSING` (có ở dns.log) | `MISSING` | `MISSING` |
| 37 | `DNS_QUERY_TYPE` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 38 | `DNS_TTL_ANSWER` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 39 | `FTP_COMMAND_RET_CODE` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 40 | `SRC_TO_DST_IAT_MIN` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 41 | `SRC_TO_DST_IAT_MAX` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 42 | `SRC_TO_DST_IAT_AVG` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 43 | `SRC_TO_DST_IAT_STDDEV` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 44 | `DST_TO_SRC_IAT_MIN` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 45 | `DST_TO_SRC_IAT_MAX` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 46 | `DST_TO_SRC_IAT_AVG` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |
| 47 | `DST_TO_SRC_IAT_STDDEV` | `EXACT` | `MISSING` | `MISSING` | `MISSING` | `MISSING` | `MISSING` |

---

## 5. Chính sách Không Điền Giá trị Giả mạo (Anti-Imputation Policy)

1. **Tuyệt đối cấm điền số 0, trung bình (mean), hoặc trung vị (median) vào các trường bị thiếu (`MISSING`) hoặc chứa `NaN`/`Inf` chỉ để ép vượt qua validation schema.**
2. Việc điền giá trị giả mạo làm méo mó vector đặc trưng 47 chiều, khiến imputer của mô hình gán median của môi trường lab vào môi trường thực tế, gây suy luận sai lệch.
3. Nếu tệp đầu vào hoặc bản ghi thiếu dù chỉ 1 đặc trưng bắt buộc hoặc chứa giá trị không hợp lệ (NaN, Inf, chuỗi lỗi):
   - Hệ thống đánh dấu `FEATURE_INCOMPLETE` hoặc `FEATURE_INCOMPATIBLE`.
   - Cổng quyết định tự động **Từ chối suy luận (`Abstain`)**.
   - Trích xuất toàn bộ metadata hợp lệ (IP nguồn/đích, Port, Protocol, Timestamp, Duration, Bytes, Packets) chuyển sang **Trace Engine (#24)** và **Risk Engine (#32)** để thực hiện tương quan sự cố không dùng ML.

---

## 6. Phân tích Chẩn đoán Đa biến & Cơ chế Lệch miền (Multivariate Diagnostic Analysis)

Kết quả thực nghiệm trên 100.000 dòng `NF-CSE-CIC-IDS2018-v3` (AWS Canada) đối chiếu với `NF-UNSW-NB15-v3` (IXIA Lab):

### A. Sự kiện đã xác minh (Verified Facts)
1. **Lệch miền TTL:** Trong mẫu kiểm định AWS, 60.708 dòng (60.7%) có `MIN_TTL=0`, 24.551 dòng có `MIN_TTL=128`, và các giá trị còn lại phân bố quanh 100-106. Không có dòng nào nằm trong bộ phím tắt lab `{31, 62, 254, 255}`.
2. **Họ tấn công `FTP-BruteForce`:** 100% bản ghi (29.980 dòng) đều có `MIN_TTL=0` và `FLOW_DURATION_MILLISECONDS=1.0`.
3. **Cột & Thứ tự đặc trưng:** Toàn bộ 47 tên cột và kiểu dữ liệu đều khớp tuyệt đối (`EXACT`) giữa hai tập dữ liệu NetFlow v3.

### B. Giả thuyết có bằng chứng thực nghiệm hỗ trợ (Supported Hypotheses)
1. **Unobserved Telemetry:** Giá trị `MIN_TTL=0` xuất hiện từ việc probe thu thập trên card mạng ảo (tap/veth) của AWS không trích xuất được TTL gói tin khởi tạo hoặc flow timeout mà không có gói SYN, khác biệt hoàn toàn với máy phát phần cứng IXIA PerfectStorm luôn gán TTL cố định.
2. **Cơ chế suy giảm dự đoán:** Cây quyết định của Random Forest baseline ưu tiên tách nhánh `MIN_TTL` ở những tầng cao nhất. Nhánh `MIN_TTL <= 15` được phân bổ vào Benign trong lab, dẫn đến việc nuốt trọn 29.980 luồng tấn công FTP-BruteForce (Recall = 0.0%). Đồng thời, các luồng Benign thật trên AWS có `MIN_TTL=128` (máy Windows) bị coi là giá trị bất thường và gán nhãn nhầm thành Attack (26.621 FP, FPR = 38.02%).

### C. Yếu tố môi trường cần nghiên cứu thêm (Unproven Factors)
1. Sự khác biệt về kiến trúc mạng thực tế (độ trễ WAN đám mây so với switch LAN nội bộ phòng thí nghiệm).
2. Tác động của các họ tấn công khác (DoS, DDoS, Web Attacks) chưa có mặt trong lát cắt 100k dòng lịch sử.
