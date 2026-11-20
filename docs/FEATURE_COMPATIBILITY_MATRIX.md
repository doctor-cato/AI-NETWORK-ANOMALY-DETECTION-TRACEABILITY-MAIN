# Source & Feature Compatibility Matrix — NetFlow Sentinel v2 (`canonical-flow-v2-18`)

Tài liệu kiểm toán tính tương thích nguồn dữ liệu mạng và ánh xạ **18 đặc trưng chuẩn tắc `canonical-flow-v2-18`** phục vụ:
1. Multi-Source Ingestion & Adapter Architecture (`src/network_anomaly/ingestion/`).
2. Out-of-Distribution & Fail-Closed Prediction Abstention Policy.
3. Định tuyến dữ liệu phi-NetFlow (`route_only=True`) sang Trace Engine và Risk Engine mà **không impute ngầm**.

> Tài liệu tương thích 47 đặc trưng cũ (`NF-UNSW-NB15-v3`) đã ngừng sử dụng và lưu trữ tại [`docs/historical/nf_unsw_nb15_v3/`](historical/nf_unsw_nb15_v3/).

---

## 1. Hệ thống Phân định Trạng thái Dữ liệu & Ràng buộc Chứng cứ

| Mã Trạng thái | Điều kiện Kỹ thuật | Trạng thái Suy luận (`eligibility`) | Hành vi Hệ thống |
|---|---|---|---|
| `PARSEABLE` | Tệp vật lý (CSV, TSV, JSONL, Zeek log) giải mã thành công; không lỗi cú pháp. | `SCHEMA_INVALID` | Chuyển bản ghi sang bộ chuyển đổi (Adapter). |
| `SCHEMA_COMPATIBLE` | Tệp đủ trường định danh/metadata theo lược đồ nguồn trong `SourceRegistry`. | `FEATURE_INCOMPLETE` / `FEATURE_INCOMPATIBLE` | Chuẩn hóa thành `CanonicalNetworkEvent` / `CanonicalSecurityEvent`. Chưa đủ 18 đặc trưng ML `canonical-flow-v2-18`. |
| `SEMANTICALLY_COMPATIBLE` | Đủ 18 đặc trưng `canonical-flow-v2-18` có cùng ngữ nghĩa, đơn vị đo (`ms`, `bytes`, `packets`), hướng luồng hai chiều; giá trị hữu hạn (`finite`). | `VALIDATION_NOT_VERIFIED` | Đủ điều kiện kỹ thuật nhưng chưa có chứng cứ benchmark gắn SHA-256 trên nguồn đó. |
| `MODEL_VALIDATED` | Cặp (mô hình, preprocessor, nguồn dữ liệu) có chứng cứ benchmark khớp SHA-256 và `feature_contract_version == "canonical-flow-v2-18"`. | `PREDICTION_AVAILABLE` | **Cho phép Inference chứng nhận** (hiện chỉ áp dụng cho `Random Forest` trên `AIT-NDS-v2`; các mô hình/nguồn khác gắn `RESEARCH_ONLY` hoặc `BLOCKED`). |
| `BENCHMARK_FAILED` | Đã chạy benchmark thực nghiệm nhưng suy giảm nghiêm trọng hoặc không đạt ngưỡng chấp thuận (ví dụ zero-shot domain shift), hoặc sai lệch SHA-256. | `BENCHMARK_UNSATISFACTORY` | **Chặn Inference chứng nhận fail-closed**; chỉ dùng metadata cho Trace & Risk Engine hoặc phân tích nghiên cứu. |
| `ABSTAINED` | Vi phạm bất biến vật lý (port ngoài `[0, 65535]`, protocol ngoài `[0, 255]`, `duration_ms < 0`, byte/packet âm, `NaN`/`Inf`, tỷ lệ ngoài `[0, 1]`). | `ABSTAINED` | **Từ chối suy luận an toàn (`ABSTAINED_OOD`).** |

---

## 2. Hợp đồng 18 Đặc trưng ML Chuẩn tắc (`canonical-flow-v2-18`)

### 2.1. 6 Trường Cơ sở Quan sát Trực tiếp (`BASE_FLOW_FEATURE_COLUMNS`)
1. `duration_ms` — Thời lượng luồng (milliseconds, `>= 0.0`)
2. `bytes_in` — Số byte chiều client $\to$ server / originator $\to$ responder (`>= 0.0`)
3. `bytes_out` — Số byte chiều server $\to$ client / responder $\to$ originator (`>= 0.0`)
4. `pkts_in` — Số gói tin chiều đi (`>= 0.0`)
5. `pkts_out` — Số gói tin chiều về (`>= 0.0`)
6. `protocol_num` — Mã giao thức IANA (`[0..255]`, ví dụ TCP=`6`, UDP=`17`, ICMP=`1`)

### 2.2. 12 Đặc trưng Động học Luồng Suy diễn Xác định (`DERIVED_FLOW_FEATURE_COLUMNS`)
Tính bằng `compute_flow_features_from_base()` trong `src/network_anomaly/data/v2_schema.py`:
- `total_bytes`, `total_pkts`
- `bytes_in_ratio`, `pkts_in_ratio`
- `bytes_per_pkt_in`, `bytes_per_pkt_out`
- `bytes_per_sec_in`, `bytes_per_sec_out`, `pkts_per_sec`
- `has_response`, `is_tcp`, `is_udp`

---

## 3. Ma trận Tương thích Nguồn Dữ liệu v2

| Source / Probe | Định dạng | Mức tương thích `canonical-flow-v2-18` | Trạng thái Suy luận ML | Ghi chú Xử lý |
|---|---|---|---|---|
| **AIT NetFlow Data Set v2 (`AIT-NDS-v2`)** | Tstat (`tcp_complete`, `tcp_nocomplete`, `udp_complete`) | **18/18 (`EXACT` / `DERIVABLE`)** | `MODEL_VALIDATED` (RF) / `RESEARCH_ONLY` (XGB, IF, AE) | Nguồn huấn luyện & kiểm thử chính (`Train 2,097,891` / `Val 377,704` / `Test 988,805`). |
| **CTU-SME-11** | Zeek `conn.log.labeled` | **18/18 (`EXACT` / `DERIVABLE`)** | Cross-source External Benchmark (`RESEARCH_ONLY`) | Dùng `orig_bytes` / `resp_bytes` (L4 payload chuẩn hóa); `duration="-"` ánh xạ tường minh sang `0.0 ms`. |
| **Live NetFlow v9 / IPFIX (`UDPFlowCollector`)** | Binary / `CanonicalSecurityEvent` | **18/18 (`DERIVABLE`)** | `REAL_MODELS` (qua `RealtimeFeatureExtractor`) | Chỉ suy luận khi đủ 6 trường cơ sở hợp lệ; thiếu trường $\to$ từ chối fail-closed. |
| **NetFlow v5 / AWS VPC Flow** | CSV / TSV | **Thiếu chiều trả về (`OUT_BYTES` / `OUT_PKTS`)** | `FEATURE_INCOMPATIBLE` | **Không zero-fill.** Chỉ trích xuất metadata cho Behavioral/Risk/Trace. |
| **DNS / HTTP / Auth / System Logs (`AIT-LDS-v2.1`, Zeek, Suricata)** | JSON / TSV / Syslog | **0/18 (Phi-NetFlow)** | `route_only=True` (`is_ml_complete=False`) | **Tuyệt đối không impute.** Đi thẳng Behavioral Vector, Risk Engine, Trace Engine. |
| **v1 CSV (`NF-UNSW-NB15-v3`, 55 cột)** | CSV cũ | **REJECTED** | `SCHEMA_INVALID` / Fail-Closed | Ngừng hỗ trợ v1 trên toàn bộ pipeline v2. |
