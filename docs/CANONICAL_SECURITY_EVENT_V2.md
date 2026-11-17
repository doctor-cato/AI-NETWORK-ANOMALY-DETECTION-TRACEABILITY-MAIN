# NetFlow Sentinel v2.0 — Canonical Security Event & Feature Contract Specification

> **Đặc tả hợp đồng dữ liệu chuẩn tắc (Issue #79 — Milestone M6.1)**  
> **Phiên bản:** 2.0.0-contract  
> **Module thực thi:** `src/network_anomaly/canonical/`

---

## 1. Mục tiêu và Nguyên tắc Thiết kế

Trong kiến trúc NetFlow Sentinel v2.0, dữ liệu được thu thập từ nhiều nguồn dị thể:
- Network Flow (NF-UNSW-NB15-v3, AIT NetFlow, NetFlow v9/IPFIX, PCAP)
- Application Logs (DNS query/response, Web/HTTP access logs)
- Identity & System Logs (Linux auth, Windows Security/Sysmon, VPN)

Để đảm bảo tính nhất quán trong suy luận AI, tính toán Vector hành vi, định tuyến Rủi ro và truy vết Chứng cứ, toàn bộ dữ liệu đi vào hệ thống phải tuân theo hợp đồng dữ liệu **`CanonicalSecurityEvent` v2.0**.

### Nguyên tắc Bất biến:
1. **Bảo tồn Nguồn gốc (Provenance Preservation):** Mỗi sự kiện phải mang `raw_provenance` chỉ rõ tệp nguồn, vị trí dòng/offset và adapter đã xử lý.
2. **Nghiêm cấm Impute Ngầm (Strictly No Implicit Imputation):** Nếu một sự kiện không phải NetFlow hoặc thiếu bất kỳ đặc trưng nào trong số 47 đặc trưng ML chuẩn, sự kiện đó phải được đánh dấu `is_ml_complete = False` và từ chối suy luận trực tiếp; tuyệt đối không được tự động điền giá trị 0 hoặc mean để ép suy luận.
3. **Định dạng Thời gian Chuẩn tắc:** Timestamp bắt buộc có timezone UTC (`ISO-8601`).
4. **Phân định Rõ Ràng giữa Network Tuples và Application Payload:** Đảm bảo khả năng tương thích cao với cả sự kiện có IP và sự kiện hệ thống nội bộ.

---

## 2. Lược đồ `CanonicalSecurityEvent` (Schema Specification)

### 2.1. Các trường Cốt lõi (Core Header)
- `event_id` (`str`): UUID v4 duy nhất cho mỗi sự kiện.
- `schema_version` (`str`): Cố định `"2.0.0"`.
- `event_timestamp` (`datetime`): Thời điểm xảy ra sự kiện, chuẩn UTC ISO-8601.
- `event_kind` (`enum`): Một trong các giá trị:
  - `flow`: Lưu lượng mạng luồng NetFlow / IPFIX / PCAP.
  - `dns`: Bản ghi truy vấn/phản hồi DNS.
  - `web`: Bản ghi truy cập HTTP / Web API.
  - `auth`: Bản ghi xác thực người dùng / VPN / SSH.
  - `system`: Bản ghi tiến trình hệ thống / Audit / Sysmon.
- `source_id` (`str`): Định danh duy nhất của nguồn cấp dữ liệu (ví dụ: `source:nf-unsw-nb15-v3`, `source:ait-syslog`).
- `entity_id` (`Optional[str]`): Định danh thực thể (máy chủ, tài khoản, thiết bị) phục vụ liên kết hành vi độc lập IP.

### 2.2. Network 5-Tuple (Tùy chọn theo loại sự kiện)
- `source_ip` (`Optional[str]`): Địa chỉ IPv4 hoặc IPv6 nguồn.
- `source_port` (`Optional[int]`): Cổng nguồn $[0, 65535]$.
- `dest_ip` (`Optional[str]`): Địa chỉ IPv4 hoặc IPv6 đích.
- `dest_port` (`Optional[int]`): Cổng đích $[0, 65535]$.
- `protocol` (`Optional[str]`): Giao thức mạng (TCP, UDP, ICMP...).

### 2.3. Specialized Payloads
- `flow_metrics`: `duration_ms`, `bytes_in`, `bytes_out`, `pkts_in`, `pkts_out`, `tcp_flags`.
- `dns_data`: `query_name`, `query_type`, `query_id`, `rcode`, `ttl_answer`.
- `http_data`: `method`, `url`, `status_code`, `user_agent`, `content_type`.
- `auth_data`: `username`, `auth_result` (`SUCCESS`, `FAILURE`, `CHALLENGE`), `service`.
- `system_data`: `process_name`, `process_id`, `action`, `return_code`.

### 2.4. Provenance & Validation Gate
- `raw_provenance`:
  - `source_file` (`str`): Tệp gốc hoặc tên giao diện mạng.
  - `line_or_offset` (`Optional[int]`): Dòng hoặc byte offset.
  - `source_checksum` (`Optional[str]`): SHA-256 tệp dữ liệu.
  - `adapter_name` (`str`): Tên adapter xử lý (ví dụ: `NetFlowV3Adapter`, `ZeekDNSAdapter`).
- `is_ml_complete` (`bool`): `True` khi đủ 47 đặc trưng ML hợp lệ; `False` nếu thiếu hoặc không áp dụng.
- `validation_status` (`ValidationStatus`): `VALID`, `FEATURE_INCOMPLETE`, `TIMESTAMP_INVALID`, `OUT_OF_BOUNDS`, `REJECTED`.

---

## 3. Hợp đồng Đặc trưng Máy học `FeatureContract`

Hợp đồng `FeatureContract` quy định giao ước bất biến đối với các mô hình AI:

### 3.1. Hợp đồng Cơ sở: `nf-unsw-nb15-v3-baseline-47`
- **Phiên bản:** `2.0.0`
- **Danh sách:** Đúng 47 đặc trưng số hóa (loại trừ 6 metadata và 2 nhãn nhị phân/đa lớp).
- **Hành vi Kiểm chứng (`validate_features`):**
  - Mọi giá trị phải chuyển đổi được sang `float`.
  - Giá trị `NaN`, `+Inf`, `-Inf` bị coi là không hợp lệ và trả về `(False, [features_loi])`.
  - **Hành vi Trích xuất (`extract_vector`):** Ném ngoại lệ `ValueError` ngay lập tức nếu thiếu bất kỳ đặc trưng nào.

---

## 4. Kiểm thử Hợp đồng (Contract Tests)

Toàn bộ các điều kiện của hợp đồng được tự động kiểm thử tại:
- `tests/contract/test_canonical_security_event_v2.py`:
  - `test_canonical_security_event_v2_flow`: Khởi tạo và kiểm tra luồng mạng.
  - `test_canonical_security_event_v2_other_kinds`: Khởi tạo DNS, Web, Auth, System.
  - `test_port_validation`: Bắt lỗi và từ chối port ngoài phạm vi.
  - `test_feature_contract_validation_and_no_imputation`: Kiểm tra từ chối bản ghi thiếu feature, chặn impute ngầm.
  - `test_v1_legacy_row_compatibility`: Chứng minh bản ghi 55 cột v1.0.0 chuyển đổi mượt mà sang v2.0.
