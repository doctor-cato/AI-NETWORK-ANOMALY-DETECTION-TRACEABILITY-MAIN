# NetFlow Sentinel v2.0 — Canonical Security Event & Feature Contract Specification

> **Đặc tả hợp đồng dữ liệu chuẩn tắc (Issue #79 — Milestone M6.1)**
> **Phiên bản:** 2.0.0-contract
> **Module thực thi:** `src/network_anomaly/canonical/`, `src/network_anomaly/data/v2_schema.py`

---

## 1. Mục tiêu và Nguyên tắc Thiết kế

Trong kiến trúc NetFlow Sentinel v2.0, dữ liệu được thu thập từ nhiều nguồn dị thể:
- **Network Flow:** `AIT-NDS-v2` (Tstat), `CTU-SME-11` (Zeek `conn.log.labeled`), NetFlow v9/IPFIX, PCAP-to-flow.
- **Application Logs:** DNS query/response, Web/HTTP access logs (`AIT-LDS-v2.1`, Zeek, Nginx/Apache).
- **Identity, Alert & System Logs:** Linux auth/audit, VPN, Windows Security/Sysmon, `AIT-ADS`.

Toàn bộ dữ liệu đi vào hệ thống tuân theo hợp đồng dữ liệu **`CanonicalSecurityEvent` v2.0** và hợp đồng đặc trưng ML **`canonical-flow-v2-18`**.

### Nguyên tắc Bất biến:
1. **Bảo tồn Nguồn gốc (Provenance Preservation):** Mỗi sự kiện mang `raw_provenance` chỉ rõ tệp nguồn, dòng/offset và adapter đã xử lý.
2. **Nghiêm cấm Impute Ngầm (Strictly No Implicit Imputation):** Nếu sự kiện không phải NetFlow hai chiều hợp lệ hoặc thiếu bất kỳ trường cơ sở nào của `canonical-flow-v2-18`, sự kiện phải gắn `is_ml_complete = False` và bị từ chối suy luận ML trực tiếp; tuyệt đối không điền 0 hoặc mean/median để ép suy luận.
3. **Định dạng Thời gian Chuẩn tắc:** Timestamp chuẩn UTC (`ISO-8601` / `timestamp_ms`).
4. **Cách ly Tuyệt đối Metadata & Target:** 5 cột trace metadata (`timestamp_ms`, `source_ip`, `dest_ip`, `source_port`, `dest_port`), 5 cột provenance và 4 cột nhãn không bao giờ lọt vào ma trận đặc trưng `X`.

---

## 2. Lược đồ `CanonicalSecurityEvent` (Schema Specification)

### 2.1. Core Header
- `event_id` (`str`): UUID duy nhất cho mỗi sự kiện.
- `schema_version` (`str`): `"2.0.0"`.
- `event_timestamp` (`datetime`): Thời điểm sự kiện theo UTC ISO-8601.
- `event_kind` (`enum`): `flow`, `dns`, `web`, `auth`, `system`.
- `source_id` (`str`): Định danh nguồn (ví dụ `source:ait-nds-v2`, `source:ctu-sme-11`, `source:ait-lds-v2.1`, `source:netflow-ipfix-live`).
- `entity_id` (`Optional[str]`): Định danh thực thể phục vụ liên kết hành vi độc lập IP.

### 2.2. Network 5-Tuple & Specialized Payloads
- **5-Tuple:** `source_ip`, `source_port` (`[0, 65535]`), `dest_ip`, `dest_port` (`[0, 65535]`), `protocol`.
- **Payloads:** `flow_metrics` (`duration_ms`, `bytes_in`, `bytes_out`, `pkts_in`, `pkts_out`), `dns_data`, `http_data`, `auth_data`, `system_data`.

### 2.3. Provenance & Validation Gate
- `raw_provenance`: `source_file`, `line_or_offset`, `source_checksum`, `adapter_name`.
- `is_ml_complete` (`bool`): `True` khi đủ 18 đặc trưng `canonical-flow-v2-18` hữu hạn và hợp lệ vật lý; `False` nếu thiếu hoặc là log ứng dụng/hệ thống.
- `validation_status` (`ValidationStatus`): `VALID`, `FEATURE_INCOMPLETE`, `TIMESTAMP_INVALID`, `OUT_OF_BOUNDS`, `REJECTED`.

---

## 3. Hợp đồng Đặc trưng Máy học: `canonical-flow-v2-18`

- **Định danh hợp đồng:** `canonical-flow-v2-18` (`FEATURE_CONTRACT_VERSION = "2.0.0"`).
- **Danh sách đầy đủ 18 đặc trưng (`ML_FEATURE_COLUMNS`):**
  - **6 Base Observed Flow Fields:** `duration_ms`, `bytes_in`, `bytes_out`, `pkts_in`, `pkts_out`, `protocol_num`.
  - **12 Derived Flow-Dynamics Features:** `total_bytes`, `total_pkts`, `bytes_in_ratio`, `pkts_in_ratio`, `bytes_per_pkt_in`, `bytes_per_pkt_out`, `bytes_per_sec_in`, `bytes_per_sec_out`, `pkts_per_sec`, `has_response`, `is_tcp`, `is_udp`.
- **Hành vi Kiểm chứng (`validate_feature_selection` & `compute_flow_features_from_base`):**
  - Từ chối ngay lập tức các cột rò rỉ (`timestamp_ms`, `source_ip`, `dest_ip`, `source_port`, `dest_port`, `label_binary`, `attack_category`, `raw_label`, `label_status`, `role_cli`, `uid`, `Label`, `Attack`, `MIN_TTL`...).
  - Giá trị âm, `NaN`, `+Inf`, `-Inf`, port/protocol ngoài miền bị từ chối fail-closed (`ValueError`).

---

## 4. Kiểm thử Hợp đồng (Contract Tests)

- `tests/contract/test_canonical_security_event_v2.py`
- `tests/contract/test_canonical_event.py`
- `tests/unit/test_v2_migration_guards.py`
- `tests/unit/test_anti_imputation_and_label_integrity.py`
