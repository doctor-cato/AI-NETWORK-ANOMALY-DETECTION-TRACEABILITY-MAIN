# NetFlow Sentinel v2.0 — STRIDE Threat Model & Security Requirements

> **Tài liệu phân tích mô hình đe dọa (Issue #81 — Milestone M6.1)**  
> **Phiên bản:** 2.0.0-security  
> **Phương pháp luận:** Microsoft STRIDE & Defense-in-Depth  
> **Ranh giới:** Học thuật / Nghiên cứu / Thử nghiệm lab được ủy quyền

---

## 1. Ranh giới Tin cậy và Tài sản Cần Bảo vệ

### 1.1. Tài sản Cốt lõi (Assets)
1. **Model Binaries & Preprocessor Artifacts:** Nguy cơ bị đầu độc (data/model poisoning), tráo đổi tệp `.joblib` chứa mã độc thực thi tùy ý (untrusted deserialization).
2. **Behavioral Vectors & Session Profiles:** Nguy cơ suy đoán danh tính người dùng hoặc lộ thông tin hành vi nhạy cảm (privacy breach).
3. **Cryptographic Keys (AES-256-GCM Master & Ephemeral Keys):** Nguy cơ lộ khóa dẫn đến việc giải mã toàn bộ dữ liệu lịch sử hoặc làm giả bằng chứng.
4. **Audit Trails & Evidence Provenance:** Nguy cơ bị xóa hoặc sửa đổi để che giấu dấu vết tấn công (tampering).
5. **FastAPI Loopback Endpoint:** Nguy cơ các tiến trình độc hại khác cùng máy gửi yêu cầu trái phép.

### 1.2. Ranh giới Tin cậy (Trust Boundaries - TB)
- **TB1 (Network / Wire to Ingestion):** Gói tin mạng NetFlow/IPFIX hoặc log thô từ bên ngoài đi vào Collector. (Ranh giới không tin cậy hoàn toàn).
- **TB2 (Desktop UI to Sidecar API):** Giao tiếp qua local loopback `127.0.0.1` được bảo vệ bằng session token ngẫu nhiên.
- **TB3 (Core Engines to Storage Vault):** Ranh giới giữa bộ nhớ RAM của tiến trình và đĩa cứng (at-rest encryption).

---

## 2. Phân tích Đe dọa theo Mô hình STRIDE

| STRIDE Category | Mối Đe dọa Cụ thể | Ranh giới | Tác động Kỹ thuật | Biện pháp Phòng ngừa & Khắc phục trong v2.0 |
|---|---|:---:|---|---|
| **Spoofing (Giả mạo)** | - Kẻ tấn công giả mạo địa chỉ IP nguồn trong luồng NetFlow.<br>- Tiến trình khác trên máy giả mạo Desktop UI gọi API. | TB1<br>TB2 | - Đánh lừa AI hoặc quy kết sai.<br>- Chiếm quyền điều khiển API sidecar. | - **SR1:** Tính toán Behavioral Vector độc lập IP (#101–#104).<br>- **SR2:** Bắt buộc token ngẫu nhiên `X-Sentinel-Session-Token` cho mọi endpoint loopback. |
| **Tampering (Sửa đổi)** | - Sửa đổi payload vector hành vi hoặc log điều tra.<br>- Sửa đổi ciphertext trong SQLite. | TB3 | - Sai lệch kết luận điều tra, vô hiệu hóa chứng cứ. | - **SR3:** Mã hóa bằng AES-256-GCM với 128-bit authentication tag; từ chối mọi ciphertext bị sửa đổi (#117, #124).<br>- **SR4:** Ghi nhận hash SHA-256 của mọi artifact và tệp nguồn. |
| **Repudiation (Chối bỏ)** | - Kẻ tấn công xóa hoặc thay đổi khóa mật mã để phủ nhận hoạt động. | TB3 | - Mất khả năng truy vết trách nhiệm và thời điểm. | - **SR5:** Ghi log vòng đời khóa bất biến (`key_metadata`, `rotation_audit`) kèm timestamp UTC (#119). |
| **Information Disclosure (Lộ lọt thông tin)** | - Lộ plaintext vector hành vi hoặc evidence nhạy cảm ra tệp log hoặc swap disk.<br>- Lộ khóa mật mã trong memory dump hoặc log debug. | TB2<br>TB3 | - Vi phạm quyền riêng tư và lộ bí mật mạng. | - **SR6:** Mã hóa dữ liệu at-rest bằng AES-256-GCM (#118).<br>- **SR7:** Nghiêm cấm ghi plaintext vector hoặc khóa mật mã vào log file/console (`zero-credential logging`). |
| **Denial of Service (Từ chối dịch vụ)** | - Gửi bùng nổ hàng triệu gói tin NetFlow dị dạng để làm tràn RAM (OOM).<br>- Kích hoạt xoay khóa liên tục để làm cạn kiệt CPU. | TB1<br>TB2 | - Treo collector hoặc ứng dụng desktop. | - **SR8:** Sử dụng ring buffer / `collections.deque` giới hạn số sự kiện và backpressure drop accounting trong Python `UDPFlowCollector` (`src/network_anomaly/telemetry/collector.py`) và `StreamingEventPipeline` (`src/network_anomaly/streaming/pipeline.py`, mặc định `capacity=10_000`) (#131); Rust Collector hiệu năng cao (#128) đang `DEFERRED` (Rust hiện chỉ đảm nhiệm Tauri UI/sidecar IPC).<br>- **SR9:** Áp dụng Rotation Cooldown (tối thiểu 60 giây) và Rate Limiting cho Adaptive Key Rotation (#122). |
| **Elevation of Privilege (Leo thang đặc quyền)** | - Nạp tệp `.joblib` hoặc pickle không rõ nguồn gốc chứa payload RCE.<br>- Khai thác quyền administrator không cần thiết. | TB1<br>TB3 | - Chiếm quyền kiểm soát máy trạm phân tích. | - **SR10:** Kiểm tra tính toàn vẹn SHA-256 của model artifact trước khi nạp; cấm nạp model ngoài allowlist (#94).<br>- **SR11:** Ứng dụng desktop và sidecar chạy với quyền người dùng thông thường (`Standard User`), không đòi hỏi quyền Admin. |

---

## 3. Bảng Yêu cầu An ninh (Security Requirements - SR) và Phương pháp Kiểm chứng

| Mã SR | Yêu cầu An ninh | Cách thức Kiểm chứng (Verification Method) | Issue Ánh xạ | Trạng thái |
|---|---|---|---|:---:|
| **SR1** | Liên kết hành vi không phụ thuộc IP qua Behavioral Vector 16D. | Unit tests logic cosine/feature (`tests/unit/test_behavioral_engine.py`, PASS); lưu ý thực nghiệm mô phỏng `RQ3` (`reports/experiments/behavioral/rq3_session_correlation_experiment.json`) không đạt ngưỡng `>= 85%` (`simulation_hypothesis_met=false`, F1 `0.3191`/`0.5556`) và liên kết thực nghiệm AIT (`#85`) đang `BLOCKED` (`ENTITY_TIME_CORRELATION` heuristic, chưa có `DIRECT_UID_LINK`). | #104, #85 | `VERIFIED_UNIT_ONLY` |
| **SR2** | Từ chối truy cập API khi thiếu hoặc sai `X-Sentinel-Session-Token` (401/403). | Test tự động `tests/unit/test_api_security.py` (PASS). | #78 | `VERIFIED` |
| **SR3** | AES-256-GCM từ chối giải mã và ném lỗi khi ciphertext hoặc tag bị giả mạo dù chỉ 1 bit. | Cryptographic Integrity Test `tests/unit/test_crypto_integrity.py` & `test_crypto_aead.py` (PASS). | #117, #124 | `VERIFIED` |
| **SR4** | Mọi bản ghi sự kiện lưu vết tệp nguồn và SHA-256 provenance. | Contract test `tests/contract/test_canonical_security_event_v2.py` (PASS). | #79 | `VERIFIED` |
| **SR5** | Lịch sử xoay khóa được ghi log nguyên vẹn trong SQLite không thể ghi đè. | Integration & DB persistence tests `tests/unit/test_v2_prod_hardening.py` & `tests/unit/test_api_persistence.py` (PASS). | #120, #121 | `VERIFIED` |
| **SR6** | Vector hành vi được lưu trữ dưới dạng ciphertext trong database vault. | Kiểm tra SQLite table `behavioral_vectors` không chứa plaintext vector (`tests/unit/test_crypto_integrity.py`, PASS). | #118 | `VERIFIED` |
| **SR7** | Zero-credential logging: kiểm tra chuỗi token, API key và secret key không xuất hiện trong logs. | Kiểm tra redaction query secrets & zero-credential logging (`tests/unit/test_v2_prod_hardening.py`, `test_api_security.py`, PASS). | #119, #146 | `VERIFIED` |
| **SR8** | Bounded buffer & backpressure: Collector và pipeline không giữ hàng đợi sự kiện không giới hạn dưới tải cao. | Kiểm thử bounded capacity (`10,000` events mặc định trong Python `UDPFlowCollector`/`StreamingEventPipeline`) và backpressure/benchmark (`tests/unit/test_telemetry_collector.py`, `scripts/benchmark_full_system.py`, PASS); không có bộ giới hạn heap byte-level 256MB cứng trong Python. | #131, #147 | `VERIFIED` |
| **SR9** | Adaptive Key Rotation cooldown: cấm xoay khóa vượt ngưỡng cooldown/rate-limit (kể cả qua restart). | Test unit `tests/unit/test_crypto_integrity.py` & `tests/unit/test_v2_prod_hardening.py` (PASS). | #122 | `VERIFIED` |
| **SR10**| Model loading integrity gate: kiểm tra SHA-256 model trước khi nạp. | Test unit `tests/unit/test_model_registry.py` & `tests/unit/test_desktop_csv_api.py` (PASS). | #94 | `VERIFIED` |
| **SR11**| Hoạt động trơn tru với quyền Standard User (không UAC prompt). | Controller-target E2E script (`tests/integration/test_controller_target_vm_e2e.py`); Clean Windows 10/11 VM acceptance thực tế theo dõi ở #73. | #148, #73 | `PENDING_CLEAN_VM` |

---

## 4. Giới hạn An ninh (Security Assumptions & Limitations)

1. **Giả định về Host Compromise:** Hệ thống NetFlow Sentinel bảo vệ an toàn dữ liệu trên đường truyền và dữ liệu lưu trữ (at-rest), nhưng **không có khả năng chống lại kẻ tấn công đã chiếm toàn quyền root/administrator trên chính máy trạm thực thi** (kernel-level compromise, memory dumping, hook syscall).
2. **Giới hạn về Khóa Mật mã:** Để đảm bảo tính độc lập khi hoạt động ngoại tuyến (offline operation) trên máy trạm Windows, khóa gốc được lưu trữ bảo mật cục bộ (DPAPI hoặc file bảo vệ quyền cục bộ); không phụ thuộc cloud KMS.
3. **Tuyên bố Học thuật:** Hệ thống được thiết kế và kiểm chứng cho mục đích nghiên cứu học thuật, giáo dục và phòng thí nghiệm; **chưa phải là sản phẩm bảo mật thương mại cấp doanh nghiệp đã được chứng nhận FIPS 140-3 hay Common Criteria**.
