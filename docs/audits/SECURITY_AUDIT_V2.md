# Báo Cáo Kiểm Định An Ninh Hệ Thống NetFlow Sentinel v2.0 (Security Audit v2.0)

**Mã tài liệu:** `AUDIT-SEC-V2-001`  
**Milestone:** `M6.7 (Desktop Dashboards & Release Packaging)`  
**Issue:** `#146`  
**Trạng thái:** **`ALL SECURITY REQUIREMENTS SATISFIED (0 CRITICAL / 0 HIGH VULNERABILITIES)`**  

---

## 1. Mục tiêu & Phạm vi Kiểm định An ninh

Kiểm định an ninh độc lập cho phiên bản NetFlow Sentinel v2.0.0, đối chiếu trực tiếp với Threat Model STRIDE (`docs/audits/THREAT_MODEL_V2.md`) và 8 yêu cầu an ninh cốt lõi (SR1–SR8).

---

## 2. Bảng Đánh Giá Yêu Cầu An Ninh (Security Requirements Audit)

| Mã SR | Yêu Cầu An Ninh | Đánh Giá | Bằng Chứng Kiểm Chứng (Evidence) |
| :---: | :--- | :---: | :--- |
| **SR1** | **Xác thực API & Fail-Closed Guard:** Mọi API endpoint nhạy cảm (`/api/v1/trace`, `/api/v1/crypto`) phải yêu cầu Bearer token hợp lệ. Thiếu token hoặc token sai phải trả về HTTP 401 không rò rỉ stacktrace. | **SATISFIED** | `tests/contract/test_trace_crypto_api.py` (Test `test_auth_guard_fail_closed` kiểm tra từ chối 401 khi thiếu token). |
| **SR2** | **Zero-Plaintext at Rest:** Vector hành vi và bằng chứng điều tra phải được mã hóa hoàn toàn bằng AES-256-GCM trước khi ghi xuống đĩa; không bao giờ lưu trữ plaintext vector trong cơ sở dữ liệu. | **SATISFIED** | `tests/integration/test_full_system_e2e.py` (Test `test_e2e_live_mode_and_zero_plaintext_in_db` kiểm tra trực tiếp byte nhị phân của tệp SQLite). |
| **SR3** | **Quản lý Khóa & Cách ly Domain:** Khóa mã hóa được sinh bằng CSPRNG chuẩn (`os.urandom(32)`), phân tách ngữ cảnh theo domain (HKDF), lưu trữ trong Keystore được phân quyền ngặt nghèo (chmod 0600). | **SATISFIED** | `src/network_anomaly/crypto/key_manager.py`, `tests/unit/test_crypto_aead.py`. |
| **SR4** | **Bảo vệ Xoay vòng Khóa (Anti-DoS):** Cơ chế xoay vòng khóa thích ứng phải có thời gian chờ (cooldown $\ge 60s$) và giới hạn tần suất ($\le 10$ lần/giờ) để ngăn chặn kẻ tấn công cố tình kích hoạt xoay khóa liên tục gây quá tải hệ thống. | **SATISFIED** | `src/network_anomaly/crypto/rotation.py` (`can_rotate` kiểm tra cooldown và rate limit), `tests/unit/test_crypto_integrity.py`. |
| **SR5** | **Chống Rò Rỉ Dữ Liệu (Zero-Leakage Split):** Quá trình phân chia dữ liệu và huấn luyện mô hình phải bảo đảm 0 overlap group thực thể giữa Train/Validation/Test; thanh lọc khoảng đệm thời gian 300s. | **SATISFIED** | `src/network_anomaly/data/split.py` (`MultiSourceTemporalSplitter`), `tests/unit/test_multi_source_split.py`. |
| **SR6** | **Bảo vệ Bí mật & Thông tin Đăng nhập:** Không lưu trữ API tokens, credentials, mật khẩu người dùng hoặc khóa bí mật trong mã nguồn, manifest, logs hoặc commit git. | **SATISFIED** | `scripts/fetch_multi_source_dataset.py` (Hàm `sanitize_url` loại bỏ toàn bộ token và user info). |
| **SR7** | **Quality Gate & OOD Rejection:** Dữ liệu đầu vào bị lỗi hoặc vượt ngưỡng dung sai phải bị chặn đứng (fail-closed); dữ liệu ngoài phân bố (OOD) phải bị từ chối suy luận (`ABSTAIN`). | **SATISFIED** | `src/network_anomaly/data/quality_gate.py`, `src/network_anomaly/ml/ood_gate.py`. |
| **SR8** | **Toàn Vẹn Bằng Chứng (Cryptographic Provenance):** Mọi báo cáo điều tra và vector hành vi đều được đính kèm mã băm SHA-256 để chống giả mạo bằng chứng pháp lý (tamper detection). | **SATISFIED** | `src/network_anomaly/trace/investigation.py` (`InvestigationReportGenerator`), `tests/unit/test_trace_engine.py`. |

---

## 3. Kết luận Kiểm định An ninh

1. Toàn bộ 8 yêu cầu an ninh SR1–SR8 đều đạt trạng thái **`SATISFIED`**.
2. Không còn bất kỳ lỗ hổng mức độ Critical hoặc High nào tồn tại trong hệ thống.
3. Hệ thống hoàn toàn sẵn sàng cho phát hành phiên bản chính thức NetFlow Sentinel v2.0.0.
