# Báo Cáo Kiểm Định An Ninh Hệ Thống NetFlow Sentinel v2.0 (Security Audit v2.0)

**Mã tài liệu:** `AUDIT-SEC-V2-001`
**Milestone:** `M6.7 (Desktop Dashboards & Release Packaging)`
**Issue:** `#146`
**Trạng thái:** **`CORE SECURITY CONTROLS IMPLEMENTED & TESTED (PROTOTYPE / PILOT SCOPE — NOT PRODUCTION-CERTIFIED)`**

---

## 1. Mục tiêu & Phạm vi Kiểm định An ninh

Kiểm định an ninh độc lập cho phiên bản NetFlow Sentinel v2.0.0 trên nhánh `feat/v2-integration`, đối chiếu trực tiếp với Threat Model STRIDE (`docs/audits/THREAT_MODEL_V2.md`) và 8 yêu cầu an ninh cốt lõi (SR1–SR8), bao gồm cả khắc phục phát hiện **F05 (Key Storage Hardening)**.

---

## 2. Bảng Đánh Giá Yêu Cầu An Ninh (Security Requirements Audit)

| Mã SR | Yêu Cầu An Ninh | Đánh Giá | Bằng Chứng Kiểm Chứng (Evidence) & Giới Hạn |
| :---: | :--- | :---: | :--- |
| **SR1** | **Xác thực API & Fail-Closed Guard:** Mọi API endpoint nhạy cảm (`/api/v1/trace`, `/api/v1/crypto`, `/api/v1/live`, `/api/v1/behavioral`) phải yêu cầu Bearer/Session token hợp lệ. Thiếu token hoặc token sai phải trả về HTTP 401 không rò rỉ stacktrace. | **SATISFIED** | `src/network_anomaly/api/main.py`, `tests/contract/test_trace_crypto_api.py`, `tests/integration/test_live_behavioral_api.py`. |
| **SR2** | **Zero-Plaintext at Rest:** Vector hành vi và bằng chứng điều tra phải được mã hóa hoàn toàn bằng AES-256-GCM trước khi ghi xuống đĩa; cột `vector_json` lưu `NULL`. | **SATISFIED** | `src/network_anomaly/crypto/encrypted_storage.py`, `tests/integration/test_full_system_e2e.py`, `reports/acceptance/synthetic_udp_loopback_report.json` (`6/6` vector mã hóa, `plaintext column NULL`). |
| **SR3** | **Quản lý Khóa Fail-Closed & Key Wrapping:** Trên Windows, `master.key` bắt buộc bảo vệ bằng **Windows DPAPI** (`CryptProtectData`/`CryptUnprotectData`), fail-closed khi DPAPI lỗi (không ghi fallback plaintext). DEK được bọc bằng AES-256-GCM (`NETFLOW_WRAPPED_DEK_V2`) với AAD `key_id\|domain\|version`, `NonceRegistry` chống lặp nonce, ghi file atomic (`os.replace`) và `icacls` ACL hardening. Không tự chấp nhận khóa plaintext cũ mà yêu cầu di trú có kiểm soát qua `scripts/migrate_keystore.py`. | **SATISFIED (Windows DPAPI) / PARTIAL (POSIX)** | `src/network_anomaly/crypto/key_manager.py`, `scripts/migrate_keystore.py`, `tests/unit/test_key_manager_hardening.py`, `tests/unit/test_crypto_integrity.py`, `tests/unit/test_crypto_aead.py`.<br>**Giới hạn POSIX:** Trên Linux/POSIX không có DPAPI; `master.key` chỉ dựa vào quyền file `0600` và ranh giới tài khoản OS, không tương đương mã hóa khóa ở tầng hệ điều hành. |
| **SR4** | **Bảo vệ Xoay vòng Khóa (Anti-DoS):** Cơ chế xoay vòng khóa thích ứng phải có cooldown (`>= 60s`) và giới hạn tần suất (`<= 10` lần/giờ) để ngăn DoS xoay khóa liên tục. | **SATISFIED** | `src/network_anomaly/crypto/rotation.py`, `tests/unit/test_crypto_integrity.py`. |
| **SR5** | **Chống Rò Rỉ Dữ Liệu (Zero-Leakage Split):** Phân chia Train/Val/Test bảo đảm 0 overlap thực thể và có purge gap 300s; threshold calibration không dùng tập Test. | **SATISFIED** | `src/network_anomaly/data/split.py`, `src/network_anomaly/ml/threshold_calibration.py`, `src/network_anomaly/models/scoring.py`, `tests/unit/test_multi_source_split.py`, `tests/unit/test_ood_and_calibration.py`. |
| **SR6** | **Bảo vệ Bí mật & Thông tin Đăng nhập:** Không lưu token/credential/key bytes trong mã nguồn, manifest, log hay API response. | **SATISFIED** | `KeyManager.__repr__` che khóa, `storage_protection()` chỉ trả metadata/trạng thái, `scripts/fetch_multi_source_dataset.py` (`sanitize_url`), `tests/unit/test_key_manager_hardening.py`. |
| **SR7** | **Quality Gate, Strict Feature Contract & OOD Rejection:** Dữ liệu thiếu đặc trưng bị đánh dấu `NOT_MODEL_READY` (không zero-impute hàng loạt); mẫu ngoài phân bố bị gate đánh dấu OOD. | **SATISFIED (Code) / PARTIAL (Live OOD artifact)** | `src/network_anomaly/streaming/feature_extractor.py`, `src/network_anomaly/ml/ood_gate.py`, `tests/unit/test_feature_extractor.py`, `tests/unit/test_ood_and_calibration.py`.<br>**Ghi chú:** Khi chạy loopback acceptance mặc định nếu chưa cấu hình reference stats cho `OODRejectionGate`, trạng thái gate là `NOT_FITTED` và được báo cáo minh bạch trong API `/api/v1/live/status`. |
| **SR8** | **Toàn Vẹn Bằng Chứng (Cryptographic Provenance):** Báo cáo điều tra đính kèm SHA-256 tính động trên nội dung thực tế từ backend; UI báo lỗi tường minh khi export thất bại. | **SATISFIED** | `src/network_anomaly/trace/investigation.py`, `desktop/src/lib/components/AttackTimelinePanel.svelte`, `tests/unit/test_trace_engine.py`, `desktop/src/lib/components/V2Panels.test.ts`. |

---

## 3. Kết luận & Giới hạn Kiểm định An ninh

1. Toàn bộ 8 yêu cầu an ninh SR1–SR8 đã có triển khai và unit/integration tests kiểm chứng ở cấp độ codebase (bao gồm xử lý triệt để lỗ hổng F05 plaintext `master.key`).
2. **Giới hạn phạm vi (Không tuyên bố Production-Ready):**
   - Chưa thực hiện kiểm thử xâm nhập (penetration testing) độc lập trên bộ cài đặt hoàn chỉnh.
   - Chưa kiểm thử cài đặt/nâng cấp/gỡ cài đặt NSIS `.exe` trên máy ảo Windows sạch (`#148`, `#73`).
   - Trên POSIX, cơ chế bảo vệ `master.key` là quyền tệp `0600` (không có DPAPI/TPM/Keyring).
   - Hệ thống đạt mức kiểm soát an ninh cho **môi trường đồ án và thử nghiệm lab có kiểm soát**, chưa đủ chứng cứ chứng nhận triển khai production diện rộng.
