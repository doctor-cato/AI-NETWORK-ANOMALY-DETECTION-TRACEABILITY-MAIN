# NetFlow Sentinel v2.0 — Keystore Incident & Backup/Restore Runbook

> **Phạm vi (#119 AC4, #123 AC3):** Tài liệu vận hành cho kho khóa AES-256-GCM (`master.key`, `k-*.key`, `keys_metadata.json`, `nonce_registry.json`) bảo vệ bởi Windows DPAPI hoặc quyền POSIX `0600`.

---

## 1. Xử lý Sự cố Keystore Không khả dụng (`KeyStorageError`, `#119 AC4`)

### 1.1. Triệu chứng thường gặp
- Backend trả HTTP `503` hoặc ném `KeyStorageError` khi gọi `/api/v1/crypto/status`, `/api/v1/behavioral/vectors/{id}`, hoặc lưu bản ghi vào `EncryptedStorageVault`.
- Nguyên nhân phổ biến:
  1. **Sai ngữ cảnh người dùng Windows DPAPI:** `master.key` được mã hóa gắn với tài khoản Windows User tạo ra nó; chạy dịch vụ bằng tài khoản khác (hoặc đổi SID người dùng) khiến `CryptUnprotectData` thất bại fail-closed.
  2. **Thiếu file hoặc sai quyền POSIX:** Thư mục `data/keys/` (hoặc `%LOCALAPPDATA%\NetFlowSentinel\keys\`) bị thiếu `master.key` / `k-*.key`, hoặc file bị sửa quyền truy cập công khai trên Linux/macOS.
  3. **Khóa cũ chưa nâng cấp định dạng wrapped DEK v2:** Tệp `k-*.key` ở định dạng legacy cần kiểm tra/chuyển đổi qua `scripts/migrate_keystore.py`.

### 1.2. Quy trình Ứng phó Fail-Closed (Không ghi đè ngầm)
1. **Dừng ghi dữ liệu mới:** Không xóa `data/keys/` hay tạo khóa mới ghi đè lên `master.key` cũ — làm vậy sẽ mất vĩnh viễn khả năng giải mã `behavioral_vectors` và `encrypted_vault` cũ trong SQLite.
2. **Kiểm tra trạng thái kho khóa ở chế độ chỉ đọc:**
   ```powershell
   .venv\Scripts\python.exe scripts/migrate_keystore.py --verify-only --keystore-dir data/keys
   ```
3. **Đối chiếu `key_id` đang tham chiếu trong SQLite:**
   ```powershell
   .venv\Scripts\python.exe -c "import sqlite3; c=sqlite3.connect('data/network_anomaly.db'); print(c.execute('SELECT key_id, status FROM key_metadata').fetchall())"
   ```
4. **Khắc phục theo nguyên nhân:**
   - Nếu chạy sai tài khoản Windows: khởi động lại ứng dụng dưới đúng tài khoản Standard User đã tạo `master.key`.
   - Nếu lỗi định dạng DEK legacy: sao lưu toàn bộ `data/keys/` trước rồi chạy `migrate_keystore.py`.
   - Nếu `master.key` hoặc `k-*.key` bị hỏng: chuyển sang Quy trình Restore ở Mục 2.

---

## 2. Quy trình Backup & Restore Keystore (`#123 AC3`)

> [!IMPORTANT]
> **Nguyên tắc đồng bộ:** Luôn sao lưu **đồng thời** thư mục `data/keys/` và tệp SQLite `data/network_anomaly.db` trong cùng cửa sổ ngừng ghi để đảm bảo mọi `ciphertext`/`nonce`/`tag` trong DB khớp với bộ `k-*.key` tương ứng.

### 2.1. Backup an toàn (Offline)
1. Đóng ứng dụng Desktop / dừng FastAPI sidecar.
2. Sao chép đồng bộ vào thư mục lưu trữ ngoại tuyến có phân quyền chỉ chủ sở hữu (`ACL` / `0700`):
   - Toàn bộ thư mục `data/keys/` (`master.key`, `k-*.key`, `keys_metadata.json`, `nonce_registry.json`, `rotation_state.json` nếu có).
   - Tệp `data/network_anomaly.db`.
3. Tính và lưu `SHA256SUMS` cho từng tệp trong bản sao lưu.
   - *Lưu ý Windows DPAPI:* `master.key` chỉ giải mã được trên **cùng Windows User + cùng máy** (hoặc user roaming profile DPAPI hợp lệ). Để di chuyển sang máy khác, phải re-wrap khóa dưới tài khoản đích hoặc giữ nguyên bảo lưu trong phạm vi lab.

### 2.2. Restore & Kiểm chứng Giải mã Dữ liệu Lịch sử
1. Dừng backend và sao lưu trạng thái lỗi hiện tại sang thư mục `data/keys.broken.<timestamp>/`.
2. Khôi phục `data/keys/` và `data/network_anomaly.db` từ bản backup đã kiểm khớp `SHA256SUMS`.
3. Xác minh lại quyền tệp, tính toàn vẹn DB và khả năng giải mã bản ghi lịch sử:
   ```powershell
   .venv\Scripts\python.exe scripts/migrate_keystore.py --verify-only --keystore-dir data/keys
   .venv\Scripts\python.exe -m pytest tests/unit/test_key_manager_hardening.py tests/unit/test_crypto_integrity.py -q
   ```
4. Không bao giờ gọi `revoke` trên `key_id` còn đang được `behavioral_vectors` hoặc `encrypted_vault` tham chiếu khi chưa re-encrypt sang khóa mới.
