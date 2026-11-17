# Hướng dẫn Triển khai & Đóng gói NetFlow Sentinel v2.0 (Controlled Pilot Deployment)

Tài liệu này mô tả yêu cầu hạ tầng, cấu hình bảo mật, quy trình triển khai trong lab mạng được cấp phép và quy trình build bộ cài Windows Standalone (#148, #149, #154).

---

## 1. Kiến trúc triển khai Controlled Pilot

Môi trường pilot tiêu chuẩn gồm:
- **Telemetry Exporter (Router / Switch / VM Lab):** Xuất NetFlow v9 hoặc IPFIX qua UDP tới máy trạm Windows trong dải mạng riêng RFC 1918 (ví dụ `192.168.1.0/24`).
- **Windows Host chạy NetFlow Sentinel v2.0:**
  - Giao diện Desktop Tauri 2 + WebView2.
  - Backend Sidecar FastAPI lắng nghe **chỉ trên loopback `127.0.0.1`** với session token CSPRNG 256-bit (`NETWORK_ANOMALY_API_TOKEN`).
  - Kho khóa cục bộ tại `data/keys/` (hoặc `%LOCALAPPDATA%\NetFlowSentinel\keys\`): `master.key` bảo vệ bằng **Windows DPAPI** (`CryptProtectData`, fail-closed không ghi plaintext fallback), các DEK `k-*.key` được bọc bằng **AES-256-GCM** dưới Master KEK (`NETFLOW_WRAPPED_DEK_V2:` gắn AAD `key_id|domain|version`), và kiểm tra/di trú khóa cũ qua `python scripts/migrate_keystore.py --verify-only`.
  - CSDL SQLite cục bộ lưu vector hành vi ở dạng bản mã AES-256-GCM (`is_encrypted=1`, `vector_json=NULL`).

---

## 2. Yêu cầu hệ thống & Môi trường Dev/Build

### 2.1 Máy vận hành Pilot (Windows 10/11 x64)
- Windows 10/11 `x86_64` với WebView2 Runtime (hoặc offline installer nhúng trong NSIS).
- Tối thiểu 4 GB RAM, ~1 GB dung lượng trống cho sidecar + 4 mô hình AI + SQLite.
- Quyền mạng cục bộ cho phép nhận UDP NetFlow (ví dụ cổng `2055`) từ thiết bị lab được cấp phép.

### 2.2 Máy Build / Developer
- Python 3.11 hoặc 3.12 (`.venv`), đã cài gói dự án và `[dev,packaging]` (`pyinstaller`).
- Node.js 22+ (`npm`).
- Rust stable MSVC (`cargo`, `rustfmt`, `clippy`) + Tauri CLI (`@tauri-apps/cli`).

---

## 3. Quy trình kiểm chứng trước triển khai

Chạy tuần tự từ thư mục gốc repository (trên Windows dùng `.venv\Scripts\python.exe`):

```powershell
# 1. Kiểm tra môi trường & OpenAPI contract
.\.venv\Scripts\python.exe scripts/check_environment.py
.\.venv\Scripts\python.exe scripts/export_openapi_spec.py --check

# 2. Kiểm tra lint & test Python toàn hệ thống
ruff check .
.\.venv\Scripts\python.exe -m pytest tests/ -q

# 3. Kiểm tra live telemetry qua UDP loopback & benchmark động
.\.venv\Scripts\python.exe scripts/run_live_lab_acceptance.py
.\.venv\Scripts\python.exe scripts/benchmark_full_system.py

# 4. Kiểm tra Frontend Svelte & Rust Tauri backend
npm --prefix desktop run check
npm --prefix desktop test
cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check
cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path desktop/src-tauri/Cargo.toml --lib
```

---

## 4. Đóng gói Windows Standalone Installer (#148)

1. Kiểm tra điều kiện đóng gói trước khi build:
   ```powershell
   .\.venv\Scripts\python.exe scripts/build_installer_v2.py --check-only
   ```
2. Chuẩn bị các mô hình `.joblib` đã xác thực vào `desktop/src-tauri/staged_bundle/` thông qua `scripts/verify_companion_artifacts.py` (tuân thủ `reports/governance/DISTRIBUTION_AUTHORIZATION.json`).
3. Chạy build sidecar PyInstaller + Frontend + Tauri NSIS installer:
   ```powershell
   .\.venv\Scripts\python.exe scripts/build_installer_v2.py --version-label 2.0.0-pilot
   ```
   Sản phẩm đầu ra tại `dist/release-assets/`:
   - `NetFlow-Sentinel-v2.0.0-pilot-windows-x64-setup.exe`
   - `SHA256SUMS.txt`
   - `installer_v2_manifest.json`

---

## 5. Lưu ý tuân thủ & Release Gate

- **Không phân phối công khai mô hình dẫn xuất `NF-UNSW-NB15-v3`** nếu `DISTRIBUTION_AUTHORIZATION.json` chưa được phê duyệt (`approved = true`). Các bản đóng gói có nhúng model chỉ dành cho môi trường nội bộ/lab được cấp phép (`private-build-only`).
- **Không lưu khóa plaintext hoặc raw key lên Git:** `.gitignore` đã chặn `data/keys/`, `*.key`, `*.db`, và `artifacts/`.
- **Kiểm thử trên máy sạch:** Trước khi gắn nhãn stable release công khai, phải hoàn tất kiểm thử cài đặt thực tế trên máy Windows 10/11 sạch không có Python/Rust (theo dõi ở Issue #73).
