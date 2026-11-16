# NetFlow Sentinel Desktop App (`v1.0.0` Stable — Rust / Tauri 2 + Svelte 5)

Ứng dụng Desktop Windows x64 cho bài toán phát hiện xâm nhập/bất thường mạng (`NF-UNSW-NB15-v3`) với **4 mô hình thật đóng gói sẵn**:
- **Random Forest** (`MODEL_VALIDATED`)
- **XGBoost** (`RESEARCH_ONLY`)
- **Isolation Forest** (`RESEARCH_ONLY`)
- **Autoencoder** (`RESEARCH_ONLY`)

---

## 1. Dành cho người dùng cuối (Standalone Installer)

Tải duy nhất tệp `NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe` từ GitHub Release `v1.0.0`:
- **Không cần cài Python, Rust, Node.js, Git hay tải Companion Bundle.**
- Nhúng sẵn ứng dụng Tauri 2 + Svelte 5, PyInstaller sidecar backend (`netflow-sentinel-backend.exe`), **cả 4 mô hình ML thật**, preprocessor, manifests, demo CSV, **WebView2 Offline Installer** và `NOTICE` / `THIRD_PARTY_NOTICES.md`.
- Tự động khởi chạy/health-check/restart/shutdown sidecar trên `127.0.0.1` với token phiên `X-Sentinel-Session-Token` và lưu DB cục bộ tại `%LOCALAPPDATA%\NetFlowSentinel\`.
- Giao diện Svelte 5 cung cấp hướng dẫn 3 bước (Nạp CSV → Phân tích & So sánh 4 mô hình → Xuất kết quả), giải thích Benign / Attack / OOD (`ABSTAINED_OOD`) / Confidence, phân biệt `MODEL_VALIDATED` với `RESEARCH_ONLY`, và thông báo lỗi tiếng Việt dễ hiểu.

Chi tiết xem [docs/WINDOWS_INSTALLATION.md](../docs/WINDOWS_INSTALLATION.md).

---

## 2. Dành cho lập trình viên (Build & Phát triển từ mã nguồn)

### Yêu cầu môi trường build

- Windows 10/11 x64 (`x86_64-pc-windows-msvc`), Rust stable + `clippy` + `rustfmt`
- Node.js 22+ & npm
- Python `>=3.11` (`pyproject.toml` dùng floor `>=3.11`; môi trường đóng gói sidecar cần `pip install -e ".[dev,packaging]"` hoặc `pyinstaller>=6.10.0`, `xgboost`, `scikit-learn`, `fastapi`, `uvicorn`)
- Mô hình thật trong `artifacts/` và dữ liệu mẫu trong `data/demo/` (không lưu nhị phân lớn trong Git)

### Kiểm tra Frontend & Rust

```powershell
npm --prefix desktop ci
npm --prefix desktop run check
npm --prefix desktop test
npm --prefix desktop run build

cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check
cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path desktop/src-tauri/Cargo.toml --lib
```

### Đóng gói PyInstaller Sidecar & Standalone NSIS Installer

```powershell
# 1. Stage 4 mô hình thật, preprocessor, demo CSV và thông báo bản quyền (chỉ build cục bộ / private runner)
python scripts/verify_companion_artifacts.py --stage-embedded-dir desktop/src-tauri/staged_bundle --distribution-scope private-build-only --target-channel local_offline

# 2. Build PyInstaller sidecar tại desktop/src-tauri/binaries/netflow-sentinel-backend-x86_64-pc-windows-msvc.exe
python scripts/build_backend_sidecar.py --output-json dist/release-assets/sidecar_build.json

# 3. Build NSIS standalone installer (sử dụng tauri.standalone.conf.json)
Push-Location desktop
npx tauri build --config src-tauri/tauri.standalone.conf.json --bundles nsis
Pop-Location
```

Xem quy trình phát hành & kiểm chứng E2E đầy đủ tại [docs/RELEASE_PROCESS.md](../docs/RELEASE_PROCESS.md).
