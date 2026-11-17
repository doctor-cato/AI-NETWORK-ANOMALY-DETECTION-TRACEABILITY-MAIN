# Hướng dẫn Cài đặt & Sử dụng trên Windows — NetFlow Sentinel v2

> **Lưu ý phiên bản Desktop Runtime:** Nhị phân shell Desktop giữ SemVer `1.0.0` (`v1.0.0` theo cấu hình `check_desktop_version.py`) trong quá trình migration nền tảng sang **NetFlow Sentinel v2** (`canonical-flow-v2-18`, `AIT-NDS-v2` + `CTU-SME-11`, CC BY 4.0) trên nhánh `feat/v2-integration`. Các tài liệu cài đặt cũ cho `NF-UNSW-NB15-v3` đã ngừng sử dụng và lưu trữ tại [`docs/historical/nf_unsw_nb15_v3/`](historical/nf_unsw_nb15_v3/).

---

## Phần A — Dành cho Người dùng cuối (Standalone Application)

### A1. Kiến trúc đóng gói Standalone
- **Ứng dụng Desktop Native:** Rust / Tauri 2 + Svelte 5 (`netflow-sentinel-desktop.exe`).
- **PyInstaller Backend Sidecar (`netflow-sentinel-backend.exe`):** Tích hợp Python runtime, FastAPI, Uvicorn, `scikit-learn`, `xgboost`, `joblib` và SQLite.
- **4 Mô hình AI v2 + Preprocessor `asinh_robust` + Dữ liệu Demo v2 (`200` dòng Validation):**
  - `Random Forest`, `XGBoost`, `Isolation Forest`, `Autoencoder` (huấn luyện lại hoàn toàn trên `AIT-NDS-v2`, hợp đồng `canonical-flow-v2-18`).
  - `v2_flow_preprocessor.joblib` và `data/demo/demo_flows.csv` + `demo_labels.csv` + `demo_manifest.json`.
- **Vận hành 100% offline** sau cài đặt; dữ liệu phiên lưu tại `%LOCALAPPDATA%\NetFlowSentinel\`.

### A2. Yêu cầu hệ thống
- **Hệ điều hành:** Windows 10 x64 hoặc Windows 11 x64 (`x86_64-pc-windows-msvc`).
- **Quyền cài đặt:** Standard User (`currentUser` tại `%LOCALAPPDATA%\NetFlow Sentinel\`).
- **WebView2 Runtime:** Nhúng offline installer trong gói NSIS.

### A3. Quy trình sử dụng 4 bước
1. **Bước 1 — Nhập CSV (`canonical-flow-v2-18`):** Mở `data/demo/demo_flows.csv` (200 flows Validation của `AIT-NDS-v2`) hoặc chọn tệp NetFlow CSV tuân thủ 18 đặc trưng chuẩn v2.
2. **Bước 2 — Phân tích với 4 AI (`AI Ready 4/4`):** Chạy `Random Forest`, `XGBoost`, `Isolation Forest` và `Autoencoder` sau khi hệ thống xác minh SHA-256 chain.
3. **Bước 3 — Đánh giá & Đối chiếu:** Kiểm tra `Benign` / `Attack` / `ABSTAINED_OOD`, đối chiếu Confusion Matrix từ `demo_labels.csv` và kiểm tra tab Behavioral / Trace / Crypto / Security Dry-Run (`executed=false`).
4. **Bước 4 — Xuất báo cáo:** Xuất CSV kết quả và JSON metadata kèm SHA-256.

---

## Phần B — Dành cho Lập trình viên (Source Build & Reproducibility)

1. **Yêu cầu môi trường dev:** Python `>=3.11` (khuyến nghị `3.12` khớp `requirements-runtime.txt`), Node.js `22+`, Rust stable (`cargo`, `rustfmt`, `clippy`).
2. **Thiết lập & chuẩn bị dữ liệu / mô hình v2 cục bộ:**
   ```powershell
   git clone https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN.git
   cd AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN
   python -m venv .venv
   .venv\Scripts\python.exe -m pip install -r requirements-runtime.txt
   .venv\Scripts\python.exe -m pip install -e ".[dev,packaging]"

   # Tải dữ liệu v2 (AIT-NDS-v2, AIT-LDS-v2.1, AIT-ADS, CTU-SME-11 — CC BY 4.0)
   .venv\Scripts\python.exe scripts/fetch_multi_source_dataset.py
   .venv\Scripts\python.exe scripts/build_v2_dataset_and_split.py
   .venv\Scripts\python.exe scripts/train_random_forest.py
   .venv\Scripts\python.exe scripts/train_xgboost.py
   .venv\Scripts\python.exe scripts/train_isolation_forest.py
   .venv\Scripts\python.exe scripts/train_autoencoder.py
   .venv\Scripts\python.exe scripts/prepare_demo_dataset.py
   .venv\Scripts\python.exe scripts/verify_companion_artifacts.py
   ```
3. **Build PyInstaller Sidecar & NSIS Installer:** Xem [`docs/DEPLOYMENT_GUIDE_V2.md`](DEPLOYMENT_GUIDE_V2.md) và [`desktop/README.md`](../desktop/README.md).
