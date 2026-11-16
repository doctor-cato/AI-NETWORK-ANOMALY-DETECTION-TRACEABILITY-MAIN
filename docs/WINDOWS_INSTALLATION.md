# Hướng dẫn Cài đặt & Sử dụng trên Windows — NetFlow Sentinel v1.0.0

Tài liệu này tách rõ hai đối tượng: **Phần A — Người dùng cuối** (sử dụng ứng dụng đóng gói standalone trên Windows 10/11 x64, không cần Python/Rust) và **Phần B — Lập trình viên** (tải mã nguồn từ `v1.0.0` Source Release để chạy dev hoặc tự đóng gói bộ cài).

> [!IMPORTANT]
> **Trạng thái phát hành `v1.0.0` hiện tại:**
> Tag `v1.0.0` trên GitHub Releases đang là **Source Release** (`NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE`, mã nguồn). Bộ cài Windows standalone (`NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe`) đã được triển khai và kiểm chứng trên máy build cục bộ (PR #72), nhưng **chưa phát hành công khai** do hai cổng nghiệm thu đang theo dõi tại **Issue #73**:
> 1. Kiểm thử trên máy ảo Windows 10/11 x64 sạch độc lập (`DEFERRED / NOT VERIFIED`).
> 2. Xác nhận căn cứ phân phối công khai các mô hình `.joblib` và `demo_*.csv` dẫn xuất từ `NF-UNSW-NB15-v3` (`UQ License ID 454104`, hiện `approved = false` trong [`DISTRIBUTION_AUTHORIZATION.json`](../reports/governance/DISTRIBUTION_AUTHORIZATION.json)).

---

## Phần A — Dành cho Người dùng cuối (Standalone Application)

### A1. Kiến trúc đóng gói khi dùng bộ cài Standalone

Khi sử dụng bộ cài `NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe` (từ bản build nội bộ được cấp phép hoặc sau khi phát hành chính thức), **mọi thành phần đều đã được tích hợp sẵn**:
- **Ứng dụng Desktop Native:** Rust / Tauri 2 + Svelte 5 (`netflow-sentinel-desktop.exe`).
- **PyInstaller Backend Sidecar (`netflow-sentinel-backend.exe`):** Tích hợp sẵn Python runtime, FastAPI, Uvicorn, `scikit-learn`, `xgboost`, `joblib` và SQLite.
- **4 Mô hình AI + Preprocessor + Dữ liệu Demo (`200` dòng):**
  - `Random Forest` (`MODEL_VALIDATED`)
  - `XGBoost`, `Isolation Forest`, `Autoencoder (MLPRegressor)` (`RESEARCH_ONLY`)
  - `nf_unsw_nb15_v3_preprocessor.joblib` và `data/demo/demo_flows.csv` + `demo_labels.csv`
- **WebView2 Offline Installer** và thông báo bản quyền (`NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE`).

**Không yêu cầu:** Không cần cài Python, `.venv`, Git, Rust, Node.js, biến môi trường hay tải thêm Companion Bundle. Phân tích chạy **100% offline**; dữ liệu phiên lưu tại `%LOCALAPPDATA%\NetFlowSentinel\`.

### A2. Yêu cầu hệ thống

| Thành phần | Yêu cầu | Ghi chú |
|---|---|---|
| **Hệ điều hành** | Windows 10 x64 hoặc Windows 11 x64 | Kiến trúc `x86_64-pc-windows-msvc` |
| **Quyền cài đặt** | Standard User (chế độ `currentUser`) | Mặc định cài vào `%LOCALAPPDATA%\NetFlow Sentinel\`, không cần Admin |
| **WebView2 Runtime** | Tự cài đặt offline nếu máy thiếu | Đã nhúng sẵn trong bộ cài NSIS |
| **Dung lượng ổ đĩa** | ~900 MB trống | Bao gồm sidecar, 4 mô hình, demo CSV và SQLite |
| **Kết nối Internet** | Không cần khi chạy phân tích | Vận hành offline sau khi cài đặt |

### A3. Cài đặt & Sử dụng trong 3 bước

1. **Kiểm tra SHA-256 (khuyến nghị khi có `SHA256SUMS.txt`):**
   ```powershell
   $InstallerFile = "NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe"
   $ActualHash = (Get-FileHash -Path $InstallerFile -Algorithm SHA256).Hash.ToLower()
   Write-Host "SHA-256 thực tế : $ActualHash"
   $ExpectedLine = (Get-Content .\SHA256SUMS.txt | Where-Object { $_ -match [regex]::Escape($InstallerFile) })
   if (-not $ExpectedLine -or -not $ExpectedLine.ToLower().StartsWith($ActualHash)) {
       throw "LỖI BẢO MẬT: SHA-256 của bộ cài không khớp với SHA256SUMS.txt!"
   }
   Write-Host "OK: SHA-256 khớp hoàn toàn." -ForegroundColor Green
   ```
2. **Chạy trình cài đặt NSIS:** Nhấn đúp `.exe`, hoàn tất cài đặt; biểu tượng **NetFlow Sentinel** xuất hiện trên Desktop và Start Menu.
3. **Mở ứng dụng & thực hiện quy trình 4 bước trên màn hình:**
   - **Bước 1 — Nhập dữ liệu CSV:** Bấm **"Mở ngay Dữ liệu Demo Chuẩn (200 flows)"** hoặc kéo-thả / chọn tệp NetFlow CSV riêng (cần đủ 47 cột theo schema `NF-UNSW-NB15-v3`).
   - **Bước 2 — Phân tích với 4 AI:** Chạy từng mô hình hoặc bấm so sánh cả 4 mô hình đang `READY`.
   - **Bước 3 — Đánh giá & Đối chiếu:** Xem nhãn `Benign`, `Attack`, `ABSTAINED_OOD` (từ chối dự đoán khi thiếu dữ liệu như `MIN_TTL = 0`), độ tin cậy và nạp `demo_labels.csv` để tính Confusion Matrix. Có thể xem Tab 4 **Security Dry-Run** (`executed=false`, chỉ mô phỏng khuyến nghị, không thay đổi firewall thật).
   - **Bước 4 — Xuất báo cáo:** Lưu CSV kết quả kèm metadata SHA-256 minh bạch.

### A4. Gỡ cài đặt & Xử lý sự cố (Người dùng cuối)

- **Gỡ cài đặt:** Mở **Windows Settings → Apps → Installed apps → NetFlow Sentinel → Uninstall** (hoặc chạy `uninstall.exe` trong `%LOCALAPPDATA%\NetFlow Sentinel\`).
- **Sidecar chưa sẵn sàng:** Bấm **Khởi động lại Backend** trong bảng trạng thái hệ thống; nhấn `Shift+F9` để xem log chẩn đoán nếu cần.
- **Cảnh báo `ABSTAINED_OOD` hoặc lỗi thiếu cột:** Hệ thống áp dụng cơ chế an toàn **fail-closed** — các dòng có `MIN_TTL == 0` hoặc lỗi vật lý được giữ ở `ABSTAINED_OOD` và CSV thiếu cột 47 đặc trưng sẽ hiển thị tên cột thiếu bằng tiếng Việt.

---

## Phần B — Dành cho Lập trình viên (Tự chạy & Đóng gói từ `v1.0.0` Source Release)

Nếu bạn tải mã nguồn từ tag `v1.0.0` trên GitHub:

1. **Yêu cầu môi trường dev:** Python `>=3.11` (CI 3.11/3.12; Windows runtime khuyến nghị 3.12+ khớp `requirements-runtime.txt`), Node.js `22+`, Rust stable (`cargo`, `rustfmt`, `clippy`).
2. **Chuẩn bị Python & Artifacts cục bộ:**
   ```powershell
   git clone https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN.git
   cd AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   python -m pip install -r requirements-runtime.txt
   python -m pip install -e ".[dev,packaging]"
   ```
   *(Lưu ý: repo không chứa raw dataset hay `.joblib` model binaries. Developer cần tải `NF-UNSW-NB15-v3`, chạy split/preprocess/train hoặc đặt bộ `.joblib` đã kiểm chứng vào `artifacts/` và chạy `python scripts/prepare_demo_dataset.py`.)*
3. **Chạy chế độ Developer (`scripts/run_api.py` + `npm --prefix desktop run tauri dev`):** xem chi tiết tại [`desktop/README.md`](../desktop/README.md) và [`docs/REPRODUCIBILITY.md`](REPRODUCIBILITY.md).
4. **Build PyInstaller Sidecar & NSIS Standalone Installer (chỉ phục vụ build/kiểm thử nội bộ khi quyền phân phối chưa mở):**
   ```powershell
   python scripts/verify_companion_artifacts.py --stage-embedded-dir desktop/src-tauri/staged_bundle --distribution-scope private-build-only --target-channel local_offline
   python scripts/build_backend_sidecar.py --output-json dist/release-assets/sidecar_build.json
   Push-Location desktop
   npx tauri build --config src-tauri/tauri.standalone.conf.json --bundles nsis
   Pop-Location
   ```

---

## Lưu ý Bản quyền

Bộ dữ liệu **NF-UNSW-NB15-v3** tuân theo **UQ License ID `454104`** (*Permitted Re-Use with Commercial Use Restriction*, DOI `10.48610/6E0EDA1`). Mã nguồn dự án dùng **Apache-2.0**. Chi tiết xem [`NOTICE`](../NOTICE) và [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
