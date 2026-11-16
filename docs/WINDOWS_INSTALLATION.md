# Hướng dẫn Cài đặt & Vận hành trên Windows (NetFlow Sentinel M6 `v0.6.0`)

Tài liệu này hướng dẫn cài đặt, chuẩn bị Python runtime + companion artifacts (4 mô hình + preprocessor + dữ liệu demo) và vận hành **NetFlow Sentinel M6 (`v0.6.0`)** trên một **máy Windows 10/11 x64 mới**, không cần môi trường phát triển (không cần Rust, Node.js hay Git).

> [!IMPORTANT]
> **Kiến trúc đóng gói của bản phát hành `v0.6.0`:**
> Gói cài đặt Windows NSIS (`NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe`) đóng gói:
> 1. **Rust Tauri 2 native shell (`netflow-sentinel-desktop.exe`)** và **giao diện Svelte 5** nhúng sẵn.
> 2. **Tài nguyên Python backend (`src/network_anomaly/`, `scripts/run_api.py`, `scripts/verify_companion_artifacts.py`, `scripts/windows_setup_runtime.ps1`, `requirements-runtime.txt`)** và các **manifest SHA-256 tin cậy (`reports/`, `data/NF_UNSW_NB15_V3_SPLIT_MANIFEST.json`)**.
>
> Vì vậy người dùng **không cần `git clone` repository** và **không cần khai báo `NETWORK_ANOMALY_REPO_ROOT`**. Dữ liệu người dùng (`.venv`, 4 model `.joblib`, `data/demo/`, `network_anomaly.db`) được lưu riêng tại thư mục có quyền ghi của tài khoản hiện tại (`%LOCALAPPDATA%\NetFlowSentinelM6`), tương thích Windows Standard User (không cần quyền Administrator).
>
> **Lưu ý về Companion Bundle (4 model & demo CSV):** Do tập dữ liệu `NF-UNSW-NB15-v3` áp dụng điều khoản *"Permitted Re-Use with Commercial Use Restriction"* (UQ 454104, phi thương mại) và GitHub Release công khai không phân phối raw CSV hoặc `.joblib` chưa cấp phép tái phân phối công khai, người dùng cần nạp **Companion Bundle ZIP** được cấp từ nguồn nội bộ/học thuật của đề tài (đối chiếu SHA-256 với `COMPANION_BUNDLE_SHA256.txt`), hoặc tự tạo từ nguồn chính thức UQ RDM.

---

## 1. Yêu cầu Hệ thống (System Requirements)

| Thành phần | Yêu cầu cụ thể | Ghi chú |
|---|---|---|
| **Hệ điều hành** | Windows 10 (64-bit, build 1903+) hoặc Windows 11 (x64) | Kiến trúc `x86_64-pc-windows-msvc`; chạy bình thường với tài khoản **Standard User** |
| **WebView2 Runtime** | Microsoft Edge WebView2 Evergreen Runtime (`{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`) | Có sẵn mặc định trên Windows 11 và Windows 10 đã cập nhật. Xem mục 3 nếu máy hoàn toàn Offline |
| **Python Runtime** | **Python `>= 3.12` (x64)** (khuyến nghị **Python 3.12**; mã nguồn `pyproject.toml` giữ floor `>= 3.11` cho CI) | Cần Python `>= 3.12` để cài đúng `numpy 2.5.x`, `pandas 3.0–3.1`, `scikit-learn 1.9.x`, `xgboost 3.4.x`, `joblib 1.6.x` trong `requirements-runtime.txt` khớp `.joblib` đã huấn luyện |
| **Dung lượng lưu trữ** | - Ứng dụng Desktop + Python `.venv`: ~600 MB<br>- Companion Bundle (4 model + preprocessor + demo): ~50 MB<br>- Bộ dữ liệu gốc `NF-UNSW-NB15-v3.csv` (chỉ cần nếu tự tạo lại từ đầu): ~1.1 GB | Nếu dùng gói Companion Bundle ZIP (~50 MB), không cần tải bộ CSV 577 MB |
| **Verified Artifacts** | 1. `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib`<br>2. `artifacts/models/random_forest/random_forest_baseline.joblib`<br>3. `artifacts/models/xgboost/xgboost_baseline.joblib`<br>4. `artifacts/models/isolation_forest/isolation_forest.joblib`<br>5. `artifacts/models/autoencoder/autoencoder_model.joblib` (+ `model_config.json`, `threshold.json`)<br>6. `data/demo/demo_flows.csv`, `demo_labels.csv`, `demo_manifest.json` | Kiểm chứng tự động bằng SHA-256 fail-closed; thiếu hoặc sai SHA-256 bị khóa ở `BLOCKED / NOT READY` (`HTTP 503`) |

---

## 2. Hướng dẫn Cài đặt trên Máy Windows Mới (Step-by-Step)

### Bước 1: Tải các tệp phát hành từ GitHub Release `v0.6.0`

Tải các tệp sau vào thư mục `Downloads\NetFlowSentinel`:
- `NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe`
- `SHA256SUMS.txt`
- `COMPANION_BUNDLE_SHA256.txt` (nếu sử dụng Companion Bundle ZIP từ kênh nội bộ/giảng dạy của nhóm)
- Tùy chọn cho thiết lập CLI: `windows_setup_runtime.ps1`, `requirements-runtime.txt`

### Bước 2: Kiểm chứng mã băm SHA-256 của bộ cài (Verify Installer SHA-256)

Mở **Windows PowerShell** tại thư mục chứa tệp tải về:

```powershell
$InstallerFile = "NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe"
$ActualHash = (Get-FileHash -Path $InstallerFile -Algorithm SHA256).Hash.ToLower()
Write-Host "SHA-256 thực tế : $ActualHash"
$ExpectedLine = (Get-Content .\SHA256SUMS.txt | Where-Object { $_ -match [regex]::Escape($InstallerFile) })
if (-not $ExpectedLine -or -not $ExpectedLine.ToLower().StartsWith($ActualHash)) {
    throw "LỖI BẢO MẬT: SHA-256 của bộ cài không khớp với SHA256SUMS.txt!"
}
Write-Host "OK: SHA-256 khớp hoàn toàn." -ForegroundColor Green
```

### Bước 3: Cài đặt Python 3.12 (nếu máy chưa có Python `>= 3.12`)

Kiểm tra nhanh trong PowerShell:

```powershell
py -3.12 --version
# Hoặc: python --version
```

Nếu máy chưa có Python `>= 3.12` (x64):

```powershell
winget install Python.Python.3.12
```

*(Hoặc tải trình cài đặt Windows x64 chính thức tại `https://www.python.org/downloads/windows/`, tích chọn **Add python.exe to PATH**).*

### Bước 4: Chạy trình cài đặt NSIS

Chạy `NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe`:
- Trình cài đặt (`installMode: currentUser`) cài ứng dụng vào `%LOCALAPPDATA%\NetFlow Sentinel M6\`, không cần quyền Administrator.
- Tự động tạo lối tắt trên **Desktop** và **Start Menu** (`NetFlow Sentinel M6`).

### Bước 5: Mở ứng dụng & Thiết lập Runtime / Companion Bundle trong giao diện Desktop

Nhấn đúp biểu tượng **NetFlow Sentinel M6** trên Desktop hoặc Start Menu:

1. **Thiết lập Python Runtime (`.venv`):**
   - Nếu máy chưa có `.venv`, khung **Chuẩn bị Môi trường Chạy Cục bộ** sẽ xuất hiện ngay khi mở ứng dụng.
   - Nhấn nút **Thiết lập Python Runtime (.venv)**. Ứng dụng tự tạo `%LOCALAPPDATA%\NetFlowSentinelM6\.venv`, cài đặt đúng phiên bản tương thích trong `requirements-runtime.txt` và khởi chạy FastAPI trên `127.0.0.1` (có mã phiên bảo mật `X-Sentinel-Session-Token`).
   - *(Nếu máy offline hoàn toàn: mở **Tùy chọn Offline / SHA-256**, nhập đường dẫn thư mục wheelhouse đã tải trước rồi bấm **Thiết lập Python Runtime (.venv)**).*

2. **Nạp Companion Bundle (4 Mô hình + Preprocessor + Demo CSV):**
   - Nhấn nút **Nạp Companion Bundle (.zip)** (hoặc **Nạp từ Thư mục**) và chọn tệp `netflow-sentinel-v0.6.0-companion-bundle.zip` được nhóm phát hành cung cấp qua nguồn riêng tư/nội bộ.
   - *(Khuyến nghị: mở **Tùy chọn Offline / SHA-256** và dán chuỗi 64 ký tự SHA-256 từ `COMPANION_BUNDLE_SHA256.txt` để kiểm tra tính toàn vẹn trước khi giải nén).*
   - Ứng dụng tự kiểm tra chống ZipSlip/symlink, đối chiếu `COMPANION_SHA256SUMS.txt` + `COMPANION_BUNDLE_MANIFEST.json` với tracked manifests, cài đặt vào `%LOCALAPPDATA%\NetFlowSentinelM6\`, và bật đủ **4 mô hình `READY`**:
     - `Random Forest` (`MODEL_VALIDATED`)
     - `XGBoost` (`RESEARCH_ONLY`)
     - `Isolation Forest` (`RESEARCH_ONLY`)
     - `Autoencoder` (`RESEARCH_ONLY`)

*(Tùy chọn CLI thay thế Bước 5: chạy script đóng gói sẵn trong thư mục cài đặt)*

```powershell
powershell -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\NetFlow Sentinel M6\scripts\windows_setup_runtime.ps1" `
  -CompanionBundleZip "C:\path\to\netflow-sentinel-v0.6.0-companion-bundle.zip" `
  -CompanionBundleSha256 "<64-hex-sha256>"
```

### Bước 6: Kiểm chứng sau khởi động & Vận hành Demo

1. Thanh tiêu đề hiển thị **Preprocessor READY** và **FastAPI :`<port>`**.
2. Bảng **Trạng thái 4 Mô hình AI** hiển thị cả 4 thẻ **Random Forest**, **XGBoost**, **Isolation Forest**, **Autoencoder** đều ở trạng thái **READY** (đóng ứng dụng và mở lại từ Start Menu/Desktop hoặc khởi động lại Windows vẫn tự khôi phục đúng `.venv` và 4 model).
3. Nhấn **Mở Demo Validation (200 flows)** → **Chạy So sánh 4 Model READY** → chuyển tab **3. Ground Truth & Confusion Matrix** bấm **Dùng demo_labels.csv** / **Đối chiếu Ground Truth** → xem **Tab 4 (Timeline & Dry-Run #27)** (`executed=false`) → **Xuất CSV + Metadata**.

---

## 3. Tự chuẩn bị Companion trên Máy Đích (nếu không có gói Companion ZIP riêng tư)

Nếu bạn là người đánh giá độc lập không sử dụng gói Companion Bundle ZIP từ kênh riêng tư, bạn có thể tự tải bộ dữ liệu gốc phi thương mại từ **The University of Queensland (DOI: `10.48610/6E0EDA1`)** và tái lập từ mã nguồn repository:

```powershell
git clone https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN.git C:\NetFlow-Sentinel-Repo
Set-Location C:\NetFlow-Sentinel-Repo
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe scripts/fetch_nf_unsw_nb15_v3.py
.\.venv\Scripts\python.exe scripts/split_and_audit_nf_unsw_nb15_v3.py
.\.venv\Scripts\python.exe scripts/preprocess_nf_unsw_nb15_v3.py
.\.venv\Scripts\python.exe scripts/train_random_forest.py
.\.venv\Scripts\python.exe scripts/train_xgboost.py
.\.venv\Scripts\python.exe scripts/train_isolation_forest.py
.\.venv\Scripts\python.exe scripts/train_autoencoder.py --enforce-target-fpr
.\.venv\Scripts\python.exe scripts/prepare_demo_dataset.py
```

---

## 4. Vận hành Ngoại tuyến (Offline / Air-Gapped Boundaries)

| Giai đoạn | Thành phần | Yêu cầu mạng | Hướng dẫn chuẩn bị cho môi trường Offline |
|---|---|---|---|
| **1. WebView2 Runtime** | Microsoft Edge WebView2 Evergreen | **Không cần Internet nếu đã cài sẵn** (Windows 11 / Win10 cập nhật) | Nếu máy Win10 cũ chưa có WebView2 và offline: cài trước `MicrosoftEdgeWebView2RuntimeInstallerX64.exe` bản Standalone Offline trước khi chạy NSIS installer. |
| **2. Python Wheelhouse** | `requirements-runtime.txt` | **Cần chuẩn bị wheelhouse trước** | Trên máy có Internet (Python 3.12 x64): `py -3.12 -m pip download -r requirements-runtime.txt -d D:\wheelhouse`. Chép `D:\wheelhouse` sang máy offline và chọn trong **Tùy chọn Offline** hoặc `-WheelhouseDir`. |
| **3. Companion Bundle** | 4 model `.joblib` + preprocessor + `data/demo/` | **100% Offline** qua USB/lưu trữ nội bộ | Nạp `netflow-sentinel-v0.6.0-companion-bundle.zip` trong giao diện Desktop kèm SHA-256 kiểm chứng. |
| **4. Runtime hàng ngày** | Tauri + FastAPI (`127.0.0.1`) + SQLite | **100% Offline (Localhost-only)** | Không gọi bất kỳ API đám mây hay kết nối Internet nào. |

---

## 5. Xử lý Sự cố & Ranh giới Bảo mật (`#26`, `#27`)

- **Cảnh báo chữ ký số Windows (SmartScreen / Unsigned Executable):** Bản nghiên cứu học thuật chưa gắn chứng thư Authenticode thương mại. **Tuyệt đối không tắt Windows Defender hay SmartScreen**; luôn kiểm chứng SHA-256 theo Bước 2 trước khi chạy.
- **Xác thực phiên Loopback (`127.0.0.1`):** Tiến trình Rust tự sinh token phiên ngẫu nhiên 256-bit (`NETWORK_ANOMALY_API_TOKEN`) cho mỗi lần khởi chạy và truyền qua header `X-Sentinel-Session-Token` tới FastAPI; các tiến trình khác trên cùng máy không có token phiên sẽ bị từ chối `HTTP 401` trên mọi endpoint `/api/v1/*`.
- **Thư mục hệ thống & UNC path:** Backend chặn truy cập đường dẫn mạng UNC (`\\server\share`), các thư mục hệ thống (`C:\Windows\System32`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`) và từ chối ghi đè CSV đầu vào khi export. Có thể khóa chặt phạm vi thư mục CSV qua biến môi trường `NETWORK_ANOMALY_ALLOWED_CSV_ROOTS`.
- **Dry-Run (#27):** Mọi khuyến nghị (`NO_ACTION`, `MONITOR`, `INVESTIGATE`, `ISOLATE_RECOMMENDED`) và quyết định xoay khóa chạy ở chế độ mô phỏng (`executed=false`), không chạm firewall OS và không xoay khóa thật.
- **Hiệu năng & Tổng quát hóa:** Random Forest & XGBoost đạt `~0.9999` F1 trong phân phối `NF-UNSW-NB15-v3` nhưng phụ thuộc nhiều vào shortcut testbed (`MIN_TTL`) và suy giảm mạnh ngoài phân phối (`NF-CSE-CIC-IDS2018-v3`); Autoencoder đạt Held-out Test `F1=0.1361`, `Recall=0.1093` dưới ràng buộc `Val FPR <= 0.05`.
