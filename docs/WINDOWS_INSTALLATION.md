# Hướng dẫn Cài đặt & Vận hành trên Windows (NetFlow Sentinel M6 `v0.6.0`)

Tài liệu này hướng dẫn cài đặt, chuẩn bị môi trường phụ thuộc (Python backend, model artifacts, dữ liệu demo) và vận hành **NetFlow Sentinel M6 (`v0.6.0`)** trên hệ điều hành Windows x64.

> [!IMPORTANT]
> **Giới hạn đóng gói của bản phát hành M6 (`v0.6.0`):**
> Gói cài đặt Windows (`NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe` / `NetFlow Sentinel M6_0.6.0_x64-setup.exe`) đóng gói **Rust Tauri 2 native shell (`netflow-sentinel-desktop.exe`)** và **giao diện Svelte 5 đã biên dịch nhúng bên trong binary**.
> Tuy nhiên, bản M6 `v0.6.0` **chưa phải là gói cài đặt độc lập hoàn toàn (not a self-contained standalone installer)**. Khi khởi chạy, tiến trình Rust tự động gọi Python cục bộ để chạy backend FastAPI (`scripts/run_api.py`) tại `127.0.0.1` và nạp các tệp mô hình `.joblib` từ thư mục gốc của repository. Do đó, máy đích bắt buộc phải chuẩn bị sẵn môi trường Python, mã nguồn repository, model artifacts đã kiểm chứng SHA-256 và Microsoft Edge WebView2 Runtime.

---

## 1. Yêu cầu Hệ thống (System Requirements)

| Thành phần | Yêu cầu cụ thể | Ghi chú |
|---|---|---|
| **Hệ điều hành** | Windows 10 (64-bit, build 1903+) hoặc Windows 11 (x64) | Kiến trúc `x86_64-pc-windows-msvc` |
| **WebView2 Runtime** | Microsoft Edge WebView2 Evergreen Runtime (`{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`) | Có sẵn mặc định trên Windows 11 và Windows 10 đã cập nhật. Xem mục 3 nếu cài đặt trên máy không có Internet |
| **Python Runtime** | Python `>= 3.10` (ưu tiên **Python 3.11** hoặc **Python 3.12** đã kiểm chứng CI; tương thích tới Python 3.14) | Cần có `python` trên `PATH` hoặc đặt biến môi trường `NETWORK_ANOMALY_PYTHON` |
| **Python Dependencies** | `numpy`, `pandas`, `scikit-learn`, `joblib`, `pyarrow`, `fastapi`, `uvicorn`, `pydantic`, `httpx` | Cài đặt qua `pip install -e .` từ `pyproject.toml` của repository |
| **Dung lượng lưu trữ** | - Ứng dụng Desktop + Python venv: ~600 MB<br>- Model & Preprocessor artifacts (`.joblib`): ~50 MB<br>- Bộ dữ liệu gốc `NF-UNSW-NB15-v3.csv` (tùy chọn khi tự sinh demo): ~1.1 GB | Nếu chỉ chạy bộ dữ liệu mẫu `data/demo/` (~200 dòng), chỉ cần < 1 MB cho dữ liệu demo |
| **Verified Artifacts** | 1. `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib`<br>2. `artifacts/models/random_forest/random_forest_baseline.joblib`<br>3. `artifacts/models/isolation_forest/isolation_forest.joblib` | Bắt buộc khớp mã băm SHA-256 trong `reports/preprocessing/*.json` và `reports/models/*.json` (cơ chế fail-closed) |
| **Biến môi trường Repo Root** | `NETWORK_ANOMALY_REPO_ROOT` | Bắt buộc thiết lập nếu chạy ứng dụng từ thư mục cài đặt NSIS (`%LOCALAPPDATA%\NetFlow Sentinel M6`) nằm ngoài cây thư mục Git repository |

---

## 2. Hướng dẫn Cài đặt Từng bước (Step-by-Step Installation)

Thực hiện các bước dưới đây trong **Windows PowerShell**:

### Bước 1: Tải gói cài đặt Windows từ GitHub Release

Tải 2 tệp phát hành từ trang GitHub Releases của dự án (phiên bản `v0.6.0-beta.1` hoặc `v0.6.0`):
- `NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe` (hoặc tên tương ứng với tag pre-release)
- `SHA256SUMS.txt`

```powershell
# Tạo thư mục tạm để tải gói cài đặt
New-Item -ItemType Directory -Force -Path "$HOME\Downloads\NetFlowSentinel" | Out-Null
Set-Location "$HOME\Downloads\NetFlowSentinel"
```

### Bước 2: Kiểm chứng mã băm SHA-256 (Verify SHA-256 Checksum)

Trước khi chạy trình cài đặt, luôn đối chiếu mã băm SHA-256 thực tế của file `.exe` với tệp `SHA256SUMS.txt`:

```powershell
$InstallerFile = "NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe"
# Cách 1 (dùng certutil có sẵn trên mọi bản Windows):
certutil -hashfile $InstallerFile SHA256
Get-Content .\SHA256SUMS.txt

# Cách 2 (dùng PowerShell Get-FileHash hoặc Python):
$ActualHash = (python -c "import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest())" $InstallerFile).Trim().ToLower()
Write-Host "SHA-256 thực tế : $ActualHash"
$ExpectedLine = (Get-Content .\SHA256SUMS.txt | Where-Object { $_ -match [regex]::Escape($InstallerFile) })
if (-not $ExpectedLine -or -not $ExpectedLine.ToLower().StartsWith($ActualHash)) {
    throw "LỖI BẢO MẬT: SHA-256 của bộ cài không khớp với SHA256SUMS.txt!"
}
Write-Host "OK: SHA-256 khớp hoàn toàn." -ForegroundColor Green
```

### Bước 3: Chạy trình cài đặt NSIS

```powershell
# Chạy trình cài đặt NSIS tương tác
Start-Process -FilePath ".\$InstallerFile" -Wait
```

- Mặc định, trình cài đặt NSIS (`currentUser`) giải nén ứng dụng vào `%LOCALAPPDATA%\NetFlow Sentinel M6\netflow-sentinel-desktop.exe` và tạo lối tắt trên Desktop / Start Menu.
- **Lưu ý về bản thực thi:** Không coi file `netflow-sentinel-desktop.exe` là bản portable độc lập hoàn chỉnh, vì ứng dụng vẫn cần kết nối tới Python backend và thư mục repository ở các bước tiếp theo.

### Bước 4: Chuẩn bị mã nguồn Python Backend

Clone hoặc giải nén repository tại phiên bản tương ứng (`v0.6.0`):

```powershell
$RepoRoot = "C:\NetFlow-Sentinel-Repo"
git clone https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN.git $RepoRoot
Set-Location $RepoRoot
git checkout v0.6.0
```

### Bước 5: Tạo môi trường ảo và cài đặt Python Dependencies

```powershell
Set-Location $RepoRoot
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .

# Kiểm tra môi trường Python theo chuẩn của dự án
.\.venv\Scripts\python.exe scripts/check_environment.py
```

### Bước 6: Chuẩn bị và xác minh Model & Preprocessor Artifacts

Đặt các tệp `.joblib` đã được huấn luyện và nghiệm thu vào đúng cấu trúc thư mục trong `$RepoRoot\artifacts\`:

- `artifacts\preprocessing\nf_unsw_nb15_v3_preprocessor.joblib`
- `artifacts\models\random_forest\random_forest_baseline.joblib`
- `artifacts\models\isolation_forest\isolation_forest.joblib`

Kiểm tra nhanh mã băm SHA-256 của 3 tệp artifact khớp với manifest trong `reports/`:

```powershell
Set-Location $RepoRoot
$ArtifactsToVerify = @(
    @{
        File = "artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib"
        Manifest = "reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json"
        Key = "artifact_sha256"
    },
    @{
        File = "artifacts/models/random_forest/random_forest_baseline.joblib"
        Manifest = "reports/models/random_forest_manifest.json"
        Key = "model_artifact_sha256"
    },
    @{
        File = "artifacts/models/isolation_forest/isolation_forest.joblib"
        Manifest = "reports/models/isolation_forest_manifest.json"
        Key = "model_artifact_sha256"
    }
)

foreach ($item in $ArtifactsToVerify) {
    if (-not (Test-Path $item.File)) {
        Write-Warning "Thiếu tệp artifact: $($item.File)"
        continue
    }
    $actual = (Get-FileHash -Path $item.File -Algorithm SHA256).Hash.ToLower()
    $manifestObj = Get-Content $item.Manifest -Raw | ConvertFrom-Json
    $expected = $manifestObj.($item.Key).ToLower()
    if ($actual -ne $expected) {
        throw "SHA-256 không khớp cho $($item.File): thực tế=$actual, manifest=$expected"
    }
    Write-Host "OK: $($item.File) ($actual)" -ForegroundColor Green
}
```

> [!NOTE]
> Trong phạm vi M6 hiện tại, hai mô hình **Random Forest** (`random_forest`) và **Isolation Forest** (`isolation_forest`) ở trạng thái `READY`. Hai mô hình **XGBoost** (`xgboost`) và **Autoencoder** (`autoencoder`) chưa có artifact nghiệm thu nên được khóa an toàn ở trạng thái `BLOCKED / NOT READY` (HTTP 503 fail-closed nếu gọi phân tích).

### Bước 7: Chuẩn bị dữ liệu Demo (`demo_flows.csv`, `demo_labels.csv`, `demo_manifest.json`)

Nếu máy đã có bộ dữ liệu gốc `data/raw/NF-UNSW-NB15-v3.csv` (khớp SHA-256 `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`), chạy lệnh sau để trích xuất 200 luồng mạng từ tập Validation (cân bằng 100 Benign / 100 Attack, không rò rỉ nhãn vào tệp flows):

```powershell
Set-Location $RepoRoot
.\.venv\Scripts\python.exe scripts/prepare_demo_dataset.py
Get-ChildItem data\demo\
```

Lệnh trên tạo ra 3 tệp trong `data/demo/`:
1. `data/demo/demo_flows.csv` — 200 dòng NetFlow (47 cột đặc trưng ML + metadata truy vết + `row_id`, hoàn toàn không chứa cột `Label` hay `Attack`).
2. `data/demo/demo_labels.csv` — Nhãn thực tế (`row_id`, `Label`, `Attack`) tách rời để kiểm chứng Confusion Matrix.
3. `data/demo/demo_manifest.json` — Biên bản provenance xác nhận SHA-256 và không chồng lấn tập Train/Test (`train_overlap_count = 0`, `test_overlap_count = 0`), giúp cổng tương thích (`InferenceEligibilityGate`) xác thực nguồn `source:nf-v3-canonical` (`MODEL_VALIDATED`).

### Bước 8: Cấu hình biến môi trường và Khởi động Ứng dụng Desktop

Khi chạy ứng dụng đã cài đặt qua NSIS, thiết lập `NETWORK_ANOMALY_REPO_ROOT` và `NETWORK_ANOMALY_PYTHON` để tiến trình Rust định vị chính xác repository và Python venv:

```powershell
$env:NETWORK_ANOMALY_REPO_ROOT = "C:\NetFlow-Sentinel-Repo"
$env:NETWORK_ANOMALY_PYTHON = "C:\NetFlow-Sentinel-Repo\.venv\Scripts\python.exe"

# Để lưu cố định cho tài khoản người dùng Windows hiện tại (tùy chọn):
[Environment]::SetEnvironmentVariable("NETWORK_ANOMALY_REPO_ROOT", $env:NETWORK_ANOMALY_REPO_ROOT, "User")
[Environment]::SetEnvironmentVariable("NETWORK_ANOMALY_PYTHON", $env:NETWORK_ANOMALY_PYTHON, "User")

# Khởi chạy ứng dụng NetFlow Sentinel M6
Start-Process "$env:LOCALAPPDATA\NetFlow Sentinel M6\netflow-sentinel-desktop.exe"
```

### Bước 9: Kiểm tra trạng thái sẵn sàng của FastAPI (Readiness Check)

Trên thanh tiêu đề của cửa sổ ứng dụng:
1. Huy hiệu **Preprocessor READY** màu xanh lá xác nhận `nf_unsw_nb15_v3_preprocessor.joblib` và cơ sở dữ liệu SQLite cục bộ đã sẵn sàng.
2. Huy hiệu **FastAPI :`<port>`** hiển thị cổng loopback (`127.0.0.1:<port>`) mà tiến trình Rust đã cấp phát động.
3. Trong bảng **Trạng thái Sẵn sàng Mô hình**, hai thẻ **Random Forest** và **Isolation Forest** hiển thị `READY` kèm SHA-256 rút gọn; **XGBoost** và **Autoencoder** hiển thị `BLOCKED / NOT READY`.

Bạn cũng có thể kiểm tra trực tiếp từ PowerShell nếu biết cổng `<port>` trên thanh tiêu đề:

```powershell
# Thay <PORT> bằng số cổng hiển thị trên huy hiệu "FastAPI :<PORT>" của giao diện
Invoke-RestMethod -Uri "http://127.0.0.1:<PORT>/health" | ConvertTo-Json -Depth 4
```

### Bước 10: Chạy quy trình Phân tích Demo, Đối chiếu Ground Truth & Xuất kết quả

1. Nhấn nút **Mở Demo Validation (200 flows)** trên thanh điều khiển để nạp `data/demo/demo_flows.csv` và kiểm tra hợp đồng 47 cột đặc trưng ML, thống kê hành vi NetFlow (#28) và cảnh báo OOD (`MIN_TTL == 0`).
2. Chọn mô hình **Random Forest** (hoặc **Isolation Forest**) và nhấn **Chạy Phân tích AI**.
   - Các dòng hợp lệ (198/200 dòng trong bộ demo) được phân lớp `Benign` / `Attack` kèm điểm `Risk Priority (#32)`.
   - Các dòng vi phạm bất biến OOD hoặc `MIN_TTL == 0` (2/200 dòng trong bộ demo) được **từ chối suy luận và từ chối tính điểm rủi ro** (`predicted_class = "ABSTAINED_OOD"`, `predicted_label = null`, `risk_level = "ABSTAINED_OOD"`).
3. Chuyển sang tab **3. Ground Truth & Confusion Matrix**, nhấn **Dùng demo_labels.csv**, sau đó nhấn **Chạy Đánh giá Ground Truth** để xem Confusion Matrix và các chỉ số `Accuracy`, `Precision`, `Recall`, `F1-Score`, `FPR` trên các dòng không bị từ chối OOD (`198 dòng đánh giá, 2 dòng OOD từ chối`).
4. Nhấn **Xuất CSV + Metadata** để lưu tệp dự đoán `.csv` và biên bản `.metadata.json` có đính kèm SHA-256.

---

## 3. Vận hành Ngoại tuyến (Offline Operation Boundaries)

Bảng dưới đây phân biệt rõ các yêu cầu ở từng giai đoạn khi triển khai cho máy trạm không có kết nối Internet (air-gapped / offline):

| Giai đoạn | Thành phần | Yêu cầu mạng | Hướng dẫn chuẩn bị cho môi trường Offline |
|---|---|---|---|
| **1. Build-time** (Biên dịch từ mã nguồn) | Rust crates (`crates.io`), npm packages (`registry.npmjs.org`), NSIS plugins | **Cần Internet** khi tải dependency lần đầu | Thực hiện trên máy build hoặc GitHub Actions runner; xuất ra tệp cài đặt `.exe` và `SHA256SUMS.txt`. |
| **2. Installation-time** (Chạy bộ cài NSIS) | Trình cài đặt NSIS (`NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe`) và Microsoft Edge WebView2 Runtime | **Không cần Internet NẾU máy đích đã có sẵn WebView2 Runtime**.<br>**Cần Internet NẾU máy đích chưa có WebView2 Runtime** (do cấu hình mặc định `downloadBootstrapper` của Tauri NSIS gọi `NSISdl::download` tới `https://go.microsoft.com/fwlink/p/?LinkId=2124703`). | Trên máy Windows hoàn toàn không có Internet và chưa có WebView2 Runtime: quản trị viên **phải cài đặt trước gói Microsoft Edge WebView2 Evergreen Standalone Offline Installer (`MicrosoftEdgeWebView2RuntimeInstallerX64.exe`)** trước khi chạy bộ cài NSIS của NetFlow Sentinel. |
| **3. Chuẩn bị Python & Artifacts** | Python installer, wheels (`pip`), mã nguồn repository, `.joblib` artifacts, `data/demo/*.csv` | **Cần chuẩn bị trước** (online hoặc qua kho wheel/USB nội bộ) | Để cài đặt Python dependencies offline, tải trước wheelhouse trên máy có mạng (`pip download -d wheelhouse .`) rồi cài trên máy đích bằng `pip install --no-index --find-links=wheelhouse -e .`. Sao chép thư mục `artifacts/` và `data/demo/` kèm manifest JSON qua phương tiện lưu trữ an toàn. |
| **4. Runtime** (Vận hành ứng dụng) | Giao diện Tauri WebView2 + FastAPI (`127.0.0.1`) + SQLite cục bộ + `InferencePipeline` | **Hoạt động 100% Offline (Localhost-only)** | Sau khi đã hoàn tất bước 2 & 3, ứng dụng chạy hoàn toàn nội bộ trên `127.0.0.1`, không gọi bất kỳ API đám mây hay kết nối mạng bên ngoài nào. |

---

## 4. Xử lý Sự cố (Troubleshooting)

### 4.1. Không tìm thấy Python (`Failed to spawn Python FastAPI backend`)
- **Nguyên nhân:** `python` không nằm trong `PATH` của Windows hoặc chỉ có Windows Store alias rỗng.
- **Cách khắc phục:** Đặt biến môi trường `NETWORK_ANOMALY_PYTHON` trỏ trực tiếp tới file `python.exe` của môi trường ảo đã cài đặt thư viện (ví dụ: `C:\NetFlow-Sentinel-Repo\.venv\Scripts\python.exe`) rồi khởi động lại ứng dụng.

### 4.2. Python thiếu dependencies (`ModuleNotFoundError: No module named 'fastapi'` / `'sklearn'`)
- **Nguyên nhân:** Ứng dụng đang gọi nhầm trình thông dịch Python hệ thống chưa cài đặt dependencies của dự án.
- **Cách khắc phục:** Kích hoạt đúng môi trường ảo và chạy:
  ```powershell
  C:\NetFlow-Sentinel-Repo\.venv\Scripts\python.exe -m pip install -e C:\NetFlow-Sentinel-Repo
  C:\NetFlow-Sentinel-Repo\.venv\Scripts\python.exe C:\NetFlow-Sentinel-Repo\scripts\check_environment.py
  ```

### 4.3. Không tìm thấy Repository Root (`Could not locate project root containing 'scripts/run_api.py'`)
- **Nguyên nhân:** Bạn đang chạy `netflow-sentinel-desktop.exe` từ thư mục cài đặt NSIS (`%LOCALAPPDATA%\NetFlow Sentinel M6`) nhưng chưa khai báo `NETWORK_ANOMALY_REPO_ROOT`.
- **Cách khắc phục:** Thiết lập biến môi trường `NETWORK_ANOMALY_REPO_ROOT` trỏ tới thư mục gốc của repository (nơi chứa `scripts/run_api.py` và `pyproject.toml`).

### 4.4. Thiếu Model hoặc Preprocessor Artifact (`Preprocessor BLOCKED` / `FileNotFoundError`)
- **Nguyên nhân:** Chưa sao chép các tệp `.joblib` vào `artifacts/preprocessing/` hoặc `artifacts/models/`.
- **Cách khắc phục:** Kiểm tra các đường dẫn bắt buộc trong `$env:NETWORK_ANOMALY_REPO_ROOT`:
  - `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib`
  - `artifacts/models/random_forest/random_forest_baseline.joblib`
  - `artifacts/models/isolation_forest/isolation_forest.joblib`

### 4.5. Mã băm SHA-256 không khớp (`SHA-256 mismatch` / `Artifact integrity check failed`)
- **Nguyên nhân:** Tệp `.joblib` bị hỏng trong quá trình sao chép hoặc không đúng phiên bản với manifest JSON trong `reports/models/` và `reports/preprocessing/`. Cơ chế bảo mật fail-closed từ chối nạp tệp `.joblib` không khớp SHA-256.
- **Cách khắc phục:** Chạy đoạn mã PowerShell ở **Bước 6** để xác định tệp bị lệch SHA-256 và sao chép lại đúng bản artifact đã nghiệm thu. Không chỉnh sửa thủ công mã băm trong manifest JSON.

### 4.6. FastAPI không khởi động trong thời gian chờ (`FastAPI backend did not become ready on http://127.0.0.1:<port>/health within 25s`)
- **Nguyên nhân:** Máy có ổ cứng chậm khi nạp `scikit-learn` / `pandas` lần đầu, hoặc tiến trình Python gặp lỗi cấu hình.
- **Cách khắc phục:**
  1. Nhấn nút **Làm mới Backend** trên thanh công cụ ứng dụng.
  2. Hoặc chạy thử trực tiếp lệnh sau trong PowerShell để xem thông báo lỗi chi tiết trên terminal:
     ```powershell
     & $env:NETWORK_ANOMALY_PYTHON "$env:NETWORK_ANOMALY_REPO_ROOT\scripts\run_api.py" --host 127.0.0.1 --port 8000
     ```

### 4.7. Cổng mạng bị chiếm (Port Conflict)
- **Nguyên nhân & Cơ chế:** Khi chạy trong Tauri Desktop, tiến trình Rust tự động xin hệ điều hành cấp một cổng trống ngẫu nhiên trên `127.0.0.1:0`, nên hiếm khi xảy ra xung đột cổng. Nếu bạn tự chạy `scripts/run_api.py --port 8000` bên ngoài và gặp lỗi `Address already in use`:
- **Cách khắc phục:** Chọn một cổng trống khác (ví dụ `--port 8015`) hoặc kiểm tra tiến trình đang chiếm cổng bằng lệnh:
  ```powershell
  Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
  ```

### 4.8. Thiếu Microsoft Edge WebView2 Runtime (Cửa sổ trắng hoặc lỗi cài đặt NSIS khi Offline)
- **Nguyên nhân:** Máy Windows 10 cũ chưa có WebView2 Runtime và không có kết nối Internet để bộ cài NSIS tải `MicrosoftEdgeWebview2Setup.exe`.
- **Cách khắc phục:** Kiểm tra sự tồn tại của khóa Registry WebView2:
  ```powershell
  Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" -ErrorAction SilentlyContinue
  ```
  Nếu lệnh trên không trả về phiên bản (`pv`), hãy tải và cài đặt **Microsoft Edge WebView2 Evergreen Standalone Installer (x64)** chính thức từ Microsoft trước khi chạy bộ cài NetFlow Sentinel.

### 4.9. Lỗi quyền ghi cơ sở dữ liệu SQLite (`sqlite3.OperationalError: unable to open database file` / `readonly database`)
- **Nguyên nhân:** Mặc định ứng dụng tạo tệp SQLite tại `%LOCALAPPDATA%\NetFlowSentinel\desktop_m6.db`. Nếu thư mục này bị giới hạn quyền ghi hoặc bạn đặt `NETWORK_ANOMALY_DB_PATH` vào một thư mục hệ thống chỉ đọc.
- **Cách khắc phục:** Đặt biến môi trường `NETWORK_ANOMALY_DB_PATH` trỏ tới một thư mục mà tài khoản người dùng hiện tại có toàn quyền đọc/ghi (ví dụ: `$HOME\NetFlowSentinelData\desktop_m6.db`).

### 4.10. Schema CSV không hợp lệ (`Missing required ML feature columns` / `ml_features_valid = false`)
- **Nguyên nhân:** Tệp CSV đầu vào thiếu một hoặc nhiều cột trong hợp đồng 47 cột đặc trưng ML của `NF-UNSW-NB15-v3`, hoặc không phải tệp `.csv` hợp lệ (hoặc rỗng / vượt quá 100 MB).
- **Cách khắc phục:** Dùng chức năng **Kiểm tra CSV** ở tab **1. Tổng quan & Kiểm tra CSV** để xem danh sách chính xác các cột bị thiếu tại mục `missing_ml_features`. Đảm bảo tệp CSV tuân thủ schema 47 đặc trưng NetFlow v3.

### 4.11. Mô hình báo `BLOCKED / NOT READY` hoặc cổng Eligibility Gate chặn suy luận (HTTP 503)
- **Nguyên nhân:**
  1. Người dùng chọn **XGBoost** hoặc **Autoencoder** (2 mô hình ngoài phạm vi baseline M6, chưa có artifact nghiệm thu).
  2. Tệp CSV chứa 100% số dòng vi phạm bất biến OOD (`MIN_TTL == 0` hoặc `hard_violation`), khiến toàn bộ batch bị từ chối suy luận (`ABSTAINED_OOD`).
  3. Tệp CSV bên ngoài không có biên bản provenance (`source:nf-v3-unverified` -> trạng thái `VALIDATION_NOT_VERIFIED`) nhưng gọi API với `allow_research_only = false`.
- **Cách khắc phục:** Sử dụng mô hình **Random Forest** (baseline chính) hoặc **Isolation Forest** trên dữ liệu hợp lệ. Khi phân tích tệp CSV bên ngoài chưa có manifest chuẩn, lưu ý trạng thái cổng tương thích sẽ là `VALIDATION_NOT_VERIFIED` (`SEMANTICALLY_COMPATIBLE`), không được coi là kết quả benchmark `MODEL_VALIDATED`.

### 4.12. Cảnh báo chữ ký số trên Windows (Unsigned Installer / Executable Warning)
- **Nguyên nhân:** Các bản build phát hành hiện tại của dự án nghiên cứu M6 chưa gắn chứng thư ký mã thương mại (Authenticode Code Signing Certificate), nên Windows có thể hiển thị hộp thoại thông báo tệp chưa được ký số.
- **Cách xử lý an toàn:**
  1. **Tuyệt đối KHÔNG tắt Windows Defender, Microsoft Defender Antivirus hay SmartScreen** trên máy.
  2. Luôn thực hiện **Bước 2 (Kiểm chứng mã băm SHA-256)** đối chiếu với tệp `SHA256SUMS.txt` từ trang GitHub Release chính thức của repository trước khi mở tệp. Chỉ tiếp tục chạy khi mã băm SHA-256 khớp 100% hoặc tự biên dịch từ mã nguồn theo hướng dẫn tại [docs/RELEASE_PROCESS.md](RELEASE_PROCESS.md).
