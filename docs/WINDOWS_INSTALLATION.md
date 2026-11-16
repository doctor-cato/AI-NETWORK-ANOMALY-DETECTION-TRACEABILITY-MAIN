# Hướng dẫn Cài đặt & Sử dụng trên Windows (NetFlow Sentinel v1.0.0)

Tài liệu này mô tả cách cài đặt và sử dụng bộ cài ứng viên **NetFlow Sentinel `v1.0.0`** cho Windows 10/11 x64. Việc phát hành Stable đang chờ nghiệm thu Windows sạch và xác nhận quyền phân phối.

> [!IMPORTANT]
> **Kiến trúc Standalone Embedded của `v1.0.0`:**
> Duy nhất một bộ cài Windows x64 (`NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe`) đã tích hợp đầy đủ:
> 1. **Ứng dụng Desktop Native (Rust Tauri 2 + Svelte 5)** (`netflow-sentinel-desktop.exe`).
> 2. **PyInstaller Backend Sidecar (`netflow-sentinel-backend.exe`)** tích hợp sẵn Python runtime, FastAPI, Uvicorn, `scikit-learn`, `xgboost`, `joblib` và SQLite persistence.
> 3. **Cả 4 mô hình ML thật đã kiểm chứng SHA-256 + Preprocessor + Configs/Manifests + Demo CSV**:
>    - `Random Forest` (`MODEL_VALIDATED`)
>    - `XGBoost` (`RESEARCH_ONLY`)
>    - `Isolation Forest` (`RESEARCH_ONLY`)
>    - `Autoencoder` (`RESEARCH_ONLY`)
>    - `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib`
>    - `data/demo/demo_flows.csv`, `data/demo/demo_labels.csv`, `data/demo/demo_manifest.json`
> 4. **WebView2 Offline Installer**, thông báo bản quyền (`NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE`), cùng tệp kiểm chứng nhúng `EMBEDDED_SHA256SUMS.txt` và `EMBEDDED_ARTIFACTS_MANIFEST.json`.
>
> Ứng dụng lưu SQLite tại `%LOCALAPPDATA%\NetFlowSentinel\`. Cấu hình cài theo người dùng hiện tại và nhúng WebView2 Offline Installer. Kiểm thử offline với Standard User trên VM sạch vẫn **NOT VERIFIED**.

---

## 1. Yêu cầu Hệ thống (System Requirements)

| Thành phần | Yêu cầu | Ghi chú |
|---|---|---|
| **Hệ điều hành mục tiêu** | Windows 10 x64 hoặc Windows 11 x64 | Kiến trúc `x86_64-pc-windows-msvc` |
| **Python / Rust / Node.js / Git** | **Không yêu cầu** đối với người dùng cuối | Python `>= 3.11` chỉ dùng khi lập trình viên tự build lại sidecar từ mã nguồn |
| **WebView2 Runtime** | Tự động cài đặt từ bộ cài nếu máy chưa có | Nhúng sẵn Microsoft Edge WebView2 **Offline Installer** |
| **Dung lượng ổ đĩa** | ~900 MB trống (sau giải nén cài đặt) | Bao gồm sidecar backend, 4 mô hình, dữ liệu demo và database cục bộ |
| **Mạng Internet** | **Không cần khi chạy & phân tích** | Chỉ cần mạng một lần lúc tải tệp `.exe` về máy |

---

## 2. Các bước Cài đặt & Sử dụng (3 bước đơn giản)

### Bước 1: Tải bộ cài & Kiểm tra SHA-256 (khuyến nghị)

Các tệp dự kiến trên GitHub Release sau khi nghiệm thu:
- `NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe`
- `SHA256SUMS.txt`

Mở **Windows PowerShell** tại thư mục vừa tải về để xác minh tính toàn vẹn của bộ cài trước khi chạy:

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

### Bước 2: Chạy trình cài đặt NSIS

Nhấn đúp vào `NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe`:
- Chọn thư mục cài đặt mặc định (mặc định cài ở chế độ `currentUser` tại `%LOCALAPPDATA%\NetFlow Sentinel\`, không cần Administrator).
- Bộ cài tự động cài WebView2 Offline (nếu máy chưa có), giải nén ứng dụng Desktop, PyInstaller Sidecar và đủ 4 mô hình thật, tạo biểu tượng trên **Desktop** và **Start Menu**.

### Bước 3: Mở **NetFlow Sentinel** và phân tích dữ liệu Demo / CSV của bạn

Nhấn đúp biểu tượng **NetFlow Sentinel** trên Desktop hoặc Start Menu:
1. Ứng dụng tự động khởi chạy **PyInstaller Backend Sidecar** trên `127.0.0.1` với mã phiên bảo mật (`X-Sentinel-Session-Token`), kiểm tra `/health` và nạp đủ **4 mô hình ở trạng thái `READY`**.
2. Giao diện hiển thị **Hướng dẫn 4 bước** ngay trên màn hình:
   - **Bước 1 — Chọn dữ liệu:** Dùng ngay dữ liệu mẫu tích hợp sẵn (`data/demo/demo_flows.csv`, kèm `demo_labels.csv` để tính Confusion Matrix) hoặc bấm chọn tệp CSV NetFlow riêng (cần đủ feature theo hợp đồng `NF-UNSW-NB15-v3`).
   - **Bước 2 — Phân tích:** Chạy một mô hình hoặc so sánh các mô hình đang `READY`.
   - **Bước 3 — Đánh giá & Đối chiếu:** Xem Benign, Attack, OOD và độ tin cậy. Chọn tệp ground truth tương ứng để tính confusion matrix và các chỉ số đánh giá.
   - **Bước 4 — Xuất kết quả:** Lưu báo cáo phân tích ra CSV và metadata SHA-256.

---

## 3. Gỡ cài đặt (Uninstall)

Mở **Windows Settings → Apps → Installed apps → NetFlow Sentinel → Uninstall** (hoặc chạy `uninstall.exe` trong thư mục cài đặt). Bộ cài gốc sẽ gỡ bỏ toàn bộ tệp thực thi, sidecar và mô hình đã cài. Dữ liệu phiên do người dùng tự lưu nằm tại `%LOCALAPPDATA%\NetFlowSentinel\` có thể giữ lại hoặc xóa thủ công tùy nhu cầu.

---

## 4. Lưu ý Bản quyền & Hỗ trợ xử lý sự cố

- **Bản quyền dữ liệu NF-UNSW-NB15-v3:** Áp dụng giấy phép **UQ License ID `454104`** (*Permitted Re-Use with Commercial Use Restriction*, DOI: `10.48610/6E0EDA1`). Chỉ sử dụng cho mục đích nghiên cứu, giảng dạy và đánh giá phi thương mại. Chi tiết xem `NOTICE` và `THIRD_PARTY_NOTICES.md` trong thư mục cài đặt.
- **Nếu ứng dụng báo sidecar chưa sẵn sàng:** Bấm **Khởi động lại Backend** ngay trong bảng trạng thái hệ thống (System Status) để Tauri sidecar tự khởi động lại và cấp mã phiên mới; xem log chi tiết tại khung chẩn đoán.
- **Nếu CSV đầu vào báo OOD hoặc thiếu cột:** Hệ thống áp dụng cơ chế an toàn **fail-closed**: các dòng vượt ngưỡng phân phối `0.1%–99.9%` của tập Train bị gắn nhãn `ABSTAINED_OOD`, và CSV sai feature contract được báo lỗi tiếng Việt cụ thể để người dùng kiểm tra lại định dạng cột.
