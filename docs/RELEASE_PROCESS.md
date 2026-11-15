# Quy trình Đóng gói, Kiểm chứng & Phát hành (Packaging & Release Process — M6 `v0.6.0`)

Tài liệu này quy định quy trình kỹ thuật chuẩn để biên dịch, kiểm chứng chất lượng, tạo gói cài đặt Windows x64 (NSIS), tính toán mã băm SHA-256 và xuất bản GitHub Release cho **NetFlow Sentinel M6 (`v0.6.0`)**.

---

## 1. Phân loại các Dạng Bản dựng & Phạm vi Đóng gói M6

Để đảm bảo tính trung thực kỹ thuật, không gây hiểu nhầm cho người dùng cuối và người đánh giá, cần phân biệt rõ 5 khái niệm dưới đây:

| Phân loại | Định nghĩa kỹ thuật | Trạng thái trong M6 (`v0.6.0`) |
|---|---|---|
| **1. Development Build** | Chạy Vite dev server (`http://localhost:1420`) kết hợp `cargo tauri dev` và tiến trình Python cục bộ. | Dùng trong quá trình phát triển (`npm --prefix desktop run tauri dev`). |
| **2. Compiled Release Executable** (`netflow-sentinel-desktop.exe`) | Tệp thực thi Windows x64 biên dịch ở chế độ `--release`, đã nhúng tài nguyên giao diện Svelte 5 (`desktop/build`). | **Có tạo ra** tại `desktop/src-tauri/target/release/netflow-sentinel-desktop.exe`. **Lưu ý:** Không được gọi hay phân phối tệp `.exe` đơn lẻ này như một "Portable App hoàn chỉnh" vì nó vẫn phụ thuộc vào Python backend, thư mục gốc của repository (`NETWORK_ANOMALY_REPO_ROOT`) và các tệp `.joblib` bên ngoài. |
| **3. NSIS Windows Installer** (`NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe`) | Bộ cài đặt Windows chuẩn NSIS giúp cài đặt `netflow-sentinel-desktop.exe`, biểu tượng, lối tắt Start Menu/Desktop và trình gỡ cài đặt (`uninst.exe`), đồng thời kiểm tra sự hiện diện của WebView2 Runtime. | **Asset phát hành chính thức** của M6 (`v0.6.0`). |
| **4. Offline-Capable Application with External Prerequisites** | Ứng dụng hoạt động hoàn toàn cục bộ (`127.0.0.1`, không gọi dịch vụ đám mây) sau khi máy đích đã được trang bị đầy đủ các điều kiện tiên quyết bên ngoài (Python, dependencies, repo root, `.joblib` artifacts, WebView2 Runtime). | **Đúng bản chất kiến trúc của M6 (`v0.6.0`)**. |
| **5. Standalone Self-Contained Application** | Gói cài đặt đính kèm toàn bộ trình thông dịch Python nhúng (embedded Python / PyInstaller sidecar), thư viện ML, mã nguồn backend và WebView2 offline installer trong một gói duy nhất không cần chuẩn bị môi trường bên ngoài. | **Chưa thuộc phạm vi M6 (`v0.6.0`)** — được ghi nhận là hạng mục nâng cấp đóng gói cho giai đoạn sau. |

---

## 2. Đồng bộ và Kiểm tra Phiên bản (Version Consistency Check)

Phiên bản của ứng dụng Desktop M6 được quản lý đồng bộ tại 5 tệp cấu hình/lockfile, tách biệt hoàn toàn với phiên bản hợp đồng API Python (`0.1.0`):

1. `desktop/src-tauri/Cargo.toml` (`[package] version`)
2. `desktop/src-tauri/Cargo.lock` (`name = "netflow-sentinel-desktop"`)
3. `desktop/package.json` (`"version"`)
4. `desktop/package-lock.json` (`"version"` và `packages[""]["version"]`)
5. `desktop/src-tauri/tauri.conf.json` (`"version"`)

### Lệnh kiểm tra đồng bộ phiên bản

```powershell
# Kiểm tra cả 5 tệp desktop khớp nhau và hợp đồng Python API giữ nguyên 0.1.0
python scripts/check_desktop_version.py --check

# Kiểm tra khớp với một phiên bản hoặc Git tag cụ thể
python scripts/check_desktop_version.py --check --expect-version 0.6.0
python scripts/check_desktop_version.py --check --expect-tag v0.6.0
```

### Lệnh cập nhật phiên bản đồng loạt (khi chuyển giữa Beta và Stable)

```powershell
# Ví dụ đặt phiên bản sang 0.6.0-beta.1 hoặc 0.6.0
python scripts/check_desktop_version.py --set-version 0.6.0
```

---

## 3. Kiểm thử Toàn diện Trước khi Đóng gói (Pre-Build Verification Suite)

Mọi bản phát hành bắt buộc phải vượt qua toàn bộ các bài kiểm tra Python, OpenAPI Contract, Svelte/TypeScript và Rust dưới đây:

### 3.1. Kiểm tra Python Backend, Linter & Pytest

```powershell
python scripts/check_environment.py
python -m ruff check src scripts tests
python -m black --check src scripts tests
python -m pytest tests/unit tests/contract tests/integration -q
```

### 3.2. Kiểm chứng Hợp đồng OpenAPI (`reports/api/openapi.json` & `API_CONTRACT.md`)

```powershell
# Kiểm tra schema FastAPI hiện tại khớp 100% với tài liệu hợp đồng đã commit
python scripts/export_openapi_spec.py --check
```

Nếu có thay đổi hợp lệ về schema API, chạy `python scripts/export_openapi_spec.py` để cập nhật trước khi commit.

### 3.3. Kiểm tra Frontend Svelte 5 & Vitest

```powershell
npm --prefix desktop ci
npm --prefix desktop run check
npm --prefix desktop test
npm --prefix desktop run build
```

### 3.4. Kiểm tra Rust (Formatting, Clippy & Unit Tests)

```powershell
cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check
cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path desktop/src-tauri/Cargo.toml
```

---

## 4. Biên dịch Ứng dụng Tauri 2 và Bộ cài đặt Windows x64 NSIS

### 4.1. Biên dịch Binary thực thi (`cargo build --release`)

```powershell
npm --prefix desktop run build
cargo build --release --manifest-path desktop/src-tauri/Cargo.toml
```

- Đầu ra: `desktop/src-tauri/target/release/netflow-sentinel-desktop.exe`

### 4.2. Đóng gói Bộ cài đặt Windows x64 NSIS (`tauri build`)

```powershell
npx --prefix desktop tauri build --bundles nsis
```

- Đầu ra trình cài đặt NSIS:
  `desktop/src-tauri/target/release/bundle/nsis/NetFlow Sentinel M6_0.6.0_x64-setup.exe`
- Script NSIS sinh tự động tại:
  `desktop/src-tauri/target/release/nsis/x64/installer.nsi`

### 4.3. Kiểm tra Tệp Thực thi và Bộ cài đặt Windows

Sau khi lệnh `tauri build` hoàn tất:
1. Kiểm tra sự tồn tại và kích thước (> 1 MB) của cả hai tệp `.exe`:
   ```powershell
   Get-Item "desktop/src-tauri/target/release/netflow-sentinel-desktop.exe", "desktop/src-tauri/target/release/bundle/nsis/*-setup.exe" | Select-Object FullName, Length, LastWriteTime
   ```
2. Chạy thử bộ cài đặt NSIS trên máy Windows x64, khởi động ứng dụng cùng biến môi trường `NETWORK_ANOMALY_REPO_ROOT`, xác nhận:
   - Tiến trình `run_api.py` khởi chạy trên `127.0.0.1:<port>` và `/health` trả về `200 OK`.
   - Phân tích `data/demo/demo_flows.csv` với Random Forest và Isolation Forest hoạt động chính xác.
   - Các dòng OOD (`MIN_TTL == 0`) nhận trạng thái `ABSTAINED_OOD` và được loại trừ khỏi Confusion Matrix (`abstained_rows = 2`).
   - Khi đóng cửa sổ ứng dụng, tiến trình con Python FastAPI được dọn dẹp sạch sẽ, không để lại tiến trình mồ côi (orphan process).

---

## 5. Đặt tên Asset Chuẩn và Tạo `SHA256SUMS.txt`

Khi chuẩn bị phát hành cho tag `<TAG>` (ví dụ `v0.6.0-beta.1` hoặc `v0.6.0`), sao chép bộ cài đặt NSIS sang tên chuẩn hóa không chứa khoảng trắng và tạo tệp `SHA256SUMS.txt`:

```powershell
$Tag = "v0.6.0"
$StageDir = "dist/release-assets"
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

$SourceSetup = (Get-ChildItem "desktop/src-tauri/target/release/bundle/nsis/*-setup.exe" | Select-Object -First 1).FullName
$AssetName = "NetFlow-Sentinel-$Tag-windows-x64-setup.exe"
$TargetSetup = Join-Path $StageDir $AssetName

Copy-Item -Path $SourceSetup -Destination $TargetSetup -Force

$Sha256 = (python -c "import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest())" $TargetSetup).Trim().ToLower()
"$Sha256  $AssetName" | Out-File -FilePath (Join-Path $StageDir "SHA256SUMS.txt") -Encoding ascii

Get-Content (Join-Path $StageDir "SHA256SUMS.txt")
```

> [!WARNING]
> **Các tệp TUYỆT ĐỐI KHÔNG đính kèm vào GitHub Release:**
> - Bộ dữ liệu thô `NF-UNSW-NB15-v3.csv` hoặc các tập dữ liệu benchmark bên ngoài.
> - Tệp mô hình `.joblib` khi chưa có xác nhận phân phối nhị phân công khai.
> - Thư mục `.venv`, `__pycache__`, cơ sở dữ liệu cục bộ `.db` / `.sqlite` hoặc tệp chứa thông tin nhạy cảm.
> - Tệp `netflow-sentinel-desktop.exe` đơn lẻ gắn nhãn "portable" (do ứng dụng chưa phải standalone độc lập).

---

## 6. Chiến lược Phát hành 2 Giai đoạn (Beta Pre-release vs Stable Release)

### 6.1. Giai đoạn 1 — Bản Thử nghiệm `v0.6.0-beta.1` (GitHub Pre-release)

Chỉ thực hiện khi cần xuất bản bản cài đặt thử nghiệm từ commit đã vượt qua toàn bộ kiểm thử:

1. Xác minh trạng thái Git sạch và đồng bộ phiên bản:
   ```powershell
   git status --porcelain
   python scripts/check_desktop_version.py --check
   ```
2. Tạo **annotated Git tag** `v0.6.0-beta.1` trỏ vào commit đã kiểm chứng:
   ```powershell
   git tag -a v0.6.0-beta.1 -m "NetFlow Sentinel v0.6.0-beta.1 (M6 Desktop Pre-release)"
   ```
3. Kiểm tra tag trỏ đúng commit mong muốn:
   ```powershell
   git show v0.6.0-beta.1 --stat
   ```
4. Đẩy tag lên GitHub để kích hoạt `.github/workflows/release.yml` (workflow tự động gắn cờ `--prerelease` cho mọi tag có hậu tố `-beta.*` / `-rc.*`):
   ```powershell
   git push origin v0.6.0-beta.1
   ```

### 6.2. Giai đoạn 2 — Bản Chính thức `v0.6.0` (Stable Release)

**Điều kiện bắt buộc trước khi tạo tag `v0.6.0`:**
- PR #67 đã được review **Approve** và **merged vào nhánh `main`**.
- Toàn bộ các kiểm tra CI trên `main` đều **PASS**.
- Phiên bản trong cả 5 tệp cấu hình desktop là `0.6.0`.

Các bước thực hiện trên nhánh `main` sau khi PR #67 đã merge:

```powershell
git checkout main
git pull --ff-only origin main

# 1. Kiểm tra working tree sạch và phiên bản khớp v0.6.0
git status --porcelain
python scripts/check_desktop_version.py --check --expect-tag v0.6.0

# 2. Tạo annotated tag v0.6.0 trên commit merge tại main
git tag -a v0.6.0 -m "NetFlow Sentinel v0.6.0 — M6 Desktop Release"

# 3. Xác minh tag trỏ đúng HEAD của origin/main
git rev-parse v0.6.0^{commit}
git rev-parse origin/main

# 4. Đẩy tag lên origin để kích hoạt GitHub Release workflow
git push origin v0.6.0
```

---

## 7. Kiểm tra GitHub Release Assets & Xử lý Sự cố Phát hành

### 7.1. Kiểm tra sau khi Workflow `.github/workflows/release.yml` hoàn tất

```powershell
# Kiểm tra trạng thái workflow
gh run list --workflow=release.yml --limit 5

# Kiểm tra thông tin bản phát hành và danh sách assets
gh release view v0.6.0
```

Xác nhận bản phát hành trên GitHub có:
1. Đúng trạng thái (`Pre-release` đối với `v0.6.0-beta.1`, hoặc `Latest` / `Stable` đối với `v0.6.0`).
2. Đính kèm đúng 2 tệp:
   - `NetFlow-Sentinel-v0.6.0-windows-x64-setup.exe`
   - `SHA256SUMS.txt`
3. Nội dung Release Notes hiển thị đầy đủ các yêu cầu môi trường runtime (Python, `.joblib` artifacts, `demo_flows.csv`, WebView2 Runtime).

### 7.2. Xử lý khi Build hoặc Release thất bại

- **Nếu bước kiểm tra phiên bản hoặc test thất bại trước khi tạo Release:**
  1. Không ép buộc bỏ qua bước kiểm tra.
  2. Nếu đã lỡ đẩy một tag bị lỗi nhưng **chưa có Release công khai**, xóa tag lỗi, sửa code thông qua PR, đợi CI xanh rồi mới tạo tag mới.
- **Nếu bản Pre-release phát hiện lỗi sau khi xuất bản:**
  1. Không ghi đè (force-push / move tag) lên tag đã phát hành.
  2. Khắc phục lỗi trong commit mới và phát hành tag kế tiếp (`v0.6.0-beta.2` hoặc `v0.6.0` sau khi merge vào `main`).

### 7.3. Những trường hợp TUYỆT ĐỐI KHÔNG được phát hành Stable (`v0.6.0`)

1. PR #67 chưa được review Approve hoặc chưa được merge vào nhánh `main`.
2. Bất kỳ job nào trong `.github/workflows/ci.yml` hoặc `.github/workflows/release.yml` bị `FAIL`.
3. Phiên bản giữa `Cargo.toml`, `Cargo.lock`, `package.json`, `package-lock.json` và `tauri.conf.json` không đồng nhất.
4. Hợp đồng OpenAPI (`reports/api/openapi.json`) bị lệch so với mã nguồn (`export_openapi_spec.py --check` báo lỗi).
5. Tệp CSV bên ngoài chưa xác minh provenance vẫn bị gán nhầm trạng thái `MODEL_VALIDATED`, hoặc dòng OOD (`ABSTAINED_OOD`) vẫn bị tính gộp vào Confusion Matrix.
6. Tài liệu hoặc ghi chú phát hành mô tả sai sự thật rằng bộ cài đặt hiện tại là bản standalone độc lập không cần Python/artifacts.
