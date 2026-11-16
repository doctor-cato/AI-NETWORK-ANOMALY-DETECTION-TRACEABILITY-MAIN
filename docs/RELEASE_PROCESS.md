# Quy trình Đóng gói & Phát hành Windows Standalone (`v1.0.0`)

Tài liệu này mô tả quy trình build, kiểm chứng fail-closed và phát hành **NetFlow Sentinel (`v1.0.0` Stable)** cho **Windows 10/11 x64** theo kiến trúc **Fully Embedded Standalone Installer** (Issue #71).

---

## 1. Kiến trúc Đóng gói & Phân tách Build-time / Runtime

### 1.1. Tách biệt Build-time Acquisition và Runtime Dependencies

- **Runtime (máy người dùng cuối):**
  - Chỉ cần tải một tệp cài đặt duy nhất: `NetFlow-Sentinel-v<version>-windows-x64-setup.exe`.
  - **Không** cần Python, Rust, Node.js, Git, biến môi trường hay Companion Bundle bên ngoài.
  - Mọi thành phần đều nằm trong thư mục cài đặt (`%LOCALAPPDATA%\NetFlow Sentinel\`):
    - `netflow-sentinel-desktop.exe` (Rust / Tauri 2 + Svelte 5 UI)
    - `netflow-sentinel-backend.exe` (PyInstaller Sidecar FastAPI + Uvicorn + scikit-learn + XGBoost)
    - WebView2 Offline Installer (nhúng bởi `tauri.conf.json` `webviewInstallMode: offlineInstaller`)
    - 4 mô hình thật (`random_forest`, `xgboost`, `isolation_forest`, `autoencoder`) + preprocessor + manifests + `data/demo/` + `NOTICE` + `THIRD_PARTY_NOTICES.md` + `LICENSE` + `EMBEDDED_ARTIFACTS_MANIFEST.json` + `EMBEDDED_SHA256SUMS.txt`.
- **Build-time (GitHub Actions / máy đóng gói):**
  - Model binaries (`.joblib`) và `demo_*.csv` **không được commit vào Git** (theo `.gitignore`).
  - Trong workflow `.github/workflows/release.yml`, bước **Build-time model acquisition** tải gói mô hình từ nguồn riêng tư được cấp phép (qua `vars.MODEL_BUNDLE_URL` + `secrets.MODEL_BUNDLE_TOKEN` hoặc `vars.MODEL_ARTIFACT_RUN_ID`), kiểm tra SHA-256 (`vars.MODEL_BUNDLE_SHA256`), xác minh quyền phân phối và stage vào `desktop/src-tauri/staged_bundle/` trước khi chạy `tauri build --config src-tauri/tauri.standalone.conf.json --bundles nsis`.
  - Các biến cũ `COMPANION_BUNDLE_URL`, `COMPANION_ARTIFACT_RUN_ID`, `COMPANION_BUNDLE_SHA256` chỉ giữ làm fallback tương thích với cảnh báo `[DEPRECATED]` ở bước build; không xóa secrets sẵn có và tuyệt đối không dùng ở máy người dùng cuối.

---

## 2. Cổng Kiểm soát Bản quyền Phân phối (Distribution Permission Gate)

Dữ liệu huấn luyện **NF-UNSW-NB15-v3** tuân theo **UQ License ID `454104`** (*Permitted Re-Use with Commercial Use Restriction*, DOI: [`10.48610/6E0EDA1`](https://doi.org/10.48610/6E0EDA1)):
- Cho phép tái sử dụng phục vụ **nghiên cứu, học thuật và trình diễn phi thương mại** khi đính kèm đầy đủ thông báo ghi nhận nguồn (`NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE`).
- Hàm `verify_distribution_permission()` trong `scripts/verify_companion_artifacts.py` ép buộc fail-closed:
  - Chế độ phát hành công khai (`--public-release`, ví dụ push tag `v1.0.0`) chỉ được phép tiếp tục khi `vars.ALLOW_EMBEDDED_MODEL_REDISTRIBUTION` (hoặc `distribution_scope`) được xác nhận là `"non-commercial-academic-approved"` và cả 3 tệp `NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE` hiện diện đầy đủ.
  - Nếu không đạt cổng bản quyền hoặc thiếu bất kỳ mô hình nào, Stable Release bị **BLOCKED / FAIL-CLOSED** (không âm thầm bỏ mô hình hoặc thay thế bằng mock).

---

## 3. Đồng bộ Phiên bản & Cổng SemVer

Kiểm tra trước khi cắt tag hoặc dispatch workflow:

```powershell
python scripts/check_desktop_version.py --check
python scripts/check_desktop_version.py --check --expect-tag v1.0.0
```

- Năm tệp desktop bắt buộc khớp 1-1:
  - `desktop/package.json`
  - `desktop/package-lock.json`
  - `desktop/src-tauri/Cargo.toml`
  - `desktop/src-tauri/Cargo.lock`
  - `desktop/src-tauri/tauri.conf.json`
- Phiên bản backend Python API trong `pyproject.toml`, `src/network_anomaly/__init__.py` và `src/network_anomaly/api/main.py` được giữ ở `0.1.0` và kiểm tra độc lập.
- Mọi Git tag phát hành (`refs/tags/v*`) — cả prerelease lẫn stable — phải là tổ tiên của `origin/main` (`git merge-base --is-ancestor $tagCommit origin/main`).

---

## 4. Các bước Build & Embedded Artifacts Verification Gate

Workflow `.github/workflows/release.yml` thực hiện lần lượt:

1. **Metadata & SemVer Gate:** kiểm tra tag format, `origin/main` ancestry, không ghi đè release đã tồn tại, khớp phiên bản 1-1.
2. **Build-time Model Acquisition & Permission Gate:**
   - Tải/kiểm chứng SHA-256 gói 4 model thật + preprocessor + demo CSV.
   - Kiểm tra `verify_companion_artifacts.py --verify-distribution-permission <scope> --public-release`.
   - Stage vào `desktop/src-tauri/staged_bundle/` qua `--stage-embedded-dir`.
   - Nếu thiếu bất kỳ model nào trên Stable Release: **FAIL-CLOSED**.
3. **Code Quality, OpenAPI & Tests:**
   - `python scripts/check_environment.py`, `ruff`, `black --check`, `scripts/export_openapi_spec.py --check`, `pytest tests/unit tests/contract tests/integration -q`.
   - Kiểm chứng baseline attestation tại `reports/releases/v1.0.0_e2e_verification.json`.
   - `npm --prefix desktop ci/run check/test/build`, `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.
4. **Build PyInstaller Sidecar (`scripts/build_backend_sidecar.py`):**
   - Đóng gói `scripts/run_api.py` + `src/network_anomaly` + FastAPI + scikit-learn + XGBoost thành `desktop/src-tauri/binaries/netflow-sentinel-backend-x86_64-pc-windows-msvc.exe` và ghi `dist/release-assets/sidecar_build.json` (kèm SHA-256).
5. **Build Standalone NSIS Installer:**
   - Chạy `npx tauri build --config src-tauri/tauri.standalone.conf.json --bundles nsis`.
6. **Embedded Artifacts Verification Gate & Clean Windows Standalone E2E:**
   - Đóng gói `dist/release-assets/NetFlow-Sentinel-<tag>-windows-x64-setup.exe` và `SHA256SUMS.txt`.
   - Chạy `scripts/verify_companion_artifacts.py --verify-e2e --standalone-embedded --no-repo-root-env --installer-path ... --sums-file ... --compiled-exe ... --expect-sidecar-sha256 ... --output-json dist/release-assets/release_e2e_verification.json`:
     - Cài đặt silent NSIS vào thư mục sạch (tạm thời), kiểm tra layout không dùng `NETWORK_ANOMALY_PYTHON` và không dùng companion ngoài thư mục cài đặt.
     - Kiểm tra SHA-256 sidecar, tất cả tệp trong `EMBEDDED_SHA256SUMS.txt`, và `EMBEDDED_ARTIFACTS_MANIFEST.json`.
     - Khởi chạy sidecar backend thực tế với `X-Sentinel-Session-Token` cô lập `%LOCALAPPDATA%` tạm.
     - Chạy inference & evaluation trên 4 model thật, kiểm tra OOD (`ABSTAINED_OOD`), xuất CSV an toàn, restart sidecar xác minh SQLite persistence, và kiểm tra không rò rỉ tiến trình con.
     - Chạy `uninstall.exe /S` và xác minh gỡ cài đặt sạch sẽ.
   - Chạy `--verify-attestation ... --expect-commit <sha> --expect-installer-sha256 <hash> --require-nsis-e2e --require-demo-files --require-standalone-embedded`.
7. **Publish Assets (chỉ khi push Git tag):**
   - Tạo GitHub Release với `NetFlow-Sentinel-<tag>-windows-x64-setup.exe`, `SHA256SUMS.txt`, `release_e2e_verification.json`, `NOTICE`, `THIRD_PARTY_NOTICES.md` và Release Notes từ `docs/releases/v1.0.0.md`.
