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
  - Trong workflow `.github/workflows/release.yml`, bước **build-time model acquisition** chỉ được phép chạy sau khi **Distribution Permission Gate** chấp thuận kênh đích, tải gói mô hình từ nguồn riêng tư được cấp phép (qua `vars.MODEL_BUNDLE_URL` + `secrets.MODEL_BUNDLE_TOKEN` hoặc `vars.MODEL_ARTIFACT_RUN_ID`), kiểm tra SHA-256 (`vars.MODEL_BUNDLE_SHA256`) và host allowlist (`vars.MODEL_BUNDLE_ALLOWED_HOSTS`), rồi stage vào `desktop/src-tauri/staged_bundle/` trước khi chạy `tauri build --config src-tauri/tauri.standalone.conf.json --bundles nsis`.
  - Các biến cũ `COMPANION_BUNDLE_URL`, `COMPANION_ARTIFACT_RUN_ID`, `COMPANION_BUNDLE_SHA256` chỉ giữ làm fallback tương thích với cảnh báo `[DEPRECATED]` ở bước build; không xóa secrets sẵn có và tuyệt đối không dùng ở máy người dùng cuối.
  - Workflow **không** bật `Swatinem/rust-cache` trên nhánh build phát hành và luôn chạy bước dọn `build/`, `staged_bundle/`, `binaries/*.exe`, `target/release/{artifacts,data,bundle}`, `dist/release-assets/` với `if: always()` để tránh rò rỉ nhị phân mô hình qua GitHub Actions Cache hoặc Workspace.

---

## 2. Cổng Kiểm soát Bản quyền & Bằng chứng Phân phối (Evidence-Based Distribution Gate)

Dữ liệu huấn luyện **NF-UNSW-NB15-v3** tuân theo **UQ License ID `454104`** (*Permitted Re-Use with Commercial Use Restriction*, DOI: [`10.48610/6E0EDA1`](https://doi.org/10.48610/6E0EDA1)):
- Giấy phép dataset cho phép sử dụng nghiên cứu/học thuật phi thương mại kèm trích dẫn đầy đủ, nhưng **không mặc định chứng minh quyền phân phối công khai tự do** cho mọi tệp mô hình `.joblib` dẫn xuất và tập con `demo_*.csv` trên GitHub Release công khai.
- Hệ thống phân tách rạch ròi 4 mức quyền tại [`reports/governance/DISTRIBUTION_AUTHORIZATION.json`](../reports/governance/DISTRIBUTION_AUTHORIZATION.json) và hàm `verify_distribution_permission()` trong `scripts/verify_companion_artifacts.py`:
  1. `research-only`: nghiên cứu và đánh giá cục bộ (`target_channel=local_offline`). Cấm upload CI artifact và cấm phát hành.
  2. `private-build-only`: đóng gói và kiểm thử nội bộ **chỉ trên máy cục bộ (`local_offline`) hoặc private repository / private runner có quyền truy cập hạn chế (`repo_is_private=true`, `target_channel=private_ci_artifact`)**. Tuyệt đối **FAIL-CLOSED** trên public repository, không tin vào tên workflow `dryrun`.
  3. `non-commercial-controlled`: phân phối học thuật có kiểm soát truy cập trong kênh riêng tư (`repo_is_private=true`, `private_ci_artifact`). Không cho phép public GitHub Release/public Actions artifact.
  4. `public-release-approved`: chỉ được phép upload lên `public_ci_artifact` hoặc `public_github_release` khi **cả 3 điều kiện** đều đạt:
     - `NOTICE`, `THIRD_PARTY_NOTICES.md` và `LICENSE` đầy đủ;
     - `reports/governance/DISTRIBUTION_AUTHORIZATION.json` ghi `public_release_authorization.approved = true`, `status = "APPROVED"`, có `legal_basis`, `maintainer_approver`, `approved_at_utc`, `evidence_ref` và `evidence_sha256` hợp lệ (chỉ lưu tham chiếu kiểm toán, không đưa tài liệu/token bí mật vào Git hay public logs);
     - `secrets.DISTRIBUTION_EVIDENCE_SHA256` khớp `evidence_sha256` bằng so sánh constant-time (`hmac.compare_digest`). Một GitHub Variable (`ALLOW_EMBEDDED_MODEL_REDISTRIBUTION`) đơn lẻ hay chuỗi cũ `non-commercial-academic-approved` bị **từ chối fail-closed**.

> [!IMPORTANT]
> **Phương án kiểm thử nội bộ an toàn:** Để kiểm thử workflow `release.yml` trên cloud khi quyền phân phối công khai chưa được phê duyệt (`approved: false`), maintainer thực hiện trên **private mirror repository** hoặc **private self-hosted runner** giới hạn quyền truy cập, giữ `distribution_scope = private-build-only`; hệ thống tự kiểm tra `gh api repos/<owner>/<repo>` xác nhận `private == true` mới cho phép upload artifact nội bộ có `retention-days: 7` và vẫn chặn `gh release create`.

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

## 4. Quy trình Release Gate & HEAD-Bound Attestation

Workflow `.github/workflows/release.yml` thực hiện fail-closed theo trình tự:

1. **Metadata, Repo Visibility & SemVer Gate:** kiểm tra clean tree, tag format, `origin/main` ancestry, không ghi đè release đã tồn tại, khớp phiên bản 1-1 và truy vấn `gh api` xác nhận `repo_is_private` / `repo_visibility` (xác định `target_channel` là `public_github_release`, `public_ci_artifact` hoặc `private_ci_artifact`).
2. **Evidence-Based Distribution Gate & Build-time Model Acquisition:**
   - Chạy `--verify-distribution-permission` **trước** khi tải hoặc stage bất kỳ tệp mô hình nào.
   - Nếu được phép, tải gói 4 model thật + preprocessor + demo CSV từ nguồn được cấp phép, kiểm tra SHA-256 và stage vào `desktop/src-tauri/staged_bundle/`.
3. **Code Quality, OpenAPI, Governance & Tests:**
   - `python scripts/check_environment.py`, `ruff`, `black --check`, `scripts/export_openapi_spec.py --check`, `--verify-distribution-permission research-only --target-channel local_offline`, `pytest tests/unit tests/contract tests/integration -q`.
   - `npm --prefix desktop ci/run check/test/build`, `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.
4. **Build PyInstaller Sidecar (`scripts/build_backend_sidecar.py`) & Standalone NSIS Installer (`tauri.standalone.conf.json`).**
5. **Embedded Artifacts Verification Gate & Standalone E2E trên máy build:**
   - Chạy `verify_companion_artifacts.py --verify-e2e --standalone-embedded --require-clean-git --no-repo-root-env --installer-path ... --sums-file ... --compiled-exe ... --expect-sidecar-sha256 ... --output-json dist/release-assets/release_e2e_verification.json`:
     - Kiểm tra cài đặt NSIS im lặng, layout nhúng (sidecar SHA-256 + `EMBEDDED_SHA256SUMS.txt` + `EMBEDDED_ARTIFACTS_MANIFEST.json`), `PATH` không phụ thuộc Python hệ thống và không dùng companion ngoài thư mục ứng dụng.
     - Kiểm tra **session auth fail-closed** (từ chối request thiếu/sai `X-Sentinel-Session-Token` với HTTP `401/403`), đủ 4 model `READY`, inference/evaluation, OOD (`ABSTAINED_OOD`), anti-spoof provenance, xuất CSV an toàn, restart sidecar kiểm tra SQLite persistence, đóng sạch không rò rỉ tiến trình và `uninstall.exe /S`.
   - Kiểm chứng lại attestation với `--expect-commit`, `--expect-installer-sha256` và `--expect-sidecar-sha256`. Máy build có repository và toolchain. Kết quả smoke giữ `clean_machine_status="NOT VERIFIED"`.
   - Để xác minh **`independent_windows_vm`**, dùng đúng installer từ lần chạy chuẩn bị phát hành và luồng **Controller ↔ Clean Windows Target**:
     - **Build/Verification Controller** (có Git, Python, repository) phát hành single-use challenge (`--issue-vm-challenge`) gắn `source_commit`, `installer_sha256`, `sidecar_sha256`, `compiled_exe_sha256`.
     - **Clean Windows Test Target** chỉ chạy PowerShell gốc (`scripts/vm_target_e2e.ps1`) với bộ cài `.exe` và challenge JSON — **không** cần Git, Python, Rust, Node.js, source checkout, Companion Bundle hay secret ký attestation — xuất `target_evidence.json`.
     - **Controller / Trusted Witness Authority** ký witness receipt (`--sign-vm-witness`, ngoài trust boundary của máy đích) và xác minh bằng `--verify-target-evidence --vm-challenge ... --vm-witness ... --consumed-nonces-file ... --clean-machine-e2e`. Dùng cùng một ledger JSON trên đĩa cục bộ của Controller cho mọi tiến trình xác minh trong cùng hệ thống. Giữ ledger và tệp `.lock` qua các lần chạy và restart, ở thư mục chỉ Controller được ghi. Thiếu ledger, ledger hỏng, lỗi ghi hoặc nonce đã dùng đều từ chối cấp attestation Clean VM. Nếu ghi báo cáo đầu ra thất bại sau khi đã lưu nonce, phát hành challenge mới. Luồng `--independent-vm-evidence` cũ đã ngừng hỗ trợ.
     - Trước khi ký bằng chứng Stable, witness ghi nhận kết quả thực tế cho cả `windows_10_x64` và `windows_11_x64` trong `windows_acceptance` của target evidence. Mỗi mục cần `evidence_ref` trỏ tới biên bản và các trường đã kiểm tra thành công `offline`, `standard_user`, `unicode_and_spaces`, `windows_reboot`, `webview2_gui_workflow`, `model_error`, `uninstall`. Luồng GUI gồm Import → Analyze → Compare → Export và Security Dry-Run. Chỉ dùng `true` khi witness đã xác minh đúng bộ cài trên VM tương ứng. Bước tự động kiểm tra restart ứng dụng, còn reboot Windows và thao tác WebView2 cần bằng chứng riêng. Controller ký toàn bộ báo cáo và ràng buộc với mã băm target evidence.
6. **Gated Artifact Upload & GitHub Release Publish:**
   - Upload bộ cài ứng viên từ lần chạy `workflow_dispatch` khi gate phân phối trả về `upload_allowed == 'true'`. Tên asset giữ nguyên phiên bản desktop. `tag_label` đặt tên cho artifact của lần chạy.
   - Sau khi nghiệm thu, cung cấp run ID qua `VERIFIED_WINDOWS_CANDIDATE_RUN_ID`, báo cáo Controller đã ký qua `VERIFIED_WINDOWS_VM_ATTESTATION` và khóa xác minh qua `NETFLOW_VM_ATTESTATION_HMAC_KEY`. Tag job tải lại đúng ứng viên cùng commit. Bước publish kiểm tra lại quyền phân phối, SHA-256 installer/sidecar và `--require-stable-windows-e2e` trước khi gọi `gh release create`. Bộ cài ứng viên có thời hạn lưu 7 ngày.
7. **Always Cleanup:** dọn các tệp build, staging, ứng viên và release assets khỏi workspace của runner ở cuối job.
8. **Database & Artifact Migration for v2.0 (Issue #80):**
   - Khi cài đặt đè hoặc nâng cấp từ v1.0.0 lên v2.0.0, bộ cài tự động gọi `scripts/migrate_v1_to_v2.py --db-path <db_path>` để cập nhật schema SQLite idempotent và tạo backup.
   - Các artifact mô hình và preprocessor từ v1.0.0 tiếp tục được tái sử dụng trực tiếp nếu SHA-256 không đổi.
