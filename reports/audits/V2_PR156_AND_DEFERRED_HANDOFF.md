# Kế hoạch Bàn giao Chậm Tiến độ (`#73`, `#148`, `#152`) & Đề xuất Cập nhật PR `#156` — NetFlow Sentinel v2.0

- **Tài liệu:** `reports/audits/V2_PR156_AND_DEFERRED_HANDOFF.md`
- **Ngày lập / Cập nhật:** `2026-11-18` (`UTC+7`)
- **Historical Implementation Snapshots (`feat/v2-integration`):**
  - `a6c87ae8397e466ab1bd3d19f82d880e71084b88` (`14` commits ahead, `0` behind `main` @ `42a656aa76f6a4cb415f858d7179aa3d8f277335`; CI Workflow **Run `#211` / ID `44278751854`**, `7/7` `SUCCESS`).
  - `5483794160e877bf2d65144f30fd1ffc181372c3` (`15` commits ahead, `0` behind `main`; CI Workflow **Run `#212` / ID `44312426631`**, `7/7` `SUCCESS`; nhận **`1` submitted GitHub review `CHANGES_REQUESTED` bởi `ViolaPeracia`** ngày `2026-11-18T13:46:21Z`, nêu `P1-01`, `P2-01..P2-03`, `P3-01`, `P3-02`).
- **Current Remediation Snapshot (`feat/v2-integration` sau `5483794`):** Khắc phục `P1-01` (nối mặc định fail-closed `"deployment"` vào Tauri sidecar + Python fallback, `run_api.py`, `create_app`, `LiveRuntime`, `LiveTelemetryService`, `LiveSystemOrchestrator`, `RealtimeInferenceEngine`; giữ inference `UNAVAILABLE` nếu thiếu `NETFLOW_OOD_GATE_SHA256`), `P2-02` (đồng bộ docs + trạng thái review), `P2-03` (`PARTIAL_UNANCHORED` khi thiếu trusted SHA), `P3-01` (`pytest -rs` trong `ci.yml`), và `P3-02` (`E0_frozen_18f_reference` khớp RF `is_canonical_baseline=false`).
- **Model Training Provenance (Tách biệt):** `training_git_commit = 79ebb678b87de19cc6b664b587726983fecaf98f` (`git_dirty = true`, `git_clean = false`, `worktree_provenance = "DIRTY_DISCLOSED"`).
- **Nhánh Website tham chiếu (`origin/site-source`):** `a01bd38ad705577fc210fdeeeb61ccbd80a0ac42` (`77` tệp: `15` MDX VI + `15` MDX EN = `30` tệp MDX, các trang `.astro`, views, scripts, workflow)
- **Pull Request `#156`:** `OPEN`, `isDraft: true`, `feat/v2-integration` $\to$ `main` *(giữ nguyên trạng thái **DRAFT / DO NOT MERGE**; không push lên `main`, không tự ý bỏ Draft hay merge, không build `.exe`/`.msi`/NSIS và không sửa nhánh `site-source`)*

---

## Tóm tắt Trạng thái Các Hạng mục Bàn giao

| Hạng mục | Issue / PR | Trạng thái Hiện hành | Kết luận & Ranh giới |
|---|---|---|---|
| **D — Windows Standalone Installer v2.0 & Clean VM E2E** | `#73` (`OPEN`, `0/8` AC, `milestone: None`), `#148` (`OPEN`, `0/4` AC, `M6.7`) | **`DEFERRED / BLOCKED / NOT VERIFIED`** | Đã sửa `tauri.standalone.conf.json`, `vm_target_e2e.ps1` và staging/verify `ood_reference_gate.json` + AE `score_normalization.json` (`20` `companion_files`, `ood_gate: FITTED`) ở `WP5`. Tuy nhiên `.venv` mới đạt `FRONTEND_READY` (`pyinstaller: false`, `makensis: false`, `staged_bundle_manifest: false`); chưa build `.exe`, chưa chạy Clean Windows 10/11 VM E2E; `DISTRIBUTION_AUTHORIZATION.json` giữ `approved: false`. |
| **F — Website `site-source` v2.0 & Guides** | `#152` (`OPEN`, `1/4` AC, `M6.7`) | **`OPEN (1/4 AC) / STALE V1`** | Nhánh `origin/site-source` (`a01bd38ad705577fc210fdeeeb61ccbd80a0ac42`, 77 tệp) vẫn đóng băng ở `v0.6.0` / `NF-UNSW-NB15-v3` / `55` cột / `47` đặc trưng / snapshot `main@d1d16e1cafa79a8f515efa4b0a0e60a50a3b5e48`. Giữ `OPEN`; chỉ cập nhật sau khi PR `#156` merge `main`. |
| **PR `#156` — Tích hợp v2.0.0** | PR `#156` (`feat/v2-integration` $\to$ `main`) | **`OPEN / DRAFT (DO NOT MERGE)`** | Các mốc lịch sử `a6c87ae` (`Run #211`) và `5483794` (`Run #212`, `1` review `CHANGES_REQUESTED` bởi `ViolaPeracia`) đạt `7/7` CI; đợt khắc phục sau `5483794` hoàn tất `P1-01` product runtime policy, `P2-02`/`P2-03`, `P3-01` (`-rs`), `P3-02` (`E0_frozen_18f_reference`), giữ `RESEARCH_ONLY` & `approved: false`, chạy CI trên commit mới nhất và mời re-review. |

---

## Phần 1 — Kế hoạch Phụ thuộc 12 Bước cho Windows Standalone Installer v2.0 (Issues `#73` & `#148`)

### 1.1. Làm rõ Sự thay thế Nghiệp vụ Pháp lý UQ `454104` của Legacy v1 `#73` bởi Hard Cutover `v2`

- **Trạng thái Issue `#73`:** `OPEN` (`milestone: None`, `0/8` AC): `chore(release,windows): follow-up clean Windows VM acceptance, binary release & UQ 454104 licensing (#71)`.
- **Vì sao UQ `454104` AC-14 của `#73` đã bị thay thế (Superseded):**
  1. Trong `#73`, **AC-14** (`DEFERRED / NOT VERIFIED — BLOCKED`) yêu cầu bằng chứng pháp lý cho phép phân phối công khai các `.joblib`, preprocessor và `demo_*.csv` dẫn xuất từ **`NF-UNSW-NB15-v3`** (University of Queensland, **UQ License ID `454104`**, DOI `10.48610/6E0EDA1`, điều khoản phi thương mại hạn chế), đồng thời ghi chú bộ cài v1 cục bộ `NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe` tại commit `e6be2ea`.
  2. Trên nhánh `feat/v2-integration`, dự án đã thực hiện **Hard Cutover v2** ([`docs/adr/ADR-dataset-hard-cutover-v2.md`](../../docs/adr/ADR-dataset-hard-cutover-v2.md), [`docs/MIGRATION_V1_TO_V2.md`](../../docs/MIGRATION_V1_TO_V2.md)): loại bỏ hoàn toàn `NF-UNSW-NB15-v3` và hợp đồng 47 cột nProbe khỏi active pipeline (`ModelRegistry`, `TrainOnlyPreprocessor`, `InferencePipeline`, FastAPI, Desktop UI) và cách ly toàn bộ di sản v1 vào thư mục chỉ đọc `*/historical/nf_unsw_nb15_v3/`.
  3. Toàn bộ 4 mô hình `.joblib`, `v2_flow_preprocessor.joblib` và `data/demo/demo_*.csv` v2 hiện tại đều được huấn luyện/trích xuất **100% từ `AIT-NDS-v2`** (`10.5281/zenodo.13168643`, **`CC BY 4.0`**); `CTU-SME-11` (`10.5281/zenodo.7958258`) và `AIT-ADS` (`10.5281/zenodo.8263181`) cũng áp dụng **`CC BY 4.0`**. Tập log **`AIT-LDS-v2.1`** (`10.5281/zenodo.19483937`, **`CC BY-NC-SA 4.0`**) được cách ly hoàn toàn khỏi trọng số ML và bộ demo phát hành.
  4. Theo đó, **AC-14 về UQ `454104` của `#73` được thay thế** bằng cơ chế kiểm soát mới tại [`reports/governance/DISTRIBUTION_AUTHORIZATION.json`](../governance/DISTRIBUTION_AUTHORIZATION.json) (`schema_version: 2`, `dataset_license_id: "CC-BY-4.0"`, `forbids_commercial_use: false`, `requires_attribution_notices: true`, `legal_basis: "verified-open-redistribution-license"`, hiện ở trạng thái **`approved: false`**, **`status: "HOLD_FOR_MAINTAINER_SIGNOFF"`**).
- **Phần của `#73` KHÔNG bị thay thế mà được kế thừa trực tiếp sang `#148`:**
  - Các tiêu chí kỹ thuật Clean Windows 10/11 x64 VM của `#73` (**AC-03, AC-07, AC-08, AC-10, AC-12, AC-13, AC-15**: cài đặt offline bằng Standard User, DPI scaling `1366×768`/High-DPI & bàn phím, thao tác GUI WebView2 đầy đủ, quy trình Controller–Target–Witness `--clean-machine-e2e --require-stable-windows-e2e`, và bộ binary assets kèm `release_e2e_verification.json`) vẫn giữ trạng thái `DEFERRED / NOT VERIFIED` và được **kế thừa toàn phần vào `#148`** (*"Kế thừa quy trình VM của #73, không tạo lại"*).

---

### 1.2. Các Khoảng trống Kỹ thuật & Tài liệu Đã Xác minh Trước Khi Build Installer

Kiểm tra trực tiếp mã nguồn và cấu hình đóng gói ghi nhận **8 khoảng trống bắt buộc phải xử lý** trước khi build NSIS `.exe` chính thức:

1. **`desktop/src-tauri/tauri.standalone.conf.json:12-14` (`[FIXED IN WORKING TREE]`):**
   - Trước đó khai báo 3 đường dẫn `staged_bundle/artifacts/models/isolation_forest/{model_config,threshold,training_metadata}.json` không tồn tại và thiếu `isolation_forest_manifest.json`. **Đã sửa trên working tree** thành `isolation_forest.joblib` + `isolation_forest_manifest.json` khớp `MODEL_SPECS["isolation_forest"]`.
2. **`artifacts/ml/ood_reference_gate.json` & `artifacts/models/autoencoder/score_normalization.json` (`[FIXED IN WORKING TREE — WP5]`):**
   - **Đã sửa & viết regression tests trên working tree:** Bổ sung cả `artifacts/ml/ood_reference_gate.json` (`8a52bfe5...`, `2,658 B`) và `artifacts/models/autoencoder/score_normalization.json` (`d7bcb78f...`, `3,891 B`) vào `desktop/src-tauri/tauri.standalone.conf.json` và `scripts/verify_companion_artifacts.py` (`20` `companion_files`, `MODEL_SPECS["autoencoder"]`, `stage_embedded_bundle()`, `verify_installed_standalone_layout()` yêu cầu `ood_gate.status == "FITTED"`), đồng thời cứng hóa `OODRejectionGate.from_artifact()`, `AutoencoderModel._verify_ae_score_normalization_payload()`, và `RealtimeInferenceEngine` fail-closed theo `runtime_mode` (`"deployment"` vs `"research"`).
3. **`scripts/vm_target_e2e.ps1:3, 457, 526` (`[FIXED IN WORKING TREE]`):**
   - Trước đó ép cứng `(198, 2)` gây fail trên `demo_flows.csv` v2 `(200, 0)`, ghi `v1.0.0` và gửi `"source:nf-v3-canonical"`. **Đã sửa trên working tree** chấp nhận cả `(200, 0)` lẫn `(198, 2)`, cập nhật `v2.0.0 standalone installer` và `"source:ait-nds-v2"`.
4. **Dấu vết `v1.0.0` trong `docs/RELEASE_PROCESS.md:92` & `.github/workflows/release.yml:12,312` (`[FIXED IN WORKING TREE]`):**
   - **Đã sửa trên working tree** `docs/RELEASE_PROCESS.md:92` (xóa câu tái sử dụng artifact `v1.0.0`, nêu rõ v2 hard cutover fail-closed) và cập nhật `v2.0.0-dryrun` / `v2.0.0 standalone builds` trong `release.yml:12,312`.
5. **Dirty Git Provenance trên 4 model manifests (`git_dirty: true`):**
   - Cả 4 manifest trong `reports/models/*_manifest.json` ghi `git_commit: "79ebb678b87de19cc6b664b587726983fecaf98f"`, `git_dirty: true`, `git_clean: false`, `worktree_provenance: "DIRTY_DISCLOSED"` (`172–199` đường dẫn dirty lúc train), trong khi `.github/workflows/release.yml:99-103, 515` và `verify_companion_artifacts.py --require-clean-git` từ chối mọi working tree bẩn.
6. **Sidecar binary cũ trên đĩa cục bộ & rà soát `HIDDEN_IMPORTS` (`scripts/build_backend_sidecar.py`):**
   - `desktop/src-tauri/binaries/netflow-sentinel-backend-x86_64-pc-windows-msvc.exe` (`127,964,277 B`, mtime `2026-11-16T16:38:58Z`, gitignored tại `.gitignore:80`) là bản build cũ từ thời v1; bắt buộc biên dịch lại cho v2.
   - `HIDDEN_IMPORTS` trong `scripts/build_backend_sidecar.py:49-142` cần đối chiếu đủ các module v2 bổ sung gần nhất (`network_anomaly.api.live_runtime`, `network_anomaly.streaming.live_service`, `network_anomaly.models.registry`, `network_anomaly.models.scoring`, `network_anomaly.models.{random_forest_protocol,xgboost_protocol,provenance}`, `network_anomaly.data.split`, `network_anomaly.ingestion.adapters.{canonical_v2,zeek,netflow_v5,suricata,aws_vpc}`).
7. **Placeholder bản quyền & Notice Rust Crates (`THIRD_PARTY_NOTICES.md` `[FIXED IN WORKING TREE]`):**
   - **Đã bổ sung trên working tree** direct Rust crates (`tauri-plugin-dialog`, `serde`, `serde_json`, `reqwest`, `tokio`, `getrandom`) và `MPL-2.0` transitive crates (`cssparser`, `cssparser-macros`, `dtoa-short`, `option-ext`, `selectors`) vào `THIRD_PARTY_NOTICES.md`.
   - `LICENSE:1` (`[Project Team / Course Assignment — placeholder; ...]`) và `pyproject.toml:12-13` (`example@institution.edu`) vẫn chờ owner/chủ sở hữu pháp lý điền chính thức trước public release.
8. **Thiếu công cụ đóng gói trên máy cục bộ & cổng `DISTRIBUTION_AUTHORIZATION.json`:**
   - Kết quả chạy `scripts/build_installer_v2.py --check-only` cho thấy `status: "FRONTEND_READY"`, thiếu `pyinstaller: false`, `makensis: false`, `staged_bundle_manifest: false`.
   - `reports/governance/DISTRIBUTION_AUTHORIZATION.json` giữ `public_release_authorization.approved: false` (`status: "HOLD_FOR_MAINTAINER_SIGNOFF"`, `evidence_sha256: null`), chặn fail-closed mọi upload/publish công khai (`public_ci_artifact`, `public_github_release`).

---

### 1.3. Kế hoạch Phụ thuộc 12 Bước (Dependency Plan — Chỉ Lập Kế hoạch, Không Thực thi Build)

| Bước | Tên Giai đoạn | Phụ thuộc | Đầu vào / Điều kiện Bắt buộc | Hành động & Lệnh Tham chiếu | Đầu ra & Tiêu chí Đạt (`Gate`) |
|---:|---|---|---|---|---|
| **01** | **Đóng băng Git Sạch & Hoàn tất Spec/Notice Trước Build** | Không | Working tree hiện tại trên `feat/v2-integration` | Các lỗi `tauri.standalone.conf.json`, staging `ood_reference_gate.json` + AE `score_normalization.json` (`WP5`), `vm_target_e2e.ps1:3,457,526`, `RELEASE_PROCESS.md:92`, `release.yml:12,312` và Rust crates trong `THIRD_PARTY_NOTICES.md` **đã được sửa sẵn trên working tree**; còn cần điền chủ sở hữu thật ở `LICENSE:1` / `pyproject.toml:12-13`, commit sạch và merge/sync nhánh chuẩn. | `git status --porcelain` rỗng; `git diff --check` exit `0`; toàn bộ CI checks xanh trên commit sạch. |
| **02** | **Tái xác minh / Tái huấn luyện Artifact Gắn Commit Sạch** | Bước `01` | Raw `AIT-NDS-v2` & `CTU-SME-11` đã verify (`fetch_multi_source_dataset.py --verify-only`) | Tái xác minh hoặc chạy lại chuỗi `train_{random_forest,xgboost,isolation_forest,autoencoder}.py` + `prepare_demo_dataset.py` + `OODReferenceGate` trên commit sạch để loại bỏ `DIRTY_DISCLOSED` (`git_dirty=false`). Đóng gói bundle nguồn build-time (`package_companion_bundle`) nếu build trên CI riêng tư. | `verify_companion_artifacts.py` trả `overall_status: READY` (`4/4` models, `demo_ready: true`); 4 manifest ghi `git_clean: true`. |
| **03** | **Kiểm tra Toolchain & Đồng bộ SemVer** | Bước `01` | Python 3.12 (`.[dev,packaging]`), Node 22, Rust MSVC stable, NSIS `makensis`, Windows SDK | Chạy `scripts/check_environment.py`, `scripts/check_desktop_version.py --check` (`2.0.0` trên 5 file desktop, `0.1.0` FastAPI), `scripts/export_openapi_spec.py --check`, `scripts/build_installer_v2.py --check-only`. | `build_installer_v2.py --check-only` đạt `tools.pyinstaller=true`, `tools.makensis=true` (chỉ còn thiếu `staged_bundle_manifest` trước Bước `04`). |
| **04** | **Cổng Quyền Phân phối & Stage `staged_bundle/`** | Bước `02`, `03` | `DISTRIBUTION_AUTHORIZATION.json`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE` | Chạy fail-closed `verify_companion_artifacts.py --verify-distribution-permission <scope> --target-channel <channel>` **trước** khi stage (`private-build-only` + `local_offline` cho thử nghiệm cục bộ, hoặc `private_ci_artifact` với `repo_is_private=true`; cấm `public_*` khi `approved=false`). Sau đó chạy `--stage-embedded-dir desktop/src-tauri/staged_bundle`. | `desktop/src-tauri/staged_bundle/` có đủ 4 model, preprocessor, manifests, `data/demo/`, notices, `EMBEDDED_ARTIFACTS_MANIFEST.json`, `EMBEDDED_SHA256SUMS.txt`. |
| **05** | **Đóng gói PyInstaller v2 Backend Sidecar** | Bước `03` | `scripts/build_backend_sidecar.py`, `scripts/run_api.py`, rà soát `HIDDEN_IMPORTS` | Chạy `python scripts/build_backend_sidecar.py --output-json dist/release-assets/sidecar_build_v2.json` để biên dịch lại và ghi đè `desktop/src-tauri/binaries/netflow-sentinel-backend-x86_64-pc-windows-msvc.exe` (xóa vết binary v1 ngày `2026-11-16`). | Binary sidecar mới, zero dependency Python hệ thống; `sidecar_build_v2.json` ghi nhận `status: "READY"`, `size_bytes`, `sha256`. |
| **06** | **Build Production Frontend (Svelte 5 + Vite)** | Bước `03` | `desktop/package.json`, `desktop/package-lock.json` | Chạy `npm --prefix desktop ci`, `npm --prefix desktop run check`, `npm --prefix desktop test`, `npm --prefix desktop run build`. | `0` lỗi TypeScript/Svelte, Vitest PASS, tạo `desktop/dist/` sạch. |
| **07** | **Cargo Quality Gate + Tauri 2 NSIS Bundle + WebView2 Offline** | Bước `04`, `05`, `06` | `tauri.conf.json` (`webviewInstallMode: offlineInstaller`, `installMode: currentUser`), `tauri.standalone.conf.json` | Chạy `cargo fmt --check`, `cargo clippy --release --all-targets -- -D warnings`, `cargo test --release --lib`, sau đó `npx tauri build --config src-tauri/tauri.standalone.conf.json --bundles nsis` (qua `build_installer_v2.py`). | Sinh `desktop/src-tauri/target/release/netflow-sentinel-desktop.exe` và `*_2.0.0_x64-setup.exe` kèm WebView2 offline installer; `rust-cache` tắt trên release build. |
| **08** | **Build-Host Standalone Smoke E2E & Checksum Manifest** | Bước `07` | `dist/release-assets/NetFlow-Sentinel-v<ver>-windows-x64-setup.exe`, `SHA256SUMS.txt` | Chạy `verify_companion_artifacts.py --verify-e2e --standalone-embedded --require-clean-git --no-repo-root-env --installer-path ... --sums-file ... --compiled-exe ... --expect-sidecar-sha256 ... --output-json dist/release-assets/release_e2e_verification.json` và `--verify-attestation ... --require-nsis-e2e --require-demo-files --require-bundled-resources --require-standalone-embedded` (lưu ý `build_installer_v2.py:200` mặc định `--version-label 2.0.0-pilot`, còn `release.yml:610` yêu cầu khớp đúng `NetFlow-Sentinel-$tagName-windows-x64-setup.exe`, ví dụ `--version-label 2.0.0` cho tag `v2.0.0`). | `e2e_status: PASS`, `standalone_embedded_mode: true`, `session_auth_fail_closed: true`; ghi nhận trung thực `clean_machine_status: "NOT VERIFIED"` cho tới Bước `11`. |
| **09** | **Phê duyệt `DISTRIBUTION_AUTHORIZATION.json` & Cấu hình Secrets** | Bước `01`, `02`, `08` | Hồ sơ đối chiếu `CC BY 4.0`, 0% `AIT-LDS-v2.1`, GPL-2.0 Bootloader Exception, `MPL-2.0`, WebView2 | Maintainer/Chủ sở hữu pháp lý lập biên bản phê duyệt ngoài repo, băm `SHA-256` (64-hex), cập nhật `reports/governance/DISTRIBUTION_AUTHORIZATION.json` (`approved: true`, `status: "APPROVED"`, `maintainer_approver`, `approved_at_utc`, `evidence_ref`, `evidence_sha256`) bằng commit sạch; cấu hình `secrets.DISTRIBUTION_EVIDENCE_SHA256`, `vars.ALLOW_EMBEDDED_MODEL_REDISTRIBUTION="public-release-approved"`, `vars.MODEL_BUNDLE_*`. | `--verify-distribution-permission public-release-approved --target-channel public_github_release --require-evidence-hash --public-release` trả `APPROVED`. |
| **10** | **Chính sách Ký số Authenticode & `SHA256SUMS.txt` Cuối** | Bước `07`, `09` | Chứng chỉ Code Signing (nếu có) hoặc quyết định phát hành không ký | Nếu có chứng chỉ Authenticode: ký `netflow-sentinel-desktop.exe` + `netflow-sentinel-backend.exe` **trước** khi đóng NSIS và ký lại `.exe` setup **trước** khi sinh `SHA256SUMS.txt` + VM challenge. Nếu không có chứng chỉ: ghi minh bạch trạng thái **Unsigned Binary / SmartScreen warning expected** trong `docs/releases/v2.0.0.md` và `SHA256SUMS.txt` (yêu cầu bảo mật `#148`). | Hash cuối của setup `.exe`, desktop `.exe` và sidecar `.exe` khớp 100% giữa `SHA256SUMS.txt` và `vm_challenge.json`. |
| **11** | **Clean Windows 10/11 x64 Standard User VM E2E (`#73` + `#148` + `#149`)** | Bước `08`, `10` | 2 VM độc lập (`windows_10_x64`, `windows_11_x64`), offline, Standard User, không Git/Python/Rust/Node | 1) Controller phát hành challenge (`--issue-vm-challenge`).<br>2) Target chạy `scripts/vm_target_e2e.ps1` (install `/S`, Unicode/spaces path, kiểm `EMBEDDED_SHA256SUMS.txt`, scrubbed `PATH`, cold WebView2 + sidecar, 4/4 models `READY`, session token 401/403, analyze/evaluate/export, restart SQLite persistence, zero orphan, uninstall `/S`).<br>3) Witness kiểm chứng thủ công đầy đủ UI trên WebView2 (`offline`, `standard_user`, `unicode_and_spaces`, `windows_reboot`, `webview2_gui_workflow` Import→Analyze→Compare→Export + Live/Behavioral/Timeline/Crypto + `Shift+F9` Dev Logs + DPI `1366×768` + `model_error` + `uninstall` + upgrade `v1→v2` DB qua `migrate_v1_to_v2.py`).<br>4) Witness ký (`--sign-vm-witness`); Controller xác minh (`--verify-target-evidence --consumed-nonces-file ... --clean-machine-e2e`). | `target_evidence.json` + signed witness + `release_e2e_verification.json` vượt qua `--require-stable-windows-e2e --verify-vm-witness` cho cả Windows 10 & Windows 11. |
| **12** | **Gắn Tag `v2.0.0`, Publish GitHub Release & Scrub Workspace** | Bước `09`, `11` | `VERIFIED_WINDOWS_CANDIDATE_RUN_ID`, `VERIFIED_WINDOWS_VM_ATTESTATION`, `NETFLOW_VM_ATTESTATION_HMAC_KEY`, `docs/releases/v2.0.0.md` | Cập nhật `docs/releases/v2.0.0.md` từ trạng thái Source Release sang Standalone Release notes; gắn tag `v2.0.0` trên commit tổ tiên của `origin/main`; chạy `.github/workflows/release.yml` để tái kiểm phân phối + attestation rồi `gh release create` đính kèm `NetFlow-Sentinel-v2.0.0-windows-x64-setup.exe`, `SHA256SUMS.txt`, `release_e2e_verification.json`, `NOTICE`, `THIRD_PARTY_NOTICES.md`. Job tự dọn `build/`, `staged_bundle/`, `binaries/*.exe`, `dist/` với `if: always()`. | GitHub Release `v2.0.0` công khai hợp lệ; workspace runner sạch 0 byte rò rỉ `.joblib`/`.exe`; đủ điều kiện đóng `#73` & `#148`. |

---

## Phần 2 — Kiểm toán Read-Only Nhánh Website `origin/site-source` (Issue `#152`)

### 2.1. Bằng chứng Snapshot & Trạng thái Issue `#152`

- **GitHub Issue `#152`:** `OPEN` (`[M6.7][P1][Docs] User guide, deployment guide và website site-source v2.0`), **`1/4` AC đã tick**:
  - `[ ]` Hướng dẫn chạy đúng từ máy sạch.
  - `[ ]` Website build/check PASS và không có claim vượt bằng chứng.
  - `[ ]` Có trang mô tả 3 chế độ và giới hạn pháp lý.
  - `[x]` Không đưa dữ liệu/dataset vào website.
- **Snapshot `origin/site-source` (chỉ đọc):**
  - Commit HEAD: **`a01bd38ad705577fc210fdeeeb61ccbd80a0ac42`** (`a01bd38 fix(site): restore all nodes and connectors in architecture SVG`).
  - Tổng số tệp trên cây `origin/site-source`: **`77` tệp** (Astro 7 + MDX + Tailwind v4 + Playwright smoke + Python claim checker).
  - **Không sửa đổi / không checkout / không đóng `#152`** trong phiên này.

### 2.2. Các Khẳng định v1 Lỗi thời Được Xác minh Trên `origin/site-source`

1. **Neo Commit & CI Checkout Cũ (`d1d16e1cafa79a8f515efa4b0a0e60a50a3b5e48`):**
   - `origin/site-source:.github/workflows/pages.yml:24`, `src/lib/links.ts:5`, `CLAIMS.md:3`, `README.md:3` và tất cả liên kết GitHub blob trong `30` tệp MDX (`15` `src/content/docs/*.mdx` + `15` `src/content/docs-en/*.mdx`) đều trỏ tới `main` tại commit `d1d16e1cafa79a8f515efa4b0a0e60a50a3b5e48` (ngày `16 Nov 2026`, giai đoạn `v0.6.0` / PR `#70`).
2. **Script Kiểm chứng Bằng chứng `scripts/check-evidence.py` Phá vỡ Nếu Đổi sang Commit v2:**
   - `scripts/check-evidence.py:26-56` đọc cứng `data/NF_UNSW_NB15_V3_MANIFEST.json`, assert `manifest["schema"]["column_count"] == 55`, đọc `reports/splits/nf_unsw_nb15_v3_split_manifest.json`, và đối chiếu các số v1 (`2,365,424`, `2,237,731`, `127,693`, 9 lớp tấn công UNSW từ `Exploits` đến `Worms` trong `src/pages/dataset.astro`; `1,655,797`, `345,371`, `345,953`, `9,443`, `8,860` trong `src/pages/results.astro`). Toàn bộ tệp v1 này đã chuyển vào `*/historical/nf_unsw_nb15_v3/` trên nhánh `feat/v2-integration`.
3. **Playwright Smoke Gate `scripts/smoke.mjs` Khóa Cứng Chuỗi v1:**
   - `scripts/smoke.mjs:58-65` assert `<h1>` trang dataset khớp `/NF-UNSW-NB15-v3/` và tìm chuỗi `"2,365,424 dòng"` / `"2,365,424 rows"`.
4. **Dữ liệu, Feature Contract & Số liệu Mô hình v1 Khắp Giao diện và Tài liệu:**
   - Khẳng định `NF-UNSW-NB15-v3` (`DOI 10.48610/6E0EDA1`, UQ non-commercial terms, `55` cột, `47` đặc trưng ML baseline `nf-unsw-nb15-v3-baseline-47`, `MIN_TTL` shortcut `0.999849`, `49.98% / 53.21%` vector lặp, `NF-CSE-CIC-IDS2018-v3` 100k sample `RF Recall 0.0 / FPR 0.3802`).
   - Thẻ benchmark cũ trên `HomeView`, `ModelsView`, `ResultsView`, `RoadmapView`, `CLAIMS.md` và `docs*/model-training.mdx`:
     - Random Forest `rf-heldout-ea330b9` (`F1 0.999853`, `TN=315,350, FP=7, FN=2, TP=30,594`),
     - XGBoost `xgb-baseline-1794755807` (`F1 0.999984`, `git_dirty=True` tại `7f51390`),
     - Isolation Forest `if-c4-20261115T055359Z` (`th -0.033527`, `Test F1 0.5064`, `Recall 0.8997`, Unknown `{Backdoor, Worms}` `0.8657`),
     - Autoencoder `ae_fpr_constrained_20261115T163000Z` (`47 -> 32 -> 16 -> 32 -> 47`, `th 17234985.792476`, `Test F1 0.1361`, `Recall 0.1093`, Unknown `0.0625`).
5. **Phiên bản Sản phẩm & Trạng thái Kiến trúc Lỗi thời (`v0.6.0` vs `v2.0.0`):**
   - Khẳng định phiên bản là `v0.6.0`, chỉ có `18` endpoint FastAPI, yêu cầu cài **Python `>= 3.12` + Companion Bundle rời** trên Windows, và liệt kê `AES-256-GCM keyring` + `live telemetry/PCAP/log correlation` là `DEFERRED` (trong khi v2 đã triển khai `Offline/Replay/Live`, 16-D Behavioral Vector, Risk 0–100, Trace Engine, AES-256-GCM DPAPI + Adaptive Key Rotation và kiến trúc Standalone PyInstaller sidecar, còn các phần thật sự hoãn/chặn là `UGR'16`, empirical `AIT` UID linkage, Rust collector `#128`, physical lab `#137`, Clean VM `#73`/`#148`, `DISTRIBUTION_AUTHORIZATION` `approved: false`).

---

### 2.3. Checklist Cập nhật Từng Tệp trên `site-source` (Khi Đủ Điều kiện Mở Khóa)

| Nhóm / Tệp trên `origin/site-source` | Nội dung Lỗi thời Hiện tại | Yêu cầu Cập nhật v2.0 |
|---|---|---|
| `.github/workflows/pages.yml` (`L24`) | `actions/checkout@v4` ghim `ref: d1d16e1cafa79a8f515efa4b0a0e60a50a3b5e48` | Cập nhật `ref` sang commit `main` sạch sau khi PR `#156` merge; giữ `python scripts/check-evidence.py`, `npm run check`, `npm run lint`, `npm run build`, `npm run verify:links`. |
| `src/lib/links.ts` (`L5`) | `evidenceCommit = "d1d16e1cafa79a8f515efa4b0a0e60a50a3b5e48"` | Cập nhật `evidenceCommit` khớp đúng SHA trên `main` hậu merge PR `#156`. |
| `CLAIMS.md` & `README.md` | Toàn bộ bảng claim & mô tả ghim `NF-UNSW-NB15-v3`, `55` cột, `v0.6.0`, UQ `454104`, 4 run v1 | Thay toàn bộ bằng claim matrix v2 (`AIT-NDS-v2`, `CTU-SME-11`, `AIT-ADS`, `AIT-LDS-v2.1` `CC BY-NC-SA 4.0`, `UGR'16 BLOCKED`, `canonical-flow-v2-18`, `v2-scenario-group-purged-v1`, 4 model v2 + negative results RQ2/RQ3/RQ4 + trạng thái `DEFERRED` của `#73/#148`, `#137`, `#153`, `DISTRIBUTION_AUTHORIZATION.json`). |
| `scripts/check-evidence.py` | Đọc `data/NF_UNSW_NB15_V3_MANIFEST.json`, assert `column_count == 55`, đọc `reports/splits/nf_unsw_nb15_v3_split_manifest.json` | Chuyển sang đọc `data/V2_SPLIT_MANIFEST.json`, `data/AIT_DATASETS_MANIFEST.json`, `data/CTU_SME_11_MANIFEST.json`, `reports/experiments/ml/model_comparison_report.json`, `reports/experiments/ml/ctu_cross_source_eval.json`; assert `canonical-flow-v2-18` (`18` features), `3,465,342` raw / `3,464,400` labeled (`2,097,891 / 377,704 / 988,805`), `CTU-Echo` (`76,073`), `CTU-Win7AD` (`175,146`). |
| `scripts/smoke.mjs` | Assert `/NF-UNSW-NB15-v3/` và `"2,365,424 dòng/rows"` | Cập nhật assertion khớp `AIT-NDS-v2` / `CTU-SME-11`, `3,464,400` flows (hoặc tiêu đề mới của `dataset/`), plus test chuyển trang tài liệu 3 chế độ & pháp lý mới. |
| `src/components/views/HomeView.astro` | Eyebrow `NF-UNSW-NB15-v3`, badge `v0.6.0`, metrics `2,36M / 47 / 4 / 18 endpoints`, F1 cards v1 | Cập nhật lên `NetFlow Sentinel v2.0`, `AIT-NDS-v2` + `CTU-SME-11`, `18` features (`canonical-flow-v2-18`), `3` modes (`Offline / Replay / Live`), metric `AIT-Test` (`RF 0.9950`, `XGB 0.9013`, `IF 0.5842`, `AE 0.5877`) + cảnh báo zero-shot `CTU-SME-11`. |
| `src/components/views/DatasetView.astro` & `src/pages/{,en/}dataset.astro` | `2,365,424 rows · 55 columns`, 9 UNSW categories, `NF_UNSW_NB15_V3_*`, UQ non-commercial | Thay bằng bảng đa nguồn v2: `AIT-NDS-v2` (`3,465,342` raw, `CC BY 4.0`), `CTU-SME-11` (`CTU-Echo 76,073`, `CTU-Win7AD 175,146` + `9,394` unmapped, `CC BY 4.0`), `AIT-ADS` (`CC BY 4.0`), `AIT-LDS-v2.1` (`CC BY-NC-SA 4.0`, excluded from weights, direct UID join `NO`), `UGR'16` (`BLOCKED HTTP 403`); schema `canonical-flow-v2-18` (6 base + 12 derived + 5 trace metadata + `taxonomy-v2`). |
| `src/components/views/ModelsView.astro` | 47 features, `1,655,797` Train, AE `47-32-16-32-47`, old thresholds & `Backdoor/Worms` | Cập nhật 18 features, `2,097,891` Train, `asinh_robust` (`MIN_BOUNDED_SCALE_FLOOR=0.25`), `OODReferenceGate`, AE `(18-16-8-16-18)`, thresholds v2 (`IF 0.031268`, `AE 0.000467`, `empirical_val_fpr <= 0.05`), và deployment tier (`RESEARCH_ONLY` / `MODEL_VALIDATED`). |
| `src/components/views/ResultsView.astro` & `src/pages/{,en/}results.astro` | Split `1,655,797 / 345,371 / 345,953 / 9,443 / 8,860`, v1 test tables, `IDS2018-v3` table, `v0.6.0` E2E | Cập nhật `AIT-Val` / `AIT-Test` (`988,805`), bảng `CTU-Echo` / `CTU-Win7AD` zero-shot + device-disjoint + CTU temporal, và toàn bộ bảng `RQ1–RQ6` kèm negative results (`H2=false`, `H3 simulation`, `H4 AE=0.2045`, `RQ5 simulation`). |
| `src/components/views/ResearchView.astro` | Phạm vi `v0.6.0` + 47 đặc trưng | Trình bày đủ `RQ1–RQ6` (`H1..H6`), kết quả âm (`H2, H3, H4`), khoảng cách synthetic-to-real và giới hạn `18-D` single-flow. |
| `src/components/views/ArchitectureView.astro` | SVG & text `v0.6.0`, `18` endpoint, AES keyring `DEFERRED` | Cập nhật SVG + mô tả v2: `Offline / Replay / Live`, `UnifiedSecurityEventV2`, Behavioral 16-D, Risk 0–100, Trace Graph/Timeline, AES-256-GCM DPAPI + Adaptive Rotation, Standalone PyInstaller sidecar; tách rõ phần thật sự `DEFERRED` (Rust collector `#128`, physical lab `#137`, Clean VM `#73/#148`). |
| `src/components/views/RoadmapView.astro` | Checkpoints M0–M7 v1 (`v0.6.0`) | Bổ sung `M6.1–M6.7` (`v2.0.0`), giữ trung thực `PR #156` status, `Source-Only` release status, và các hạng mục `BLOCKED`/`DEFERRED` (`#73/#148`, `#137`, `#152`, `#153`, `UGR'16`, `DISTRIBUTION_AUTHORIZATION`). |
| `src/layouts/Layout.astro`, `src/pages/{,en/}*.astro`, `src/content.config.ts`, `DocsIndexView.astro`, `DocDetailView.astro` | Tiêu đề/meta/placeholder tìm kiếm tham chiếu v1 hoặc thiếu link hướng dẫn 3 chế độ/pháp lý | Cập nhật branding `NetFlow Sentinel v2.0`, placeholder docs search, nav/footer legal & version labels. |
| `src/content/docs/*.mdx` (`15` tệp) & `src/content/docs-en/*.mdx` (`15` tệp) | Tất cả `30` tệp MDX gắn `d1d16e1...` và mô tả `NF-UNSW-NB15-v3`, `55` cột, `47` features, `v0.6.0`, `Companion Bundle` | Cập nhật đồng bộ song ngữ VI/EN toàn bộ `15` hướng dẫn (`overview`, `data-acquisition`, `data-validation`, `methodology`, `model-training`, `inference-and-ingestion`, `architecture`, `api-and-security-dry-run`, `desktop-and-windows`, `installation`, `development`, `testing`, `reproducibility`, `references`, `limitations`) sang v2 + **bổ sung hướng dẫn chuyên biệt đáp ứng AC3 `#152`** về **3 chế độ (Offline / Replay / Live), 4 dashboard mới, triển khai lab RFC 1918 và ranh giới pháp lý (`CC BY 4.0` vs `CC BY-NC-SA 4.0`, `HOLD_FOR_MAINTAINER_SIGNOFF`)**. |

### 2.4. Cổng Chặn (Blocking Gates) cho Issue `#152`

1. **Cổng 1 (`PR #156` Merged to `main`):** `src/lib/links.ts` (`evidenceCommit`) và `.github/workflows/pages.yml` (`checkout ref`) bắt buộc trỏ tới commit ổn định đã merge trên `main`; không neo vào nhánh `feat/v2-integration` chưa merge.
2. **Cổng 2 (Đồng bộ Số liệu & Negative Results v2):** Toàn bộ số liệu `RQ1–RQ6`, 4 model, `CTU-SME-11`, `OODReferenceGate` và cảnh báo `AIT-LDS-v2.1` / `UGR'16` phải đồng bộ 1-1 với commit trên `main` và vượt qua `scripts/check-evidence.py` đã viết lại.
3. **Cổng 3 (Cổng Phát hành Công khai & Clean VM `#73`/`#148`):** Khi `DISTRIBUTION_AUTHORIZATION.json` giữ `approved: false` và Clean VM E2E (`#73`/`#148`) giữ `NOT VERIFIED`, website tuyệt đối **không** đăng link tải `.exe` hay tuyên bố `Production-Ready` / `Clean VM Verified` — chỉ công bố bản `Source Release` / `Controlled Lab Prototype` và ranh giới pháp lý `CC BY 4.0` vs `CC BY-NC-SA 4.0`.
4. **Cổng 4 (Quality Gate trên nhánh `site-source`):** `python scripts/check-evidence.py`, `npm run check` (`astro check`), `npm run lint` (`prettier --check`), `npm run build` (`astro build`), `npm run verify:links` và `npm run smoke` (Playwright + axe-core) đều phải PASS. Hiện tại **`#152` giữ `OPEN (1/4 AC)`**.

---

## Phần 3 — Nội dung Mô tả Đồng bộ cho PR `#156` (Cập nhật trực tiếp trên GitHub qua `gh pr edit 156`, giữ nguyên `OPEN / Draft`)

> [!IMPORTANT]
> PR `#156` (`feat/v2-integration` $\to$ `main`) **tiếp tục giữ trạng thái `OPEN` và `Draft` (`Do Not Merge`)**. Không merge, không bỏ Draft, và không push lên `main`. Bản template dưới đây đồng bộ kiến trúc v2.0.0, WP1–WP7 + WP-A/B/C/F, trạng thái model (`RESEARCH_ONLY`, `DIRTY_DISCLOSED` @ `79ebb678`), CI `Run #211` trên `a6c87ae`, acceptance criteria, governance (`approved: false`), và reviewer checklist; bản cập nhật trực tiếp lên GitHub PR `#156` bổ sung SHA commit remediation cuối cùng và CI run mới nhất sau khi push.

---

### [Bắt đầu Nội dung Đồng bộ PR `#156`]

```markdown
## Summary

Pull Request thực hiện **Full Dataset Migration (Hard Cutover)** và tích hợp toàn bộ phân hệ **NetFlow Sentinel v2.0.0** trên nhánh `feat/v2-integration` vào `main`, hướng tới mốc **Academic & Controlled Lab Functional Prototype**.

> **Trạng thái PR:** **OPEN / DRAFT — DO NOT MERGE (KHÔNG tuyên bố Production-Ready hoặc Public-Release-Ready).**
> - **Historical Implementation Snapshots:** `a6c87ae8397e466ab1bd3d19f82d880e71084b88` ([Run #211 / ID 44278751854](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/actions/runs/44278751854), `7/7` `SUCCESS`) và `5483794160e877bf2d65144f30fd1ffc181372c3` ([Run #212 / ID 44312426631](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/actions/runs/44312426631), `7/7` `SUCCESS`; nhận review `CHANGES_REQUESTED` của `ViolaPeracia`). Đợt khắc phục mới nhất đóng `P1-01`/`P2-02`/`P2-03`/`P3-01`/`P3-02` trên `feat/v2-integration`.
> - **Model Training Provenance (Tách biệt):** `training_git_commit = 79ebb678b87de19cc6b664b587726983fecaf98f`, `git_dirty = true`, `git_clean = false`, `worktree_provenance = "DIRTY_DISCLOSED"`. Không retrain hay ghi đè `E0`.
> - **Submitted GitHub Reviews:** `1` (`CHANGES_REQUESTED` bởi `ViolaPeracia`, `COLLABORATOR`, tại `5483794160e877bf2d65144f30fd1ffc181372c3` lúc `2026-11-18T13:46:21Z`). Chờ review lại trên HEAD mới sau khi CI pass.

---

## 1. Scope & Kiến trúc v2.0.0 (Hard Cutover `NF-UNSW-NB15-v3`)

- **Hard Cutover v1 → v2:** Loại bỏ hoàn toàn `NF-UNSW-NB15-v3` (`55` cột / `47` nProbe features / UQ `454104`) khỏi active pipeline (`ModelRegistry`, `TrainOnlyPreprocessor`, `InferencePipeline`, `FeatureCompatibilityEvaluator`, FastAPI, Desktop UI); chuyển toàn bộ di sản v1 sang lưu trữ chỉ đọc `*/historical/nf_unsw_nb15_v3/`. Bắt buộc `feature_contract_version == "canonical-flow-v2-18"` và chuỗi băm SHA-256 `split -> preprocessor -> model -> ood_gate -> score_normalization` fail-closed (**không fallback v1**). ([`ADR-dataset-hard-cutover-v2.md`](docs/adr/ADR-dataset-hard-cutover-v2.md), [`MIGRATION_V1_TO_V2.md`](docs/MIGRATION_V1_TO_V2.md)).
- **Kiến trúc Sản phẩm v2.0.0:** Desktop **Rust / Tauri 2 + Svelte 5 (`2.0.0`)** + Sidecar **FastAPI (`127.0.0.1`, OpenAPI `0.1.0`)**, `X-Sentinel-Session-Token` (constant-time `hmac.compare_digest`), 3 chế độ (`Offline / Replay / Live`), Python `UDPFlowCollector` (NetFlow v9/IPFIX) + `StreamingEventPipeline` (`capacity=10_000`), Behavioral Vector 16-D, Risk Scoring `[0..100]`, Trace Graph/Timeline, `AES-256-GCM` (`DPAPI`/POSIX perms + Adaptive Key Rotation), Security Dry-Run (`executed=false`).

---

## 2. Dataset & Preprocessing (`canonical-flow-v2-18`)

- **`AIT-NDS-v2`** (`10.5281/zenodo.13168643`, **CC BY 4.0**, dataset SHA-256 `cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf`): `3,464,400` flows có nhãn + `942` unmapped = `3,465,342` raw flows.
- **Split `v2-scenario-group-purged-v1`** (`ed542ee80babca26f6e8ad977168b061e18e99a24be1cbe1ec8767b66d6339e8`, LF): `ait_train` (`2,097,891`: `1,825,866` Benign / `272,025` Attack), `ait_val` (`377,704`: `206,676` / `171,028`), `ait_test` (`988,805`: `812,980` / `175,825`); zero scenario & `(scenario, 5-tuple, ts)` overlap.
- **Preprocessor (`TrainOnlyPreprocessor`, `asinh_robust`, `MIN_BOUNDED_SCALE_FLOOR = 0.25`):** Fit duy nhất trên `ait_train`, SHA-256 `0866dec7252d36d3f2bb2becddf266787cc49ddf19306a8e003ba1e951cf51a7`.
- **`CTU-SME-11`** (`10.5281/zenodo.7958258`, **CC BY 4.0**): `CTU-Echo` (`76,073`) & `CTU-Windows7AD` (`175,146` labeled + `9,394` unmapped; `175,101` sau khử `45` nhóm LAN overlap).
- **`AIT-LDS-v2.1`** (`10.5281/zenodo.19483937`, **CC BY-NC-SA 4.0**): Cách ly **100%** khỏi weights/preprocessor/`data/demo/`; direct UID link `NO` (`#85`). **`AIT-ADS`** (`CC BY 4.0`). **`UGR'16`**: **`BLOCKED`** (`HTTP 403`).

---

## 3. Model Status, Deployment Tier & WP3 Controlled Ablation (`E0–E5`)

- **Model Status & Tier:** Toàn bộ 4 baseline models (`RF`, `XGB`, `IF`, `AE`) đạt `artifact_verified = True`, `in_domain_evaluated = True`, **`cross_source_validated = False`**, **`deployment_tier = "RESEARCH_ONLY"`**, **`production_ready = False`** (`compatibility.py` giữ riêng `random_forest` ở `MODEL_VALIDATED` cho in-domain CSV dry-run; `xgboost`/`isolation_forest`/`autoencoder` bị khóa `HOLD_RESEARCH_ONLY_MODEL`).
- **Training Provenance:** `training_git_commit = 79ebb678b87de19cc6b664b587726983fecaf98f`, `git_dirty = true`, `git_clean = false`, `DIRTY_DISCLOSED`.

| Mô hình (`Run ID`, SHA-256) | `AIT-Val` (`F1` / `FPR`) | `AIT-Test` (`N=988,805`) `F1` / `ROC-AUC` / `FPR` | `CTU-Echo` Zero-Shot | `CTU-Win7AD` Zero-Shot |
|---|---|---|---|---|
| **Random Forest** (`v2-rf-20261117T231214Z`, `b2e42f85...`) | `0.9997` / `0.0002` | **`0.9950`** / `0.9994` / `0.0002` | `F1=0.0474` (`R=0.0264, FPR=0.0811`) | `F1=0.0712` (`R=0.5412, FPR=0.1608`) |
| **XGBoost** (`v2-xgb-20261117T231609Z`, `33d201f8...`) | `0.9996` / `0.0002` | **`0.9013`** / `0.9884` / `0.0002` | `F1=0.1436` (`R=0.0832, FPR=0.0700`) | `F1=0.0738` (`R=0.5623, FPR=0.1611`) |
| **Isolation Forest** (`v2-if-20261118T020525Z`, `11b16900...`) | `0.9213` / `0.0500` | **`0.5842`** / `0.8330` / `0.0290` | **`F1=0.8853`** (`R=0.9908, FPR=0.2292`) | `F1=0.0464` (`R=0.9760, FPR=0.4722`) |
| **Autoencoder** (`v2-ae-20261118T020635Z`, `e6afecef...`) | `0.9215` / `0.0500` | **`0.5877`** / `0.5544` / `0.0276` | `F1=0.7325` (`R=0.9990, FPR=0.6746`) | `F1=0.0326` (`R=0.9921, FPR=0.6925`) |

- **WP3 Controlled Ablation & Leakage Disclosure (`scripts/run_wp3_controlled_ablation.py`, `wp3_controlled_ablation_report.json`):**
  - `E0_frozen_18f_reference` (RF giữ `is_canonical_baseline=false`, `rf-v2-tuned-leaf5-cwbalanced_subsample`), `E1` (6f), `E2`/`E2b` (byte/rate ablation), `E3a`/`E3b` (protocol one-hot IF/AE), `E4` (5-fold LOSO CV trong `AIT-Train`), `E5` (Tier 1 Zero-Shot vs Tier 2/3 `RESEARCH_ONLY` adaptation) dẫn tới quyết định **`RETAIN_E0_BASELINE_ARTIFACTS`**.
  - **Minh bạch ranh giới split (`WP-B`):** `ait_test` và `ctu_*` **không** dùng để fit model, fit transform, calibrate threshold hay tune hyperparameter trong `E0–E4` (`ait_test_used_for_training=false`, `ait_test_used_for_threshold_calibration=false`, `ctu_used_for_training_in_zero_shot_experiments=false`), nhưng **`selection_recommendation` có trích dẫn hậu nghiệm kết quả `AIT-Test` và `CTU`** (`ait_test_used_for_posthoc_candidate_selection=true`, `ctu_used_for_posthoc_candidate_selection=true`, `holdout_independent_selection=false`, `selection_type="posthoc_holdout_informed_retention_decision"`).

---

## 4. WP1–WP7, WP-A–F & Khắc phục `CHANGES_REQUESTED` (`P1-01`, `P2`, `P3`), OOD Runtime Policy

- **Tổng hợp Trạng thái Remediation:**
  - `WP1–WP5`, `WP-A`, `WP-B`: **DONE** (cứng hóa OOD in-memory/contract & minh bạch WP3 leakage disclosure; RF giữ `is_canonical_baseline=false` với tên `E0_frozen_18f_reference`).
  - `P1-01` (**Product Runtime OOD Policy**): **DONE** — `RealtimeInferenceEngine`, `LiveRuntime`, `create_app`, `run_api.py` và cả **embedded backend sidecar** + **Python script fallback** trong `desktop/src-tauri/src/backend.rs` (+ `build.rs` `option_env!("NETFLOW_OOD_GATE_SHA256")`) mặc định fail-closed `"deployment"` (`require_ood_gate=true`); cấm downgrade `"deployment" -> "research"`; `"research"` chỉ kích hoạt khi chọn tường minh (như `scripts/run_live_lab_acceptance.py`); AI inference ở `"deployment"` giữ fail-closed `"UNAVAILABLE"` nếu thiếu trusted `NETFLOW_OOD_GATE_SHA256`.
  - `P2-03` & `WP-F` (**OOD Integrity Verification & Trust Anchor**): **PASS (Tách cấu trúc vs Anchor) / `PARTIAL_UNANCHORED` khi thiếu external SHA** — `verify_companion_artifacts.py` tách rõ `structural_schema_verified` + `preprocessor_linkage_verified` (`true`) khỏi `trusted_digest_verified` (`false` trừ khi cấp `--expect-ood-gate-sha256` / `NETFLOW_OOD_GATE_SHA256` / `NETFLOW_EMBEDDED_OOD_GATE_SHA256`); không coi self-computed hash hay unsigned co-located manifest là anchor độc lập.
  - `P2-02` (**Audit Docs & PR Status**), `P3-01` (**CI `pytest -rs`**), `P3-02` (**RF `E0_frozen_18f_reference`**): **DONE** (đồng bộ đầy đủ, công bố exact CI skip reasons & `1` `CHANGES_REQUESTED` review của `ViolaPeracia`).
- **OOD Validation & Companion Artifacts:**
  - `desktop/src-tauri/tauri.standalone.conf.json` & `scripts/verify_companion_artifacts.py`: stage và kiểm SHA-256 đủ `20` `companion_files` bao gồm `ood_reference_gate.json` (`8a52bfe5...`, `fit_rows=2,097,891`) và AE `score_normalization.json` (`d7bcb78f...`); đối khớp 64-hex SHA trong `COMPANION_BUNDLE_MANIFEST.json`, `EMBEDDED_ARTIFACTS_MANIFEST.json` và `EMBEDDED_SHA256SUMS.txt`.
  - `src/network_anomaly/ml/ood_gate.py`: `from_artifact()`, `verify_ood_gate_artifact()`, `validate_ood_gate_instance()`, `resolve_expected_ood_gate_sha256()` (hỗ trợ `NETFLOW_OOD_GATE_SHA256` và `NETFLOW_EMBEDDED_OOD_GATE_SHA256`), và `cross_check_same_boundary_embedded_manifest()`.
  - `src/network_anomaly/streaming/realtime_inference.py` + `live_orchestrator.py` + `live_service.py` + `api/live_runtime.py`: tách `runtime_mode` (`"deployment"` mặc định fail-closed vs `"research"` tường minh), **cấm direct in-memory `ood_gate` injection và bắt buộc trusted `expected_ood_gate_sha256` ở `deployment` mode / `require_ood_gate=True`** (chặn cả fake `is_fitted=True` và unsigned same-boundary manifest), bắt fail-closed runtime error trong `evaluate_sample()`, và truyền/kiểm khớp `runtime_mode` + `require_ood_gate` + `expected_ood_gate_sha256` xuyên suốt chuỗi khởi chạy.

---

## 5. Audit Findings, Acceptance Criteria & CI/Test Evidence

- **Audit Findings & Remediation:** `F-01` (Threat Model Python collector), `F-02` (RQ2 taxonomy `Exploitation_And_C2 N=5`), `F-03` (`DIRTY_DISCLOSED` `79ebb678`), `F-04` (4 cổng `ModelRegistry`/`compatibility.py`/containment), `R-137` (live alert SQLite/UI), `R-OOD-COMPANION`, `R-OOD-INMEM-BYPASS` (`WP-A` — internal API/trust-boundary validation bypass), `R-WP3-LEAKAGE-DISCLOSURE` (`WP-B`), `R-OOD-EXPECTED-SHA` (`WP-F` P2 — `UNRESOLVED / ACCEPTED LIMITATION` cho built-in unanchored OOD artifact), `R-AUDIT-PR156-RESYNC` (`WP-C/D`). Chi tiết tại [`reports/audits/V2_FINDING_REGISTER.md`](reports/audits/V2_FINDING_REGISTER.md).
- **Acceptance Criteria (Phân định trung thực):**
  - `#131` (`M6.6`): **`PASS`** (chờ merge `main`; Python UDP collector).
  - `#137` (`M6.6`): **`PARTIAL` (`3/5`)** — Synthetic UDP loopback (`13/13` stages, `real_device_tested=false`) **KHÔNG** thay thế physical router/switch lab (`BLOCKED`).
  - `#73` / `#148` (`M6.7`): **`UNVERIFIED` (`0/4`)** — Build Windows `.exe` trong `desktop-tauri-windows` **KHÔNG** phải NSIS installer validation; Clean Windows 10/11 VM E2E chưa chạy.
  - `#85` (`M6.2`): **`PARTIAL` (`2/3`)** — Empirical `AIT-NDS-v2 ↔ AIT-LDS-v2.1` UID linkage **`BLOCKED`** (`DIRECT_UID_LINK=False`).
  - `#152` (`M6.7`): **`PARTIAL` (`1/4`)** — `origin/site-source` còn ở v1 chờ merge PR `#156`.
  - `#153` (`M6.7`): **`UNVERIFIED` (`0/4`)** — `OUTLINE_ONLY` (`docs/PRESENTATION_OUTLINE.md`).
  - `#154` (`M6.7`): **`BLOCKED` (`0/4`)** — `DISTRIBUTION_AUTHORIZATION.json` giữ `approved: false`.
- **CI / Test Evidence:**
  - Historical `a6c87ae8397e466ab1bd3d19f82d880e71084b88`: `7/7` CI jobs trên [Run #211 (ID 44278751854)](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/actions/runs/44278751854) (`test (ubuntu-latest)` `585 passed, 21 skipped`, `test (windows-latest)` `587 passed, 19 skipped`).
  - Historical `5483794160e877bf2d65144f30fd1ffc181372c3`: `7/7` CI jobs trên [Run #212 (ID 44312426631)](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/actions/runs/44312426631) (`1` submitted review `CHANGES_REQUESTED` bởi `ViolaPeracia`).
  - **Lưu ý CI:** Kiểm tra raw dataset integrity (`verify_ait_manifest` / `fetch_multi_source_dataset`) trên CI bị **`SKIPPED`** do không có raw archives tại `data/raw/ait_nds_v2`, tách biệt với test-level skips được hiển thị qua `pytest -q -rs --tb=short`.
  - Kết quả kiểm thử cục bộ & CI run gắn với HEAD SHA mới nhất sau đợt khắc phục `P1-01`/`P2`/`P3` được cập nhật trực tiếp ở đầu PR `#156` sau khi push.

---

## 6. Known Limitations, Deferred Work & Governance Status

- **Known Limitations:** Zero-shot cross-source `CTU-SME-11` chưa đạt ngưỡng triển khai; `Credential_Attack` (`N=78`) recall `14.10%`; `Exploitation_And_C2` (`N=5`) không đủ lực thống kê; IF/AE mù trước slow DNS tunneling (`Data_Exfiltration`); model `E0` train từ `dirty` worktree (`79ebb678`, `DIRTY_DISCLOSED`); `RQ3`/`RQ5` là simulation; synthetic UDP loopback không thay thế lab vật lý; placeholder `LICENSE:1` / `pyproject.toml:12-13` vẫn giữ.
- **Deferred Work:** `UGR'16` (`HTTP 403`), `#85` empirical UID linkage, `#137` physical lab, `#73`/`#148` PyInstaller/NSIS build + Clean Windows 10/11 VM E2E, `#128` Rust Collector crate, `#152` `site-source`, `#153` PPTX/PDF.
- **Governance & Distribution Status:** [`reports/governance/DISTRIBUTION_AUTHORIZATION.json`](reports/governance/DISTRIBUTION_AUTHORIZATION.json) giữ nguyên **`approved: false`** và **`status: "HOLD_FOR_MAINTAINER_SIGNOFF"`**; `AIT-LDS-v2.1` (`CC BY-NC-SA 4.0`) cách ly 100% khỏi ML artifacts & demo CSV (`CC BY 4.0`). **KHÔNG** đủ điều kiện phát hành công khai.

---

## 7. Reviewer Checklist

- [ ] Thực hiện review lại sau đợt sửa `CHANGES_REQUESTED` (hiện có `1` submitted review `CHANGES_REQUESTED` bởi `ViolaPeracia` tại `5483794`)
- [ ] Kiểm tra diff `P1-01` & `P2-03` (`ood_gate.py`, `realtime_inference.py`, `live_runtime.py`, `api/main.py`, `run_api.py`, `run_live_lab_acceptance.py`, `desktop/src-tauri/{build.rs,src/backend.rs}`, `verify_companion_artifacts.py`) và regression tests
- [ ] Xác nhận cơ chế fail-closed mặc định `"deployment"` giữ live AI inference `"UNAVAILABLE"` nếu build/operator không cung cấp `NETFLOW_OOD_GATE_SHA256` ngoài trust boundary `artifacts/` (`PARTIAL_UNANCHORED`)
- [ ] Kiểm tra `WP-B` & `P3-02` (`run_wp3_controlled_ablation.py`, `wp3_controlled_ablation_report.json` với `E0_frozen_18f_reference`, `random_forest_manifest.json` giữ `is_canonical_baseline=false`) — xác nhận `E0` không bị retrain/thay SHA
- [ ] Xác nhận GitHub Actions CI (`ci.yml` với `pytest -q -rs --tb=short`) PASS trên HEAD SHA mới nhất của `feat/v2-integration` và công bố skip reasons (Ubuntu & Windows)
- [ ] Xác nhận giữ `isDraft: true` nếu các gate `#73/#148`, `#137`, `#154` vẫn chưa mở khóa

Refs #76, #77, #78, #79, #80, #81, #82, #83, #84, #85, #86, #87, #88, #89, #90, #91, #92, #93, #94, #95, #96, #97, #98, #99, #100, #101, #102, #103, #104, #105, #106, #107, #108, #109, #110, #111, #112, #113, #114, #115, #116, #117, #118, #119, #120, #121, #122, #123, #124, #125, #126, #127, #128, #129, #130, #131, #132, #133, #134, #135, #136, #137, #138, #139, #140, #141, #142, #143, #144, #145, #146, #147, #148, #149, #150, #151, #152, #153, #154, #155
```

### [Kết thúc Nội dung Đồng bộ PR `#156`]
