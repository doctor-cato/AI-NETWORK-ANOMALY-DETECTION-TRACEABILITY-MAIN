# Kế hoạch Bàn giao Chậm Tiến độ (`#73`, `#148`, `#152`) & Đề xuất Cập nhật PR `#156` — NetFlow Sentinel v2.0

- **Tài liệu:** `reports/audits/V2_PR156_AND_DEFERRED_HANDOFF.md`
- **Ngày lập / Cập nhật:** `2026-11-18` (`UTC+7`)
- **Nhánh & Commit tham chiếu (`feat/v2-integration`):** `f5dacb1e9b520dac3fe066fc706707d1fd76c4be` (`12` commits ahead, `0` behind `main` @ `42a656aa76f6a4cb415f858d7179aa3d8f277335`; CI Run `#44251784370` đạt `7/7 SUCCESS`, `493` files changed, `+64,634 / -19,347` + cụm hoàn tất PR `#156` đang ở working tree chưa commit)
- **Nhánh Website tham chiếu (`origin/site-source`):** `a01bd38ad705577fc210fdeeeb61ccbd80a0ac42` (`77` tệp: `15` MDX VI + `15` MDX EN = `30` tệp MDX, các trang `.astro`, views, scripts, workflow)
- **Pull Request `#156`:** `OPEN`, `isDraft: true`, `feat/v2-integration` $\to$ `main` *(giữ nguyên trạng thái **DRAFT / DO NOT MERGE**; nội dung mô tả PR `#156` tại Mục 3 đã được đồng bộ lên GitHub qua `gh pr edit 156`, nhưng không commit/push, không bỏ Draft, không merge, không build `.exe`/`.msi`/NSIS và không sửa nhánh `site-source`)*

---

## Tóm tắt Trạng thái Các Hạng mục Bàn giao

| Hạng mục | Issue / PR | Trạng thái Hiện hành | Kết luận & Ranh giới |
|---|---|---|---|
| **D — Windows Standalone Installer v2.0 & Clean VM E2E** | `#73` (`OPEN`, `0/8` AC, `milestone: None`), `#148` (`OPEN`, `0/4` AC, `M6.7`) | **`DEFERRED / BLOCKED / NOT VERIFIED`** | Đã sửa `tauri.standalone.conf.json`, `vm_target_e2e.ps1` và staging/verify `ood_reference_gate.json` + AE `score_normalization.json` (`20` `companion_files`, `ood_gate: FITTED`) ở `WP5`. Tuy nhiên `.venv` mới đạt `FRONTEND_READY` (`pyinstaller: false`, `makensis: false`, `staged_bundle_manifest: false`); chưa build `.exe`, chưa chạy Clean Windows 10/11 VM E2E; `DISTRIBUTION_AUTHORIZATION.json` giữ `approved: false`. |
| **F — Website `site-source` v2.0 & Guides** | `#152` (`OPEN`, `1/4` AC, `M6.7`) | **`OPEN (1/4 AC) / STALE V1`** | Nhánh `origin/site-source` (`a01bd38ad705577fc210fdeeeb61ccbd80a0ac42`, 77 tệp) vẫn đóng băng ở `v0.6.0` / `NF-UNSW-NB15-v3` / `55` cột / `47` đặc trưng / snapshot `main@d1d16e1cafa79a8f515efa4b0a0e60a50a3b5e48`. Giữ `OPEN`; chỉ cập nhật sau khi PR `#156` merge `main`. |
| **PR `#156` — Tích hợp v2.0.0** | PR `#156` (`feat/v2-integration` $\to$ `main`) | **`OPEN / DRAFT (DO NOT MERGE)`** | Commit `f5dacb1e` đạt `7/7` CI checks (`Run #44251784370`). Working tree hiện có thêm cụm hoàn tất WP2–WP6 (`WP3 E0–E5` ablation, `WP5` fail-closed `OODRejectionGate` + companion staging/verify, cập nhật docs kiểm toán) chưa commit/push nên cần review, commit sạch và re-run CI từ xa trước khi mở review hoặc chuyển Ready. |

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

## Phần 3 — Nội dung Mô tả Đồng bộ cho PR `#156` (Đã cập nhật qua `gh pr edit 156`, giữ nguyên `OPEN / Draft`)

> [!IMPORTANT]
> PR `#156` (`feat/v2-integration` $\to$ `main`) **tiếp tục giữ trạng thái `OPEN` và `Draft` (`Do Not Merge`)**. Không chạy `git commit`, `git push`, hay đổi `isDraft: true`. Nội dung dưới đây phản ánh chính xác commit `f5dacb1e9b520dac3fe066fc706707d1fd76c4be` (`CI Run #44251784370 7/7 PASS`, `493` files changed, `+64,634 / -19,347`) và cụm hoàn tất WP2–WP6 đang chờ commit trên working tree.

---

### [Bắt đầu Nội dung Đồng bộ PR `#156`]

```markdown
## Tổng quan

Pull Request thực hiện **Full Dataset Migration (Hard Cutover)** và tích hợp đầy đủ các phân hệ của **NetFlow Sentinel v2.0.0** trên nhánh `feat/v2-integration` vào `main`, hướng tới mốc **Academic & Controlled Lab Functional Prototype**.

> **Trạng thái PR:** **OPEN / DRAFT — KHÔNG MERGE TỰ ĐỘNG (KHÔNG tuyên bố Production-Ready hoặc Public-Release-Ready).**
> - Commit `f5dacb1e9b520dac3fe066fc706707d1fd76c4be` (`12` commits ahead, `0` behind `main` @ `42a656aa76f6a4cb415f858d7179aa3d8f277335`; `493` files changed, `+64,634 / -19,347`) đã vượt qua `7/7` GitHub Actions checks ([CI Run #44251784370](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/actions/runs/44251784370)).
> - **Hiện trạng nhánh cục bộ (WP2–WP6 trên working tree):** Bổ sung kết quả controlled ablation `E0–E5` (`scripts/run_wp3_controlled_ablation.py`), tách bạch 3 trục provenance (`DIRTY_DISCLOSED`), cứng hóa fail-closed `OODRejectionGate` + `RealtimeInferenceEngine` (`research` vs `deployment`) + staging/SHA-256 `ood_reference_gate.json` & AE `score_normalization.json` (`20` `companion_files`), regression tests mới và đồng bộ toàn bộ báo cáo audit. Cần review, commit sạch và chạy lại CI từ xa trước khi maintainer bỏ Draft.
> - **Hạng mục ngoài phạm vi / `BLOCKED` / `DEFERRED`:** `UGR'16` (`HTTP 403`), liên kết UID trực tiếp `AIT-NDS-v2 ↔ AIT-LDS-v2.1` (`#85`), nghiệm thu phần cứng lab vật lý (`#137`), Windows NSIS Clean VM E2E (`#73`/`#148`), Rust Collector crate (`#128`), phê duyệt phân phối công khai `DISTRIBUTION_AUTHORIZATION.json` (`approved: false`), website `site-source` (`#152`), và báo cáo/slide bảo vệ (`#153` — `OUTLINE_ONLY`).

---

## 1. Hard Cutover & Cách ly Hoàn toàn `NF-UNSW-NB15-v3`

- Loại bỏ hoàn toàn `NF-UNSW-NB15-v3` (UQ `454104`) và hợp đồng 47 đặc trưng nProbe khỏi toàn bộ active pipeline (`ModelRegistry`, `TrainOnlyPreprocessor`, `InferencePipeline`, `FeatureCompatibilityEvaluator`, FastAPI, Desktop UI).
- Chuyển toàn bộ tài liệu, manifest, split, script, báo cáo và hồ sơ bảo vệ v1 sang lưu trữ chỉ đọc tại `data/historical/nf_unsw_nb15_v3/`, `docs/historical/nf_unsw_nb15_v3/`, `scripts/historical/nf_unsw_nb15_v3/`, `reports/historical/nf_unsw_nb15_v3/` và `tests/historical/`.
- Bắt buộc `feature_contract_version == "canonical-flow-v2-18"` và chuỗi băm SHA-256 `split -> preprocessor -> model -> ood_gate -> score_normalization` fail-closed; **không có fallback sang v1**.
- Tài liệu quyết định & migration: [`docs/adr/ADR-dataset-hard-cutover-v2.md`](docs/adr/ADR-dataset-hard-cutover-v2.md), [`docs/MIGRATION_V1_TO_V2.md`](docs/MIGRATION_V1_TO_V2.md).

---

## 2. Nguồn Dữ liệu v2, Feature Contract, Split & Tiền xử lý (`canonical-flow-v2-18`)

- **`AIT-NDS-v2`** (`10.5281/zenodo.13168643`, **CC BY 4.0**, Tstat từ PCAP `AIT-LDS-v2.0`, dataset SHA-256 `cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf`): Khôi phục đủ **`3,464,400` flows có nhãn + `942` unmapped = `3,465,342` raw flows**.
- **Split `v2-scenario-group-purged-v1`** (`ed542ee80babca26f6e8ad977168b061e18e99a24be1cbe1ec8767b66d6339e8`, chuẩn LF):
  - `ait_train` (`fox, harrison, santos, wardbeck, wilson`): `2,097,891` (`1,825,866` Benign / `272,025` Attack)
  - `ait_val` (`russellmitchell`): `377,704` (`206,676` Benign / `171,028` Attack)
  - `ait_test` (`shaw, wheeler`): `988,805` (`812,980` Benign / `175,825` Attack)
  - Zero overlap theo kịch bản và `(scenario, 5-tuple, ts)`.
- **Preprocessor, OOD Gate & AE Sidecar:**
  - `TrainOnlyPreprocessor(asinh_robust)` fit duy nhất trên `ait_train`: `0866dec7252d36d3f2bb2becddf266787cc49ddf19306a8e003ba1e951cf51a7` (`MIN_BOUNDED_SCALE_FLOOR = 0.25`).
  - `OODReferenceGate` (`artifacts/ml/ood_reference_gate.json`, `8a52bfe5ad156560a3949afd5d4860c175ce5d158c38eb47aae07342102e9825`): fit trên `2,097,891` raw `ait_train` flows (`ood_gate = FITTED`).
  - AE `score_normalization.json` (`d7bcb78f7439930ee61b53e6e970ff1535d52ad10f2a025ad4877629a7478847`): kiểm cross-check trong `AutoencoderModel` và stage kèm standalone.
- **`CTU-SME-11`** (`10.5281/zenodo.7958258`, **CC BY 4.0**): `CTU-Echo` (`76,073`: `39,497` Benign / `36,576` Attack) và `CTU-Windows7AD` (`175,146` labeled + `9,394` unmapped; `175,101` sau khử `45` nhóm LAN overlap trong đánh giá đa nguồn).
- **`AIT-LDS-v2.1`** (`10.5281/zenodo.19483937`, **CC BY-NC-SA 4.0**) & **`AIT-ADS`** (`10.5281/zenodo.8263181`, **CC BY 4.0**): Cách ly 100% `AIT-LDS-v2.1` khỏi trọng số ML và `data/demo/`; liên kết trực tiếp UID `AIT-NDS-v2 ↔ AIT-LDS-v2.1` giữ **`NO / BLOCKED`** ([`docs/dataset/AIT_LINKAGE_FEASIBILITY.md`](docs/dataset/AIT_LINKAGE_FEASIBILITY.md)).
- **`UGR'16`:** **`BLOCKED`** (`HTTP 403` / *Portal en Mantenimiento*); không dùng dữ liệu tổng hợp thay thế ([`reports/audits/V2_UGR16_ALTERNATIVES_REVIEW.md`](reports/audits/V2_UGR16_ALTERNATIVES_REVIEW.md)).

---

## 3. Baseline 4 Mô hình (`E0`), Thí nghiệm Kiểm soát `E1–E5` & Cổng `RESEARCH_ONLY`

Cả 4 mô hình đạt `overall_status: READY` (`20` `companion_files`, `ood_gate = FITTED`), hiệu chuẩn ngưỡng chỉ trên `AIT-Val` (`test_touched = false`), nhưng giữ **`deployment_tier = "RESEARCH_ONLY"`** và **`production_ready = false`** (`cross_source_validated_count = 0`):

| Mô hình (`Run ID`, Artifact SHA-256) | `AIT-Val` (`F1` / `FPR`) | `AIT-Test` (`N=988,805`) `P` / `R` / `F1` / `Macro-F1` / `ROC` / `FPR` | `CTU-Echo` Zero-Shot | `CTU-Win7AD` Zero-Shot |
|---|---|---|---|---|
| **Random Forest** (`v2-rf-20261117T231214Z`, `b2e42f85...`) | `0.9997` / `0.0002` | `0.9989` / `0.9911` / **`0.9950`** / `0.9969` / `0.9994` / `0.0002` | `F1=0.0474` (`R=0.0264, FPR=0.0811, ROC=0.6137`) | `F1=0.0712` (`R=0.5412, FPR=0.1608, ROC=0.8392`) |
| **XGBoost** (`v2-xgb-20261117T231609Z`, `33d201f8...`) | `0.9996` / `0.0002` | `0.9989` / `0.8211` / **`0.9013`** / `0.9411` / `0.9884` / `0.0002` | `F1=0.1436` (`R=0.0832, FPR=0.0700, ROC=0.7017`) | `F1=0.0738` (`R=0.5623, FPR=0.1611, ROC=0.6978`) |
| **Isolation Forest** (`v2-if-20261118T020525Z`, `11b16900...`) | `0.9213` / `0.0500` | `0.7775` / `0.4678` / **`0.5842`** / `0.7576` / `0.8330` / `0.0290` | **`F1=0.8853`** (`R=0.9908, FPR=0.2292, ROC=0.9571`) | `F1=0.0464` (`R=0.9760, FPR=0.4722, ROC=0.7649`) |
| **Autoencoder** (`v2-ae-20261118T020635Z`, `e6afecef...`) | `0.9215` / `0.0500` | `0.7860` / `0.4693` / **`0.5877`** / `0.7597` / `0.5544` / `0.0276` | `F1=0.7325` (`R=0.9990, FPR=0.6746, ROC=0.7810`) | `F1=0.0326` (`R=0.9921, FPR=0.6925, ROC=0.7280`) |

- **Lưu ý nhóm tấn công hiếm trên `AIT-Test`:** `Exploitation_And_C2` chỉ có **`N = 5` mẫu** (`5/5 = 1.0` ở cả 4 model — **KHÔNG** kết luận tổng quát hóa `100%`), `Post_Exploitation_Discovery` **`N = 39`** (`RF/XGB/IF 0.8974`, `AE 0.1026`), `Credential_Attack` **`N = 78`** (`RF/XGB/IF 0.1410`, `AE 0.0641`), `Data_Exfiltration` `N = 80,075` (`RF 0.9860`, `XGB 0.6128`, `IF 0.0`, `AE 0.0005`).
- **Thí nghiệm kiểm soát `WP3 E1–E5` (`scripts/run_wp3_controlled_ablation.py`, `reports/experiments/ml/wp3_controlled_ablation_report.json`):**
  - `E1` (6 base features): Bỏ 12 engineered features kéo `XGB AIT-Test Exfil` sụp từ `0.6128` -> `0.0803` (`Test F1 0.7324`).
  - `E2`/`E2b` (byte/rate ablation): Cắt `6` biến byte/rate thô (`E2`) giữ `RF Win7AD FPR=0.1599`; cắt sạch cả `bytes_per_pkt_{in,out}` (`E2b`) chứng minh nhân quả khi `RF Win7AD F1` nhảy `0.0712 -> 0.5665` (`AUC=0.8869, FPR=0.0028`), nhưng `AIT-Val FPR` tăng 388x (`0.0002 -> 0.0770`) và `CTU-Echo` sụp `F1=0.0067 (R=0.0034)`.
  - `E3a`/`E3b` (semantic protocol one-hot cho IF/AE): `E3a` nâng `AE AIT-Test F1` (`0.5877 -> 0.6496`) và cắt `CTU-Echo FPR` (`0.6746 -> 0.4222`), nhưng đổi contract thành `21` chiều và giữ `CTU-Win7AD FPR=0.6335`.
  - `E4` (5-fold LOSO CV trong `AIT-Train`): `RF` `F1=0.9876 ± 0.0062`, trong khi `XGB` biến động lớn (`min=0.7585` & `Exfil=0.0230` khi hold-out `harrison`) và `IF` (`0.5179 ± 0.2361`).
  - `E5` (Domain adaptation 3 tầng): Tách rõ `Tier 1 (Zero-Shot)` vs `Tier 2 (AIT+Echo -> unseen Win7AD: RF F1=0.0928, AUC=0.8280; AE AUC=0.9520, FPR=0.4688, RESEARCH_ONLY)` vs `Tier 3 (Same-Device Temporal CTU-Echo: RF F1=0.9634, RESEARCH_ONLY)`.
  - **Quyết định chọn Candidate:** **`RETAIN_E0_BASELINE_ARTIFACTS`** (giữ nguyên 4 artifact đã ký SHA-256 trên hợp đồng `canonical-flow-v2-18`).
- **Tách bạch 3 trục Provenance (`WP4`):** `artifact_integrity_verified = PASS`, `dataset_provenance_verified = PASS (AIT/CTU) / BLOCKED (UGR'16)`, **`source_reproducibility_verified = DIRTY_DISCLOSED`** (`training_git_commit = 79ebb678b87de19cc6b664b587726983fecaf98f`, `git_dirty = true` giữ nguyên trung thực, không giả mạo).

---

## 4. Kết quả Nghiên cứu RQ1–RQ6 & Giới hạn Trung thực

- **RQ1 (`model_comparison_report.json`):** `RF F1=0.9950` > `XGB 0.9013` >> `AE 0.5877` / `IF 0.5842` trên `988,805` flows `AIT-Test`.
- **RQ2 (`rq2_imbalance_report.json`, Negative Result `h2_full_confirmed = false`):** `RF_CostSensitive` đạt `F1=0.994749`, nhưng `Credential_Attack` (`N=78`) dừng ở `14.10%` (`RF/XGB/IF`) và `6.41%` (`AE`).
- **RQ3 (`rq3_session_correlation_experiment.json`, Simulation Negative Result `simulation_hypothesis_met = false`):** `cos>=0.85` `F1=0.3191`, `cos>=0.95` `F1=0.5556`; empirical AIT giữ **`BLOCKED`** (`#85`).
- **RQ4 (`rq4_unknown_attack_report.json`, Negative Result `unsupervised_ge_0_75_both = false`):** `44` unknown holdout (`zero_leakage_verified=true`): `IF 0.9091`, `RF 0.9091`, `XGB 0.7500`, **`AE 0.2045`**.
- **RQ5 (`rq5_rotation_experiment.json`, Simulation):** Giảm `87.5%` exposure (`1200.0s -> 150.01s`) và `85.0%` blast radius (`40 -> 6`).
- **RQ6 (`crypto_benchmark_report.json` & `system_performance_benchmark.json`, Benchmarked):** AES-256-GCM 256B P95 `13.3 us` (`75,851.2 ops/s`); CPU E2E (`4/4 REAL_MODELS`) `16.38 events/s` (Med `61.75 ms`).
- **Traceability (`traceability_evaluation.json`):** `1.0 / 1.0` vs dynamic grep `0.375 / 0.50` trên kịch bản synthetic `8` events.

---

## 5. Kiến trúc v2, Hardening WP5 & Synthetic Lab Acceptance (`#137`)

- **Kiến trúc sản phẩm:** Desktop **Rust / Tauri 2 + Svelte 5 (`2.0.0`)** + Sidecar **FastAPI (`127.0.0.1`, OpenAPI `0.1.0`)**, `X-Sentinel-Session-Token`, `UnifiedSecurityEventV2`, Behavioral Vector 16-D, Risk Scoring `[0..100]`, Trace Engine & Attack Timeline, `AES-256-GCM` (`DPAPI` / POSIX perms + Adaptive Key Rotation), Security Dry-Run (`executed=false`, khóa `HOLD_RESEARCH_ONLY_MODEL`), Python UDP NetFlow v9/IPFIX Collector (`#128` Rust crate `DEFERRED`).
- **WP5 Companion & Runtime Fail-Closed Hardening:**
  - `tauri.standalone.conf.json` + `scripts/verify_companion_artifacts.py`: bổ sung staging/checksum kiểm chứng đủ `20` `companion_files` (bao gồm `ood_reference_gate.json` `8a52bfe5...` và AE `score_normalization.json` `d7bcb78f...`) và bắt buộc `ood_gate.status == "FITTED"` khi kiểm layout standalone.
  - `src/network_anomaly/ml/ood_gate.py`: validate strict schema `schema_version=1`, `artifact_type="ood_reference_gate"`, `min_bounds <= max_bounds`, positive stds, `fit_rows > 0`, khớp `expected_feature_names` & `expected_preprocessor_sha256`.
  - `src/network_anomaly/models/autoencoder.py`: cross-check sidecar `score_normalization.json` trước deserialize.
  - `src/network_anomaly/streaming/realtime_inference.py`: bổ sung `runtime_mode` (`"research"` vs `"deployment"`, `NETFLOW_RUNTIME_MODE`), tách bạch `FITTED` / `NOT_FITTED` / `ERROR`, khóa fail-closed `inference_mode="UNAVAILABLE"` & abstention khi OOD `ERROR` (mọi mode) hoặc non-`FITTED` ở `"deployment"`.
- **Synthetic UDP Loopback (`#137`, `reports/acceptance/synthetic_udp_loopback_report.json`):** `Verdict: ACCEPTED` (`6/6` flows, `ood_gate=FITTED`, `4/4 VALIDATED`, `1` alert `HIGH` `risk=84.0`, `6/6` ciphertext); **`real_device_tested: false`**, physical lab vẫn `BLOCKED`.

---

## 6. Hạng mục `BLOCKED` / `DEFERRED` & Điều kiện Trước Merge / Release

| Hạng mục | Trạng thái | Điều kiện Mở khóa |
|---|---|---|
| Commit sạch working tree WP2–WP6 & re-run CI | **CẦN LÀM TRƯỚC KHI BỎ DRAFT** | Commit thay đổi sau `f5dacb1e`, push `feat/v2-integration`, xác nhận GitHub Actions CI (`ci.yml`, `lint-audit.yml`) PASS trên commit mới. |
| `UGR'16` ISP Validation (`#82, #83, #97`) | **`BLOCKED`** | Cổng NESG trả `HTTP 403`; khảo sát nguồn thay thế tại `reports/audits/V2_UGR16_ALTERNATIVES_REVIEW.md`. |
| Empirical `AIT-NDS-v2 ↔ AIT-LDS-v2.1` UID Linkage (`#85`) | **`BLOCKED` (`2/3 AC`)** | Không có UID chung & thiếu PCAP `v2.0` cục bộ. |
| Nghiệm thu Thiết bị Lab Vật lý (`#137`) | **`PARTIAL` (`3/5 AC`)** | Chỉ có synthetic UDP loopback; chưa có router/switch phần cứng. |
| Clean Windows 10/11 VM NSIS Installer E2E (`#73, #148`) | **`DEFERRED / NOT VERIFIED`** | Companion staging `ood_reference_gate.json` & `score_normalization.json` đã xong trên code/config; vẫn cần placeholder `LICENSE`/`pyproject`, build PyInstaller + NSIS và chạy Controller–Target–Witness VM. |
| `DISTRIBUTION_AUTHORIZATION.json` (`#154`) | **`HOLD_FOR_MAINTAINER_SIGNOFF` (`approved: false`)** | Giữ nguyên `approved: false`; cần Maintainer ký hồ sơ phân phối công khai `CC BY 4.0` + `secrets.DISTRIBUTION_EVIDENCE_SHA256` trước mọi release công khai. |
| Website `site-source` (`#152`) | **`OPEN` (`1/4 AC`)** | Chờ merge PR `#156` để neo `evidenceCommit` trên `main` và cập nhật từ `v0.6.0` sang `v2.0`. |
| Defense Report & Slides (`#153`) | **`OUTLINE_ONLY` (`0/4 AC`)** | Mới có `docs/REPORT_OUTLINE.md` và `docs/PRESENTATION_OUTLINE.md`. |
| Rust NetFlow Collector Crate (`#128`) | **`DEFERRED`** | Tách hậu v2.0; bản v2.0 dùng Python `UDPFlowCollector`. |

Refs #76, #77, #78, #79, #80, #81, #82, #83, #84, #85, #86, #87, #88, #89, #90, #91, #92, #93, #94, #95, #96, #97, #98, #99, #100, #101, #102, #103, #104, #105, #106, #107, #108, #109, #110, #111, #112, #113, #114, #115, #116, #117, #118, #119, #120, #121, #122, #123, #124, #125, #126, #127, #128, #129, #130, #131, #132, #133, #134, #135, #136, #137, #138, #139, #140, #141, #142, #143, #144, #145, #146, #147, #148, #149, #150, #151, #152, #153, #154, #155
```

### [Kết thúc Nội dung Đồng bộ PR `#156`]
