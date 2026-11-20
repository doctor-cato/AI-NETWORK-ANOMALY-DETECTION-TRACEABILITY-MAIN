# V2 Baseline Evidence Ledger — NetFlow Sentinel v2.0

- **Ngày lập sổ cái (Phase 0):** `2026-11-18` (`+07:00`) / `2026-11-17T22:00Z`
- **Repository:** `doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN`
- **Branch:** `feat/v2-integration` (`HEAD == origin/feat/v2-integration == 79ebb678b87de19cc6b664b587726983fecaf98f`)
- **Base branch:** `main` (`42a656aa76f6a4cb415f858d7179aa3d8f277335`, đi sau 10 commits)
- **Pull Request:** `#156` (`feat(v2): NetFlow Sentinel v2.0.0 integration`, `OPEN`, `isDraft: true`, `mergeStateStatus: BLOCKED`)
- **Tài liệu nguồn tổng hợp Phase 0:**
  - [V2_CI_AUDIT.md](V2_CI_AUDIT.md) (Agent A — Repository & CI/CD)
  - [V2_ISSUE_AC_AUDIT.md](V2_ISSUE_AC_AUDIT.md) (Agent B — Issues `#76–#155` & M7, Milestones `M6.1–M6.7`)
  - [V2_DATA_QUALITY_AUDIT.md](V2_DATA_QUALITY_AUDIT.md) (Agent C — Dataset, Feature Contract & Domain Shift)
  - [V2_MODEL_AUDIT.md](V2_MODEL_AUDIT.md) (Agent D — ML Baseline & Provenance)

---

## 1. Verified Local State (Trạng thái Cục bộ Đã Xác minh)

| Hạng mục | Bằng chứng đo trực tiếp trên Windows Working Tree | Trạng thái |
|---|---|---|
| **Git & Working Tree** | `git status --short --branch`: `## feat/v2-integration...origin/feat/v2-integration`; `git diff --check`: exit `0`; `HEAD = 79ebb678b87de19cc6b664b587726983fecaf98f` | **PASS** |
| **Environment & Contracts** | `.venv\Scripts\python.exe scripts/check_environment.py` (`Python 3.12.10`, core packages OK); `export_openapi_spec.py --check` (`PASS`); `parse_dag.py` (`80 nodes, 0 cycles`); `migrate_keystore.py --verify-only --json` (`DPAPI_PROTECTED`, 6 DEKs `WRAPPED_V2`) | **PASS** |
| **Frontend Svelte / Vite** | `npm --prefix desktop run check` (`0` errors, `0` warnings); `npm --prefix desktop test` (`5` files, `33` tests passed) | **PASS** |
| **Rust / Tauri 2 Backend** | `cargo fmt --check` (`PASS`), `cargo clippy --all-targets -- -D warnings` (`0` warnings), `NETWORK_ANOMALY_REQUIRE_PYTHON_TEST=1 cargo test --lib` (`9 passed, 0 failed`) | **PASS** |
| **Pytest Cục bộ (`.venv`)** | `.venv\Scripts\python.exe -m pytest tests -q --tb=short -rs`: **`578 passed, 3 skipped, 0 failed`** (`ruff` vắng trong `.venv`, `black` vắng trong `.venv`, `non_existent_huge_dataset.csv`). *(Lưu ý: pass trên Windows disk với `.gitignore`-d files và CRLF)* | **PASS (có điều kiện)** |
| **Raw Datasets (18/18 files)** | `AIT-NDS-v2` (8 scenario zips + 2 docs), `AIT-LDS-v2.1` (2 no-pcaps zips, `CC BY-NC-SA 4.0`), `AIT-ADS` (`ait_ads.zip` + `labels.csv`), `CTU-SME-11` (2 tar.bz2 + 2 docs): khớp 100% size, MD5, SHA-256 và khả năng parse | **PASS (cục bộ)** |
| **Processed Data & Split Disk Integrity** | 8 tệp `data/processed/v2/*.csv.gz` và 3 tệp `splits/*_indices.csv.gz` khớp SHA-256 với `V2_SPLIT_MANIFEST.json`, nhưng thiếu `233,185` dòng raw (`Finding DATA-A01`) và sai đơn vị UDP (`DATA-A02`) | **FAIL (Contract/Data bugs)** |
| **4 Model Artifacts & Registry (Disk)** | `random_forest_baseline.joblib` (`0dd7aaaf...`, 6.44 MB), `xgboost_baseline.joblib` (`6bb5a6f2...`, 0.23 MB), `isolation_forest.joblib` (`aca66915...`, 0.89 MB), `autoencoder_model.joblib` (`2032f8ca...`, 0.024 MB), `v2_flow_preprocessor.joblib` (`d33dfe09...`, 1,694 B); `ModelRegistry().summary()` `4/4 VALIDATED`, `verify_companion_artifacts()` `READY` trên Windows CRLF | **PASS (trên CRLF disk)** / **FAIL (trên LF Git)** |
| **Demo Subset (`.gitignored`)** | `data/demo/demo_flows.csv` (`36,296 B`, `0af10c7a...`), `demo_labels.csv` (`7,124 B`, `63bb875a...`), `demo_manifest.json` (`9,757 B`, `1b9b253e...`) tồn tại cục bộ | **PASS (trên CRLF disk)** |
| **Ruff & Black (Python 3.12 tools)** | `ruff check src scripts tests --statistics`: **`67` errors** (`41 I001`, `25 F401`, `1 F541`; `36` active + `31` historical). `black --check src scripts tests`: **`43` files would reformat** | **FAIL** |

---

## 2. Verified Remote State (Trạng thái Remote GitHub Đã Xác minh)

| Hạng mục | Bằng chứng từ GitHub REST / CLI (`gh`) | Trạng thái |
|---|---|---|
| **Remote Branch `origin/feat/v2-integration`** | `79ebb678b87de19cc6b664b587726983fecaf98f` (`main` ở `42a656aa76f6a4cb415f858d7179aa3d8f277335`) | **SYNCED** |
| **Pull Request `#156`** | `OPEN`, `isDraft: true`, `mergeable: MERGEABLE`, `mergeStateStatus: BLOCKED`, `reviews: []` | **DRAFT / BLOCKED** |
| **CI Run `#44171616420` (`lint`)** | `FAILURE` — Fail ở Ruff (`67` lỗi); step Black bị `SKIPPED` | **FAIL** |
| **CI Run `#44171616420` (`test` matrix 4 jobs)** | `FAILURE` trên cả 4 tổ hợp (`ubuntu/windows × 3.11/3.12`): `13 failed` (`547 passed, 21 skipped` Linux; `549 passed, 19 skipped` Windows). Steps dataset/lab/benchmark bị `SKIPPED` do step pytest fail | **FAIL** |
| **CI Run `#44171616420` (`desktop-frontend`)** | `SUCCESS` (`svelte-check`, `vitest` 5/33, `vite build`) | **PASS** |
| **CI Run `#44171616420` (`desktop-tauri-windows`)** | `SUCCESS` (`cargo fmt`, `check_desktop_version`, `npm build`, `clippy`, `cargo test` 9/9, `cargo build`) | **PASS** |
| **GitHub Issues (`#76–#155` & M7/None)** | 88 open issues (`372` AC checkboxes: `61 [x]`, `311 [ ]`). Đề xuất sau kiểm toán: `233 [x]` / `139 [ ]` (`+194` tick mới, `-22` untick sai/hồi quy) | **AUDIT COMPLETED** |
| **GitHub Milestones (`M6.1–M6.7` & `M7`)** | 7 milestones `M6.1–M6.7` (`OPEN`), `M7` (`OPEN`), plus stale counters ở `M1/M5/M6/M7` | **OPEN** |
| **Distribution Governance** | `reports/governance/DISTRIBUTION_AUTHORIZATION.json`: `public_release_authorization.approved: false` (`status: HOLD_FOR_MAINTAINER_SIGNOFF`), `permission_tiers.private_build_only.scope: "private-build-only"` | **BLOCKED (public release)** |

---

## 3. Local / Remote Divergence (Sai lệch Giữa Cục bộ và Clean Git Checkout / CI)

1. **Sai lệch Byte CRLF vs LF (`split_manifest_sha256` & `preprocessor_manifest`) — Nguyên nhân của `10/13` CI Test Failures:**
   - `.gitattributes:3` quy định `* text=auto eol=lf` (`i/lf` trong Git index).
   - Trên Windows working tree sạch (`HEAD 79ebb67`), `67` file tracked có CRLF (`w/crlf`), trong đó `data/V2_SPLIT_MANIFEST.json` và `reports/splits/v2_split_manifest.json` có **CRLF SHA-256 = `1b7fa7aebaf3560f27b3d23ec05919a83aacd1ed6ea5448f96a6a42c7a264e0a` (`4,851 B`)**, còn Git blob (`HEAD:data/V2_SPLIT_MANIFEST.json`) có **LF SHA-256 = `7840d5cdd18acb29ad222ec7d29e26e645fabb76646b62081e1d7368488eefe8` (`4,716 B`)**.
   - Tương tự `reports/preprocessing/v2_flow_preprocessing_manifest.json`: CRLF `473b5646...` (`2,769 B`) vs LF `eff0c30c...` (`2,668 B`).
   - Do tất cả code/manifest (`desktop_csv.py:691`, `test_desktop_csv_api.py:38`, `v2_flow_preprocessing_manifest.json`, 4 model manifests) ghim hash CRLF `1b7fa7ae...`, nên trên CI checkout LF:
     - `verify_e2e_attestation()` fail ở `scripts/verify_companion_artifacts.py:4185-4188` (gây 8 fails trong `test_verify_companion_artifacts.py` + 1 fail trong `test_controller_target_vm_e2e.py`).
     - `_verify_canonical_demo_manifest()` trả `('source:flow-v2-unverified', False)` (gây fail `test_f01_provenance_anti_spoofing_matrix`).
2. **Tài liệu / Artifact `.gitignored` chỉ tồn tại cục bộ (`Local-Only`):**
   - `artifacts/`, `data/raw/`, `data/processed/`, `data/demo/`, `data/keys/` đều bị `.gitignore` chặn. Trên CI không có model `.joblib` (`run_live_lab_acceptance.py` & `benchmark_full_system.py` khi chạy chỉ đạt `0/4 UNAVAILABLE`) và không có `data/demo/*`.
   - `/docs/audits/` bị `.gitignore:69` chặn nên 4 tài liệu (`V2_GAP_ANALYSIS.md`, `THREAT_MODEL_V2.md`, `RESEARCH_QUESTIONS_VALIDATION.md`, `SECURITY_AUDIT_V2.md`) tồn tại cục bộ nhưng **vắng mặt hoàn toàn trên Git/CI**.
3. **`.venv` cục bộ vs CI `lint` / `test` environments:**
   - `.venv` thiếu `ruff` và `black` (2 test trong `test_code_quality_gates.py` bị `SKIPPED`), còn trên CI `test` jobs cũng thiếu `ruff`/`black` (chỉ có job `lint` cài `ruff==0.17.5`, `black==26.10.1`, trong khi `lint-audit.yml` cài `ruff==0.17.1`).
4. **Mutation ngoài ý muốn khi chạy `--verify-only`:**
   - `scripts/fetch_multi_source_dataset.py --verify-only` trên máy có `data/raw/` tự ghi đè 3 manifest (`AIT_DATASETS_MANIFEST.json`, `CTU_SME_11_MANIFEST.json`, `EXTERNAL_DATASETS_PROVENANCE.json`) với `generated_at_utc` mới thay vì chỉ đọc kiểm chứng.

---

## 4. Missing Files (Tệp Thiếu / Tham chiếu Gãy)

| Đường dẫn Thiếu / Tham chiếu Sai | Vị trí Tham chiếu | Tác động |
|---|---|---|
| `reports/releases/v0.6.0_e2e_verification.json` *(đã dời sang `reports/historical/nf_unsw_nb15_v3/releases/`)* | `tests/unit/test_verify_companion_artifacts.py:147-151` | Gây `FileNotFoundError` cho 3 unit tests trên mọi clean CI checkout vắng `data/demo/*` |
| `artifacts/ml/ood_reference_gate.json` | Issue `#99` AC1 & `reports/acceptance/synthetic_udp_loopback_report.json:53` (`ood_gate=NOT_FITTED`) | Statistical OOD reference gate chưa được fit và lưu artifact cho runtime |
| `tests/unit/test_multi_source_pipeline.py` | `.github/workflows/lint-audit.yml:91` | Path dead trong `SCOPED_LIST` |
| 5 file test không tồn tại trong `THREAT_MODEL_V2.md` | `docs/audits/THREAT_MODEL_V2.md` (Issue `#81`) | Dẫn chứng test sai tên / không có thật |
| 3 API routes không tồn tại (`/api/v1/telemetry/status`, `/api/v1/telemetry/events`, `/api/v1/behavioral/sessions`) | `docs/USER_GUIDE_V2.md:12-13` | Tài liệu hướng dẫn sai route thực tế trong `src/network_anomaly/api/main.py` |
| `data/raw/ugr16/` | `data/EXTERNAL_DATASETS_PROVENANCE.json` | Portal UGR'16 trả `HTTP 403` (`BLOCKED`) |
| `data/raw/non_existent_huge_dataset.csv` | `tests/integration/test_full_system_e2e.py:145-151` | Test negative path dùng `pytest.skip()` khiến suite luôn báo 1 skip |

---

## 5. Stale Artifacts, Version Drift & Dirty Snapshots

| Thành phần | Hiện trạng Lỗi thời / Stale | Bằng chứng |
|---|---|---|
| **Git Snapshot của 4 Model & Preprocessor** | Trained trên working tree chưa commit (`git_commit="05240b44b2a057a9942d6297ae75f2b4cb48ea2f"`, `git_dirty=True`), trước commit `79ebb678` | `reports/models/*_manifest.json` (`2026-11-17T18:17:45Z–18:36:14Z`) |
| **Desktop Product Version** | Configs/lockfiles/Tauri window title giữ **`1.0.0`** / `v1.0.0`, trong khi Svelte UI (`App.svelte`) hiển thị **`v2.0.0`** và `build_installer_v2.py` dùng `2.0.0-pilot` | `desktop/package.json:4`, `Cargo.toml:3`, `tauri.conf.json:4,15`, `tests/unit/test_desktop_version_sync.py:38-44,168-170` |
| **Active Documentation & Audit Snapshot** | `docs/RELEASE_PROCESS.md:1,3,50,92` còn `v1.0.0` và chỉ dẫn tái sử dụng artifact v1; `.agents/reports/V2_CURRENT_AUDIT.md` dừng ở snapshot v1 `ebc27fc`; `docs/DEPLOYMENT_GUIDE_V2.md:80`, `RELEASE_PROCESS.md:29`, `README.md:33`, `DATASET.md:10`, `TRACEABILITY_MATRIX.md:10`, `WINDOWS_INSTALLATION.md:41` ghi nhầm `AIT-LDS-v2.1` là `CC BY 4.0` thay vì `CC BY-NC-SA 4.0`; `scripts/run_live_lab_acceptance.py:14` ghi `47 model features`; `scripts/build_v2_dataset_and_split.py:15,518` ghi `robust` / `RobustScaler` thay vì `asinh_robust` (`DATA-A08`) | Direct file inspection |
| **Absolute Personal Paths trong JSON/Docs** | `C:\Users\ASUS\...` xuất hiện trong `model_comparison_report.json:51,120,189,237`, `xgboost_manifest.json:87`, `isolation_forest_manifest.json:6`, `xgboost_v2_eval.json:87`, `isolation_forest_v2_eval.json:6`, `demo_manifest.json`, `reports/audit/00-index.md:6,44` | Direct file inspection |
| **Legacy v1 References trong Metadata/Code** | `isolation_forest_manifest.json` ghi `"target": "Label"`; `xgboost_manifest.json` giữ `"provenance_note"` từ chối `load_verified()`; `RandomForest` `.joblib` nội bộ giữ `split_status="PLANNED / NOT VERIFIED"`; `evaluate_traceability.py` dùng 8 sự kiện giả + hardcoded baseline + sai toán `+65.0%`; `scripts/verify_companion_artifacts.py` khai báo 3 sidecar legacy không tồn tại cho IF | Direct inspection & `V2_MODEL_AUDIT.md` |

---

## 6. Invalid / Flawed Manifests & Data Contracts

1. **CRLFs trong Manifests:** `data/V2_SPLIT_MANIFEST.json`, `reports/splits/v2_split_manifest.json`, `reports/preprocessing/v2_flow_preprocessing_manifest.json`, `reports/datasets/v2_multi_source_profile.json`, và 4 model manifests dùng CRLF trên Windows, làm `split_manifest_sha256` (`1b7fa7ae...`) vô hiệu trên Git/CI LF (`7840d5cd...`).
2. **Dataset Truncation Bug (`DATA-A01`, CRITICAL):** `data/processed/v2/` và `V2_SPLIT_MANIFEST.json` chỉ chứa `3,231,215` labeled + `942` unmapped (`3,232,157`), **mất âm thầm `233,185` dòng `tcp_complete.csv` (`6.73%` của `3,465,342` raw)** do alignment `RangeIndex` của `pd.read_csv(..., chunksize=250_000)` với `_classify_series()` trong `scripts/build_v2_dataset_and_split.py:141-247`.
3. **Tstat UDP Duration Unit Bug (`DATA-A02`, CRITICAL):** `v2_schema.py:281` và `build_v2_dataset_and_split.py:205-208` đọc `c_durat:4`/`s_durat:13` (đơn vị **giây**) trực tiếp làm `duration_ms`, khiến `93.7%–97.5%` UDP AIT flows bị kẹp về `1.0 ms` và thổi phồng tốc độ tới `5.38e10 B/s`.
4. **Cross-Source Byte Accounting Conflict (`DATA-A03`, CRITICAL):** AIT Tstat `c_bytes_all`/`s_bytes_all` đếm **L4 payload bytes** (`0 B` khi SYN scan), còn `build_v2_dataset_and_split.py:287-288` & `v2_schema.py:350-351` lấy Zeek `orig_ip_bytes`/`resp_ip_bytes` (bao gồm IP+L4 header, `80–88 B` khi SYN scan) — đảo dấu `bytes_in_ratio` (`KS = 0.9905`) và làm RF/XGB sụp đổ zero-shot trên CTU (`F1=0.0` / `ROC-AUC=0.0373`). (Còn `zeek.py:73-84` lại dùng `orig_bytes`, tạo xung đột giữa các adapter nội bộ).
5. **Preprocessor Domain-Shift Amplifiers (`DATA-A04`, HIGH):** `TrainOnlyPreprocessor` giữ `protocol_num` unscaled (`passthrough`, gặp `ICMP=1` trên CTU tạo MSE `7.58–10.06` -> AE FPR `65.20%–85.45%`) và không có `min_scale_floor` cho `pkts_in_ratio` (`IQR_arcsinh = 0.044269` phóng đại flow một chiều `has_response=0` lên `+9.039 sigma`).
6. **5-Tuple Cross-Device Conflict trong CTU (`DATA-A09`, MEDIUM):** `ctu_echo` và `ctu_windows7ad` chia sẻ `42` cặp `(5-tuple, timestamp_ms)` (`47` dòng LAN `192.168.1.50 <-> 192.168.1.108`) với nhãn đối nghịch (`Malicious` ở Echo vs `Benign` ở Win7AD).

---

## 7. Blocked Dataset Sources & External Dependencies

| Nguồn / Hạng mục | Trạng thái | Bằng chứng & Giới hạn |
|---|---|---|
| **UGR'16** (`https://nesg.ugr.es/nesg-ugr16/`) | **`BLOCKED`** | Portal NESG trả `HTTP 403` / `Portal en Mantenimiento`. Không có tệp local; tuyệt đối không tạo benchmark thay thế (`#82, #83, #97`). |
| **`AIT-NDS-v2 ↔ AIT-LDS-v2.1` Direct Flow-UID Join** | **`BLOCKED / NOT VERIFIED`** | `AIT-NDS-v2` sinh từ `AIT-LDS-v2.0`, log trong repo là `v2.1`; `direct_uid_join_possible: false` (`#85, #104`). Chỉ hỗ trợ correlation theo thực thể IP + cửa sổ thời gian UTC. |
| **Physical Network Switch/Router Lab** | **`BLOCKED`** | `scripts/run_live_lab_acceptance.py` chỉ chạy mô phỏng UDP loopback `127.0.0.1` (`real_device_tested: false`, `alerts: NOT_TRIGGERED`; `#137`). |
| **Clean Windows 10/11 VM Installer & Public Distribution** | **`BLOCKED`** | `DISTRIBUTION_AUTHORIZATION.json` có `approved: false`; chưa chạy `vm_target_e2e.ps1` + `--sign-vm-witness` trên máy Windows sạch (`#71, #73, #148, #149, #154`). |
| **Dataset `AIT-LDS-v2.1` Commercial Redistribution** | **Restricted (`CC BY-NC-SA 4.0`)** | Chỉ dùng nghiên cứu học thuật/trace audit, không trộn vào artifact phân phối thương mại. |

---

## 8. Reproduction Gaps (Lỗ hổng Khả năng Tái lập)

1. **Không tái lập được kiểm chứng provenance từ clean Git checkout (`git clone`):** do bất đồng nhất CRLF (`1b7fa7ae...`) vs LF (`7840d5cd...`) trên split/preprocessor/model manifests và thiếu fixture `v0.6.0_e2e_verification.json` khi `.gitignore`-d `data/demo/` vắng mặt.
2. **Không tái lập được huấn luyện trên clean commit:** 4 model artifacts hiện tại được train trên commit `05240b44` với `git_dirty=True` (`215–275` file thay đổi), trước commit `79ebb678`.
3. **Không tái lập được toàn bộ dữ liệu thô AIT-NDS-v2 trong split hiện hành:** `233,185` dòng (`6.73%`) bị rơi âm thầm do lỗi chunk index, và toàn bộ `udp_complete.csv` mang đơn vị sai 1,000x.
4. **Không tái lập được CI quality gate đồng nhất ở local:** `.venv` và 4 CI `test` jobs thiếu `ruff`/`black` (bỏ qua `test_code_quality_gates.py`), đồng thời `ci.yml` (`ruff==0.17.5`) lệch `lint-audit.yml` (`ruff==0.17.1`).
5. **Khoảng trống tích hợp sản phẩm ảnh hưởng tái lập/nghiệm thu:** `SourceRegistry` thiếu 4 v2 adapters (`#89/#90/#93`), `db.py` `SCHEMA_SQL` thiếu bảng v2 (`#107`), `BehavioralVector` chưa tích hợp vào CSV pipeline (`#106`) và ép NaN thành `0.0` thiếu missingness flags (`#101/#102`), `KeyRotationPolicy` thiếu persistence/clock injection (`#120/#122`).

---

## 9. Phán quyết Gate Phase 0

- **Trạng thái hoàn thành Phase 0 Audit:** **COMPLETED & AUDITED** — **Agent I (Independent Verification Auditor)** đã xác minh trực tiếp toàn bộ phát hiện kỹ thuật trọng yếu, raw/processed SHA-256, Git/CI logs và mã nguồn là chính xác; 4 điểm đính chính biên tập mà Agent I chỉ ra (bảng Milestone Mục 3 `V2_ISSUE_AC_AUDIT.md`, tham chiếu dòng trong `V2_DATA_QUALITY_AUDIT.md`, bổ sung `DATA-A08` & đồng bộ bảng `V2_FINDING_REGISTER.md`, số file `67 w/crlf` & khóa `DISTRIBUTION_AUTHORIZATION.json`) đã được sửa đồng bộ (`0 CRLF`).
- **Quyết định thiết kế cần chốt trước Phase 1–5:** Chuyển về bước lập kế hoạch chi tiết cho: (1) khắc phục `DATA-A01` (233,185 dòng rơi do chunk index), `DATA-A02` (AIT UDP `seconds -> ms`), và lựa chọn chuẩn byte `DATA-A03` (`orig_bytes`/`resp_bytes` L4 payload vs `orig_ip_bytes` + header normalization); (2) thiết kế nâng cấp `TrainOnlyPreprocessor` (`DATA-A04`: xử lý `protocol_num` và `pkts_in_ratio` IQR collapse mà vẫn giữ tương thích unit test); (3) các lỗ hổng product integration (`PROD-01..PROD-05`, `.gitignore` `/docs/audits/`, `SourceRegistry`, `db.py` schema, `BehavioralVector` CSV integration, `OODReferenceGate` artifact, `KeyRotationPolicy` persistence/clock injection).
