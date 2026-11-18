# BÁO CÁO KIỂM TOÁN REPOSITORY & CI/CD — NETFLOW SENTINEL V2.0 (`V2_CI_AUDIT`)

**Phạm vi:** Read-only Repository, Git/PR #156, GitHub Actions CI/CD, Local Build/Test Verification & 4.1 Baseline Findings Audit
**Nhánh kiểm toán:** `feat/v2-integration`
**HEAD đã kiểm chứng (Local == Remote):** `79ebb678b87de19cc6b664b587726983fecaf98f` (`feat(v2): complete hard dataset cutover to AIT-NDS-v2 and CTU-SME-11`)
**Nhánh gốc (`main`):** `42a656aa76f6a4cb415f858d7179aa3d8f277335` (`Merge pull request #74`)
**Pull Request:** `#156` (`feat(v2): NetFlow Sentinel v2.0.0 integration`, `OPEN`, `isDraft=true`, `mergeStateStatus=BLOCKED`)
**CI Run mới nhất:** `#44171616420` (Workflow `CI`, `conclusion=failure`, 5/7 jobs `FAILURE`, 2/7 jobs `SUCCESS`)
**Vai trò kiểm toán:** Agent A — Repository & CI/CD Auditor (Read-only; không sửa source, test, config hay trạng thái Git)

---

## 1. Trạng thái Git, Branch, PR #156 & GitHub Actions

### 1.1. Trạng thái Git Local vs Remote

| Thành phần | Giá trị quan sát trực tiếp | Trạng thái |
|---|---|---|
| Branch hiện tại | `feat/v2-integration` (tracking `origin/feat/v2-integration`) | Đồng bộ |
| Local `HEAD` | `79ebb678b87de19cc6b664b587726983fecaf98f` | Khớp Remote |
| Remote `origin/feat/v2-integration` | `79ebb678b87de19cc6b664b587726983fecaf98f` | Khớp Local |
| Base `main` & `merge-base` | `42a656aa76f6a4cb415f858d7179aa3d8f277335` | `feat/v2-integration` đi trước `main` 10 commits |
| Working tree (`git status --short --branch`) | `## feat/v2-integration...origin/feat/v2-integration` (không có file tracked bị sửa) | Sạch |
| `git diff --check` | Exit code `0`, không có lỗi whitespace/conflict | **PASS** |
| `git diff --name-status main...HEAD` | **465 files** (`A`: 183, `M`: 139, `R`: 137, `D`: 6; `+47,933 / -19,241` lines) | Đã đối chiếu |
| Branch Protection trên `main` | `strict: true`, `required_approving_review_count: 1`, required checks: `test (ubuntu-latest, 3.11)`, `test (ubuntu-latest, 3.12)`, `test (windows-latest, 3.11)`, `test (windows-latest, 3.12)` | Đã bật |

**Lịch sử 10 commits trên `main..HEAD`:**
`a71d95b` → `0826f14` → `74249ce` → `6a25a24` → `6b90db9` → `7da287c` → `6a4193a` → `ebc27fc` → `05240b4` → `79ebb67`.

**Tệp cục bộ `.gitignored` đang tồn tại trên máy dev (vắng mặt trên CI clean checkout):**
- `artifacts/models/` (4 model `.joblib` + sidecars), `artifacts/preprocessing/v2_flow_preprocessor.joblib`
- `data/demo/demo_flows.csv`, `data/demo/demo_labels.csv`, `data/demo/demo_manifest.json`
- `data/raw/{ait_nds_v2,ait_lds_v2_1,ait_ads,ctu_sme_11}/`, `data/processed/v2/`, `data/keys/`

### 1.2. Pull Request #156 & CI Run #44171616420

- **PR #156:** `https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/pull/156`
  - `state`: `OPEN`, `isDraft`: `true`, `baseRefName`: `main`, `headRefName`: `feat/v2-integration`, `headRefOid`: `79ebb678b87de19cc6b664b587726983fecaf98f`, `mergeable`: `MERGEABLE`, `mergeStateStatus`: `BLOCKED`, `reviews`: `[]`.
- **GitHub Actions Run `#44171616420` (`CI`, trigger `pull_request` trên `79ebb67`):**

| Job | Kết luận | Chi tiết bước thực thi |
|---|---|---|
| `lint` (`ubuntu-latest`) | **FAIL** | Step 5 `Ruff` fail (**67 lỗi**); Step 6 `Black` bị **SKIPPED** do Ruff fail trước. |
| `test (ubuntu-latest, 3.11)` | **FAIL** | Pytest: **13 failed, 547 passed, 21 skipped** (tổng 581 tests). Steps 12–14 bị **SKIPPED** do step 11 fail (steps 7, 8, 12 chỉ bật ở `ubuntu-latest, 3.12`). |
| `test (ubuntu-latest, 3.12)` | **FAIL** | Steps 6–10 (`check_environment`, `export_openapi_spec --check`, `verify_companion_artifacts --verify-distribution-permission`, `compileall`, imports) **PASS**. Step 11 pytest: **13 failed, 547 passed, 21 skipped**. Steps 12 (`Verify AIT multi-source dataset manifest & checksums`), 13 (`Validate live telemetry & authorized lab acceptance`), 14 (`Verify full system performance benchmark`) bị **SKIPPED** bởi GHA do step 11 fail. |
| `test (windows-latest, 3.11)` | **FAIL** | Pytest: **13 failed, 549 passed, 19 skipped**. Steps 13–14 bị **SKIPPED** do step 11 fail. |
| `test (windows-latest, 3.12)` | **FAIL** | Pytest: **13 failed, 549 passed, 19 skipped**. Steps 13–14 bị **SKIPPED** do step 11 fail. |
| `desktop-frontend` (`ubuntu-latest`) | **PASS** | `npm --prefix desktop ci`, `run check`, `test`, `run build` đều **PASS**. |
| `desktop-tauri-windows` (`windows-latest`) | **PASS** | `cargo fmt --check`, `check_desktop_version.py --check`, `npm ci && build`, `cargo clippy -- -D warnings`, `cargo test --lib`, `cargo build --bins` đều **PASS**. |

**Phân rã 13 test failures giống hệt nhau trên cả 4 tổ hợp OS/Python của CI run `#44171616420`:**
1. `tests/integration/test_controller_target_vm_e2e.py::test_controller_target_vm_e2e_full_lifecycle_and_negative_gates` — `RuntimeError: Tracked preprocessor manifest split_manifest_sha256 does not match split manifest.`
2. `tests/unit/test_desktop_csv_api.py::test_f01_provenance_anti_spoofing_matrix` — `AssertionError: assert ('source:flow-v2-unverified', False) == ('source:ait-nds-v2', True)`
3. `tests/unit/test_verify_companion_artifacts.py` (**11 tests fail**):
   - 3 tests fail với `FileNotFoundError` tại `reports/releases/v0.6.0_e2e_verification.json`:
     - `test_verify_e2e_attestation_accepts_valid_payload_and_cli`
     - `test_verify_e2e_attestation_rejects_tampered_model_hash`
     - `test_verify_e2e_attestation_rejects_stale_script_and_commit_version_binding`
   - 3 tests fail trực tiếp với `RuntimeError: Tracked preprocessor manifest split_manifest_sha256 does not match split manifest.`:
     - `test_verify_e2e_attestation_rejects_missing_or_mismatched_nsis_e2e`
     - `test_verify_e2e_attestation_clean_checkout_without_demo_files_and_require_demo_flag`
     - `test_verify_e2e_attestation_requires_all_four_frontend_ready_models`
   - 5 tests fail `AssertionError: Regex pattern did not match` (do hàm `verify_e2e_attestation()` ném `RuntimeError: Tracked preprocessor manifest split_manifest_sha256 does not match split manifest.` trước khi chạy tới điều kiện tampered đang test):
     - `test_verify_e2e_attestation_rejects_model_manifest_and_ae_calibration_tamper` (expected `'run_id mismatch'`)
     - `test_verify_e2e_attestation_rejects_cm_metrics_and_containment_bypass` (expected `'metric inconsistency'`)
     - `test_verify_nsis_installer_e2e_rejects_orphan_backend_and_uninstall_leftovers` (expected `'invalid nsis_e2e verification flags'`)
     - `test_verify_e2e_attestation_require_bundled_resources_enforces_production_mode` (expected `'bundled resources'`)
     - `test_verify_e2e_attestation_require_standalone_embedded` (expected `'standalone embedded NSIS'`)

---

## 2. Audit `.github/workflows/` (Duplicates, Version Mismatch & Redundancies)

| Hạng mục kiểm tra | Quan sát trong `.github/workflows/` | Tác động |
|---|---|---|
| **Version mismatch của `ruff`** | `ci.yml:22` cài `"ruff==0.17.5" "black==26.10.1"`; `lint-audit.yml:35` cài `"ruff==0.17.1" "black==26.10.1"`; `release.yml:85` cài `pip install -e ".[dev,packaging]"` dùng `pyproject.toml:44-45` (`black>=24.0.0`, `ruff>=0.6.0`) không ghim version. | Kết quả lint có thể lệch giữa `CI`, `Lint audit`, và `Release Windows Desktop`. |
| **Thiếu `ruff`/`black` trong `test` matrix & `.venv` local** | `ci.yml:68` chỉ chạy `pip install -e .` (không có `[dev]`); `.venv` cục bộ cũng không có `ruff` và `black`. | `tests/unit/test_code_quality_gates.py:40,54` luôn bị **SKIPPED** cả cục bộ lẫn trong 4 job `test` của CI. |
| **Duplicate workflow & stale `SCOPED_LIST`** | `lint-audit.yml` (chỉ chạy `workflow_dispatch`) lặp lại `ruff` và `black` của `ci.yml` `lint`. Danh sách `SCOPED_LIST` trong `lint-audit.yml:47-95` chứa đường dẫn đã không còn tồn tại (`tests/unit/test_multi_source_pipeline.py` missing; `src/network_anomaly/eda` vẫn còn trong danh sách) và bỏ sót một số tệp v2 mới nếu không nằm trong `CHANGED_PY`. | Bảo trì hai danh sách lint tách biệt, dễ lệch phạm vi. |
| **Quét lint vào thư mục `historical/`** | `ci.yml:24-26` chạy `ruff check src scripts tests` và `black --check src scripts tests`. `pyproject.toml:69` (`[tool.black]`) và `[tool.ruff]` không loại trừ `scripts/historical/` hay `tests/historical/`. | 31/67 lỗi `Ruff` (`I001`) nằm trong `scripts/historical/nf_unsw_nb15_v3/` và `tests/historical/nf_unsw_nb15_v3/` (dù `pytest` đã `norecursedirs = ["tests/historical", "historical"]`). |
| **Matrix redundancies trong `ci.yml`** | Job `test` chạy ma trận 2×2 (`ubuntu-latest`/`windows-latest` × `3.11`/`3.12`), lặp lại y hệt `compileall`, import check, toàn bộ `581` tests trên 4 runner; đồng thời chạy `run_live_lab_acceptance.py` và `benchmark_full_system.py` **2 lần** (trên cả Ubuntu 3.12 và Windows 3.12). | Tăng thời gian/chi phí runner mà không tăng coverage cho các bước không phụ thuộc OS/Python version. |
| **Duplicate checks giữa `ci.yml` và `release.yml`** | `release.yml:414-456` chạy lại toàn bộ Python tests, Ruff, Black, OpenAPI, npm check/test/build, cargo fmt/clippy/test vốn đã có trong `ci.yml`. `desktop-tauri-windows` (`ci.yml:133-150`) không cache `.venv` và chạy lại `npm ci && npm run build` đã chạy ở `desktop-frontend`. | Chấp nhận được ở release gate để cách ly runner, nhưng tốn thời gian nếu không tái sử dụng hoặc tối ưu cache. |

---

## 3. Kết quả Kiểm tra Cục bộ trên HEAD `79ebb67`

> Phân định rành mạch: Các kết quả dưới đây đo trực tiếp trên môi trường máy phát triển Windows (`Python 3.12.10` tại `.venv\Scripts\python.exe`, `ruff 0.17.5` và `black 26.10.1` tại `Python312\Scripts\`), nơi có sẵn `.joblib` artifacts, `data/demo/`, `data/raw/` và `data/keys/` (`.gitignored`). **Không đồng nhất với kết quả CI clean checkout.**

| Kiểm tra | Lệnh thực thi | Kết quả | Bằng chứng / Giới hạn |
|---|---|---|---|
| Git status | `git status --short --branch` | **PASS** | `## feat/v2-integration...origin/feat/v2-integration`, working tree sạch. |
| Git whitespace | `git diff --check` | **PASS** | Exit code `0`, 0 lỗi. |
| Environment | `.venv\Scripts\python.exe scripts/check_environment.py` | **PASS** | `OK python 3.12.10` + `pandas`, `numpy`, `sklearn`, `xgboost`, `joblib`, `matplotlib`, `seaborn`, `cryptography`, `pydantic`, `network_anomaly`. |
| OpenAPI sync | `.venv\Scripts\python.exe scripts/export_openapi_spec.py --check` | **PASS** | `reports/api/openapi.json` & `reports/api/API_CONTRACT.md` đồng bộ. |
| Desktop version | `.venv\Scripts\python.exe scripts/check_desktop_version.py --check` | **PASS** (khớp nội bộ `1.0.0`) | `1.0.0` nhất quán trên 5 file config/lockfile; API `0.1.0`. **(Lệch mục tiêu `v2.0.0` — xem Finding `CI-F10`).** |
| Ruff lint | `C:\Users\ASUS\AppData\Local\Programs\Python\Python312\Scripts\ruff.exe check src scripts tests --statistics` | **FAIL** | `ruff 0.17.5`: **67 lỗi** (`41 I001`, `25 F401`, `1 F541`); gồm **36 lỗi** ở 23 active files + **31 lỗi `I001`** ở `historical/`. |
| Black format | `C:\Users\ASUS\AppData\Local\Programs\Python\Python312\Scripts\black.exe --check src scripts tests` | **FAIL** | `black 26.10.1`: **43 files would be reformatted** (toàn bộ là active files), `200 files unchanged`. |
| Svelte typecheck | `npm --prefix desktop run check` | **PASS** | `svelte-check found 0 errors and 0 warnings`. |
| Frontend unit tests | `npm --prefix desktop test` | **PASS** | `vitest`: `5 passed (5)` files, `33 passed (33)` tests. |
| Rust fmt | `cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check` | **PASS** | Exit code `0`. |
| Rust clippy | `cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings` | **PASS** | Exit code `0`, 0 warnings. |
| Rust lib tests | `NETWORK_ANOMALY_REQUIRE_PYTHON_TEST=1 cargo test --manifest-path desktop/src-tauri/Cargo.toml --lib` | **PASS** | `9 passed; 0 failed`. |
| Companion artifacts | `.venv\Scripts\python.exe scripts/verify_companion_artifacts.py` | **PASS** (cục bộ) | `overall_status: READY`, `4/4` models, `demo_ready: true`. Phụ thuộc `.joblib` và `data/demo/` cục bộ + CRLF trên đĩa. |
| Dataset verify | `.venv\Scripts\python.exe scripts/fetch_multi_source_dataset.py --verify-only` | **PASS** (cục bộ) | Exit `0` (`data/raw/` hiện diện cục bộ; ghi đè manifest thay vì chỉ đọc — xem `CI-F06`). Trên CI **SKIPPED** do thiếu raw data. |
| Keystore verify | `.venv\Scripts\python.exe scripts/migrate_keystore.py --verify-only --json` | **PASS** | `DPAPI_PROTECTED`, 6 DEK `WRAPPED_V2`, `verify_status: CURRENT`. |
| Full Pytest suite | `.venv\Scripts\python.exe -m pytest tests -q --tb=no -rs` | **PASS (có 3 SKIPPED)** | `578 passed, 3 skipped, 117 warnings in 111.28s`. 3 skip: `ruff` vắng trong `.venv`, `black` vắng trong `.venv`, `non_existent_huge_dataset.csv`. |

---

## 4. Xác minh 11 Finding của Mục 4.1 trên HEAD `79ebb67`

1. **`split_manifest_sha256` mismatch — XÁC NHẬN `FAIL` (P0):**
   - `scripts/build_v2_dataset_and_split.py:485-486` ghi `data/V2_SPLIT_MANIFEST.json` và `reports/splits/v2_split_manifest.json` bằng `write_text(..., encoding="utf-8")` không chỉ định `newline="\n"`. Trên Windows, file trên đĩa mang CRLF (`4,851` bytes), SHA-256 = `1b7fa7aebaf3560f27b3d23ec05919a83aacd1ed6ea5448f96a6a42c7a264e0a`.
   - Quy tắc `.gitattributes:3` (`* text=auto eol=lf`) chuẩn hóa Git blob trong `HEAD` thành LF (`4,716` bytes), SHA-256 = `7840d5cdd18acb29ad222ec7d29e26e645fabb76646b62081e1d7368488eefe8`.
   - Tất cả manifest và hằng số liên kết (`reports/preprocessing/v2_flow_preprocessing_manifest.json`, 4 model manifests trong `reports/models/`, `src/network_anomaly/api/desktop_csv.py:691`, `tests/unit/test_desktop_csv_api.py:38`, `tests/integration/test_inference_e2e.py:82`, `tests/unit/test_inference_pipeline.py:70`, `reports/experiments/ml/model_comparison_report.json:12`, `reports/experiments/ml/rq4_unknown_attack_report.json:13`, `data/demo/demo_manifest.json`) đang giữ digest CRLF `1b7fa7ae...`.
   - Khi CI checkout từ Git (cả Linux lẫn Windows), `data/V2_SPLIT_MANIFEST.json` mang LF (`7840d5cd...`), làm gãy `verify_e2e_attestation()` và `_verify_canonical_demo_manifest()`.

2. **`test_f01_provenance_anti_spoofing_matrix` failure trên CI — XÁC NHẬN `FAIL` (P0):**
   - Thất bại trên cả 4 runner CI tại `tests/unit/test_desktop_csv_api.py:707`: `assert ('source:flow-v2-unverified', False) == ('source:ait-nds-v2', True)`.
   - Nguyên nhân trực tiếp từ finding (1): test fixture `controlled_anchor` (`tests/unit/test_desktop_csv_api.py:689`) gắn cứng `CANONICAL_SPLIT_MANIFEST_SHA256 = "1b7fa7ae..."` (CRLF), không khớp file `data/V2_SPLIT_MANIFEST.json` LF (`7840d5cd...`) trên CI khi `_verify_canonical_demo_manifest()` (`src/network_anomaly/api/desktop_csv.py:738-744`) tính SHA-256 thực tế của file trên đĩa.

3. **Thiếu `reports/releases/v0.6.0_e2e_verification.json` trong `tests/unit/test_verify_companion_artifacts.py` — XÁC NHẬN `FAIL` (P0):**
   - Commit `79ebb67` đã di chuyển `reports/releases/v0.6.0_e2e_verification.json` sang `reports/historical/nf_unsw_nb15_v3/releases/v0.6.0_e2e_verification.json`.
   - `tests/unit/test_verify_companion_artifacts.py:143-151` chỉ chạy nhánh fallback đọc `reports/releases/v0.6.0_e2e_verification.json` khi `data/demo/*` (`.gitignored`) vắng mặt — điều này xảy ra trên mọi clean CI checkout (cục bộ không kích hoạt vì có `data/demo/*`), gây `FileNotFoundError` cho 3 unit tests. Ngoài ra file lịch sử v0.6.0 đó chứa `demo_sha256` của v1 đã nghỉ hưu.

4. **`verify_companion_artifacts` test failures — XÁC NHẬN `FAIL` (P0):**
   - Tổng cộng **11 tests** trong `tests/unit/test_verify_companion_artifacts.py` và **1 test** trong `tests/integration/test_controller_target_vm_e2e.py:349` fail trên CI (12/13 failures toàn bộ CI run): 3 test fail do Finding (3) (`FileNotFoundError`), 8 test còn lại trong `test_verify_companion_artifacts.py` + 1 test VM E2E fail do `verify_e2e_attestation()` (`scripts/verify_companion_artifacts.py:4185-4188`) ném `RuntimeError: Tracked preprocessor manifest split_manifest_sha256 does not match split manifest.` trước cả khi chạm tới các điều kiện tamper/flag được kỳ vọng.

5. **Ruff & Black errors + `.venv` thiếu `ruff`/`black` — XÁC NHẬN `FAIL` (P0):**
   - CI `lint` job fail ở bước Ruff với **67 lỗi** (36 active: 25 `F401`, 10 `I001`, 1 `F541`; 31 `I001` trong `historical/`) và bỏ qua Black (**43 active files** cần reformat).
   - Đồng thời `.venv` cục bộ và 4 job `test` trên CI không cài `ruff`/`black`, làm `tests/unit/test_code_quality_gates.py:40,54` luôn báo **SKIPPED** thay vì thực thi cổng chất lượng.

6. **Dataset checksum verification `SKIPPED` trên CI — XÁC NHẬN `BLOCKED` / `SKIPPED` (P1):**
   - Trong `ci.yml:85-87`, step `Verify AIT multi-source dataset manifest & checksums` bị GHA **SKIPPED** ở run `#44171616420` vì step 11 (`pytest`) fail trước đó.
   - Kể cả khi step 11 xanh (như ở run `#44129176011`), `data/raw/ait_nds_v2` bị `.gitignore` và vắng mặt trên CI, nên `scripts/fetch_multi_source_dataset.py:294-313` in `[fetch_multi_source_dataset] SOURCE_INTEGRITY: SKIPPED` và trả exit `0` mà không kiểm tra checksum dữ liệu thô nào.
   - Khi chạy cục bộ trên máy có sẵn `data/raw/`, `--verify-only` vẫn gọi `verify_and_generate_manifest()` và `write_ctu_and_master_manifests()` ghi lại file manifest (`scripts/fetch_multi_source_dataset.py:365-366,481-482`) thay vì xác minh read-only dựa trên SHA-256 đã chốt.

7. **Live telemetry acceptance (`scripts/run_live_lab_acceptance.py`) — XÁC NHẬN `SKIPPED` trên CI run `#44171616420` / `ACCEPTED_WITH_LIMITATIONS` khi step 11 pass (P1):**
   - Đọc trực tiếp `scripts/run_live_lab_acceptance.py`: script khởi tạo `LiveTelemetryService` lắng nghe UDP `127.0.0.1:0` (ephemeral loopback), gửi 1 gói NetFlow v9 kèm template + 1 gói NetFlow v9 data-only (kiểm tra template cache) + 1 gói IPFIX dùng private lab enterprise IE `PEN 50000` / `IE 50000+i` (IEEE-754 `float64` cho 18 feature `ML_FEATURE_COLUMNS`) + 1 gói lỗi `b"\x00\x09\x00"`.
   - Không kết nối switch/router thật; fixture mặc định tạo `0` alert (`alerts: NOT_TRIGGERED`); docstring dòng 14 vẫn ghi nhầm `"The 47 model features"`.
   - Trên CI run `#44171616420` bị GHA **SKIPPED** do step 11 fail; trên run `#44129176011` (trên CI không có `.joblib` models) đạt `ACCEPTED_WITH_LIMITATIONS` với `ai_inference: UNAVAILABLE`.

8. **Full performance benchmark & `non_existent_huge_dataset.csv` — XÁC NHẬN `SKIPPED` (P1):**
   - Step `Verify full system performance benchmark` (`ci.yml:91-93`, `scripts/benchmark_full_system.py`) bị GHA **SKIPPED** ở run `#44171616420` do step 11 fail; khi chạy trên CI không có `.joblib` models (như run `#44129176011`), `inference_readiness` là `0/4 (UNAVAILABLE)`, chỉ đo 200 synthetic events không có suy luận AI thật.
   - `tests/integration/test_full_system_e2e.py:145-151` (`test_missing_dataset_artifact_skips_cleanly`) kiểm tra `Path("data/raw/non_existent_huge_dataset.csv")` và **luôn `pytest.skip(...)`** cả cục bộ lẫn trên CI (là bài test kiểm tra hành vi skip khi thiếu file, không phải benchmark dataset lớn thật).

9. **Demo provenance chuyển thành `source:flow-v2-unverified` trên CI — XÁC NHẬN `FAIL` (P0):**
   - `src/network_anomaly/api/desktop_csv.py:684-696` (`TRUSTED_CANONICAL_VALIDATION_SUBSETS`) ghim cứng `"split_manifest_sha256": "1b7fa7ae..."` (digest CRLF).
   - `_verify_canonical_demo_manifest()` (`src/network_anomaly/api/desktop_csv.py:738-744`) đối chiếu digest đó với `_sha256_file(CANONICAL_SPLIT_MANIFEST_PATH)` (LF `7840d5cd...` trên CI) và fail closed về `("source:flow-v2-unverified", False)`. Kèm theo đó, `data/demo/*` bị `.gitignore` nên `test_live_demo_csv_rf_and_if_cli_parity_and_blocked_models` cũng bị skip trên CI.

10. **Desktop version vẫn hiển thị `v1.0.0` — XÁC NHẬN `FAIL` / Version Drift (P1):**
    - `desktop/package.json:4`, `desktop/package-lock.json`, `desktop/src-tauri/Cargo.toml:3`, `desktop/src-tauri/Cargo.lock`, và `desktop/src-tauri/tauri.conf.json:4` đều để `"1.0.0"`.
    - `desktop/src-tauri/tauri.conf.json:15` đặt tiêu đề cửa sổ `"NetFlow Sentinel v1.0.0 — Phân tích Bất thường Lưu lượng Mạng"`.
    - Ngược lại, `desktop/src/App.svelte:695,697` hiển thị `"NetFlow Sentinel v2.0.0"` / `"Phiên bản v2.0.0"`, `scripts/build_installer_v2.py:122,239` dùng mặc định `"2.0.0-pilot"`, còn `tests/unit/test_desktop_version_sync.py:38-44,168-170` lại khóa kiểm tra `1.0.0` và `v1.0.0`. `check_desktop_version.py --check` chỉ báo PASS vì 5 file config/lock khớp nhau ở `1.0.0`.

11. **Documentation claims không phù hợp & personal paths — XÁC NHẬN `FAIL` (P1):**
    - `docs/RELEASE_PROCESS.md:1,3,50` vẫn ghi `v1.0.0` (`NetFlow Sentinel (v1.0.0 Stable)`), dòng `92` hướng dẫn *"Các artifact mô hình và preprocessor từ v1.0.0 tiếp tục được tái sử dụng trực tiếp nếu SHA-256 không đổi"* (trái với hard cutover v2 từ chối artifact v1), và dòng `29` gộp `AIT-LDS-v2.1` vào `CC BY 4.0`.
    - `docs/DEPLOYMENT_GUIDE_V2.md:80`, `README.md:33`, `docs/DATASET.md:10`, `docs/TRACEABILITY_MATRIX.md:10`, `docs/WINDOWS_INSTALLATION.md:41` đều ghi `AIT-LDS-v2.1` theo `CC BY 4.0`, mâu thuẫn với `data/AIT_DATASETS_MANIFEST.json:15`, `data/EXTERNAL_DATASETS_PROVENANCE.json:14`, `NOTICE:39`, `THIRD_PARTY_NOTICES.md:13`, `reports/governance/DISTRIBUTION_AUTHORIZATION.json:57` (`AIT-LDS-v2.1` là **CC BY-NC-SA 4.0**).
    - `desktop/README.md:13` ghi `NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe`; `scripts/run_live_lab_acceptance.py:14` ghi nhầm `"The 47 model features"`.
    - `.agents/reports/V2_CURRENT_AUDIT.md` là snapshot cũ từ commit `ebc27fc` (trước hard cutover v2 ở `79ebb67`, vẫn ghi 47 đặc trưng `NF-UNSW-NB15-v3`).
    - Đường dẫn máy cá nhân (`C:\Users\ASUS\...` / `C:/Users/ASUS/...`) xuất hiện trong các artifact báo cáo/manifest tracked: `reports/experiments/ml/model_comparison_report.json:51,120,189,237`, `reports/models/isolation_forest_manifest.json:6`, `reports/models/xgboost_manifest.json:87`, `reports/evaluation/isolation_forest_v2_eval.json:6`, `reports/evaluation/xgboost_v2_eval.json:87`, và `reports/audit/00-index.md:6,44`.

---

## 5. Evidence Ledger (Chuẩn 13 Trường theo Mục 3.3)

### Finding `CI-F01`
- **Finding ID:** `CI-F01`
- **Priority:** `P0`
- **File/module liên quan:** `scripts/build_v2_dataset_and_split.py:485-486`, `data/V2_SPLIT_MANIFEST.json`, `reports/splits/v2_split_manifest.json`, `reports/preprocessing/v2_flow_preprocessing_manifest.json`, `reports/models/*_manifest.json`, `.gitattributes:3`
- **Mô tả vấn đề:** `split_manifest_sha256` ghi trong preprocessor manifest, 4 model manifests, test fixtures và trust anchor là SHA-256 của bản CRLF trên Windows (`1b7fa7ae...`, 4,851 bytes), không khớp với Git blob LF (`7840d5cd...`, 4,716 bytes) khi CI checkout.
- **Root cause:** `build_v2_dataset_and_split.py` ghi JSON bằng `Path.write_text(..., encoding="utf-8")` thiếu `newline="\n"`, tạo file CRLF trên Windows; sau đó preprocessing/training băm file CRLF trên đĩa, trong khi `.gitattributes` (`* text=auto eol=lf`) ép Git lưu và checkout LF trên mọi runner CI.
- **Agent phụ trách:** `Agent G — Product Integration & Security Engineer` (phối hợp `Agent C` / `Agent D` tái đồng bộ manifest hash)
- **Proposed fix:** Chuẩn hóa ghi toàn bộ JSON/CSV manifest và split với `newline="\n"` (LF), cập nhật lại `split_manifest_sha256` (`7840d5cd...`) trong `v2_flow_preprocessing_manifest.json`, 4 model manifests, `demo_manifest.json`, `desktop_csv.py`, các file report/test liên quan, hoặc đối chiếu ở lớp chuẩn hóa LF nhất quán với `.gitattributes`.
- **Test command:** `.venv\Scripts\python.exe -c "import hashlib,subprocess,json; from pathlib import Path; b=subprocess.check_output(['git','show','HEAD:data/V2_SPLIT_MANIFEST.json']); p=json.loads(Path('reports/preprocessing/v2_flow_preprocessing_manifest.json').read_text()); assert hashlib.sha256(b).hexdigest()==p['split_manifest_sha256']"`
- **Expected result:** SHA-256 của `HEAD:data/V2_SPLIT_MANIFEST.json` (LF) khớp `split_manifest_sha256` trong `v2_flow_preprocessing_manifest.json` và 4 model manifests.
- **Actual result:** `FAIL` — Git LF blob SHA-256 = `7840d5cdd18acb29ad222ec7d29e26e645fabb76646b62081e1d7368488eefe8`, Disk CRLF & manifests = `1b7fa7aebaf3560f27b3d23ec05919a83aacd1ed6ea5448f96a6a42c7a264e0a`.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, CI Run `44171616420` (`https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/actions/runs/44171616420`)
- **Related GitHub issue:** `#92`, `#93`, `#154`
- **Acceptance status:** `FAIL`

### Finding `CI-F02`
- **Finding ID:** `CI-F02`
- **Priority:** `P0`
- **File/module liên quan:** `tests/unit/test_desktop_csv_api.py:38,689,704-707`, `src/network_anomaly/api/desktop_csv.py:691,738-744`
- **Mô tả vấn đề:** Test `test_f01_provenance_anti_spoofing_matrix` fail trên cả 4 job `test` của CI (`ubuntu-latest`/`windows-latest` × `3.11`/`3.12`) vì trả về `('source:flow-v2-unverified', False)` thay vì `('source:ait-nds-v2', True)`.
- **Root cause:** `CANONICAL_SPLIT_MANIFEST_SHA256` trong `test_desktop_csv_api.py:38` ghim digest CRLF `1b7fa7ae...`; trên CI, `data/V2_SPLIT_MANIFEST.json` có LF (`7840d5cd...`), nên `_verify_canonical_demo_manifest()` từ chối ở bước kiểm tra split manifest SHA-256.
- **Agent phụ trách:** `Agent G — Product Integration & Security Engineer`
- **Proposed fix:** Sau khi chuẩn hóa LF cho `V2_SPLIT_MANIFEST.json`, cập nhật `CANONICAL_SPLIT_MANIFEST_SHA256` và `TRUSTED_CANONICAL_VALIDATION_SUBSETS` sang digest LF thống nhất (`7840d5cd...`), chạy lại `test_desktop_csv_api.py` trên file LF.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_desktop_csv_api.py -k test_f01_provenance_anti_spoofing_matrix -q`
- **Expected result:** `1 passed` cả cục bộ (LF) lẫn trên CI Linux/Windows.
- **Actual result:** `FAIL` trên CI run `44171616420` (`AssertionError: assert ('source:flow-v2-unverified', False) == ('source:ait-nds-v2', True)`); cục bộ chỉ pass giả tạo nhờ CRLF trên đĩa.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, CI Run `44171616420` (`test (ubuntu-latest, 3.12)` & `test (windows-latest, 3.12)`)
- **Related GitHub issue:** `#139`, `#150`, `#154`
- **Acceptance status:** `FAIL`

### Finding `CI-F03`
- **Finding ID:** `CI-F03`
- **Priority:** `P0`
- **File/module liên quan:** `tests/unit/test_verify_companion_artifacts.py:143-151`, `reports/historical/nf_unsw_nb15_v3/releases/v0.6.0_e2e_verification.json`
- **Mô tả vấn đề:** 3 unit tests trong `test_verify_companion_artifacts.py` fail với `FileNotFoundError: .../reports/releases/v0.6.0_e2e_verification.json` trên mọi clean CI checkout.
- **Root cause:** Commit `79ebb67` di chuyển `reports/releases/v0.6.0_e2e_verification.json` vào `reports/historical/nf_unsw_nb15_v3/releases/`, nhưng `_build_valid_attestation_payload()` vẫn trỏ tới đường dẫn cũ khi `data/demo/*` (`.gitignored`) vắng mặt trên CI, đồng thời file v0.6.0 cũ chứa hash demo của v1.
- **Agent phụ trách:** `Agent G — Product Integration & Security Engineer`
- **Proposed fix:** Thay nhánh fallback đọc file v0.6.0 trong `_build_valid_attestation_payload()` bằng fixture `demo_sha256` hợp lệ của v2 (tính deterministic trong `tmp_path` hoặc đọc trực tiếp từ trust anchor v2 khi chạy test synthetic thay vì dựa vào `reports/releases/v0.6.0_e2e_verification.json`).
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_verify_companion_artifacts.py -k "accepts_valid_payload_and_cli or tampered_model_hash or stale_script" -q`
- **Expected result:** `3 passed` ngay cả khi `data/demo/` vắng mặt trên clean checkout.
- **Actual result:** `FAIL` trên CI run `44171616420` (`FileNotFoundError: .../reports/releases/v0.6.0_e2e_verification.json`); cục bộ pass vì `.gitignore`-d `data/demo/` tồn tại trên đĩa.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, CI Run `44171616420`
- **Related GitHub issue:** `#71`, `#148`, `#154`
- **Acceptance status:** `FAIL`

### Finding `CI-F04`
- **Finding ID:** `CI-F04`
- **Priority:** `P0`
- **File/module liên quan:** `tests/unit/test_verify_companion_artifacts.py`, `tests/integration/test_controller_target_vm_e2e.py:349`, `scripts/verify_companion_artifacts.py:4185-4188`
- **Mô tả vấn đề:** Tổng 11 tests trong `test_verify_companion_artifacts.py` và 1 test trong `test_controller_target_vm_e2e.py` fail trên CI (8 test fail vì mismatch `split_manifest_sha256` tại `verify_e2e_attestation`, 3 test fail vì `FileNotFoundError` ở `CI-F03`).
- **Root cause:** Kết hợp của `CI-F01` (manifest CRLF hash vs Git checkout LF hash làm `verify_e2e_attestation()` throw sớm trước mọi bước kiểm tra `run_id`, `metric inconsistency`, `nsis_e2e`, `bundled resources`, `standalone embedded`) và `CI-F03`.
- **Agent phụ trách:** `Agent G — Product Integration & Security Engineer`
- **Proposed fix:** Sửa `CI-F01` và `CI-F03` để khôi phục đồng bộ `split_manifest_sha256` trên checkout LF và loại phụ thuộc file v0.6.0 trong fixture test, sau đó xác minh lại toàn bộ `test_verify_companion_artifacts.py` và `test_controller_target_vm_e2e.py` trong môi trường không có `data/demo/`.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_verify_companion_artifacts.py tests/integration/test_controller_target_vm_e2e.py -q`
- **Expected result:** `0 failed` trên cả clean CI checkout (Linux & Windows) lẫn máy cục bộ.
- **Actual result:** `FAIL` — 12 tests failed trên CI run `44171616420` (11 ở `test_verify_companion_artifacts.py`, 1 ở `test_controller_target_vm_e2e.py`).
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, CI Run `44171616420`
- **Related GitHub issue:** `#71`, `#73`, `#148`, `#154`
- **Acceptance status:** `FAIL`

### Finding `CI-F05`
- **Finding ID:** `CI-F05`
- **Priority:** `P0`
- **File/module liên quan:** `src/`, `scripts/`, `tests/`, `pyproject.toml:66-76`, `tests/unit/test_code_quality_gates.py:40,54`, `.github/workflows/ci.yml:22,68`
- **Mô tả vấn đề:** Job `lint` trên CI fail với **67 lỗi Ruff** (`41 I001`, `25 F401`, `1 F541`; 36 ở active files và 31 `I001` ở `historical/`) và **43 active files vi phạm Black**; đồng thời `.venv` cục bộ và CI `test` matrix thiếu `ruff`/`black` nên `test_code_quality_gates.py` bị `SKIPPED`.
- **Root cause:** Commit `79ebb67` sửa nhiều script/test nhưng không chạy `ruff`/`black` (do `.venv` chỉ cài `-e .` thiếu `[dev]`, commit message ghi nhận local ruff/black bị skip); ngoài ra `pyproject.toml` không exclude `historical/` khỏi Ruff/Black dù `pytest` đã exclude `tests/historical`.
- **Agent phụ trách:** `Agent G — Product Integration & Security Engineer`
- **Proposed fix:** Sửa toàn bộ 36 lỗi Ruff và 43 định dạng Black ở active files; quyết định rõ chính sách exclude hoặc format `scripts/historical/` & `tests/historical/` cho nhất quán; cài `[dev]` (hoặc ghim `ruff==0.17.5`, `black==26.10.1`) vào `.venv` dev để `test_code_quality_gates.py` chạy thật thay vì skip.
- **Test command:** `ruff check src scripts tests --statistics && black --check src scripts tests && .venv\Scripts\python.exe -m pytest tests/unit/test_code_quality_gates.py -q`
- **Expected result:** `0` lỗi Ruff, `0` file cần reformat Black, `3 passed, 0 skipped` ở `test_code_quality_gates.py`.
- **Actual result:** `FAIL` — Ruff exit `1` (67 lỗi), Black exit `1` (43 files would reformat), `test_code_quality_gates.py` `2 skipped, 1 passed` trong `.venv`.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, CI Run `44171616420` (`lint` job)
- **Related GitHub issue:** `#37`, `#154`
- **Acceptance status:** `FAIL`

### Finding `CI-F06`
- **Finding ID:** `CI-F06`
- **Priority:** `P1`
- **File/module liên quan:** `.github/workflows/ci.yml:85-87`, `scripts/fetch_multi_source_dataset.py:284-374,472-483`
- **Mô tả vấn đề:** Xác minh dataset checksum bị `SKIPPED` trên CI; đồng thời trên máy có sẵn `data/raw/`, `--verify-only` vẫn ghi lại manifest JSON trên đĩa thay vì kiểm tra read-only đối chiếu SHA-256 đã lưu.
- **Root cause:** Dữ liệu raw lớn bị `.gitignore` và vắng mặt trên GitHub Actions runner nên `--verify-only` trả `SKIPPED` (exit `0`) ở run bình thường (và ở run `#44171616420` bị GHA skip hoàn toàn do step pytest fail). Mặt khác `verify_and_generate_manifest()` khi thấy file raw lại tạo payload mới và `manifest_path.write_text(...)` ngay cả khi truyền `--verify-only`.
- **Agent phụ trách:** `Agent C — Dataset & Feature Contract Auditor`
- **Proposed fix:** Tách rõ chế độ `--verify-only` thành read-only strictly verifying recorded SHA-256/MD5 trong `AIT_DATASETS_MANIFEST.json` & `CTU_SME_11_MANIFEST.json` (khi raw file có mặt) mà không ghi đè manifest; bổ sung bước verify manifest schema/provenance JSON ngay trên CI và giữ tách biệt trạng thái `BLOCKED/SKIPPED` cho raw checksums trên runner công khai.
- **Test command:** `.venv\Scripts\python.exe scripts/fetch_multi_source_dataset.py --verify-only` (trên môi trường có raw data và môi trường sạch không raw data)
- **Expected result:** Trên môi trường sạch: báo `SKIPPED` rõ ràng cho raw checksums và verify schema manifest không lỗi; trên môi trường có raw data: verify read-only khớp SHA-256 đã ghi mà không làm dirty workspace.
- **Actual result:** Trên CI run `#44171616420`: step bị GHA `SKIPPED`; trên CI run `#44129176011`: `SOURCE_INTEGRITY: SKIPPED` (exit `0`); cục bộ: `SUCCESS: Official AIT manifest written to data\AIT_DATASETS_MANIFEST.json` (exit `0`).
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `scripts/fetch_multi_source_dataset.py`, CI Runs `#44171616420`, `#44129176011`
- **Related GitHub issue:** `#82`, `#83`
- **Acceptance status:** `BLOCKED`

### Finding `CI-F07`
- **Finding ID:** `CI-F07`
- **Priority:** `P1`
- **File/module liên quan:** `.github/workflows/ci.yml:88-90`, `scripts/run_live_lab_acceptance.py:14,442-451,488-491`, `docs/telemetry/SYNTHETIC_UDP_LOOPBACK_ACCEPTANCE.md`
- **Mô tả vấn đề:** Bước `Validate live telemetry & authorized lab acceptance` bị `SKIPPED` trên CI run `#44171616420`; khi step 11 pass (như run `#44129176011`), kết quả trên CI là `ACCEPTED_WITH_LIMITATIONS` với `ai_inference: UNAVAILABLE` vì thiếu `.joblib` models; đồng thời docstring dòng 14 vẫn ghi nhầm `"47 model features"`.
- **Root cause:** Step 13 phụ thuộc thành công của step 11 (`pytest`), trong khi trên CI clean checkout không có 4 model `.joblib` nên `inference_mode == "UNAVAILABLE"`, và kịch bản chỉ phát UDP synthetic qua `127.0.0.1` dùng private IE `PEN 50000` (không phải router/switch thật, `alerts: NOT_TRIGGERED`).
- **Agent phụ trách:** `Agent G — Product Integration & Security Engineer`
- **Proposed fix:** Sửa docstring dòng 14 từ `47` sang `18` (`canonical-flow-v2-18`); giữ nguyên phân định trung thực `Synthetic UDP Loopback Integration Acceptance` (không thổi phồng thành hardware router/switch lab); sau khi sửa pytest CI để step 13 chạy lại, tách rõ tiêu chí pass ở chế độ synthetic infrastructure vs real-model inference.
- **Test command:** `.venv\Scripts\python.exe scripts/run_live_lab_acceptance.py`
- **Expected result:** Khi có 4 model artifacts: `Verdict: ACCEPTED`; trên CI không artifacts: `ACCEPTED_WITH_LIMITATIONS` được ghi nhận minh bạch và step không bị kẹt bởi test failure khác.
- **Actual result:** `SKIPPED` bởi GHA trong CI run `#44171616420`; `ACCEPTED_WITH_LIMITATIONS` trong CI run `#44129176011`; cục bộ đang có report từ `2026-11-17T18:54:23Z` với `ACCEPTED` (`REAL_MODELS`, `alerts=NOT_TRIGGERED`).
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `scripts/run_live_lab_acceptance.py`, `docs/telemetry/SYNTHETIC_UDP_LOOPBACK_ACCEPTANCE.md`
- **Related GitHub issue:** `#132`, `#135`, `#137`
- **Acceptance status:** `BLOCKED`

### Finding `CI-F08`
- **Finding ID:** `CI-F08`
- **Priority:** `P1`
- **File/module liên quan:** `.github/workflows/ci.yml:91-93`, `scripts/benchmark_full_system.py`, `tests/integration/test_full_system_e2e.py:145-151`
- **Mô tả vấn đề:** Step `Verify full system performance benchmark` bị `SKIPPED` trên CI run `#44171616420` (và khi chạy trên CI thiếu model ở run `#44129176011` chỉ benchmark với `0/4 UNAVAILABLE`); đồng thời `test_missing_dataset_artifact_skips_cleanly` kiểm tra `data/raw/non_existent_huge_dataset.csv` luôn `SKIPPED` (1/3 skip cục bộ).
- **Root cause:** Step 14 bị GHA bỏ qua do step 11 fail; trên CI sạch thiếu model `.joblib` nên `benchmark_full_system.py` chạy không có AI inference thật; còn `test_missing_dataset_artifact_skips_cleanly` là test cố tình check file không tồn tại bằng `pytest.skip()` thay vì test benchmark thật.
- **Agent phụ trách:** `Agent G — Product Integration & Security Engineer`
- **Proposed fix:** Đổi tên/tách rõ `test_missing_dataset_artifact_skips_cleanly` thành unit/contract test kiểm tra hàm guard fail-closed/skip với `tmp_path` (trả `PASS` thay vì tự `pytest.skip` trong suite CI), và gắn nhãn rõ phạm vi `benchmark_full_system.py` trên CI (`no-model pipeline overhead`) vs máy có 4 model thật.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/integration/test_full_system_e2e.py -q -rs && .venv\Scripts\python.exe scripts/benchmark_full_system.py --events 50 --micro-iters 20`
- **Expected result:** `4 passed, 0 skipped` ở `test_full_system_e2e.py` và báo cáo benchmark đo đúng trên 4 model thực tế.
- **Actual result:** Trong lần chạy cục bộ `test_full_system_e2e.py`: `3 passed, 1 skipped` (`non_existent_huge_dataset.csv`); trên CI run `#44171616420`: `Verify full system performance benchmark` bị `SKIPPED`.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `tests/integration/test_full_system_e2e.py:145-151`, `scripts/benchmark_full_system.py`
- **Related GitHub issue:** `#138`, `#147`
- **Acceptance status:** `FAIL`

### Finding `CI-F09`
- **Finding ID:** `CI-F09`
- **Priority:** `P0`
- **File/module liên quan:** `src/network_anomaly/api/desktop_csv.py:684-696,738-744`, `scripts/prepare_demo_dataset.py`
- **Mô tả vấn đề:** Trên CI (Linux & Windows checkout LF), xác minh provenance của `demo_flows.csv` bị hạ xuống `("source:flow-v2-unverified", False)` thay vì `("source:ait-nds-v2", True)`.
- **Root cause:** `TRUSTED_CANONICAL_VALIDATION_SUBSETS` trong `desktop_csv.py:691` ghi cứng `"split_manifest_sha256": "1b7fa7ae..."` (digest CRLF của `V2_SPLIT_MANIFEST.json`). Khi checkout từ Git (`eol=lf`), `CANONICAL_SPLIT_MANIFEST_PATH` có digest `7840d5cd...`, khiến `_verify_canonical_demo_manifest()` trả về mismatch và fail closed thành `source:flow-v2-unverified`.
- **Agent phụ trách:** `Agent G — Product Integration & Security Engineer`
- **Proposed fix:** Chuẩn hóa `V2_SPLIT_MANIFEST.json` và `demo_flows.csv` / `demo_labels.csv` / `demo_manifest.json` sang LF (`newline="\n"`), cập nhật `TRUSTED_CANONICAL_VALIDATION_SUBSETS` trong `desktop_csv.py` và tái chạy `prepare_demo_dataset.py` để đồng bộ toàn bộ SHA-256 trên chuẩn LF.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_desktop_csv_api.py -q` (sau khi checkout LF `data/V2_SPLIT_MANIFEST.json`)
- **Expected result:** Provenance demo trả về `("source:ait-nds-v2", True)` và đạt `MODEL_VALIDATED` trên cả LF lẫn Windows.
- **Actual result:** `FAIL` trên CI checkout LF (`anchor["split_manifest_sha256"] == git_blob_sha256` là `False`: `1b7fa7ae... != 7840d5cd...`).
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `src/network_anomaly/api/desktop_csv.py:684-744`, CI Run `#44171616420`
- **Related GitHub issue:** `#139`, `#150`, `#154`
- **Acceptance status:** `FAIL`

### Finding `CI-F10`
- **Finding ID:** `CI-F10`
- **Priority:** `P1`
- **File/module liên quan:** `desktop/package.json:4`, `desktop/package-lock.json`, `desktop/src-tauri/Cargo.toml:3`, `desktop/src-tauri/Cargo.lock`, `desktop/src-tauri/tauri.conf.json:4,15`, `desktop/src/App.svelte:695,697`, `tests/unit/test_desktop_version_sync.py:38-44,168-170`, `scripts/build_installer_v2.py:122,239`
- **Mô tả vấn đề:** Phiên bản cấu hình đóng gói Desktop và tiêu đề cửa sổ Tauri vẫn giữ `1.0.0` / `v1.0.0`, mâu thuẫn với giao diện Svelte (`App.svelte` hiển thị `v2.0.0`) và mục tiêu phát hành `NetFlow Sentinel v2.0.0` (`2.0.0-pilot` trong `build_installer_v2.py`).
- **Root cause:** Quá trình hard cutover v2 cập nhật text hiển thị trong `App.svelte` lên `v2.0.0` nhưng chưa dùng `scripts/check_desktop_version.py --set-version` nâng version SemVer trên 5 file config/lockfile, `tauri.conf.json` window title, và `tests/unit/test_desktop_version_sync.py`.
- **Agent phụ trách:** `Agent G — Product Integration & Security Engineer` (phối hợp `Agent H` cho docs)
- **Proposed fix:** Thống nhất target version v2 (ví dụ `2.0.0-rc.1` hoặc `2.0.0` theo quyết định release của Orchestrator) bằng `scripts/check_desktop_version.py --set-version <ver>`, cập nhật `tauri.conf.json` `app.windows[0].title`, `tests/unit/test_desktop_version_sync.py`, và `desktop/README.md`.
- **Test command:** `.venv\Scripts\python.exe scripts/check_desktop_version.py --check && .venv\Scripts\python.exe -m pytest tests/unit/test_desktop_version_sync.py -q`
- **Expected result:** Tất cả 5 tệp desktop, tiêu đề Tauri, UI Svelte, và installer builder đồng bộ đúng SemVer v2 mục tiêu.
- **Actual result:** `FAIL` (drift version) — `package.json`, `Cargo.toml`, `tauri.conf.json` đều là `1.0.0` và title cửa sổ là `NetFlow Sentinel v1.0.0`, trong khi `App.svelte` hiển thị `v2.0.0`.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `desktop/package.json:4`, `desktop/src-tauri/Cargo.toml:3`, `desktop/src-tauri/tauri.conf.json:4,15`, `desktop/src/App.svelte:695,697`
- **Related GitHub issue:** `#148`, `#149`, `#154`
- **Acceptance status:** `FAIL`

### Finding `CI-F11`
- **Finding ID:** `CI-F11`
- **Priority:** `P1`
- **File/module liên quan:** `docs/RELEASE_PROCESS.md:1,3,29,50,92`, `docs/DEPLOYMENT_GUIDE_V2.md:80`, `README.md:33`, `docs/DATASET.md:10`, `docs/TRACEABILITY_MATRIX.md:10`, `docs/WINDOWS_INSTALLATION.md:41`, `desktop/README.md:13`, `.agents/reports/V2_CURRENT_AUDIT.md`, `reports/experiments/ml/model_comparison_report.json:51,120,189,237`, `reports/models/{isolation_forest,xgboost}_manifest.json`, `reports/evaluation/{isolation_forest,xgboost}_v2_eval.json`
- **Mô tả vấn đề:** Nhiều tài liệu active còn claim sai hoặc cũ (tái sử dụng model v1.0.0 trong `RELEASE_PROCESS.md`, ghi nhầm `AIT-LDS-v2.1` là `CC BY 4.0` thay vì `CC BY-NC-SA 4.0`, giữ `V2_CURRENT_AUDIT.md` ở snapshot v1 `ebc27fc`), và đường dẫn máy cá nhân `C:\Users\ASUS\...` bị ghi vào JSON reports/manifests tracked trên Git.
- **Root cause:** Quá trình viết lại tài liệu và xuất report/manifest khi chuyển sang v2 chưa đồng bộ hết tất cả tài liệu governance/deployment, và các script train/eval ghi `str(model_path.resolve())` tuyệt đối vào JSON tracked.
- **Agent phụ trách:** `Agent H — Documentation & Research Engineer` (tài liệu) & `Agent D` / `Agent E` / `Agent F` (chuẩn hóa relative path trong JSON artifacts)
- **Proposed fix:** Cập nhật `docs/RELEASE_PROCESS.md` bỏ chỉ dẫn tái sử dụng artifact v1 và chuyển sang quy trình v2; sửa nhãn license `AIT-LDS-v2.1` thành `CC BY-NC-SA 4.0` trong `DEPLOYMENT_GUIDE_V2.md`, `RELEASE_PROCESS.md`, `README.md`, `DATASET.md`, `TRACEABILITY_MATRIX.md`, `WINDOWS_INSTALLATION.md`; chuẩn hóa đường dẫn trong JSON reports/manifests thành đường dẫn tương đối từ repo root (không lộ `C:\Users\ASUS\...`).
- **Test command:** Kiểm tra grep `C:\\Users\\` / `C:/Users/` trên `reports/` & `docs/`, kiểm tra đối chiếu license với `data/EXTERNAL_DATASETS_PROVENANCE.json` và `NOTICE`.
- **Expected result:** Zero đường dẫn máy cá nhân trong active reports/manifests; 100% tài liệu khớp kiến trúc hard cutover v2 và phân biệt đúng `CC BY-NC-SA 4.0` cho `AIT-LDS-v2.1`.
- **Actual result:** `FAIL` — Phát hiện 8 vị trí `C:\Users\ASUS` / `C:/Users/ASUS` trong 5 JSON active (`model_comparison_report.json`, 2 manifests, 2 eval reports) + `reports/audit/00-index.md`, và sai lệch nội dung ở các doc nêu trên.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `docs/RELEASE_PROCESS.md`, `docs/DEPLOYMENT_GUIDE_V2.md`, `reports/experiments/ml/model_comparison_report.json`
- **Related GitHub issue:** `#148`, `#151`, `#152`, `#154`
- **Acceptance status:** `FAIL`

### Finding `CI-F12`
- **Finding ID:** `CI-F12`
- **Priority:** `P2`
- **File/module liên quan:** `.github/workflows/ci.yml`, `.github/workflows/lint-audit.yml`, `.github/workflows/release.yml`, `pyproject.toml:66-76`
- **Mô tả vấn đề:** Hạ tầng workflow CI/CD có lệch phiên bản `ruff` (`0.17.5` vs `0.17.1` vs `>=0.6.0`), `SCOPED_LIST` lỗi thời ở `lint-audit.yml` (`tests/unit/test_multi_source_pipeline.py` không tồn tại), `ci.yml` quét Ruff/Black cả vào thư mục `historical/`, và chạy trùng `run_live_lab_acceptance.py` + `benchmark_full_system.py` trên 2 OS.
- **Root cause:** Khi refactor cutover v2, `lint-audit.yml` và `pyproject.toml` chưa được đồng bộ đầy đủ với cấu trúc mới và phiên bản tool được pin trong `ci.yml`.
- **Agent phụ trách:** `Agent G — Product Integration & Security Engineer`
- **Proposed fix:** Pin thống nhất phiên bản `ruff==0.17.5` và `black==26.10.1` trong `pyproject.toml` (`[project.optional-dependencies].dev`), `ci.yml`, `lint-audit.yml` và `release.yml`; rà soát lại `lint-audit.yml` (xóa path không tồn tại hoặc hợp nhất chiến lược lint `historical/`); cân nhắc tách bước benchmark/acceptance nặng khỏi ma trận OS trùng lặp mà vẫn giữ nguyên 4 required checks `test (...)`.
- **Test command:** Kiểm tra YAML và đối chiếu version pin trên `.github/workflows/*.yml` + `pyproject.toml`
- **Expected result:** 100% workflow dùng cùng phiên bản `ruff` và `black`, không có path dead trong `lint-audit.yml`.
- **Actual result:** `FAIL` — Lệch version `ruff` (`0.17.5` / `0.17.1` / `>=0.6.0`) và `tests/unit/test_multi_source_pipeline.py` trong `lint-audit.yml` không tồn tại.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `.github/workflows/ci.yml`, `.github/workflows/lint-audit.yml`, `.github/workflows/release.yml`
- **Related GitHub issue:** `#37`, `#76`, `#154`
- **Acceptance status:** `FAIL`

---

## 6. Kết luận Phase 0 (CI/CD & Repository Baseline)

1. **Local vs Remote:** Local working tree sạch và `HEAD` khớp `origin/feat/v2-integration` (`79ebb67`), nhưng kết quả kiểm thử cục bộ (`578 passed, 3 skipped`) **không đại diện cho clean checkout**, vì dựa trên các tệp `.gitignored` (`artifacts/`, `data/demo/`, `data/raw/`) và file `V2_SPLIT_MANIFEST.json` mang CRLF trên đĩa Windows.
2. **Nguyên nhân gốc của CI đỏ:** CI run `#44171616420` fail vì **3 cụm lỗi P0 kỹ thuật**:
   - Lệch CRLF vs LF trên `V2_SPLIT_MANIFEST.json` (`CI-F01`, gây dây chuyền `CI-F02`, `CI-F04`, `CI-F09` — chiếm 10/13 pytest failures trên CI);
   - Fixture trong `test_verify_companion_artifacts.py` trỏ vào `reports/releases/v0.6.0_e2e_verification.json` đã di chuyển sang `historical/` (`CI-F03` — chiếm 3/13 pytest failures trên CI);
   - Chưa chạy `ruff` và `black` sau khi chỉnh code v2 ở `79ebb67` (`CI-F05` — 67 lỗi Ruff và 43 file Black).
3. **Khuyến nghị hành động tiếp theo (Phase 1):** Khắc phục theo thứ tự `CI-F01` → `CI-F03` → `CI-F02`/`CI-F04`/`CI-F09` → `CI-F05` → `CI-F08`/`CI-F10`/`CI-F11`/`CI-F12`, và giữ nguyên PR `#156` ở trạng thái **Draft** cho tới khi toàn bộ status check trên GitHub Actions xanh và có kết quả nghiệm thu độc lập.
