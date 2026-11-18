# V2 Finding Register — NetFlow Sentinel v2.0

- **Ngày lập sổ đăng ký:** `2026-11-18` (`+07:00`) / `2026-11-17T22:05Z`
- **Baseline HEAD:** `feat/v2-integration` @ `79ebb678b87de19cc6b664b587726983fecaf98f`
- **Quy ước trạng thái (Mục 3.3 `PROMPT.md`):** `PASS` | `FAIL` | `BLOCKED` | `UNVERIFIED` | `DEFERRED` | `NOT_APPLICABLE`
- **Tổng hợp nguồn:** [V2_CI_AUDIT.md](V2_CI_AUDIT.md), [V2_DATA_QUALITY_AUDIT.md](V2_DATA_QUALITY_AUDIT.md), [V2_MODEL_AUDIT.md](V2_MODEL_AUDIT.md), [V2_ISSUE_AC_AUDIT.md](V2_ISSUE_AC_AUDIT.md), [V2_BASELINE_EVIDENCE_LEDGER.md](V2_BASELINE_EVIDENCE_LEDGER.md).

---

## 1. Bảng Tóm tắt Chỉ mục Findings

| Finding ID | Priority | Nhóm | Trạng thái | Tóm tắt ngắn | Related Issue(s) |
|---|---|---|---|---|---|
| `CI-F01` | `P0` | CI / Provenance | `FAIL` | `split_manifest_sha256` lệch CRLF (`1b7fa7ae...`) vs Git LF (`7840d5cd...`) | `#92`, `#93`, `#154` |
| `CI-F02` | `P0` | CI / Desktop API | `FAIL` | `test_f01_provenance_anti_spoofing_matrix` fail trên CI do CRLF anchor | `#139`, `#150`, `#154` |
| `CI-F03` | `P0` | CI / Test Fixture | `FAIL` | `test_verify_companion_artifacts.py` trỏ vào `reports/releases/v0.6.0_e2e_verification.json` đã chuyển | `#71`, `#148`, `#154` |
| `CI-F04` | `P0` | CI / Attestation | `FAIL` | 11 tests `test_verify_companion_artifacts.py` + 1 test VM E2E fail trên CI | `#71`, `#73`, `#148`, `#154` |
| `CI-F05` | `P0` | CI / Code Quality | `FAIL` | 67 lỗi Ruff (`36` active + `31` historical), 43 active files Black, `.venv` thiếu tools | `#37`, `#60`, `#154` |
| `CI-F06` | `P1` | Dataset / CI | `BLOCKED` | Raw checksum `SKIPPED` trên CI; `--verify-only` cục bộ ghi đè 3 manifest JSON | `#82`, `#83` |
| `CI-F07` | `P1` | Telemetry / CI | `BLOCKED` | `run_live_lab_acceptance.py` chạy UDP loopback giả lập (`alerts=NOT_TRIGGERED`), docstring ghi 47 features | `#132`, `#135`, `#137` |
| `CI-F08` | `P1` | Benchmark / Test | `FAIL` | `test_missing_dataset_artifact_skips_cleanly` luôn `pytest.skip()`; benchmark CI thiếu models | `#138`, `#147` |
| `CI-F09` | `P0` | Demo Provenance | `FAIL` | Demo provenance trên LF checkout bị hạ thành `source:flow-v2-unverified` | `#139`, `#150`, `#154` |
| `CI-F10` | `P1` | Release / Desktop | `FAIL` | Desktop configs/lockfiles & Tauri window title giữ `1.0.0` / `v1.0.0` lệch UI `v2.0.0` | `#148`, `#149`, `#154` |
| `CI-F11` | `P1` | Docs & Paths | `FAIL` | `RELEASE_PROCESS.md` ghi v1; nhiều docs ghi sai license `AIT-LDS-v2.1`; lộ path `C:\Users\ASUS\` | `#18`, `#148`, `#151`, `#152`, `#154` |
| `CI-F12` | `P2` | CI Optimization | `FAIL` | Lệch version `ruff` (`0.17.5` vs `0.17.1`), path chết trong `lint-audit.yml`, matrix lặp dư thừa | `#37`, `#76`, `#154` |
| `DATA-A01` | `P0` | Dataset Builder | `FAIL` | Bug align `RangeIndex` của `chunksize=250_000` làm rơi âm thầm `233,185` dòng AIT (`6.73%`) | `#84`, `#88`, `#92` |
| `DATA-A02` | `P0` | Feature Unit | `FAIL` | `AIT udp_complete.csv` `c_durat:4`/`s_durat:13` là giây (không phải ms) -> `93.7–97.5%` bị kẹp `1 ms` | `#88`, `#93`, `#95` |
| `DATA-A03` | `P0` | Cross-Source Byte | `FAIL` | AIT Tstat L4 payload bytes (`0 B`) vs CTU Zeek `orig_ip_bytes` IP+header (`80–88 B`) đảo chiều Attack | `#88`, `#95`, `#97` |
| `DATA-A04` | `P0` | Preprocessing | `FAIL` | `protocol_num` unscaled passthrough (`ICMP=1` -> MSE `7.58–10.06`) + `pkts_in_ratio` IQR collapse (`0.044`) | `#95`, `#99`, `#100` |
| `DATA-A05` | `P1` | Probe / Adapter | `FAIL` | Probe signature `pkts_in=1` vs `2`, mid-stream `pkts_in=0`, xung đột nhãn 18-D trên 48–75 vectors | `#86`, `#88`, `#95` |
| `DATA-A06` | `P1` | 5-Tuple Leakage | `FAIL` | `ctu_echo` vs `ctu_windows7ad` chia sẻ 42 `(5-tuple, ts)` (47 dòng) với nhãn đối nghịch | `#92`, `#97` |
| `DATA-A07` | `P2` | External Blockers | `BLOCKED` | `UGR'16` HTTP `403`; `AIT-NDS-v2 ↔ AIT-LDS-v2.1` `direct_uid_join_possible=false` | `#82`, `#85`, `#97`, `#104` |
| `DATA-A08` | `P2` | Builder Docstring | `FAIL` | `build_v2_dataset_and_split.py:15,518` ghi `robust`/`RobustScaler` thay vì `asinh_robust` | `#84`, `#92` |
| `ML-01` | `P0` | Model Provenance | `FAIL` | 4 model train trên dirty snapshot `05240b44` (`git_dirty=True`); `RF` `.joblib` thiếu `split_ref`; `AE` thiếu split check | `#94`, `#95`, `#154` |
| `ML-02` | `P0` | Supervised Cross-Source | `FAIL` | Zero-shot `CTU-Echo F1=0.0` (RF/XGB, XGB AUC=`0.0373`), `CTU-Win7AD F1=0.0/0.0007` | `#94`, `#95`, `#97` |
| `ML-03` | `P1` | Rare / Exfil Recall | `FAIL` | `AIT-Test` `Data_Exfiltration` recall `60.6%/57.5%` (Sup) & `0.00%/0.05%` (Unsup); `Credential_Attack` `14.1%` | `#94`, `#96`, `#98` |
| `ML-04` | `P0` | Unsupervised FPR | `FAIL` | Zero-shot Autoencoder `CTU-Echo FPR=0.6520`, `CTU-Win7AD FPR=0.8545`; IF `FPR=0.2086 / 0.4334` | `#94`, `#99`, `#100` |
| `ML-05` | `P2` | Metadata / Explainability | `FAIL` | `xgboost` `provenance_note` mâu thuẫn; `IF` ghi `target="Label"`; `IF/AE` `top_features=[]`; `>` vs `>=` threshold | `#94`, `#100`, `#105` |
| `PROD-01` | `P0` | Ingestion / Adapters | `FAIL` | `parse_timestamp_utc` fallback `now()`, `IdentityAuthAdapter` hardcode `2020-11-05`, thiếu `SourceRegistry` & URL redaction | `#79`, `#86`, `#89`, `#90`, `#93` |
| `PROD-02` | `P1` | ML Runtime / OOD | `FAIL` | Thiếu `artifacts/ml/ood_reference_gate.json` (`ood_gate=NOT_FITTED`) | `#99`, `#137` |
| `PROD-03` | `P1` | Behavioral / CSV | `FAIL` | `BehavioralVectorBuilder` ép NaN thành `0.0` thiếu cờ; thiếu profiler (`#103`); không tích hợp CSV (`#106`) | `#101`, `#102`, `#103`, `#106` |
| `PROD-04` | `P1` | Trace / DB / Crypto | `FAIL` | `db.py` `SCHEMA_SQL` thiếu bảng v2 (`#107`); `evaluate_traceability.py` hardcoded/sai toán (`#114`); `KeyRotationPolicy` không persist/clock injection (`#120/#122`); thiếu `cryptography` notice | `#18`, `#107`, `#114`, `#117`, `#120`, `#122` |
| `PROD-05` | `P0` | Audit Docs & Gitignore | `FAIL` | `.gitignore:69` chặn `/docs/audits/`; `THREAT_MODEL_V2.md` dẫn 5 test giả; `USER_GUIDE_V2.md` dẫn 3 route không tồn tại; `ARCHITECTURE_V2.md` mâu thuẫn | `#76`, `#78`, `#81`, `#128`, `#146`, `#151`, `#152` |
| `PROD-06` | `P1` | Distribution / VM | `BLOCKED` | `DISTRIBUTION_AUTHORIZATION.json` `approved=false`; thiếu Clean Windows VM E2E & `site-source` v2 | `#71`, `#73`, `#148`, `#149`, `#152`, `#154` |

---

## 2. Chi tiết 13 Trường cho Từng Finding

### Nhóm 1 — CI, Repository & Release Infrastructure (`CI-F01` .. `CI-F12`)

#### `CI-F01`
- **Finding ID:** `CI-F01`
- **Priority:** `P0`
- **File/module liên quan:** `scripts/build_v2_dataset_and_split.py:485-486`, `data/V2_SPLIT_MANIFEST.json`, `reports/splits/v2_split_manifest.json`, `reports/preprocessing/v2_flow_preprocessing_manifest.json`, `reports/models/*_manifest.json`, `.gitattributes:3`
- **Mô tả vấn đề:** `split_manifest_sha256` lưu trong preprocessor, 4 model manifests, test fixtures và trust anchor là SHA-256 bản CRLF Windows (`1b7fa7ae...`, 4,851 B), khác với bản LF trong Git blob (`7840d5cd...`, 4,716 B).
- **Root cause:** Ghi tệp trên Windows bằng `write_text(..., encoding="utf-8")` thiếu `newline="\n"`, trong khi `.gitattributes` (`* text=auto eol=lf`) checkout thành LF trên CI.
- **Agent phụ trách:** `Agent G` / `Agent C`
- **Proposed fix:** Ghi toàn bộ JSON/CSV/MD bằng `newline="\n"` (`lineterminator="\n"`), tái sinh split & manifests theo chuẩn LF.
- **Test command:** `.venv\Scripts\python.exe -c "import hashlib,subprocess,json; from pathlib import Path; b=subprocess.check_output(['git','show','HEAD:data/V2_SPLIT_MANIFEST.json']); p=json.loads(Path('reports/preprocessing/v2_flow_preprocessing_manifest.json').read_text()); assert hashlib.sha256(b).hexdigest()==p['split_manifest_sha256']"`
- **Expected result:** Assert pass; mọi JSON tracked có 0 CRLF.
- **Actual result:** `FAIL` (`1b7fa7ae... != 7840d5cd...`).
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, CI Run `44171616420`
- **Related GitHub issue:** `#92`, `#93`, `#154`
- **Acceptance status:** `FAIL`

#### `CI-F02`
- **Finding ID:** `CI-F02`
- **Priority:** `P0`
- **File/module liên quan:** `tests/unit/test_desktop_csv_api.py:38,689,704-707`, `src/network_anomaly/api/desktop_csv.py:691,738-744`
- **Mô tả vấn đề:** `test_f01_provenance_anti_spoofing_matrix` fail trên cả 4 job CI (`('source:flow-v2-unverified', False)` thay vì `('source:ait-nds-v2', True)`).
- **Root cause:** Hằng `CANONICAL_SPLIT_MANIFEST_SHA256` và `TRUSTED_CANONICAL_VALIDATION_SUBSETS` ghim digest CRLF `1b7fa7ae...`, không khớp checkout LF trên CI.
- **Agent phụ trách:** `Agent G`
- **Proposed fix:** Chuẩn hóa LF cho `V2_SPLIT_MANIFEST.json`, cập nhật digest LF mới vào `desktop_csv.py` và `test_desktop_csv_api.py`.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_desktop_csv_api.py -k test_f01_provenance_anti_spoofing_matrix -q`
- **Expected result:** `1 passed` trên cả disk LF và CI Linux/Windows.
- **Actual result:** `FAIL` trên CI run `44171616420`.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, CI Run `44171616420`
- **Related GitHub issue:** `#139`, `#150`, `#154`
- **Acceptance status:** `FAIL`

#### `CI-F03`
- **Finding ID:** `CI-F03`
- **Priority:** `P0`
- **File/module liên quan:** `tests/unit/test_verify_companion_artifacts.py:143-151`, `reports/historical/nf_unsw_nb15_v3/releases/v0.6.0_e2e_verification.json`
- **Mô tả vấn đề:** 3 tests trong `test_verify_companion_artifacts.py` fail với `FileNotFoundError` trên clean CI checkout vắng `data/demo/*`.
- **Root cause:** Nhánh fallback đọc `reports/releases/v0.6.0_e2e_verification.json` đã di chuyển vào `reports/historical/nf_unsw_nb15_v3/releases/` tại commit `79ebb67`.
- **Agent phụ trách:** `Agent G`
- **Proposed fix:** Thay nhánh fallback bằng fixture synthetic hoặc `data/demo/demo_manifest.json` / trust anchor v2 không phụ thuộc file v0.6.0.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_verify_companion_artifacts.py -k "accepts_valid_payload_and_cli or tampered_model_hash or stale_script" -q`
- **Expected result:** `3 passed` ngay cả khi thiếu `data/demo/`.
- **Actual result:** `FAIL` trên CI run `44171616420`.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, CI Run `44171616420`
- **Related GitHub issue:** `#71`, `#148`, `#154`
- **Acceptance status:** `FAIL`

#### `CI-F04`
- **Finding ID:** `CI-F04`
- **Priority:** `P0`
- **File/module liên quan:** `tests/unit/test_verify_companion_artifacts.py`, `tests/integration/test_controller_target_vm_e2e.py:349`, `scripts/verify_companion_artifacts.py:4185-4188`
- **Mô tả vấn đề:** 11 tests trong `test_verify_companion_artifacts.py` + 1 test trong `test_controller_target_vm_e2e.py` fail trên CI.
- **Root cause:** Hệ quả kết hợp của `CI-F01` (nên ném `RuntimeError` trước khi chạm các assert tamper/flags) và `CI-F03`.
- **Agent phụ trách:** `Agent G`
- **Proposed fix:** Khắc phục `CI-F01` và `CI-F03`, cập nhật danh sách sidecar IF trong `verify_companion_artifacts.py` nếu cần.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_verify_companion_artifacts.py tests/integration/test_controller_target_vm_e2e.py -q`
- **Expected result:** `0 failed` trên clean LF checkout.
- **Actual result:** `FAIL` (`12 failed` trên CI run `44171616420`).
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, CI Run `44171616420`
- **Related GitHub issue:** `#71`, `#73`, `#148`, `#154`
- **Acceptance status:** `FAIL`

#### `CI-F05`
- **Finding ID:** `CI-F05`
- **Priority:** `P0`
- **File/module liên quan:** `src/`, `scripts/`, `tests/`, `pyproject.toml:66-76`, `tests/unit/test_code_quality_gates.py:40,54`, `.github/workflows/ci.yml:22,68`
- **Mô tả vấn đề:** Job `lint` trên CI fail với 67 lỗi Ruff (`36` active, `31` historical) + 43 active files Black; `.venv` cục bộ & 4 job `test` thiếu `ruff`/`black` làm `test_code_quality_gates.py` bị skip.
- **Root cause:** Code commit `79ebb67` chưa chạy `ruff`/`black`; `.venv` chỉ cài `-e .` thiếu `[dev]`.
- **Agent phụ trách:** `Agent G`
- **Proposed fix:** Đồng bộ `ruff==0.17.5` và `black==26.10.1` vào `.venv`, chạy `ruff check --fix` và `black`, kiểm tra chính sách exclude/format `historical/`.
- **Test command:** `.venv\Scripts\python.exe -m ruff check src scripts tests && .venv\Scripts\python.exe -m black --check src scripts tests && .venv\Scripts\python.exe -m pytest tests/unit/test_code_quality_gates.py -q`
- **Expected result:** Exit `0` cho Ruff/Black và `3 passed, 0 skipped` ở `test_code_quality_gates.py`.
- **Actual result:** `FAIL` (67 Ruff errors, 43 Black reformats, 2 skipped trong `.venv`).
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, CI Run `44171616420` (`lint`)
- **Related GitHub issue:** `#37`, `#60`, `#154`
- **Acceptance status:** `FAIL`

#### `CI-F06`
- **Finding ID:** `CI-F06`
- **Priority:** `P1`
- **File/module liên quan:** `.github/workflows/ci.yml:85-87`, `scripts/fetch_multi_source_dataset.py:284-374,472-483`
- **Mô tả vấn đề:** Raw checksum `SKIPPED` trên CI; khi chạy `--verify-only` trên máy có raw data lại tự ghi đè 3 manifest JSON đang track.
- **Root cause:** Dữ liệu raw bị `.gitignore`; `verify_and_generate_manifest()` ghi lại file ngay cả khi truyền `--verify-only`.
- **Agent phụ trách:** `Agent C`
- **Proposed fix:** Sửa `--verify-only` thành thực sự chỉ đọc (verify size/MD5/SHA-256 trên đĩa so với manifest mà không ghi đè file), và kiểm tra schema manifest JSON độc lập trên CI.
- **Test command:** `.venv\Scripts\python.exe scripts/fetch_multi_source_dataset.py --verify-only && git status --short data/`
- **Expected result:** Exit `0` không làm thay đổi tracked manifests trong `data/`.
- **Actual result:** `BLOCKED` trên CI (raw vắng mặt); cục bộ ghi đè 3 manifest JSON.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `reports/audits/V2_ISSUE_AC_AUDIT.md`
- **Related GitHub issue:** `#82`, `#83`
- **Acceptance status:** `BLOCKED`

#### `CI-F07`
- **Finding ID:** `CI-F07`
- **Priority:** `P1`
- **File/module liên quan:** `.github/workflows/ci.yml:88-90`, `scripts/run_live_lab_acceptance.py:14,442-451`, `docs/telemetry/SYNTHETIC_UDP_LOOPBACK_ACCEPTANCE.md`
- **Mô tả vấn đề:** `run_live_lab_acceptance.py` chạy UDP loopback giả lập `127.0.0.1` (`real_device_tested=false`, `alerts=NOT_TRIGGERED`), docstring dòng 14 ghi nhầm 47 features, và bị skip trên CI run `44171616420` (hoặc `UNAVAILABLE` khi thiếu `.joblib`).
- **Root cause:** Thiếu thiết bị lab router/switch vật lý; docstring chưa cập nhật; CI step bị kẹt sau pytest fail.
- **Agent phụ trách:** `Agent G` & `Agent H`
- **Proposed fix:** Sửa docstring sang `18 features` (`canonical-flow-v2-18`), bổ sung test kịch bản kích hoạt alert qua UDP loopback, và giữ phân định trung thực UDP loopback simulation vs physical lab (`BLOCKED`).
- **Test command:** `.venv\Scripts\python.exe scripts/run_live_lab_acceptance.py`
- **Expected result:** Pass UDP loopback với 4 real models khi có artifact; ghi rõ `BLOCKED` cho physical switch/router.
- **Actual result:** `BLOCKED` đối với thiết bị vật lý; `SKIPPED` trên CI `44171616420`.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `reports/acceptance/synthetic_udp_loopback_report.json`
- **Related GitHub issue:** `#132`, `#135`, `#137`
- **Acceptance status:** `BLOCKED`

#### `CI-F08`
- **Finding ID:** `CI-F08`
- **Priority:** `P1`
- **File/module liên quan:** `.github/workflows/ci.yml:91-93`, `scripts/benchmark_full_system.py`, `tests/integration/test_full_system_e2e.py:145-151`
- **Mô tả vấn đề:** `test_missing_dataset_artifact_skips_cleanly` luôn `pytest.skip()` (làm bộ đếm pytest có `skipped`); step benchmark CI bị GHA skip khi pytest fail và chạy với `0/4 UNAVAILABLE` trên CI sạch.
- **Root cause:** Dùng `pytest.skip()` cho một negative-guard test thay vì `assert`.
- **Agent phụ trách:** `Agent G`
- **Proposed fix:** Sửa `test_missing_dataset_artifact_skips_cleanly` thành assertion thực sự kiểm tra hành vi missing-file guard mà không gọi `pytest.skip()`.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/integration/test_full_system_e2e.py -q -rs`
- **Expected result:** `4 passed, 0 skipped`.
- **Actual result:** `FAIL` (`3 passed, 1 skipped`).
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `tests/integration/test_full_system_e2e.py:145-151`
- **Related GitHub issue:** `#138`, `#147`
- **Acceptance status:** `FAIL`

#### `CI-F09`
- **Finding ID:** `CI-F09`
- **Priority:** `P0`
- **File/module liên quan:** `src/network_anomaly/api/desktop_csv.py:684-696,738-744`, `scripts/prepare_demo_dataset.py`
- **Mô tả vấn đề:** Demo CSV provenance bị chuyển thành `("source:flow-v2-unverified", False)` trên mọi checkout LF (Linux/Windows CI).
- **Root cause:** `TRUSTED_CANONICAL_VALIDATION_SUBSETS` lưu `split_manifest_sha256` CRLF (`1b7fa7ae...`) và `prepare_demo_dataset.py` ghi CRLF.
- **Agent phụ trách:** `Agent G`
- **Proposed fix:** Tái chạy `prepare_demo_dataset.py` với `newline="\n"` sau khi chuẩn hóa LF `V2_SPLIT_MANIFEST.json`, cập nhật `TRUSTED_CANONICAL_VALIDATION_SUBSETS`.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_desktop_csv_api.py -q`
- **Expected result:** `("source:ait-nds-v2", True)` và `MODEL_VALIDATED` trên LF.
- **Actual result:** `FAIL` trên LF (`1b7fa7ae... != 7840d5cd...`).
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `src/network_anomaly/api/desktop_csv.py:684-744`
- **Related GitHub issue:** `#139`, `#150`, `#154`
- **Acceptance status:** `FAIL`

#### `CI-F10`
- **Finding ID:** `CI-F10`
- **Priority:** `P1`
- **File/module liên quan:** `desktop/package.json:4`, `desktop/package-lock.json`, `desktop/src-tauri/Cargo.toml:3`, `desktop/src-tauri/Cargo.lock`, `desktop/src-tauri/tauri.conf.json:4,15`, `tests/unit/test_desktop_version_sync.py`
- **Mô tả vấn đề:** Toàn bộ metadata desktop & tiêu đề cửa sổ Tauri vẫn là `1.0.0` / `v1.0.0`, lệch với `App.svelte` (`v2.0.0`) và `build_installer_v2.py` (`2.0.0-pilot`).
- **Root cause:** Chưa chạy `check_desktop_version.py --set-version` nâng lên `2.0.0` khi chuyển sang v2.
- **Agent phụ trách:** `Agent G`
- **Proposed fix:** Nâng toàn bộ 5 file desktop + window title + `test_desktop_version_sync.py` lên `2.0.0`.
- **Test command:** `.venv\Scripts\python.exe scripts/check_desktop_version.py --check --expect-version 2.0.0 && .venv\Scripts\python.exe -m pytest tests/unit/test_desktop_version_sync.py -q`
- **Expected result:** Pass với phiên bản `2.0.0`.
- **Actual result:** `FAIL` (đang ở `1.0.0`).
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`, `desktop/src-tauri/tauri.conf.json:4,15`
- **Related GitHub issue:** `#148`, `#149`, `#154`
- **Acceptance status:** `FAIL`

#### `CI-F11`
- **Finding ID:** `CI-F11`
- **Priority:** `P1`
- **File/module liên quan:** `docs/RELEASE_PROCESS.md`, `docs/DEPLOYMENT_GUIDE_V2.md`, `README.md`, `docs/DATASET.md`, `docs/TRACEABILITY_MATRIX.md`, `docs/WINDOWS_INSTALLATION.md`, `desktop/README.md`, `.agents/reports/V2_CURRENT_AUDIT.md`, `reports/experiments/ml/model_comparison_report.json`, `reports/models/{xgboost,isolation_forest}_manifest.json`, `data/demo/demo_manifest.json`
- **Mô tả vấn đề:** `RELEASE_PROCESS.md` ghi `v1.0.0` và chỉ dẫn tái sử dụng artifact v1; 6 tài liệu ghi nhầm `AIT-LDS-v2.1` là `CC BY 4.0` thay vì `CC BY-NC-SA 4.0`; `V2_CURRENT_AUDIT.md` lỗi thời; nhiều JSON active chứa đường dẫn `C:\Users\ASUS\...`.
- **Root cause:** Cập nhật cutover v2 chưa rà soát toàn bộ docs/JSON outputs.
- **Agent phụ trách:** `Agent H` & `Agent D/E/F`
- **Proposed fix:** Sửa toàn bộ docs, phân biệt rõ `CC BY-NC-SA 4.0`, bỏ đường dẫn tuyệt đối khỏi scripts/JSONs, tái đồng bộ `V2_CURRENT_AUDIT.md`.
- **Test command:** Quét grep đường dẫn cá nhân và kiểm tra toàn bộ internal links trong `docs/` & `README.md`.
- **Expected result:** `0` đường dẫn cá nhân trong active files; `0` mâu thuẫn license/v1.
- **Actual result:** `FAIL`.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`
- **Related GitHub issue:** `#18`, `#148`, `#151`, `#152`, `#154`
- **Acceptance status:** `FAIL`

#### `CI-F12`
- **Finding ID:** `CI-F12`
- **Priority:** `P2`
- **File/module liên quan:** `.github/workflows/ci.yml`, `.github/workflows/lint-audit.yml`, `pyproject.toml`
- **Mô tả vấn đề:** `ci.yml` dùng `ruff==0.17.5`, `lint-audit.yml` dùng `ruff==0.17.1` và có path không tồn tại `tests/unit/test_multi_source_pipeline.py`; matrix lặp bước acceptance/benchmark 2 lần.
- **Root cause:** Workflow chưa đồng bộ sau refactor v2.
- **Agent phụ trách:** `Agent G`
- **Proposed fix:** Pin thống nhất `ruff==0.17.5` & `black==26.10.1` ở `pyproject.toml`, `ci.yml`, `lint-audit.yml`; xóa path chết và tối ưu bước trùng lặp trong matrix.
- **Test command:** Kiểm tra YAML và đối chiếu version pin + pytest/lint pass.
- **Expected result:** Thống nhất version và loại bỏ redundancy mà không giảm coverage gate.
- **Actual result:** `FAIL`.
- **Evidence path:** `reports/audits/V2_CI_AUDIT.md`
- **Related GitHub issue:** `#37`, `#76`, `#154`
- **Acceptance status:** `FAIL`

---

### Nhóm 2 — Dataset Quality & Feature Compatibility (`DATA-A01` .. `DATA-A07`)

#### `DATA-A01`
- **Finding ID:** `DATA-A01`
- **Priority:** `P0`
- **File/module liên quan:** `scripts/build_v2_dataset_and_split.py:141-145,192,215,237-247`
- **Mô tả vấn đề:** Mất âm thầm `233,185` dòng `tcp_complete.csv` (`6.73%` của `3,465,342` raw AIT-NDS-v2), gồm `167,672` dòng `wilson`, `31,478` `shaw`, `34,035` `wheeler` (`334` `Credential_Attack` = `13.22%`, `7` `Exploitation_And_C2` = `16.28%`).
- **Root cause:** `pd.read_csv(..., chunksize=250_000)` giữ `RangeIndex(250000, ...)` cho chunk thứ 2+, trong khi `_classify_series()` trả về `pd.Series` index `0..n-1`; phép gán `feat_df["label_status"] = lst` align sai index tạo toàn `<NA>`.
- **Agent phụ trách:** `Agent C`
- **Proposed fix:** `chunk = chunk.reset_index(drop=True)` sau khi đọc chunk, gán giá trị theo mảng NumPy / index đồng nhất, và thêm assertion kiểm tra `len(df_labeled) + len(df_unmapped) == raw_rows` cho từng scenario.
- **Test command:** `.venv\Scripts\python.exe scripts/build_v2_dataset_and_split.py` + kiểm tra tổng dòng `3,464,400` labeled + `942` unmapped = `3,465,342`.
- **Expected result:** `0` dòng bị rơi; bảo toàn toàn bộ `334` `Credential_Attack` và `7` `Exploitation_And_C2` bị mất.
- **Actual result:** `FAIL` (`3,232,157 != 3,465,342`).
- **Evidence path:** `reports/audits/V2_DATA_QUALITY_AUDIT.md` (Mục 1 & 2.3)
- **Related GitHub issue:** `#84`, `#88`, `#92`
- **Acceptance status:** `FAIL`

#### `DATA-A02`
- **Finding ID:** `DATA-A02`
- **Priority:** `P0`
- **File/module liên quan:** `src/network_anomaly/data/v2_schema.py:281`, `scripts/build_v2_dataset_and_split.py:205-208`
- **Mô tả vấn đề:** Đơn vị `duration_ms` của `AIT udp_complete.csv` bị sai `1000x` (`c_durat:4`/`s_durat:13` lưu **giây**, không phải ms), làm `93.7%–97.5%` UDP flows bị kẹp về `1.0 ms` và thổi phồng `bytes_per_sec_*`/`pkts_per_sec` tới `5.38e10 B/s`.
- **Root cause:** Parser Tstat đọc thẳng `c_durat`/`s_durat` như mili-giây mà không nhân `1000.0` (và không tính span `s_first_abs` vs `c_first_abs` khi cả hai chiều có timestamp hợp lệ).
- **Agent phụ trách:** `Agent C`
- **Proposed fix:** Nhân `* 1000.0` cho `c_durat:4`/`s_durat:13` trong Tstat UDP parser (và hợp nhất span đầu-cuối khi có `s_first_abs > 0` với `s_pkts_all > 0`, tối thiểu `max(c_durat, s_durat) * 1000.0`), thêm unit test đơn vị `udp_complete` trong `test_v2_migration_guards.py` / `test_ingestion_adapters.py`.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_ingestion_adapters.py tests/unit/test_v2_migration_guards.py -q`
- **Expected result:** `duration_ms` nhất quán mili-giây trên TCP, UDP và Zeek.
- **Actual result:** `FAIL` (`bootp` 60.4s bị ghi `60.4 ms`, 95% UDP < 1.0 ms).
- **Evidence path:** `reports/audits/V2_DATA_QUALITY_AUDIT.md` (Mục 3.1 & 3.2)
- **Related GitHub issue:** `#88`, `#93`, `#95`
- **Acceptance status:** `FAIL`

#### `DATA-A03`
- **Finding ID:** `DATA-A03`
- **Priority:** `P0`
- **File/module liên quan:** `src/network_anomaly/data/v2_schema.py:282-283,295-296,350-351`, `scripts/build_v2_dataset_and_split.py:209-210,222-223,287-288`, `src/network_anomaly/ingestion/adapters/zeek.py:73-84`
- **Mô tả vấn đề:** AIT Tstat đo L4 payload bytes (`0 B` cho TCP SYN scan), còn `build_v2_dataset_and_split.py` & `v2_schema.py` lấy Zeek `orig_ip_bytes`/`resp_ip_bytes` (IP+L4 headers, `80–88 B` cho scan), đảo ngược hoàn toàn phân phối `bytes_in_ratio` (`KS=0.9905`) và làm RF/XGB zero-shot sụp đổ.
- **Root cause:** Bất đồng nhất định nghĩa lớp mạng (`L4 payload` vs `L3 IP packet bytes`) và xung đột giữa `build_v2_dataset_and_split.py` (`orig_ip_bytes`) với `zeek.py` (`orig_bytes`).
- **Agent phụ trách:** `Agent C` & `Agent D`
- **Proposed fix:** Thống nhất hợp đồng L4 payload bytes (`orig_bytes`/`resp_bytes` với `"-"` -> `0.0` cho Zeek, hoặc chuẩn hóa header-aware trong adapter với kiểm thử thực nghiệm ở Phase 2/3/4) và đồng bộ giữa `v2_schema.py`, `build_v2_dataset_and_split.py`, `zeek.py`.
- **Test command:** Chạy lại phân tích feature shift & cross-source benchmark sau đồng nhất adapter.
- **Expected result:** Không còn đảo chiều `bytes_in_ratio` chỉ do header TCP/IP.
- **Actual result:** `FAIL` (Attack `bytes_in==0` 56.95% ở AIT vs 0.0% ở CTU).
- **Evidence path:** `reports/audits/V2_DATA_QUALITY_AUDIT.md`, `reports/experiments/ml/domain_analysis/DOMAIN_SHIFT_ANALYSIS.md`
- **Related GitHub issue:** `#88`, `#95`, `#97`
- **Acceptance status:** `FAIL`

#### `DATA-A04`
- **Finding ID:** `DATA-A04`
- **Priority:** `P0`
- **File/module liên quan:** `src/network_anomaly/preprocessing/pipeline.py:300-370`
- **Mô tả vấn đề:** `protocol_num` giữ passthrough nguyên giá trị (`1, 6, 17`) khi vào AE/IF gây MSE `7.58–10.06` trên ICMP (`proto=1` ở CTU -> FPR `100%`), và `pkts_in_ratio` có `IQR_arcsinh = 0.044269` phóng đại flow một chiều lên `+9.04 sigma`.
- **Root cause:** `TrainOnlyPreprocessor` không đặt `min_scale_floor` cho `asinh_robust` và đưa `protocol_num` thô không scale vào cùng ma trận feature liên tục.
- **Agent phụ trách:** `Agent C` & `Agent F`
- **Proposed fix:** Bổ sung `min_scale_floor` (hoặc scaling/one-hot an toàn cho `protocol_num` tại tầng preprocessing/model wrapper mà vẫn giữ tương thích API/unit tests `TrainOnlyPreprocessor`).
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_preprocessing_pipeline.py -q`
- **Expected result:** Không còn hiện tượng nổ scale trên ratio bounded `[0, 1]` và không còn cú sốc MSE do `protocol_num=1` chưa scale.
- **Actual result:** `FAIL` (AE `CTU-Echo FPR = 0.6520`, `CTU-Win7AD FPR = 0.8545`).
- **Evidence path:** `reports/audits/V2_MODEL_AUDIT.md` (Mục 4.3), `reports/audits/V2_DATA_QUALITY_AUDIT.md` (Mục 1)
- **Related GitHub issue:** `#95`, `#99`, `#100`
- **Acceptance status:** `FAIL`

#### `DATA-A05`
- **Finding ID:** `DATA-A05`
- **Priority:** `P1`
- **File/module liên quan:** `src/network_anomaly/ingestion/adapters/{v2_adapter,canonical_v2}.py`, `src/network_anomaly/data/v2_schema.py`
- **Mô tả vấn đề:** Probe artifact (`pkts_in==1` ở AIT 88.9–99.6% vs `pkts_in==2` ở CTU-Echo 91.8%), CTU mid-stream `pkts_in==0`, và xung đột nhãn trực tiếp trên cùng vector 18-D (`48` vectors / `126,166` dòng AIT-Train; `75` vectors / `13,862` dòng CTU-Echo).
- **Root cause:** Khác biệt thực tế giữa bộ sinh lưu lượng / probe Tstat vs Zeek và giới hạn thông tin đơn-flow 18 chiều.
- **Agent phụ trách:** `Agent C`, `Agent D`, `Agent E`
- **Proposed fix:** Kiểm tra feature ablation (`pkts_in` vs rate/symmetry), không cho phép mô hình học shortcut `pkts_in == 1`, và công bố rõ giới hạn Bayes error đơn-flow trong tài liệu.
- **Test command:** Feature ablation & cross-source evaluation reports.
- **Expected result:** Giảm phụ thuộc vào artifact số gói cố định `pkts_in == 1`.
- **Actual result:** `FAIL` (126k dòng Train xung đột nhãn trên cùng 18-D vector).
- **Evidence path:** `reports/experiments/ml/domain_analysis/DOMAIN_SHIFT_ANALYSIS.md` (Mục 4.1–4.2)
- **Related GitHub issue:** `#86`, `#88`, `#95`
- **Acceptance status:** `FAIL`

#### `DATA-A06`
- **Finding ID:** `DATA-A06`
- **Priority:** `P1`
- **File/module liên quan:** `data/processed/v2/ctu_{echo,windows7ad}.csv.gz`, `scripts/run_ctu_cross_source_eval.py`
- **Mô tả vấn đề:** `ctu_echo` và `ctu_windows7ad` chia sẻ `42` cặp `(5-tuple, ts)` (`45` `canonical_flow_group`, `47` dòng LAN `192.168.1.50 <-> 192.168.1.108`) với nhãn đối nghịch giữa hai thiết bị cùng capture.
- **Root cause:** Hai thiết bị giao tiếp trực tiếp trên cùng mạng LAN được gán nhãn từ góc nhìn riêng từng thiết bị.
- **Agent phụ trách:** `Agent C`
- **Proposed fix:** Deduplicate / loại trừ overlap `(5-tuple, time_bucket)` khi dùng làm split huấn luyện & đánh giá giữa Echo và Win7AD trong Experiment C/D.
- **Test command:** Kiểm tra `canonical_flow_group` overlap giữa train và eval splits trong `run_ctu_cross_source_eval.py` == 0.
- **Expected result:** `0` group overlap giữa tập train và test trong thí nghiệm CTU.
- **Actual result:** `FAIL` (`45` overlapping groups khi không dedup).
- **Evidence path:** `reports/audits/V2_DATA_QUALITY_AUDIT.md` (Mục 4.2)
- **Related GitHub issue:** `#92`, `#97`
- **Acceptance status:** `FAIL`

#### `DATA-A07`
- **Finding ID:** `DATA-A07`
- **Priority:** `P2`
- **File/module liên quan:** `data/EXTERNAL_DATASETS_PROVENANCE.json`, `docs/dataset/AIT_LINKAGE_FEASIBILITY.md`, `reports/datasets/v2_multi_source_profile.json`
- **Mô tả vấn đề:** `UGR'16` trả HTTP `403` (`Portal en Mantenimiento`); liên kết trực tiếp flow-UID `AIT-NDS-v2 ↔ AIT-LDS-v2.1` không khả dụng (`direct_uid_join_possible: false`).
- **Root cause:** Hạ tầng nguồn dữ liệu ngoài và chênh lệch phiên bản nguồn AIT (`v2.0` vs `v2.1`).
- **Agent phụ trách:** `Agent C` & `Agent H`
- **Proposed fix:** Giữ trạng thái `BLOCKED` cho `UGR'16` và `NOT VERIFIED` cho direct UID join; sử dụng temporal+IP correlation có kiểm chứng giới hạn.
- **Test command:** `fetch_multi_source_dataset.py` status check & `DOMAIN_SHIFT_ANALYSIS.md`.
- **Expected result:** Minh bạch trạng thái `BLOCKED`, không bịa dữ liệu thay thế.
- **Actual result:** `BLOCKED`.
- **Evidence path:** `reports/audits/V2_DATA_QUALITY_AUDIT.md` (Mục 1 & 2.2)
- **Related GitHub issue:** `#82`, `#85`, `#97`, `#104`
- **Acceptance status:** `BLOCKED`

#### `DATA-A08`
- **Finding ID:** `DATA-A08`
- **Priority:** `P2`
- **File/module liên quan:** `scripts/build_v2_dataset_and_split.py:15,518`, `docs/dataset/V2_LEAKAGE_AUDIT.md`
- **Mô tả vấn đề:** Docstring dòng 15 và báo cáo xuất dòng 518 ghi phương pháp scaling là `"robust"` / `RobustScaler`, trong khi dòng `495` chạy thực tế `scaler_type="asinh_robust"`.
- **Root cause:** Docstring và template báo cáo chưa được cập nhật sau khi đổi scaler từ `robust` sang `asinh_robust`.
- **Agent phụ trách:** `Agent C` & `Agent H`
- **Proposed fix:** Cập nhật docstring dòng 15 và template dòng 518 của `scripts/build_v2_dataset_and_split.py` khớp chính xác cấu hình scaler thực tế.
- **Test command:** Đối chiếu `scripts/build_v2_dataset_and_split.py` với `reports/preprocessing/v2_flow_preprocessing_manifest.json`.
- **Expected result:** Docstring, `V2_LEAKAGE_AUDIT.md` và preprocessing manifest khớp 100%.
- **Actual result:** `FAIL` (`"robust"`/`RobustScaler` vs `"asinh_robust"`).
- **Evidence path:** `reports/audits/V2_DATA_QUALITY_AUDIT.md` (Mục 1, `A08`)
- **Related GitHub issue:** `#84`, `#92`
- **Acceptance status:** `FAIL`

---

### Nhóm 3 — Machine Learning Models & Provenance (`ML-01` .. `ML-05`)

#### `ML-01`
- **Finding ID:** `ML-01`
- **Priority:** `P0`
- **File/module liên quan:** `scripts/train_{random_forest,xgboost,isolation_forest,autoencoder}.py`, `src/network_anomaly/models/{random_forest,xgboost_model,isolation_forest,autoencoder}.py`, `reports/models/*_manifest.json`
- **Mô tả vấn đề:** 4 model train trên dirty snapshot `05240b44` (`git_dirty=True`); `RF` `.joblib` nội bộ giữ `split_status="PLANNED / NOT VERIFIED"`; `AutoencoderModel.load_verified()` chưa hỗ trợ kiểm tra `expected_split_manifest_sha256`; manifests ghim hash CRLF.
- **Root cause:** Chạy train trước khi hoàn tất sửa lỗi và commit code; thiếu truyền metadata đầy đủ vào `RandomForestProtocol` & `AutoencoderModel`.
- **Agent phụ trách:** `Agent D`, `Agent E`, `Agent F`
- **Proposed fix:** Sửa code truyền đủ metadata và kiểm tra split SHA-256 trong `AutoencoderModel.load_verified()`, chuẩn hóa LF, và retrain đầy đủ ở Phase 4–5.
- **Test command:** Gọi `{RF,XGB,IF,AE}.load_verified(..., expected_split_manifest_sha256=LF_SHA)` và `verify_companion_artifacts.py`.
- **Expected result:** Cả 4 model đều `load_verified()` pass trên hash LF chuẩn.
- **Actual result:** `FAIL` trên LF (`Split manifest SHA-256 mismatch`).
- **Evidence path:** `reports/audits/V2_MODEL_AUDIT.md` (Mục 2.1 & 2.2)
- **Related GitHub issue:** `#94`, `#95`, `#154`
- **Acceptance status:** `FAIL`

#### `ML-02`
- **Finding ID:** `ML-02`
- **Priority:** `P0`
- **File/module liên quan:** `scripts/train_{random_forest,xgboost}.py`, `reports/experiments/ml/ctu_cross_source_eval.json`
- **Mô tả vấn đề:** Supervised baseline (RF & XGB) đạt `F1 ~ 0.89–0.90` trên `AIT-Test` nhưng sụp đổ zero-shot trên CTU (`CTU-Echo`: `RF F1=0.0`, `XGB F1=0.0, ROC-AUC=0.0373`; `CTU-Win7AD`: `RF F1=0.0`, `XGB F1=0.000735`).
- **Root cause:** `DATA-A02` + `DATA-A03` (byte accounting mismatch & UDP duration unit), cộng thêm độ tập trung feature cao (`XGB bytes_in+bytes_per_sec_in = 55.4%`) và thiếu probability/threshold calibration.
- **Agent phụ trách:** `Agent E`
- **Proposed fix:** Sau khi sửa `DATA-A01/A02/A03`, thực hiện ablation bỏ shortcut byte Tstat/Zeek, tuning regularization, calibration trên `AIT-Val`, và đánh giá riêng Zero-shot vs Multi-source adaptation.
- **Test command:** `.venv\Scripts\python.exe scripts/run_ctu_cross_source_eval.py`
- **Expected result:** Khắc phục inverted ranking (`ROC-AUC=0.0373`) và cải thiện rõ ràng hiệu năng cross-source với báo cáo trung thực.
- **Actual result:** `FAIL`.
- **Evidence path:** `reports/audits/V2_MODEL_AUDIT.md` (Mục 3.1 & 4.1)
- **Related GitHub issue:** `#94`, `#95`, `#97`
- **Acceptance status:** `FAIL`

#### `ML-03`
- **Finding ID:** `ML-03`
- **Priority:** `P1`
- **File/module liên quan:** `scripts/train_*.py`, `scripts/run_rq2_rare_attack_experiment.py`, `reports/evaluation/*_v2_eval.json`
- **Mô tả vấn đề:** Trên `AIT-Test`, `Data_Exfiltration` recall chỉ đạt `60.64%` (RF), `57.45%` (XGB), `0.00%` (IF), `0.046%` (AE); `Credential_Attack` chỉ đạt `14.10%` (`11/78` ở RF/XGB), và ở baseline dữ liệu mất `13.22%` `Credential_Attack` do `DATA-A01`.
- **Root cause:** Thiếu cost-sensitive weighting (`class_weight=None` / `scale_pos_weight=1.0`), threshold cố định `0.5`, mất dữ liệu chunk (`DATA-A01`), và trùng lắp phân phối đơn-flow trên `Credential_Attack` & `dnsteal` DNS.
- **Agent phụ trách:** `Agent E` & `Agent F`
- **Proposed fix:** Khôi phục đủ 3,464,400 dòng (`DATA-A01`), thử nghiệm có kiểm soát `class_weight` / `scale_pos_weight` + validation threshold calibration cho RF/XGB; ghi nhận trung thực giới hạn đơn-flow với `Credential_Attack` & `Data_Exfiltration`.
- **Test command:** Chạy lại `train_random_forest.py`, `train_xgboost.py`, `run_rq2_rare_attack_experiment.py`.
- **Expected result:** `Data_Exfiltration` recall trên Supervised tăng lên mức cao (`>= 95%` như `RF_CostSensitive` trong RQ2) mà giữ `FPR <= 0.002`.
- **Actual result:** `FAIL`.
- **Evidence path:** `reports/audits/V2_MODEL_AUDIT.md` (Mục 3.2, 3.3 & 4.2)
- **Related GitHub issue:** `#94`, `#96`, `#98`
- **Acceptance status:** `FAIL`

#### `ML-04`
- **Finding ID:** `ML-04`
- **Priority:** `P0`
- **File/module liên quan:** `scripts/train_{isolation_forest,autoencoder}.py`, `src/network_anomaly/models/{isolation_forest,autoencoder}.py`, `src/network_anomaly/preprocessing/pipeline.py`
- **Mô tả vấn đề:** Autoencoder đạt `FPR = 0.6520` trên `CTU-Echo` và `0.8545` trên `CTU-Win7AD` (`100%` FPR trên ICMP); Isolation Forest đạt `FPR = 0.2086` trên `CTU-Echo` và `0.4334` trên `CTU-Win7AD`; AE trên `Post_Exploitation_Discovery` chỉ đạt `10.81%` (`RQ4 unknown=21.43%`).
- **Root cause:** `DATA-A04` (`protocol_num=1` unscaled passthrough + `pkts_in_ratio` IQR collapse), plus ngưỡng `p95` siêu hẹp (`0.000228`) vs Zeek Benign UDP `~2ms` và loss MSE không chuẩn hóa theo feature.
- **Agent phụ trách:** `Agent F`
- **Proposed fix:** Khắc phục scaling/encoding của `protocol_num` & `pkts_in_ratio`, thử nghiệm loss/architecture/per-feature residual normalization và quantile sweep `p95–p99.5` trên `AIT-Val` (không dùng `CTU-Test` để tune).
- **Test command:** Chạy lại `train_isolation_forest.py`, `train_autoencoder.py`, `run_rq4_unknown_attack_experiment.py`.
- **Expected result:** Giảm mạnh CTU Benign FPR (đặc biệt triệt tiêu 100% ICMP FPR) và nâng unknown recall trên `AIT-Test`.
- **Actual result:** `FAIL`.
- **Evidence path:** `reports/audits/V2_MODEL_AUDIT.md` (Mục 3.1, 4.3 & 5.2)
- **Related GitHub issue:** `#94`, `#99`, `#100`
- **Acceptance status:** `FAIL`

#### `ML-05`
- **Finding ID:** `ML-05`
- **Priority:** `P2`
- **File/module liên quan:** `src/network_anomaly/models/{xgboost_model,isolation_forest,registry}.py`, `scripts/generate_model_comparison_report.py`, `scripts/_v2_train_common.py`
- **Mô tả vấn đề:** `xgboost_manifest.json` chứa `provenance_note` mâu thuẫn; `isolation_forest_manifest.json` ghi `"target": "Label"`; `model_comparison_report.json` để `"top_features": []` cho IF/AE; `calibrate_unsupervised_threshold_on_validation` dùng `>` trong khi evaluate dùng `>=`; `ModelRegistry` phát `UserWarning` feature names.
- **Root cause:** Di sản mã nguồn v1 và không thống nhất dtype/interface khi sinh manifest và report.
- **Agent phụ trách:** `Agent E`, `Agent F`, `Agent G`
- **Proposed fix:** Làm sạch metadata trong `save()`, tính permutation importance cho cả 4 model vào `model_comparison_report.json`, thống nhất `>=` giữa calibration & eval, truyền DataFrame đúng cột trong `ModelRegistry` để bỏ `UserWarning`.
- **Test command:** `.venv\Scripts\python.exe scripts/generate_model_comparison_report.py && .venv\Scripts\python.exe -m pytest tests/unit/test_model_registry.py -q`
- **Expected result:** `0` UserWarning, `top_features` đầy đủ cho 4 model, metric/FPR nhất quán.
- **Actual result:** `FAIL`.
- **Evidence path:** `reports/audits/V2_MODEL_AUDIT.md` (Mục 2.2)
- **Related GitHub issue:** `#94`, `#100`, `#105`
- **Acceptance status:** `FAIL`

---

### Nhóm 4 — Product Integration, Security & Issues (`PROD-01` .. `PROD-06`)

#### `PROD-01`
- **Finding ID:** `PROD-01`
- **Priority:** `P0`
- **File/module liên quan:** `src/network_anomaly/ingestion/adapters/v2_adapter.py`, `src/network_anomaly/ingestion/registry.py`, `tests/unit/test_v2_adapters.py`, `tests/integration/test_multi_source_pipeline.py`
- **Mô tả vấn đề:** `parse_timestamp_utc` fallback về `datetime.now()` khi thiếu timestamp; `IdentityAuthAdapter.adapt_line` hardcode `2020-11-05`; adapters tự sinh `"0.0.0.0"`/`"unknown_user"`/`"local_host"`; `ApplicationWebAdapter` không lọc URL query/credential; 4 v2 adapters chưa đăng ký vào `SourceRegistry`.
- **Root cause:** Triển khai v2 adapters tách rời khỏi `SourceRegistry` và vi phạm quy tắc fail-closed / không bịa giá trị thay thế.
- **Agent phụ trách:** `Agent G`
- **Proposed fix:** Sửa `v2_adapter.py` loại bỏ `datetime.now()`/hardcoded `2020-11-05`/fabricated IDs (fail-closed hoặc gắn `None` + missing policy rõ ràng), thêm redaction URL query/secret trong `ApplicationWebAdapter`, đăng ký 4 v2 adapters vào `SourceRegistry`, và bổ sung đầy đủ unit/integration tests.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_v2_adapters.py tests/integration/test_multi_source_pipeline.py -q`
- **Expected result:** Pass toàn bộ test missing timestamp, missing user/host, URL redaction và `SystemAuditAdapter`.
- **Actual result:** `FAIL` (vi phạm AC của `#86, #89, #90, #93`).
- **Evidence path:** `reports/audits/V2_ISSUE_AC_AUDIT.md` (Mục 5 & 7)
- **Related GitHub issue:** `#79`, `#86`, `#89`, `#90`, `#93`
- **Acceptance status:** `FAIL`

#### `PROD-02`
- **Finding ID:** `PROD-02`
- **Priority:** `P1`
- **File/module liên quan:** `src/network_anomaly/ml/ood_gate.py`, `artifacts/ml/ood_reference_gate.json`, `scripts/run_live_lab_acceptance.py`
- **Mô tả vấn đề:** Không có artifact `artifacts/ml/ood_reference_gate.json` trên đĩa, khiến `synthetic_udp_loopback_report.json:53` ghi `ood_gate=NOT_FITTED`.
- **Root cause:** Chưa fit & lưu `OODReferenceGate` trên `AIT-Train` sau khi fit preprocessor để gắn vào runtime orchestrator/API.
- **Agent phụ trách:** `Agent G` & `Agent F`
- **Proposed fix:** Fit và lưu `artifacts/ml/ood_reference_gate.json` (kèm SHA-256 trong manifest/metadata) sau khi hoàn tất huấn luyện model, nối vào `ModelRegistry` / `LiveOrchestrator`.
- **Test command:** `.venv\Scripts\python.exe scripts/run_live_lab_acceptance.py`
- **Expected result:** `ood_gate` hoạt động với fitted reference bounds thay vì `NOT_FITTED`.
- **Actual result:** `FAIL` (file `artifacts/ml/ood_reference_gate.json` không tồn tại).
- **Evidence path:** `reports/audits/V2_ISSUE_AC_AUDIT.md` (Mục 5), `reports/acceptance/synthetic_udp_loopback_report.json:53`
- **Related GitHub issue:** `#99`, `#137`
- **Acceptance status:** `FAIL`

#### `PROD-03`
- **Finding ID:** `PROD-03`
- **Priority:** `P1`
- **File/module liên quan:** `src/network_anomaly/behavioral/{vector,sessionizer,similarity}.py`, `src/network_anomaly/api/desktop_csv.py`, `src/network_anomaly/inference/predict.py`
- **Mô tả vấn đề:** `BehavioralVectorBuilder` chuyển NaN/Inf thành `0.0` mà không phát missingness indicator; thiếu Entity Baseline Profiler chỉ fit trên dữ liệu train (`#103`); `BehavioralVector` chưa tích hợp vào luồng CSV inference (`#106`).
- **Root cause:** Tách rời luồng live streaming và luồng offline CSV; thiếu missingness flag trong vector schema.
- **Agent phụ trách:** `Agent G`
- **Proposed fix:** Bổ sung missing-feature indicator policy vào `BehavioralVector`, xây dựng `EntityBaselineProfiler` (fit trên Train benign/baseline, đo phân bố similarity trên Val), và nối tóm tắt `BehavioralVector` vào pipeline CSV (`#106`).
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_behavioral_engine.py tests/unit/test_desktop_csv_api.py -q`
- **Expected result:** Pass với missingness flags, baseline profiler và CSV behavioral vector summary.
- **Actual result:** `FAIL` (chưa đạt AC `#101, #102, #103, #106`).
- **Evidence path:** `reports/audits/V2_ISSUE_AC_AUDIT.md` (Mục 5 & 7)
- **Related GitHub issue:** `#101`, `#102`, `#103`, `#106`
- **Acceptance status:** `FAIL`

#### `PROD-04`
- **Finding ID:** `PROD-04`
- **Priority:** `P1`
- **File/module liên quan:** `src/network_anomaly/api/db.py`, `scripts/evaluate_traceability.py`, `src/network_anomaly/crypto/rotation.py`, `THIRD_PARTY_NOTICES.md`
- **Mô tả vấn đề:** `db.py` `SCHEMA_SQL` thiếu bảng `unified_security_events`, `behavioral_vectors`, `encrypted_vault` cho DB tạo mới (`#107`); `evaluate_traceability.py` dùng 8 sự kiện giả + hardcoded baseline + lỗi số học `+65.0%` (`#114`); `KeyRotationPolicy` thiếu clock injection (`#120`) và không lưu cooldown/rate-limit qua restart (`#122`); `THIRD_PARTY_NOTICES.md` thiếu giấy phép `cryptography` (`#18/#117`).
- **Root cause:** Các chi tiết độ bền và tính toán chưa đồng bộ với DB schema, SQLite persistence và testability.
- **Agent phụ trách:** `Agent G` & `Agent H`
- **Proposed fix:** Bổ sung bảng v2 + repository query theo `entity`/`time_range` vào `db.py`; sửa `evaluate_traceability.py` tính toán thực tế từ baseline engine & đúng số học; hỗ trợ clock injection & SQLite persistence cho `KeyRotationPolicy`; bổ sung mục `cryptography` vào `THIRD_PARTY_NOTICES.md`.
- **Test command:** `.venv\Scripts\python.exe -m pytest tests/unit/test_crypto_integrity.py tests/unit/test_trace_engine.py tests/integration/test_migration_v1_to_v2.py -q`
- **Expected result:** Pass đầy đủ các test mới về schema v2, rotation persistence/clock và traceability evaluation.
- **Actual result:** `FAIL`.
- **Evidence path:** `reports/audits/V2_ISSUE_AC_AUDIT.md` (Mục 5 & 7)
- **Related GitHub issue:** `#18`, `#107`, `#114`, `#117`, `#120`, `#122`
- **Acceptance status:** `FAIL`

#### `PROD-05`
- **Finding ID:** `PROD-05`
- **Priority:** `P0`
- **File/module liên quan:** `.gitignore:69`, `docs/audits/THREAT_MODEL_V2.md`, `docs/USER_GUIDE_V2.md:12-13`, `docs/ARCHITECTURE_V2.md:14,49,215`
- **Mô tả vấn đề:** `/docs/audits/` bị `.gitignore:69` chặn nên 4 file audit v2 không có trên Git/CI; `THREAT_MODEL_V2.md` dẫn 5 tên file test không tồn tại; `USER_GUIDE_V2.md` ghi 3 route API không tồn tại (`/api/v1/telemetry/status`, `/api/v1/telemetry/events`, `/api/v1/behavioral/sessions`); `ARCHITECTURE_V2.md` mâu thuẫn Rust vs Python collector.
- **Root cause:** Quy tắc `.gitignore` cũ còn chặn `/docs/audits/` và tài liệu viết trước khi route/tên file test được chốt.
- **Agent phụ trách:** `Agent H` & `Agent G`
- **Proposed fix:** Cho phép track `docs/audits/V2_*.md` và `docs/audits/THREAT_MODEL_V2.md`, `RESEARCH_QUESTIONS_VALIDATION.md`, `SECURITY_AUDIT_V2.md` (giữ ignore các file session tạm nếu cần), đồng bộ đường dẫn test/API route thực tế theo `src/network_anomaly/api/main.py` và làm rõ `#128` Python collector.
- **Test command:** `git check-ignore docs/audits/*.md` + kiểm tra mọi API route trong `docs/USER_GUIDE_V2.md` khớp `reports/api/openapi.json`.
- **Expected result:** Các tài liệu kiến trúc/bảo mật v2 được track và khớp 100% mã nguồn & OpenAPI.
- **Actual result:** `FAIL`.
- **Evidence path:** `reports/audits/V2_ISSUE_AC_AUDIT.md` (Mục 5 & 7), `.gitignore:69`
- **Related GitHub issue:** `#76`, `#78`, `#81`, `#128`, `#146`, `#151`, `#152`
- **Acceptance status:** `FAIL`

#### `PROD-06`
- **Finding ID:** `PROD-06`
- **Priority:** `P1`
- **File/module liên quan:** `reports/governance/DISTRIBUTION_AUTHORIZATION.json`, `scripts/build_installer_v2.py`, `scripts/vm_target_e2e.ps1`
- **Mô tả vấn đề:** `DISTRIBUTION_AUTHORIZATION.json` giữ `approved: false` (`HOLD_FOR_MAINTAINER_SIGNOFF`); chưa có bằng chứng chạy Clean Windows 10/11 VM x64 E2E cho bộ cài v2.0; nhánh `site-source` vẫn ở v1.0.0.
- **Root cause:** Phụ thuộc môi trường VM ngoài, ký phê duyệt của maintainer và deploy nhánh ngoài.
- **Agent phụ trách:** `Agent G` & `Agent H`
- **Proposed fix:** Kiểm tra `--check-only` cho `build_installer_v2.py` trong repo, đồng bộ tài liệu hướng dẫn và giữ rõ trạng thái `BLOCKED` cho bước clean VM & public release nếu không có môi trường ngoài.
- **Test command:** `.venv\Scripts\python.exe scripts/build_installer_v2.py --check-only`
- **Expected result:** Build readiness check nội bộ pass; phần VM & release ghi rõ `BLOCKED`.
- **Actual result:** `BLOCKED`.
- **Evidence path:** `reports/audits/V2_ISSUE_AC_AUDIT.md` (Mục 6 & 7)
- **Related GitHub issue:** `#71`, `#73`, `#148`, `#149`, `#152`, `#154`
- **Acceptance status:** `BLOCKED`

---

## 5. Cập nhật Trạng thái Hậu Khắc phục (Post-Remediation Status: `2026-11-18`)

> [!NOTE]
> Các mục `1–4` phía trên lưu giữ nguyên bản snapshot điều tra Phase 0 trên `HEAD 79ebb67`. Bảng dưới đây ghi nhận **trạng thái hiện hành đã được xác minh trực tiếp** sau các pha khắc phục (`Phases 1–10`) trên working tree `feat/v2-integration`.

| Finding ID | Trạng thái Hiện hành | Bằng chứng Kiểm chứng Hậu Khắc phục & Ghi chú |
|---|---|---|
| `CI-F01` | `PASS` | `V2_SPLIT_MANIFEST.json` chuẩn hóa LF với SHA-256 `ed542ee80babca26f6e8ad977168b061e18e99a24be1cbe1ec8767b66d6339e8`; tất cả model/demo/doc dùng cùng digest LF này. |
| `CI-F02` | `PASS` | `scripts/verify_companion_artifacts.py` chỉ khai báo `isolation_forest_manifest.json`; `overall_status: READY`, `demo_ready: true`. |
| `CI-F03` | `PASS` | Bỏ giới hạn `<= 98` cứng, chấp nhận `source:ait-nds-v2` & OOD `(198,2)`/`(200,0)`, xử lý Windows `tmp_dir.cleanup()`, và khắc phục ngưỡng Unsupervised `<= 0.05` (`IF 0.049991`, `AE 0.049996`); `verify_companion_artifacts.py --verify-e2e` thoát `0` (`e2e_status: PASS`). |
| `CI-F04` | `PASS` | `tests/unit/test_verify_companion_artifacts.py`, `tests/integration/test_controller_target_vm_e2e.py`, `tests/integration/test_four_model_integrity_e2e.py` pass trong full `pytest` (`589 passed, 0 failed, 0 skipped`). |
| `CI-F05` | `PASS` | Cài đặt `ruff==0.17.5` & `black==26.10.1`; `ruff check src scripts tests` -> `0` lỗi; `black --check src scripts tests` -> `244 files unchanged`. |
| `CI-F06` | `PARTIAL (Read-only PASS; UGR'16 BLOCKED)` | Sửa `fetch_multi_source_dataset.py --verify-only` sang chỉ đọc thuần túy (`git diff -- data/EXTERNAL_DATASETS_PROVENANCE.json` trống); `UGR'16` giữ trạng thái `BLOCKED` (`HTTP 403`). |
| `CI-F07` | `PARTIAL (Synthetic PASS; Physical BLOCKED)` | Sửa docstring `18 canonical v2`, `run_live_lab_acceptance.py` đạt `Verdict: ACCEPTED` với `ood_gate=FITTED` và 4/4 `VALIDATED`; phần thiết bị router/switch vật lý giữ `BLOCKED`. |
| `CI-F08` | `PASS` | Sửa `tests/integration/test_full_system_e2e.py` không dùng `pytest.skip()`; toàn bộ `589 passed, 0 failed, 0 skipped`. |
| `CI-F09` | `PASS` | Cập nhật `TRUSTED_CANONICAL_VALIDATION_SUBSETS` trong `desktop_csv.py` và tái sinh LF `data/demo/*`; `demo_flows.csv` đạt `source:ait-nds-v2` và `provenance_verified=True`. |
| `CI-F10` | `PASS` | Đồng bộ desktop lên `2.0.0` (package, lockfiles, Cargo, `tauri.conf.json`, `v2.0.0.md`); `scripts/check_desktop_version.py --check` & `npm check/test/build` + `cargo fmt/clippy/test` PASS. |
| `CI-F11` | `PASS` | Đồng bộ `THIRD_PARTY_NOTICES.md` (`cryptography`), `RELEASE_PROCESS.md`, `USER_GUIDE_V2.md`, `ARCHITECTURE_V2.md`, `RESEARCH_QUESTIONS.md`, `EVALUATION.md`, `DATASET.md`, `METHODOLOGY.md`, `REPRODUCIBILITY.md`, `TRACEABILITY_MATRIX.md`, `V2_SESSION_CHECKPOINT.md`, `V2_CURRENT_AUDIT.md`; `0` relative link lỗi và `0` đường dẫn cá nhân trong JSON/docs tạo mới. |
| `CI-F12` | `PASS` | Pin thống nhất `ruff==0.17.5` & `black==26.10.1` trong `pyproject.toml`, `ci.yml`, `lint-audit.yml`; xóa path chết và tối ưu CI matrix. |
| `DATA-A01` | `PASS` | Sửa chunk `reset_index(drop=True)` trong `build_v2_dataset_and_split.py`: bảo toàn trọn vẹn `3,464,400` labeled + `942` unmapped = `3,465,342` dòng gốc AIT (`Train 2,097,891 / Val 377,704 / Test 988,805`, `0` dòng rơi). |
| `DATA-A02` | `PASS` | Chuẩn hóa Tstat UDP duration `* 1000.0` (`s -> ms`) trong `v2_schema.py` & `build_v2_dataset_and_split.py`. |
| `DATA-A03` | `PASS` | Chuẩn hóa Zeek bytes sang L4 payload (`orig_bytes`/`resp_bytes`) thống nhất giữa `v2_schema.py`, `build_v2_dataset_and_split.py`, và `zeek.py`. |
| `DATA-A04` | `PASS` | Bổ sung `MIN_BOUNDED_SCALE_FLOOR = 0.25` trong `TrainOnlyPreprocessor` và Per-Feature Benign Standardization cho Autoencoder; giảm bùng nổ scale feature ratio. |
| `DATA-A05` | `PASS (Audited & Documented)` | Không còn phụ thuộc `MIN_TTL`; đã thực hiện feature ablation & công bố trung thực giới hạn Bayes error của không gian đơn-flow 18 chiều. |
| `DATA-A06` | `PASS` | Loại bỏ `45` nhóm LAN overlap `(5-tuple, 300s)` trong `run_ctu_cross_source_eval.py` (`ctu_windows7ad: 175,146 -> 175,101`) cho Exps C & D. |
| `DATA-A07` | `BLOCKED` | Giữ trạng thái trung thực `UGR'16 = BLOCKED` (`HTTP 403`) và `AIT-NDS-v2 ↔ AIT-LDS-v2.1` direct UID join `NOT VERIFIED` (`RQ3` dùng `SIMULATION`). |
| `DATA-A08` | `PASS` | Đồng bộ docstring và báo cáo `build_v2_dataset_and_split.py` / `V2_LEAKAGE_AUDIT.md` về `asinh_robust`. |
| `ML-01` | `PASS` | Train lại cả 4 model trên split LF chuẩn `ed542ee8...` & preprocessor `0866dec7...`; sửa `SplitReference`/`PreprocessingReference` trong RF, đường dẫn POSIX tương đối, và kiểm tra `expected_split_manifest_sha256` trong `AutoencoderModel.load_verified()`. |
| `ML-02` | `PASS` | Retrain RF (`balanced_subsample`, `min_samples_leaf=5`, Test `F1=0.994967`) & XGB (Test `F1=0.901289`), mở rộng `CTU_CROSS_SOURCE_EVAL.md` & `ctu_cross_source_eval.json` với Experiments A–E và ablation trung thực (`CTU` zero-shot & multi-source). |
| `ML-03` | `PASS` | Khôi phục đủ dữ liệu chunk + `balanced_subsample`; `RF_CostSensitive` đạt `F1=0.994749`, `Data_Exfiltration` cải thiện mạnh trên Supervised; tiếp tục báo cáo trung thực kết quả âm `Credential_Attack` (`h2_full_confirmed=false`). |
| `ML-04` | `PASS` | IF (`th=0.031268`, `sha256=11b16900...`, `Val FPR=0.049991`, `CTU-Echo F1=0.885328`) & AE (`th=0.000467`, `sha256=e6afecef...`, `Val FPR=0.049996`, `CTU-Echo F1=0.732531`); RQ4 recalibrate Val loại bỏ 58 dòng holdout và `empirical_val_fpr <= 0.05` đạt chuẩn. |
| `ML-05` | `PASS` | Làm sạch manifest metadata XGB/IF, bổ sung Val permutation importance `top_features` cho IF/AE trong `model_comparison_report.json`, và thêm `_to_estimator_frame` ở `RandomForestModel` triệt tiêu `UserWarning` feature names. |
| `PROD-01` | `PASS` | `v2_adapter.py` bỏ fallback `datetime.now()` / `2020-11-05` / IDs giả, bổ sung redaction query secret, đăng ký đủ 5 v2 adapters vào `SourceRegistry`, kiểm thử bởi `test_v2_prod_hardening.py`. |
| `PROD-02` | `PASS` | Fit & lưu `artifacts/ml/ood_reference_gate.json` trên `2,097,891` raw train flows; scope `_load_ood_gate()` theo `artifacts_dir`; `run_live_lab_acceptance.py` báo `ood_gate=FITTED`. |
| `PROD-03` | `PASS` | Bổ sung `missing_feature_count`/`missing_feature_names` vào `BehavioralVector`, triển khai & export `EntityBaselineProfiler` (`fit` trên baseline), và gắn summary/contract rõ ràng. |
| `PROD-04` | `PASS` | Tách `V2_SCHEMA_SQL` (`initialize_schema(include_v2=True)`) + query theo `entity`/`time_range`, thêm `clock_fn` & SQLite cooldown/rate-limit persistence vào `KeyRotationPolicy`, sửa `evaluate_traceability.py` (`1.0` vs dynamic grep `0.375`, `+62.5%`), bổ sung `cryptography` vào `THIRD_PARTY_NOTICES.md`. |
| `PROD-05` | `PASS` | Mở track `docs/audits/` khỏi `.gitignore`, sửa tên test trong `THREAT_MODEL_V2.md`, đồng bộ route API trong `USER_GUIDE_V2.md` theo OpenAPI `0.1.0`, chốt `#128` Python collector trong `ARCHITECTURE_V2.md`. |
| `PROD-06` | `BLOCKED` | Giữ trung thực `DISTRIBUTION_AUTHORIZATION.json` (`approved: false`), chưa chạy Clean Windows 10/11 VM installer E2E (`#73`, `#148`), và nhánh `site-source` nằm ngoài nhánh này (`#152`). |

