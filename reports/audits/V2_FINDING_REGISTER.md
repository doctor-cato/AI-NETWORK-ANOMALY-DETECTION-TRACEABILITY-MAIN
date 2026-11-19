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
| `PROD-05` | `PASS` | Mở track `docs/audits/` khỏi `.gitignore`, sửa tên test & API routes trong `USER_GUIDE_V2.md`, chốt `#128` Python collector trong `ARCHITECTURE_V2.md`. |
| `PROD-06` | `BLOCKED` | Giữ trung thực `DISTRIBUTION_AUTHORIZATION.json` (`approved: false`), chưa chạy Clean Windows 10/11 VM installer E2E (`#73`, `#148`), và nhánh `site-source` nằm ngoài nhánh này (`#152`). |

---

## 6. Kiểm toán Hậu `HEAD 121a43e9` & Khắc phục Bổ sung (`F-01..F-04`, `#137`, `Governance / Deferred`)

- **Commit tham chiếu trực tiếp:** `feat/v2-integration` @ `121a43e93f99326336186ae11301aeae800853bf` (kèm cụm remediation working tree chưa commit).

| Finding ID | Severity | Location | Trạng thái |
|---|---|---|---|
| `F-01` | `P1` | `docs/audits/THREAT_MODEL_V2.md` | **`PASS` (Fixed)** |
| `F-02` | `P2` | `scripts/run_rq2_rare_attack_experiment.py`, `rq2_imbalance_report.{json,md}`, `metrics.py`, `V2_CURRENT_AUDIT.md` | **`PASS` (Fixed)** |
| `F-03` | `P1` | `reports/models/*_manifest.json` (`git_dirty: true`) | **`DISCLOSED / BLOCKED_REPRODUCIBLE_CLEAN_COMMIT`** |
| `F-04` | `P0` | `registry.py`, `compatibility.py`, `response_policy.py`, `schemas.py`, `desktop_csv.py`, `types.ts`, `openapi.json` | **`PASS` (Fixed & Tested)** |
| `R-137` | `P1` | `alert_manager.py`, `live_service.py`, `live_runtime.py`, `LiveMonitoringPanel.svelte`, `run_live_lab_acceptance.py` | **`PARTIAL` (Synthetic+GUI `PASS`; Physical Lab `BLOCKED`)** |
| `R-GOV` | `P1` | `DISTRIBUTION_AUTHORIZATION.json`, `LICENSE`, `tauri.standalone.conf.json`, `vm_target_e2e.ps1` | **`BLOCKED / DEFERRED` (Audit Logged)** |

### Chi tiết Findings (9 Trường Chuẩn)

1. **`F-01` — Threat Model `THREAT_MODEL_V2.md` mâu thuẫn kiến trúc Collector & đánh giá SR1/SR8**
   - **Severity:** `P1`
   - **Location:** `docs/audits/THREAT_MODEL_V2.md:34,43,50`
   - **Evidence:** Phiên bản trước ghi `"trong Rust Collector (#131)"`, gắn `SR1` là `VERIFIED` theo `>= 85%` correlation bằng `test_behavioral_engine.py`, và ghi `SR8` không cấp phát quá `256MB`.
   - **Root Cause:** Tài liệu Threat Model chưa đồng bộ sau khi chốt Python `UDPFlowCollector` (`#128` Rust Collector hoãn) và sau kết quả âm của `RQ3` (`simulation_hypothesis_met = false`).
   - **Impact:** Sai lệch kiến trúc thực thi và phóng đại mức kiểm chứng của liên kết hành vi `16-D`.
   - **Fix Implemented / Status:** **`PASS` (Fixed)** — Sửa dòng `34` nêu đúng Python `UDPFlowCollector` (`queue_capacity=10_000`) + `StreamingEventPipeline` (`capacity=10_000`, `#128 DEFERRED`); chuyển `SR1` sang `VERIFIED_UNIT_ONLY` kèm tham chiếu trung thực `RQ3` (`F1=0.3191/0.5556`) & `#85` (`BLOCKED`); chuẩn hóa `SR8` theo giới hạn hàng đợi sự kiện `10,000` events thay vì ngưỡng heap byte cứng `256MB`.
   - **Tests Added / Verified:** Đối chiếu trực tiếp `THREAT_MODEL_V2.md`, `test_telemetry_collector.py`, `test_behavioral_engine.py`, `rq3_session_correlation_experiment.json`.
   - **Residual Risk / Open Gate:** `SR1` vẫn `BLOCKED` ở mức liên kết thực nghiệm đa nguồn AIT (`#85`); `SR11` giữ `PENDING_CLEAN_VM` (`#73`/`#148`).

2. **`F-02` — Ví dụ taxonomy v1 `(e.g., Worms)` trong RQ2 & `metrics.py`**
   - **Severity:** `P2`
   - **Location:** `scripts/run_rq2_rare_attack_experiment.py:256`, `reports/experiments/imbalance/rq2_imbalance_report.{json,md}`, `src/network_anomaly/evaluation/metrics.py:443`, `.agents/reports/V2_CURRENT_AUDIT.md:422`
   - **Evidence:** Chuỗi giải thích Limitations vẫn nhắc `"tiny (e.g., Worms)"` dù `Worms` là lớp của `NF-UNSW-NB15-v3`, không phải `taxonomy-v2` trên `AIT-NDS-v2`.
   - **Root Cause:** Ví dụ văn bản còn sót từ đặc tả v1 khi viết template RQ2.
   - **Impact:** Dễ gây nhầm lẫn dữ liệu nền khi bảo vệ RQ2 dù toàn bộ tính toán sử dụng đúng dữ liệu `AIT-NDS-v2`.
   - **Fix Implemented / Status:** **`PASS` (Fixed)** — Cập nhật thành `(e.g., Exploitation_And_C2 with N=5 test flows)` trong script/JSON/MD và `metrics.py`; bổ sung chú giải lịch sử ở `.agents/reports/V2_CURRENT_AUDIT.md:422`; không thay đổi bất kỳ số metric hay `h2_full_confirmed=false`.
   - **Tests Added / Verified:** `ruff check`, `black --check`, kiểm tra toàn vẹn JSON và số liệu không đổi trong `rq2_imbalance_report.json`.
   - **Residual Risk / Open Gate:** Kết quả khoa học `H2` giữ nguyên kết quả âm trung thực (`Credential_Attack` Recall `0.1410` RF/XGB/IF, `0.0641` AE).

3. **`F-03` — Dirty Worktree Provenance trên 4 Model Manifests (`git_dirty=true`)**
   - **Severity:** `P1`
   - **Location:** `reports/models/{random_forest,xgboost,isolation_forest,autoencoder}_manifest.json` (`environment.git`), `artifacts/models/*/*_manifest.json`
   - **Evidence:** Cả 4 manifest ghi `git_commit: "79ebb678b87de19cc6b664b587726983fecaf98f"`, `git_dirty: true`, `git_clean: false`, `worktree_provenance: "DIRTY_DISCLOSED"`.
   - **Root Cause:** 4 mô hình được tái huấn luyện tại thời điểm working tree chưa commit trước khi tạo commit `121a43e`.
   - **Impact:** Ảnh hưởng tính tái lập từ một commit Git sạch và bị chặn bởi `--require-clean-git` trong `.github/workflows/release.yml` (Bước `02` kế hoạch đóng gói).
   - **Fix Implemented / Status:** **`DISCLOSED / BLOCKED_REPRODUCIBLE_CLEAN_COMMIT`** — Kiểm toán giữ nguyên bản provenance trên đĩa (tuyệt đối không sửa tay `git_dirty=false`), gắn rõ giới hạn `DIRTY_DISCLOSED` trong tài liệu audit & outline bảo vệ.
   - **Tests Added / Verified:** Đối chiếu trực tiếp 4 manifest + `verify_companion_artifacts.py` + đối chiếu `verify_companion_artifacts.py` gate `--require-clean-git`.
   - **Residual Risk / Open Gate:** Bắt buộc commit sạch mã nguồn trước và tái xác minh/tái huấn luyện artifact gắn commit sạch nếu mở khóa `#148` / `#154`.

4. **`F-04` — Lệch tầng `ModelRegistry` vs `compatibility.py`, fallback hash-only & kiểm chứng `split_manifest_sha256`**
   - **Severity:** `P0`
   - **Location:** `src/network_anomaly/models/registry.py`, `src/network_anomaly/ingestion/compatibility.py`, `src/network_anomaly/api/{response_policy.py,schemas.py,desktop_csv.py}`, `desktop/src/lib/types.ts`, `reports/api/openapi.json`
   - **Evidence:** Trước sửa đổi, `ModelRegistry` gán `deployment_tier="PRODUCTION_ELIGIBLE"` cho cả `random_forest` và `xgboost` chỉ dựa trên `threshold is not None`; `load_v2_benchmark_registry()` có fallback `True if (model_sha and prep_sha)` khi thiếu `benchmark_passed`, đọc nhầm khóa `test_evaluation` thay vì `evaluation.ait_test`, và `_load_preprocessor()` bỏ sót `split_manifest_sha256`.
   - **Root Cause:** Trộn lẫn cổng tính toàn vẹn artifact (`ARTIFACT_VERIFIED`) với cổng chứng nhận triển khai (`PRODUCTION_ELIGIBLE`), và lệch mapping schema giữa manifest v2 thực tế với `compatibility.py`.
   - **Impact:** Nguy cơ cấp nhầm `PRODUCTION_ELIGIBLE` cho `xgboost` hoặc mô hình chưa vượt qua kiểm định cross-source (`CTU-Echo` / `CTU-Win7AD`), hoặc cấp `benchmark_passed` khi thiếu metric thực đo.
   - **Fix Implemented / Status:** **`PASS` (Fixed & Tested)** — (a) Tách rõ 4 cờ/tầng `artifact_verified`, `in_domain_evaluated`, `cross_source_validated`, `deployment_tier` trên `ModelStatus`, `BenchmarkEvidence`, `ModelStatusItem`, và `collect_models_status()`; (b) Dùng chung helper `_evaluate_manifest_readiness_tiers`, đọc `evaluation.ait_test`, `ctu_echo`, `ctu_windows7ad`, bỏ fallback hash-only và cưỡng chế `UNVALIDATED` nếu thiếu hash hoặc metric; (c) Trích `split_manifest_sha256` từ `preprocessor_manifest_path` trong `_load_preprocessor()` và reject fail-closed `ModelReadiness.ERROR` khi thiếu hoặc lệch; (d) Giữ `xgboost`/`isolation_forest`/`autoencoder` trong `RESEARCH_ONLY_MODEL_KEYS` và khóa `HOLD_RESEARCH_ONLY_MODEL` trong `_evaluate_containment_authority()`, đồng thời đổi fallback mặc định ở `schemas.py:604` & `response_policy.py:177` sang `"source:flow-v2-unverified"`; (e) Bổ sung `production_ready`, `cross_source_validated_count`, `ai_ready_semantics` vào `ModelRegistry.summary()`.
   - **Tests Added / Verified:** 6 kịch bản test mới (bao gồm missing/mismatched `split_manifest_sha256` & containment hold) tại `tests/unit/test_model_registry.py`, `tests/unit/test_compatibility_evaluator.py`, `tests/integration/test_four_model_integrity_e2e.py`, kèm `export_openapi_spec.py` và `verify_companion_artifacts.py`.
   - **Residual Risk / Open Gate:** Tất cả 4 mô hình hiện giữ `deployment_tier = "RESEARCH_ONLY"` và `production_ready = false` trên `ModelRegistry` do `cross_source_validated = false` (`CTU-Echo`/`CTU-Win7AD`), trong khi `compatibility.py` giữ `random_forest` ở `MODEL_VALIDATED` riêng cho in-domain CSV dry-run (`AIT-NDS-v2`).

5. **`R-137` — Pipeline cảnh báo Live `#137`, độ trễ/mất đồng bộ SQLite & giao diện Svelte**
   - **Severity:** `P1`
   - **Location:** `src/network_anomaly/streaming/{alert_manager.py,live_service.py}`, `src/network_anomaly/api/live_runtime.py`, `desktop/src/lib/components/LiveMonitoringPanel.svelte`, `scripts/run_live_lab_acceptance.py`
   - **Evidence:** `LiveTelemetryService` append trùng alert theo batch; `LiveAlertManager` không nạp lại bảng SQLite `live_alerts` và `_dedup_cache` khi khởi tạo; `LiveRuntime.recent_alerts()` trước sửa trả rỗng hoặc ẩn alert phiên cũ sau restart, lệch thứ tự FIFO vs DESC; `LiveMonitoringPanel` hiển thị sai nhãn `Risk >= 45`; fixture `large_outbound_transfer` chỉ đạt `62.8`.
   - **Root Cause:** Thiếu đồng bộ giữa `LiveAlertManager`, cache service, merge đa phiên SQLite+live, UI filter text và tham số fixture synthetic loopback.
   - **Impact:** Cảnh báo `HIGH` không được kích hoạt trong acceptance và có nguy cơ lặp dòng, lệch thứ tự hoặc che mất cảnh báo phiên trước sau restart.
   - **Fix Implemented / Status:** **`PARTIAL` (Synthetic + GUI `PASS`; Physical Lab `BLOCKED`)** — Hydrate `live_alerts` + rehydrate `_dedup_cache` trong `LiveAlertManager._load_existing_alerts()`, seed và trả newest-first `list(reversed(self._alerts))` trong `LiveTelemetryService`, merge dedup SQLite + live theo `alert_id` và sort `last_seen_utc DESC` trong `LiveRuntime.recent_alerts()`, sửa nhãn `Medium (Risk >= 30)` + keyed `{#each}` trong `LiveMonitoringPanel.svelte`, hiệu chỉnh `large_outbound_transfer` (`duration_ms=1.0, bytes_out=60000.0`) tạo `1` alert thật (`risk_score=84.035`, `HIGH`) và chụp ảnh GUI thực tế `reports/acceptance/live_gui_alert_synthetic_loopback.png`.
   - **Tests Added / Verified:** `scripts/run_live_lab_acceptance.py` (`ACCEPTED`, `13/13` stages `PASS`), `test_e2e_api_live_udp_loopback_generates_deduplicated_persisted_alert` (phủ cả restart + merge newest-first trong `test_full_system_e2e.py`), `V2Panels.test.ts` (`34 passed`), `svelte-check` (`0 errors`).
   - **Residual Risk / Open Gate:** Chưa test trên router/switch phần cứng thật (`real_device_tested: false`, `#137` giữ `OPEN 3/5 AC`).

6. **`R-GOV` — Khoảng trống Pháp lý, Staging Bundle & Target VM Trước Release (`DISTRIBUTION_AUTHORIZATION` / `#73` / `#148` / `#152`)**
   - **Severity:** `P1`
   - **Location:** `reports/governance/DISTRIBUTION_AUTHORIZATION.json`, `LICENSE:1`, `pyproject.toml:12-13`, `THIRD_PARTY_NOTICES.md`, `desktop/src-tauri/tauri.standalone.conf.json`, `scripts/vm_target_e2e.ps1`, `docs/RELEASE_PROCESS.md:92`, `.github/workflows/release.yml`, `origin/site-source` (`a01bd38ad`)
   - **Evidence:** `DISTRIBUTION_AUTHORIZATION.json` giữ `approved: false`; trước sửa `tauri.standalone.conf.json` trỏ 3 file `isolation_forest` không tồn tại, `vm_target_e2e.ps1:457` ép `(198, 2)` và `source:nf-v3-canonical`, `RELEASE_PROCESS.md:92` & `release.yml` còn dấu vết `v1.0.0`, `THIRD_PARTY_NOTICES.md` thiếu liệt kê Rust crates; `origin/site-source` còn 77 tệp ở `v0.6.0` / `NF-UNSW-NB15-v3`.
   - **Root Cause:** Các tác vụ đóng gói Windows (`#73`/`#148`) và website (`#152`) đang `DEFERRED` khỏi đợt kiểm toán hiện tại.
   - **Impact:** Chặn phát hành công khai (`public_github_release`) và cần xử lý trước khi build NSIS installer hoặc cập nhật website.
   - **Fix Implemented / Status:** **`PARTIAL_SPEC_FIXED / DEFERRED`** — Đã sửa trên working tree `tauri.standalone.conf.json:13`, `vm_target_e2e.ps1:3,457,526`, `RELEASE_PROCESS.md:92`, `release.yml:12,312`, và bổ sung direct + `MPL-2.0` transitive Rust crates vào `THIRD_PARTY_NOTICES.md`. Phần companion `ood_reference_gate.json` và `score_normalization.json` đã được đóng tại Mục 7 (`R-OOD-COMPANION`); các mục còn lại (thay placeholder `LICENSE:1`/`pyproject.toml:12-13`, build sidecar/NSIS, Clean VM E2E, `DISTRIBUTION_AUTHORIZATION.json`, `site-source`) tiếp tục giữ `BLOCKED / DEFERRED` theo kế hoạch 12 bước tại `V2_PR156_AND_DEFERRED_HANDOFF.md`.
   - **Tests Added / Verified:** Read-only matrix trên `verify_companion_artifacts.py --verify-distribution-permission`, `cargo metadata`, `build_installer_v2.py --check-only`, `git show origin/site-source:...`.
   - **Residual Risk / Open Gate:** Cần Maintainer signoff (`DISTRIBUTION_AUTHORIZATION.json`), Clean VM Windows 10/11 E2E (`#73`/`#148`), và merge PR `#156` trước khi mở `#152` / `#154`.

---

## 7. Phát hiện Xử lý Trong Đợt Hoàn tất PR `#156` (`feat/v2-integration` @ `f5dacb1e` + Working Tree, `2026-11-18`)

7. **`R-OOD-COMPANION` — Thiếu Staging `ood_reference_gate.json` & AE `score_normalization.json`, và Lọt `NOT_FITTED/ERROR` OOD ở Runtime (`WP5`)**
   - **Severity:** `P1`
   - **Location:** `desktop/src-tauri/tauri.standalone.conf.json`, `scripts/verify_companion_artifacts.py`, `src/network_anomaly/ml/ood_gate.py`, `src/network_anomaly/streaming/realtime_inference.py`, `src/network_anomaly/models/autoencoder.py`
   - **Evidence:** Trước sửa đổi, `tauri.standalone.conf.json` không khai báo `ood_reference_gate.json` và `score_normalization.json`; `verify_companion_artifacts.py` không stage hay verify SHA-256 của 2 file này; `AutoencoderModel` không cross-check file `score_normalization.json` nằm cạnh; `RealtimeInferenceEngine` gộp chung file missing (`NOT_FITTED`) và corrupt (`ERROR`) mà không ép abstention fail-closed theo `runtime_mode`.
   - **Root Cause:** Companion verification mới dừng ở model/preprocessor chính, chưa bao phủ phụ lục OOD và sidecar AE trên đường dẫn standalone/runtime.
   - **Impact:** Bản cài standalone có thể thiếu OOD gate hoặc tải nhầm/hỏng companion artifact mà vẫn xuất cảnh báo giả định hợp lệ thay vì từ chối fail-closed.
   - **Fix Implemented / Status:** **`PASS` (Fixed & Tested)** — (a) Bổ sung `artifacts/ml/ood_reference_gate.json` (`8a52bfe5...`) và `artifacts/models/autoencoder/score_normalization.json` (`d7bcb78f...`) vào `tauri.standalone.conf.json` và `verify_companion_artifacts.py` (`20` `companion_files`, `MODEL_SPECS["autoencoder"]`, `SIDECAR_MANIFEST_MAPPINGS` bổ sung `isolation_forest_manifest.json`, `stage_embedded_bundle()`, `verify_installed_standalone_layout()` yêu cầu `ood_gate.status == "FITTED"`); (b) Bổ sung `verify_ood_gate_artifact()`, từ chối `NaN`/`Inf` (`NON_FINITE_FEATURE_VALUE`) ở `evaluate_sample()`, và ép bắt buộc `schema_version=1`, `artifact_type="ood_reference_gate"`, `min_bounds <= max_bounds`, positive stds, `provenance.fit_rows > 0`, `expected_feature_names`, `expected_preprocessor_sha256` ở `from_artifact()` trong `ood_gate.py`; (c) Bổ sung `_verify_ae_score_normalization_payload()` và bắt buộc tồn tại sidecar `score_normalization.json` cho manifest `canonical-flow-v2-18` có khai báo `score_normalization` trong `autoencoder.py`; (d) Thêm `runtime_mode` (`"research"` vs `"deployment"`, env `NETFLOW_RUNTIME_MODE`, nối vào `LiveSystemOrchestrator`), cấm `require_ood_gate=False` khi `runtime_mode="deployment"`, tách `FITTED` / `NOT_FITTED` / `ERROR` và khóa fail-closed `inference_mode="UNAVAILABLE"`, `abstained_due_to_ood=True`, `is_ood=True` trong `RealtimeInferenceEngine`.
   - **Tests Added / Verified:** `tests/unit/test_verify_companion_artifacts.py`, `tests/unit/test_ood_and_calibration.py`, `tests/unit/test_realtime_inference.py`, toàn bộ suite `pytest tests -q -rs` (`598 passed`, trước lượt vá P2 cuối; đã re-verify targeted test suite hậu vá P2), `verify_companion_artifacts.py` (`READY`, `ood_gate=FITTED`) và `run_live_lab_acceptance.py` (`ACCEPTED`).
   - **Residual Risk / Open Gate:** Quy trình đóng gói NSIS installer và Clean Windows VM (`#73`/`#148`) vẫn `DEFERRED / NOT VERIFIED` ngoài phạm vi PR `#156`.

8. **`R-WP3-ABLATION` — Đối chiếu Ablation Có Kiểm soát `E0`–`E5` & Cảnh báo Nhóm Hiếm `Exploitation_And_C2` (`N=5`)**
   - **Severity:** `P2`
   - **Location:** `scripts/run_wp3_controlled_ablation.py`, `reports/experiments/ml/wp3_controlled_ablation_report.json`, `reports/experiments/ml/model_improvement_summary.json`, `reports/audits/V2_MODEL_AUDIT.md`
   - **Evidence:** Chạy thí nghiệm có kiểm soát `E0`–`E5` (`986.03s`, không dùng `AIT-Test`/`CTU` để fit model, fit transform hay calibrate threshold). Kết quả `E2b` chứng minh `bytes_per_pkt_{in,out}` gây FP trên `CTU-Win7AD` (`RF F1` tăng lên `0.5665` khi bỏ hết byte features nhưng `AIT-Val FPR` vọt `0.0770` và `CTU-Echo` tụt `F1=0.0067`); `E3a` one-hot protocol nâng AE `AIT-Test F1` (`0.5877 -> 0.6496`) và giảm `CTU-Echo FPR` (`0.6746 -> 0.4222`) nhưng đổi schema `21` chiều và giữ `Win7AD FPR=0.6335`; `E4` LOSO CV cho thấy `XGB Exfil=0.0230` ở fold `harrison`; `Exploitation_And_C2` ở `AIT-Test` chỉ có `N=5` mẫu. *(Ghi chú bổ sung: nhãn leakage ban đầu `test_touched_for_selection_or_threshold = false` đã được chuẩn hóa lại ở mục `11. R-WP3-LEAKAGE-DISCLOSURE` bên dưới.)*
   - **Root Cause:** Domain shift tầng protocol/flow-duration/payload giữa capture AIT với Zeek `CTU-SME-11` không thể giải quyết bằng ablation đơn giản trên `canonical-flow-v2-18` zero-shot mà không đánh đổi in-domain.
   - **Impact:** Mọi thay đổi model candidate hấp tấp sẽ làm gãy hợp đồng `18` cột hoặc phá hỏng in-domain FPR; việc nêu `100%` cho `Exploitation_And_C2` sẽ gây hiểu nhầm học thuật.
   - **Fix Implemented / Status:** **`PASS` (Completed & Documented; Epistemics Refined in Finding #11)** — Ghi nhận `RETAIN_E0_BASELINE_ARTIFACTS` (giữ 4 artifact đã ký SHA-256 trên hợp đồng `canonical-flow-v2-18`, toàn bộ `deployment_tier = "RESEARCH_ONLY"`), tách rõ `Tier 1 Zero-Shot` vs `Tier 2 Device-Disjoint` vs `Tier 3 Same-Device Temporal` (`RESEARCH_ONLY`), ghi cảnh báo thống kê `N=5` và `DIRTY_DISCLOSED` (`git_dirty: true`, `79ebb678`).

9. **`R-PR156-SYNC` — Đồng bộ Tài liệu Kiểm toán & Mô tả PR `#156` (Đợt `2c8acc1d`)**
   - **Severity:** `P2`
   - **Location:** PR `#156` description, `reports/audits/{V2_FINAL_AUDIT,V2_MODEL_AUDIT,V2_FINDING_REGISTER,V2_ISSUE_AC_AUDIT,V2_PR156_AND_DEFERRED_HANDOFF,V2_DISTRIBUTION_GOVERNANCE_REVIEW}.md`, `docs/PRESENTATION_OUTLINE.md`
   - **Evidence:** Ở đợt `f5dacb1e` $\to$ `2c8acc1d` (CI Run `#44271966268`), cụm WP2–WP6 được commit lên `feat/v2-integration`; tuy nhiên một số tài liệu vẫn giữ SHA `f5dacb1e`, `12` commits, `493` files, và mô tả PR `#156` chưa đồng bộ lại sau `2c8acc1d`.
   - **Root Cause:** Tài liệu kiểm toán và PR body được cập nhật trước khi commit `2c8acc1d` và trước lượt phát hiện WP-A/WP-B mới nhất.
   - **Impact:** Reviewer đọc PR `#156` hoặc audit report có thể nhầm HEAD, CI run hoặc trạng thái working tree.
   - **Fix Implemented / Status:** **`SUPERSEDED_BY_R_AUDIT_PR156_RESYNC` (xem mục `12`)** — Lịch sử cũ được giữ nguyên để bảo toàn audit trail; trạng thái hiện hành được đồng bộ tại Mục 8 bên dưới.

---

## 8. Phát hiện & Khắc phục Hậu Kiểm PR `#156` (`a6c87ae` CI Run `#211` + Đợt Vá `WP-F` & Doc Sync, `2026-11-18`)

10. **`R-OOD-INMEM-BYPASS` — Trust-Boundary Validation Bypass cho In-Memory `OODRejectionGate` (`WP-A`)**
    - **Severity:** `P1` *(internal API / trust-boundary validation bypass; không có bằng chứng khai thác từ xa qua mạng)*
    - **Original Finding:** Trong `src/network_anomaly/streaming/realtime_inference.py`, nhánh `_load_ood_gate(gate=...)` khi nhận `gate is not None` chỉ kiểm tra `if gate.is_fitted:` và trả về trạng thái `"FITTED"` mà không kiểm tra `isinstance(gate, OODRejectionGate)`, danh sách `feature_names` (`ML_FEATURE_COLUMNS`), shape/finite của `means`/`stds`/`min_bounds`/`max_bounds`, `stds > 0`, `min_bounds <= max_bounds`, `provenance.fit_rows`, hay `preprocessor_artifact_sha256`, thậm chí cho phép in-memory object lọt qua cả khi `runtime_mode == "deployment"`. Ngoài ra `infer_event()` chưa bắt runtime error từ `evaluate_sample()`, `LiveTelemetryService` chưa nhận `runtime_mode`, và `LiveSystemOrchestrator` bỏ qua `runtime_mode` nếu `inference_engine` được truyền vào.
    - **Remediation Commit:** `a6c87ae8397e466ab1bd3d19f82d880e71084b88` (`fix(v2): close OOD gate validation bypass, clarify WP3 leakage policy, and sync PR #156 audits`).
      - `src/network_anomaly/ml/ood_gate.py`: lưu `provenance` & `artifact_sha256` trên `OODRejectionGate`; kiểm finite & feature uniqueness trong `fit()`; bổ sung `validate_ood_gate_instance()`.
      - `src/network_anomaly/streaming/realtime_inference.py`: `_load_ood_gate()` từ chối fail-closed (`ERROR`) mọi direct in-memory `ood_gate` injection trong `deployment` mode hoặc `require_ood_gate=True`, áp dụng `validate_ood_gate_instance()` cho research gate, và `infer_event()` bắt fail-closed runtime error từ `evaluate_sample()`.
      - `src/network_anomaly/streaming/live_orchestrator.py` & `live_service.py`: truyền và kiểm khớp `runtime_mode`/`require_ood_gate`.
    - **Verification Evidence:** Regression tests trong `tests/unit/test_ood_and_calibration.py` & `tests/unit/test_realtime_inference.py` + CI Run `#211` (ID `44278751854`, `7/7` jobs `PASS`: Ubuntu `585 passed, 21 skipped`, Windows `587 passed, 19 skipped`).
    - **Current Status:** **`PASS`** *(đã xác minh trên implementation snapshot `a6c87ae` & CI Run `#211`)*
    - **Remaining Limitation:** Internal API/trust-boundary bypass (không phải network exploit); Clean Windows VM standalone runtime vẫn `NOT VERIFIED`; persisted expected SHA trust anchor được tách theo dõi tại mục `13. R-OOD-EXPECTED-SHA`.

11. **`R-WP3-LEAKAGE-DISCLOSURE` — Khai báo `leakage_policy` WP3 Gộp Nhầm với Quyết định Lựa chọn Hậu Nghiệm (`WP-B`)**
    - **Severity:** `P2`
    - **Original Finding:** `scripts/run_wp3_controlled_ablation.py` và `reports/experiments/ml/wp3_controlled_ablation_report.json` từng ghi `ait_test_touched_for_selection: false`, `ctu_touched_for_zero_shot_selection: false`, và `test_touched_for_selection_or_threshold: false`, trong khi `selection_recommendation` (`RETAIN_E0_BASELINE_ARTIFACTS`) lại trích dẫn trực tiếp kết quả `AIT-Test Data_Exfiltration`, `CTU-Win7AD`, `CTU-Echo` và `AIT-Val FPR`.
    - **Remediation Commit:** `a6c87ae8397e466ab1bd3d19f82d880e71084b88` — tách biệt từng hoạt động trong `scripts/run_wp3_controlled_ablation.py` và đồng bộ `wp3_controlled_ablation_report.json`, `model_improvement_summary.json`, `V2_MODEL_AUDIT.md` (không retrain hay đổi SHA `E0`).
    - **Verification Evidence:** `tests/unit/test_rq_and_benchmark_contracts.py::test_wp3_leakage_policy_and_report_schema_consistency` + CI Run `#211` (ID `44278751854`, `7/7` `PASS`).
    - **Current Status:** **`PASS`**
    - **Remaining Limitation:** Quyết định giữ `E0` là quyết định phân tích hậu nghiệm có tham khảo holdout (`holdout_independent_selection = false`), không phải lựa chọn candidate hoàn toàn độc lập với holdout; 4 model `E0` giữ `deployment_tier = RESEARCH_ONLY` và `DIRTY_DISCLOSED` (`79ebb678`).

12. **`R-AUDIT-PR156-RESYNC` — Đồng bộ Snapshot `a6c87ae` / CI Run `#211`, Audit Docs & PR `#156` Body (`WP-C` & `WP-D`)**
    - **Severity:** `P2`
    - **Original Finding:** Các tài liệu kiểm toán (`V2_FINAL_AUDIT`, `V2_MODEL_AUDIT`, `V2_FINDING_REGISTER`, `V2_ISSUE_AC_AUDIT`, `V2_PR156_AND_DEFERRED_HANDOFF`, `V2_DISTRIBUTION_GOVERNANCE_REVIEW`, `PRESENTATION_OUTLINE`) và mô tả PR `#156` có độ trễ so với HEAD & CI run thực tế (ban đầu `2c8acc1d` / `#44271966268`, sau đó `a6c87ae` / Run `#211` ID `44278751854` và bản vá `WP-F`).
    - **Remediation:** Tách bạch rõ **Model Training Provenance** (`79ebb678`, `git_dirty=true`), **Implementation & CI Verification Snapshot** (`a6c87ae`, Run `#211` ID `44278751854`), và **Documentation/WP-F Remediation Commit**; đồng bộ toàn bộ 7 tài liệu và cập nhật trực tiếp PR `#156` body (giữ nguyên `OPEN / Draft`, `approved: false`).
    - **Verification Evidence:** Đối chiếu `git rev-parse`, `gh pr view 156`, `gh run view`, `verify_companion_artifacts.py`, và CI run gắn với commit `5483794` (Run `#212`, ID `44312426631`).
    - **Current Status:** **`SUPERSEDED_BY_SECTION_9` (`P2-02`)** — Review `CHANGES_REQUESTED` bởi `ViolaPeracia` trên `5483794` đã chỉ ra độ trễ đồng bộ tài liệu và đếm sai số review; xem Section 9 bên dưới.
    - **Remaining Limitation:** Các rào cản ngoài phạm vi (`UGR'16`, `#85`, `#137` physical lab, `#73`/`#148` Clean VM, `DISTRIBUTION_AUTHORIZATION.json`, `#152`, `#153`, và review lại sau `CHANGES_REQUESTED`) giữ nguyên chưa đóng.

13. **`R-OOD-EXPECTED-SHA` — Persisted OOD Gate Expected SHA-256 Verification & Missing Built-in Trust Anchor (`WP-F`)**
    - **Severity:** `P2`
    - **Original Finding:** `verify_ood_gate_artifact()` hỗ trợ tham số `expected_sha256`, nhưng `RealtimeInferenceEngine._load_ood_gate()` gọi `verify_ood_gate_artifact()` mà không truyền `expected_sha256`. Vì vậy persisted `ood_reference_gate.json` chỉ được kiểm cấu trúc JSON, schema, array bounds và `preprocessor_artifact_sha256`, chưa đối chiếu với một expected artifact SHA-256 đáng tin cậy tại runtime.
    - **Threat Boundary & Investigation:**
      - `artifacts/ml/ood_reference_gate.json` nằm trong thư mục `.gitignore`, không có manifest được theo dõi trong `reports/` (khác với 4 model `.joblib` và `v2_flow_preprocessor.joblib` vốn có manifest trong `reports/models/` & `reports/preprocessing/`).
      - `EMBEDDED_ARTIFACTS_MANIFEST.json` và `EMBEDDED_SHA256SUMS.txt` (do `stage_embedded_bundle()` sinh khi đóng gói standalone) và `COMPANION_BUNDLE_MANIFEST.json` là các tệp JSON/text **không ký số**, nằm trên **cùng thư mục cài đặt/filesystem trust boundary** với `artifacts/ml/ood_reference_gate.json`. Vì vậy chúng không thể làm trust anchor độc lập chống việc sửa đồng thời cả artifact lẫn manifest.
    - **Remediation Implemented:**
      - `src/network_anomaly/ml/ood_gate.py`: bổ sung `resolve_expected_ood_gate_sha256()` (nhận `expected_ood_gate_sha256` hoặc env `NETFLOW_OOD_GATE_SHA256`, từ chối coi unsigned co-located manifest là anchor độc lập) và `cross_check_same_boundary_embedded_manifest()` (kiểm khớp nếu có `EMBEDDED_ARTIFACTS_MANIFEST.json`/`EMBEDDED_SHA256SUMS.txt`/`COMPANION_BUNDLE_MANIFEST.json` cùng thư mục để bắt mismatch).
      - `src/network_anomaly/streaming/realtime_inference.py`, `live_orchestrator.py`, `live_service.py`: thêm `expected_ood_gate_sha256`, truyền vào `verify_ood_gate_artifact(..., expected_sha256=...)`, từ chối fail-closed (`ERROR`, `ood_gate_trust_anchor="missing_trusted_expected_sha256"`) trong `deployment` mode nếu thiếu external expected SHA hoặc lệch SHA, và giữ nguyên contract `research` mode (`unanchored_local_artifact` / `unanchored_same_boundary_manifest`).
      - `scripts/verify_companion_artifacts.py`: bổ sung trường `ood_gate` vào `COMPANION_BUNDLE_MANIFEST.json`, kiểm `ood_gate` trong `_verify_companion_bundle_manifest()` và bắt buộc khớp `EMBEDDED_ARTIFACTS_MANIFEST.json` + `EMBEDDED_SHA256SUMS.txt` trong `verify_installed_standalone_layout()`.
    - **Verification Evidence:** Regression tests trong `tests/unit/test_realtime_inference.py` & `tests/unit/test_verify_companion_artifacts.py` (đúng SHA PASS, sai SHA REJECT, sửa JSON hợp lệ vẫn REJECT, sai preprocessor SHA REJECT, thiếu expected SHA trong `deployment` mode fail-closed, `research` mode giữ contract, companion/embedded manifest mismatch REJECT).
    - **Current Status:** **`PASS (Runtime SHA Enforcement) / PARTIAL_UNANCHORED (Built-in Default Anchor)`** *(xem thêm `14. P1-01` & `16. P2-03` tại Mục 9 sau review `CHANGES_REQUESTED` tại `5483794`)*
    - **Conditions to Close:** Track một signed/authoritative OOD manifest trong Git hoặc ký cryptographic/Authenticode `EMBEDDED_ARTIFACTS_MANIFEST.json` (hoặc cấp `NETFLOW_OOD_GATE_SHA256` tại `cargo build` `build.rs` `option_env!` hoặc biến môi trường operator ngoài trust boundary `artifacts/`).

---

## 9. Khắc phục Review `CHANGES_REQUESTED` trên `5483794` / CI Run `#212` (`ViolaPeracia`, `2026-11-18`)

- **Historical Context Preserved:** Commit `5483794160e877bf2d65144f30fd1ffc181372c3` đạt CI Run `#212` (ID `44312426631`, `7/7` `SUCCESS`) nhưng nhận **`1` submitted GitHub review (`CHANGES_REQUESTED`)** từ `ViolaPeracia` (`COLLABORATOR`, `2026-11-18T13:46:21Z`), tách biệt với model training provenance (`79ebb678`, `DIRTY_DISCLOSED`) và snapshot trước đó (`a6c87ae`, Run `#211`).

14. **`P1-01` — Nối Chính sách OOD `deployment` Vào Toàn bộ Product Entry Points**
    - **Severity:** `P1`
    - **Original Finding:** Tại `5483794`, `RealtimeInferenceEngine` mặc định `NETFLOW_RUNTIME_MODE="research"`, `LiveRuntime.start()` không truyền `runtime_mode` hay `expected_ood_gate_sha256`, `desktop/src-tauri/src/backend.rs` không set `NETFLOW_RUNTIME_MODE`/`NETFLOW_OOD_GATE_SHA256` ở cả 2 nhánh sidecar/Python fallback, và `scripts/run_live_lab_acceptance.py` dựng `LiveTelemetryService` không khai báo profile.
    - **Remediation Implemented:**
      - `src/network_anomaly/ml/ood_gate.py`: `resolve_expected_ood_gate_sha256()` hỗ trợ thêm `NETFLOW_EMBEDDED_OOD_GATE_SHA256` (`"build_embedded_sha256"`), không coi unsigned co-located manifest là anchor độc lập.
      - `src/network_anomaly/streaming/realtime_inference.py`: thêm `resolve_runtime_policy()`, đổi mặc định khi vắng env sang fail-closed `"deployment"` (`require_ood_gate=True`, `policy_source="default_fail_closed:deployment"`), báo cáo `runtime_policy_source` & `expected_ood_gate_sha256_configured` trong `readiness()`.
      - `src/network_anomaly/api/live_runtime.py` & `main.py`: `LiveRuntime`, `LiveRuntime.start()`, `create_app()` nhận và nối tường minh `runtime_mode`/`require_ood_gate`/`expected_ood_gate_sha256` xuống `LiveTelemetryService -> LiveSystemOrchestrator -> RealtimeInferenceEngine`; cấm hạ cấp ngầm `deployment -> research`; báo trạng thái fail-closed tiền khởi chạy (`UNAVAILABLE` nếu thiếu trusted SHA).
      - `scripts/run_api.py` & `scripts/run_live_lab_acceptance.py`: `run_api.py` mặc định `deployment` (hỗ trợ `--runtime-mode`, `--ood-gate-sha256`); `run_live_lab_acceptance.py` chọn tường minh `research` cho lab tổng hợp khi thiếu SHA ngoài và ghi rõ vào report.
      - `desktop/src-tauri/build.rs` & `src/backend.rs`: dùng `option_env!("NETFLOW_OOD_GATE_SHA256")` + runtime env qua `resolve_backend_runtime_policy()` & `apply_backend_runtime_policy()`, áp dụng đồng nhất cho cả **embedded backend sidecar** và **Python script fallback** (mặc định `NETFLOW_RUNTIME_MODE=deployment`, `NETFLOW_REQUIRE_OOD_GATE=true`; giữ inference `UNAVAILABLE` nếu thiếu trusted SHA; không downgrade về `research`).
    - **Verification Evidence:** Regression tests trong `tests/unit/test_realtime_inference.py`, `tests/integration/test_full_system_e2e.py`, và Rust unit tests trong `desktop/src-tauri/src/backend.rs` (`test_runtime_policy_defaults_fail_closed_to_deployment`, `test_sidecar_and_python_fallback_receive_identical_runtime_policy`, `test_spawn_and_clean_shutdown_python_backend`).
    - **Current Status:** **`PASS`** *(entry-point wiring & fail-closed behavior verified; live AI inference ở `deployment` mode giữ `UNAVAILABLE` khi operator/build chưa cấu hình `NETFLOW_OOD_GATE_SHA256`, và cả 4 model tiers vẫn giữ `RESEARCH_ONLY`)*

15. **`P2-02` — Đồng bộ Hóa Toàn Bộ Audit Docs & Trạng thái Review PR `#156`**
    - **Severity:** `P2`
    - **Original Finding:** 7 tài liệu audit còn ghim snapshot cũ (`a6c87ae` / Run `#211`) hoặc ghi `0` submitted reviews sau khi `5483794` (Run `#212`) đã nhận `1` review `CHANGES_REQUESTED` từ `ViolaPeracia`.
    - **Remediation & Status:** **`PASS`** — Đã tách 3 mốc (`79ebb678` `DIRTY_DISCLOSED`, `a6c87ae`/Run `#211`, `5483794`/Run `#212` + `CHANGES_REQUESTED`) và hiện trạng sửa lỗi trên 7 tài liệu + PR `#156` description (giữ `OPEN / DRAFT`).

16. **`P2-03` — Tách Biệt Phân cấp Khẳng định Toàn vẹn OOD trong `verify_companion_artifacts.py` & `V2_MODEL_AUDIT.md`**
    - **Severity:** `P2`
    - **Original Finding:** `verify_companion_artifacts()` gọi `verify_ood_gate_artifact()` không truyền expected SHA, tạo ấn tượng PASS toàn vẹn dù chỉ tự tính hash + kiểm cấu trúc/preprocessor linkage.
    - **Remediation & Status:** **`PASS`** — `scripts/verify_companion_artifacts.py` nhận `--expect-ood-gate-sha256` / env, chạy `cross_check_same_boundary_embedded_manifest()`, tách riêng `structural_schema_verified`, `preprocessor_linkage_verified`, `trusted_digest_verified`, `integrity_verification_status` (`"PASS"` vs `"PARTIAL_UNANCHORED"` vs `"FAIL"`), `trust_anchor_source`; `V2_MODEL_AUDIT.md` cập nhật khớp trung thực.

17. **`P3-01` — Hiển thị Lý do Test Skip trong CI (`.github/workflows/ci.yml`)**
    - **Severity:** `P3`
    - **Original Finding:** CI hiện count `21 skipped` (Ubuntu) / `19 skipped` (Windows) ở Run `#211`/`#212` nhưng không in skip reasons tách biệt với raw dataset `SKIPPED`.
    - **Remediation & Status:** **`PASS`** — Đã cập nhật `.github/workflows/ci.yml` thành `python -m pytest tests -q -rs --tb=short` (không xóa/làm yếu test). Kết quả xác minh trên CI **Run `#213` (ID `44330918241`, `5cfa5fe`)**:
      - **Ubuntu 3.11/3.12 (`590 passed, 22 skipped`):** `2` skip đặc thù Windows (`test_controller_target_vm_e2e.py:683` PowerShell, `test_key_manager_hardening.py:99` DPAPI) + `20` skip do checkout Git không chứa binary `.joblib`/OOD/demo bị `.gitignore` (`test_four_model_integrity_e2e.py:288`, `test_full_system_e2e.py:166`, `test_inference_e2e.py:376`, `test_m6_desktop_e2e.py:182`, `test_multi_source_inference.py:116`, `test_pipeline.py:616,650`, `test_security_dry_run_integration.py:24,107`, `test_desktop_csv_api.py:366,1129`, `test_inference_pipeline.py:251`, `test_model_registry.py:108 [2], 171 [1]`, `test_preprocessing_pipeline.py:628`, `test_realtime_inference.py:150,547`, `test_verify_companion_artifacts.py:1900,2415`).
      - **Windows 3.11/3.12 (`592 passed, 20 skipped`):** Cùng `20` skip binary `.gitignore` trên runner (`2` test Windows PowerShell/DPAPI đều `PASS`).
      - **Local full environment:** `612 passed, 0 skipped`.
      - **Tách biệt với raw dataset integrity step:** Step `Verify AIT multi-source dataset manifest & checksums` ghi riêng `[fetch_multi_source_dataset] SOURCE_INTEGRITY: SKIPPED — official raw files absent (data/raw/ait_nds_v2)`.

18. **`P3-02` — Thống nhất Thuật ngữ RF Reference (`is_canonical_baseline=false` vs `E0`)**
    - **Severity:** `P3`
    - **Original Finding:** `random_forest_manifest.json` ghi `is_canonical_baseline=false` (`rf-v2-tuned-leaf5-cwbalanced_subsample`) trong khi WP3 dùng tên `E0_canonical_18f_baseline`.
    - **Remediation & Status:** **`PASS`** — `scripts/run_wp3_controlled_ablation.py`, `reports/experiments/ml/wp3_controlled_ablation_report.json`, `model_improvement_summary.json` và `V2_MODEL_AUDIT.md` đổi nhãn sang **`E0_frozen_18f_reference`** và giữ nguyên `random_forest_manifest.json` (`is_canonical_baseline=false`, không retrain hay sửa SHA).

---

## 10. Đợt Đồng bộ Mới nhất (`ac709f3` / CI Run `#215` & Phase 2–3 Option B)

19. **Wave 1–2 (`ac709f3`, CI Run `#215` / ID `44351520341`, `7/7` `SUCCESS`) & Phase 2–3 Remediation (`2026-11-19`):**
    - Đóng thêm: sở hữu `LICENSE`/`pyproject.toml` (`doctor-cato`), rà soát nguồn `UGR'16` (`UWF-ZeekData24` `95,871` flows read-only `XGB F1=0.9472`), Behavioral 16-D CSV + `EntityBaselineProfiler` detail/UI, đánh giá chỉ-đọc 4 `AggregationPolicy` + `RiskScorer`, `KEYSTORE_RUNBOOK.md` + DB migration rollback, `10,000`-event `tracemalloc` test, phân trang `2,000` alerts + 4-phase timeline Vitest, benchmark `--repeats 3` CV%, Real-Dataset UDP Loopback Replay ở `deployment` mode + trusted OOD SHA (`replay_real_netflow_udp.py`), System-Level Crypto A/B Overhead (`benchmark_crypto_overhead.py`, `121.7` vs `181.2 flow/s`, CPU `+53.56%`), thí nghiệm Multi-Class 6 lớp (`AIT-Test` `RF_multiclass Macro-F1=0.7347`), Cross-Source Calibration Diagnostic, và RQ3 Feature-Standardized Cosine (`UWF-ZeekData24` `F1=0.7192`).
    - Đồng bộ lại PR `#156` description (cập nhật từ mốc cũ `20c4414`/`Run #214`) và giữ PR ở `OPEN / isDraft: true` chờ re-review.

---

## 11. Phát hiện & Khắc phục Kiểm toán Chuyên sâu Cục bộ (Hậu `8e04960`, `2026-11-19`)

> [!NOTE]
> Commit đã push gần nhất là `8e049603a8841da11a082fcb077b2e3d5dbb8e92` (CI **Run `#217` / ID `44377910551`**, `7/7` `SUCCESS`, bổ sung `reports/ml/ood_reference_gate_manifest.json` được kiểm chéo bởi `_verify_repo_ood_gate_manifest()`). Các finding dưới đây được phát hiện và vá trên **working tree cục bộ** (chưa commit, đang chờ kiểm chứng toàn repo và push CI mới).

| Finding ID | Severity | Location | Trạng thái |
|---|---|---|---|
| `R-TRACE-GRAPH-CRASH` | `P1` | `src/network_anomaly/api/{main,schemas}.py`, `src/network_anomaly/trace/investigation.py` | **`PASS` (Fixed & Targeted Tested)** |
| `R-RISK-NAN-FAILOPEN` | `P1` | `src/network_anomaly/risk/scoring.py` | **`PASS` (Fixed & Targeted Tested)** |
| `R-BENCH-UNAVAILABLE-DRIFT` | `P1` | `scripts/benchmark_full_system.py`, `reports/benchmarks/system_performance_benchmark.json`, `docs/benchmarks/SYSTEM_PERFORMANCE.md` | **`PASS` (Fixed & Regenerated)** |
| `R-UI-144-BENCHMARK` | `P1` | `src/network_anomaly/api/{main,schemas}.py`, `desktop/src-tauri/src/{commands,lib}.rs`, `desktop/src/lib/{api,types}.ts`, `ModelComparisonPanel.svelte`, `LiveMonitoringPanel.svelte` | **`PASS` (Fixed & Targeted Tested)** |
| `R-LIVE-107-130-WIRING` | `P1` | `src/network_anomaly/api/db.py`, `src/network_anomaly/streaming/{live_orchestrator,live_service}.py`, `src/network_anomaly/ingestion/adapters/v2_adapter.py`, `src/network_anomaly/behavioral/vector.py`, `src/network_anomaly/pipeline/multi_source.py` | **`PASS` (Fixed & Targeted Tested)** |
| `R-CRYPTO-KEYID-RISKSCORE` | `P1` | `src/network_anomaly/crypto/{key_manager,rotation}.py`, `src/network_anomaly/api/db.py` | **`PASS` (Fixed & Targeted Tested)** |
| `R-API-DEV-TOKEN-WARN` | `P2` | `src/network_anomaly/api/main.py`, `scripts/run_api.py` | **`PASS` (Fixed & Targeted Tested)** |
| `R-COMPAT-TIER-DISCLOSURE` | `P2` | `src/network_anomaly/ingestion/compatibility.py` | **`PASS` (Fixed & Targeted Tested)** |

### Chi tiết 8 Findings Mới

20. **`R-TRACE-GRAPH-CRASH` — HTTP 500 tại `GET /api/v1/trace/graph`, Phân trang `/trace/timeline` & `artifact_version` cho Investigation Report (`#111`, `#113`, `#115`)**
    - **Severity:** `P1`
    - **Location:** `src/network_anomaly/api/{main,schemas}.py`, `src/network_anomaly/trace/investigation.py`, `reports/api/{openapi.json,API_CONTRACT.md}`
    - **Evidence & Root Cause:** `GET /api/v1/trace/graph` thao tác trực tiếp thuộc tính nội bộ thay vì gọi `graph.add_node(...)` / `graph.add_edge(...)` theo đúng `EntityRelationshipGraph` (gây lệch `_adj`, `_rev_adj`, `edges` -> HTTP 500) và thiếu cờ `truncated` trên `TraceGraphResponse`. `GET /api/v1/trace/timeline` chưa cắt trang đúng theo `offset`/`limit`. `InvestigationReport` và `InvestigationReportResponse` thiếu trường `artifact_version`.
    - **Fix Implemented / Status:** **`PASS` (Fixed & Targeted Tested)** — Dùng `graph.add_node(...)` / `graph.add_edge(...)`, thêm `truncated: bool = False` vào `TraceGraphResponse`; sửa phân trang `/api/v1/trace/timeline` (`limit=max(200, limit + offset)`, `stage_items[offset : offset + limit]`, giữ `total_stages`); thêm `artifact_version: str = "2.0.0"` vào `InvestigationReport` và `InvestigationReportResponse` (không đổi công thức `artifact_hash`); tái sinh OpenAPI (`export_openapi_spec.py --check` PASS).
    - **Verification Evidence:** Regression tests trong `tests/unit/test_trace_engine.py` và `tests/integration/test_trace_crypto_api.py` (`34 passed` trong cụm kiểm tra API/Trace).

21. **`R-RISK-NAN-FAILOPEN` — `RiskScorer` Không Chặn `NaN`/`Inf` & Giá trị Âm `auth_failure_count`**
    - **Severity:** `P1`
    - **Location:** `src/network_anomaly/risk/scoring.py`, `tests/unit/test_risk_engine.py`
    - **Evidence & Root Cause:** Đầu vào `NaN`/`Inf` ở `ai_probability` hoặc `behavioral_anomaly_score` có thể làm sai lệch phép tính/so sánh ngưỡng kích hoạt rotation; `auth_failure_count` âm không được chuẩn hóa về `0`.
    - **Fix Implemented / Status:** **`PASS` (Fixed & Targeted Tested)** — Kiểm tra `math.isfinite()` cho `ai_probability` và `behavioral_anomaly_score`, đặt thành phần non-finite về `0.0` kèm lý do fail-closed, kẹp `raw_score <= 65.0`, khóa `trigger_adaptive_rotation = False`, và chuẩn hóa `auth_failure_count = max(0, int(auth_failure_count))`.
    - **Verification Evidence:** `tests/unit/test_risk_engine.py` nằm trong cụm `52 passed` (`ruff`/`black` PASS).

22. **`R-BENCH-UNAVAILABLE-DRIFT` — `system_performance_benchmark.json` Chạy Thiếu Context `deployment` + Explicit OOD SHA (`0/4` vs `4/4 REAL_MODELS`)**
    - **Severity:** `P1`
    - **Location:** `scripts/benchmark_full_system.py`, `reports/benchmarks/system_performance_benchmark.json`, `docs/benchmarks/SYSTEM_PERFORMANCE.md`
    - **Evidence & Root Cause:** `benchmark_full_system.py` thiếu CLI `--runtime-mode` / `--ood-gate-sha256` để tái lập benchmark `deployment` + explicit OOD SHA, dễ khiến báo cáo bị ghi đè thành `UNAVAILABLE` khi chạy không tham số.
    - **Fix Implemented / Status:** **`PASS` (Fixed & Regenerated)** — Thêm `--runtime-mode` và `--ood-gate-sha256` vào `scripts/benchmark_full_system.py` (mặc định không tham số trên CI vẫn thoát `0`), tái sinh thật với `--runtime-mode deployment --ood-gate-sha256 8a52bfe5ad156560a3949afd5d4860c175ce5d158c38eb47aae07342102e9825 --repeats 3`: đạt `4/4 REAL_MODELS`, `ood_gate_status="FITTED"`, `ood_gate_trust_anchor="explicit_expected_sha256"`, E2E mean `18.813 flow/s` (`CV=9.88%`; latest `20.19 flow/s`), median latency `46,745.5 us` (repeat mean `51,899.2 us`, `CV=15.7%`), Replay mean `19.093 flow/s` (`CV=4.41%`), `dropped_events=0`.
    - **Verification Evidence:** `reports/benchmarks/system_performance_benchmark.json`, `docs/benchmarks/SYSTEM_PERFORMANCE.md` & `tests/unit/test_audit_remediation_bench_live.py` (cụm `117 passed`).

23. **`R-UI-144-BENCHMARK` — Thiếu Báo cáo Benchmark Chính thức (`AIT-Test` + Cross-Source CTU/UWF) & `Dropped events` Counter trên Desktop UI (`#140`, `#144`)**
    - **Severity:** `P1`
    - **Location:** `src/network_anomaly/api/{main,schemas}.py`, `desktop/src-tauri/src/{commands,lib}.rs`, `desktop/src/lib/{api,types}.ts`, `desktop/src/lib/components/{ModelComparisonPanel,LiveMonitoringPanel}.svelte`, `desktop/src/lib/components/V2Panels.test.ts`
    - **Evidence & Root Cause:** `ModelComparisonPanel.svelte` chưa nạp số liệu benchmark chính thức từ `model_comparison_report.json` + `ctu_cross_source_eval.json` + `uwf_zeekdata24_cross_source_eval.json`; `LiveMonitoringPanel.svelte` chưa hiển thị tổng `dropped` (`collector.events_dropped + pipeline.total_dropped`).
    - **Fix Implemented / Status:** **`PASS` (Fixed & Targeted Tested)** — Thêm `GET /api/v1/models/benchmark-report` (trả `EMPTY` an toàn khi thiếu file, gắn `deployment_tier="RESEARCH_ONLY"`), Tauri command `get_model_benchmark_report` + `getModelBenchmarkReport()`, khu vực **"Báo cáo Benchmark Chính thức (AIT-NDS-v2 Test & Cross-Source CTU/UWF)"** trong `ModelComparisonPanel.svelte` (ghi rõ `tree_feature_importances`/`validation_permutation_importance`, không gọi là SHAP), và counter `Dropped events` trong `LiveMonitoringPanel.svelte`.
    - **Verification Evidence:** `npm --prefix desktop run check` (`0 errors, 0 warnings`), `npm --prefix desktop run test` (`5 files, 39/39 tests`), `npm --prefix desktop run build` PASS, `cargo fmt/clippy/test --lib` (`11/11 tests`) PASS.

24. **`R-LIVE-107-130-WIRING` — Nối `LiveLogTailer` (`#130`), `V2_SCHEMA_SQL` (`#107`), Chuẩn hóa Adapter (`#89/#90`), Missingness (`#101/#102`) & `AIT` Linkage Warning (`#93`)**
    - **Severity:** `P1`
    - **Location:** `src/network_anomaly/api/db.py`, `src/network_anomaly/streaming/{live_orchestrator,live_service}.py`, `src/network_anomaly/ingestion/adapters/v2_adapter.py`, `src/network_anomaly/behavioral/vector.py`, `src/network_anomaly/pipeline/multi_source.py`
    - **Evidence & Root Cause:** `LiveTelemetryService` chưa tích hợp `LiveLogTailer`; `LiveSystemOrchestrator` chưa ghi `insert_unified_security_event(...)`; `query_unified_security_events()` thiếu bộ lọc `start_time`/`end_time`; `ApplicationDNSAdapter`/`SystemAuditAdapter` thiếu `adapt_line()` hoàn chỉnh và `v2_adapter.py` còn giá trị giả `"0.0.0.0"`, `"unknown_user"`, `"local_host"`; `behavioral/vector.py` chưa đánh dấu thiếu `dns_intensity`/`http_intensity`/`auth_failure_ratio` khi thiếu sự kiện ứng dụng; `PipelineCoverageReport` thiếu `ait_linkage_status="NOT_VERIFIED"`.
    - **Fix Implemented / Status:** **`PASS` (Fixed & Targeted Tested)** — Nối `log_paths` + `LiveLogTailer` vào `LiveTelemetryService` (worker loop + shutdown flush + `log_tailers` status); `LiveSystemOrchestrator` khởi tạo `DatabaseManager` có `V2_SCHEMA_SQL` và gọi `insert_unified_security_event(...)`; bổ sung `start_time`/`end_time` parameterized vào `query_unified_security_events()`; bổ sung `adapt_line()` & bỏ giá trị giả trong `v2_adapter.py`; thêm missingness flags cho `dns_intensity`/`http_intensity`/`auth_failure_ratio` trong `behavioral/vector.py`; thêm `ait_linkage_status="NOT_VERIFIED"` + warning trong `pipeline/multi_source.py`.
    - **Verification Evidence:** `tests/integration/test_live_service.py`, `tests/unit/test_v2_adapters.py`, `tests/unit/test_behavioral_engine.py`, `tests/unit/test_audit_remediation_bench_live.py` (`117 passed` cụm bench/live/adapters + `8 passed` cụm persistence/migration).

25. **`R-CRYPTO-KEYID-RISKSCORE` — Path Traversal ở `KeyManager` & Thiếu Cột `rotation_audit.risk_score` (`#119`, `#121`, `#122`)**
    - **Severity:** `P1`
    - **Location:** `src/network_anomaly/crypto/{key_manager,rotation}.py`, `src/network_anomaly/api/db.py`, `tests/unit/test_key_manager_hardening.py`
    - **Evidence & Root Cause:** `key_id` không được chuẩn hóa trước khi tạo đường dẫn DEK file trong `KeyManager`; bảng `rotation_audit` thiếu cột `risk_score` để lưu/khôi phục điểm rủi ro kích hoạt rotation qua restart.
    - **Fix Implemented / Status:** **`PASS` (Fixed & Targeted Tested)** — Thêm `_validate_safe_identifier()` (`^[A-Za-z0-9._-]+$`) và `_dek_file_path()` kiểm tra `.resolve().parent == self.keystore_dir.resolve()` trên toàn bộ thao tác DEK trong `KeyManager`; thêm cột `risk_score REAL` vào DDL `rotation_audit`, migration idempotent `PRAGMA table_info(rotation_audit)` + `ALTER TABLE`, và persist/reload trong `KeyRotationPolicy`.
    - **Verification Evidence:** `tests/unit/test_key_manager_hardening.py`, `tests/unit/test_crypto_integrity.py`, `tests/unit/test_crypto_aead.py` (`52 passed` cụm risk/crypto + `8 passed` persistence/migration).

26. **`R-API-DEV-TOKEN-WARN` — Không Cảnh báo Khi Chạy API Không Có `NETWORK_ANOMALY_API_TOKEN`**
    - **Severity:** `P2`
    - **Location:** `src/network_anomaly/api/main.py`, `scripts/run_api.py`
    - **Evidence & Root Cause:** Khi khởi động chế độ dev thiếu `NETWORK_ANOMALY_API_TOKEN`, ứng dụng chạy không xác thực trên loopback mà không ghi log cảnh báo rõ ràng.
    - **Fix Implemented / Status:** **`PASS` (Fixed & Targeted Tested)** — Thêm `logger.warning("NETWORK_ANOMALY_API_TOKEN is not set; API routes are running without authentication on loopback.")` trong `create_app` và cảnh báo `[SECURITY WARNING]` tương ứng trong `scripts/run_api.py`, kèm regression test trong `tests/integration/test_trace_crypto_api.py`.

27. **`R-COMPAT-TIER-DISCLOSURE` — Tường minh `deployment_tier = "RESEARCH_ONLY"` & `scope_note` trong `compatibility.py`**
    - **Severity:** `P2`
    - **Location:** `src/network_anomaly/ingestion/compatibility.py`, `tests/unit/test_compatibility_evaluator.py`
    - **Evidence & Root Cause:** Báo cáo tương thích cho đường dẫn in-domain CSV dry-run của `random_forest` (`MODEL_VALIDATED`) cần công bố tường minh `deployment_tier="RESEARCH_ONLY"` và `scope_note` tách biệt chứng nhận triển khai thực tế.
    - **Fix Implemented / Status:** **`PASS` (Fixed & Targeted Tested)** — Thêm `scope_note` vào `BenchmarkEvidence` và `deployment_tier="RESEARCH_ONLY"` + `scope_note="in_domain_csv_dry_run_only_not_production_certified"` vào `CompatibilityEvaluationReport`, nêu rõ containment bị chặn bởi `response_policy.py` (không đổi status `MODEL_VALIDATED` của CSV dry-run `random_forest` hay khóa `RESEARCH_ONLY` trên 4 models).
    - **Verification Evidence:** `tests/unit/test_compatibility_evaluator.py` & `tests/unit/test_response_policy.py` trong cụm `117 passed`.

