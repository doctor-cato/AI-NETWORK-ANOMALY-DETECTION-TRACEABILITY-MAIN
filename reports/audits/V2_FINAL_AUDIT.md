# Báo cáo Kiểm toán Cuối kỳ Độc lập — NetFlow Sentinel v2.0 (`V2_FINAL_AUDIT.md`)

- **Vai trò thực hiện:** Kiểm toán viên Độc lập Cuối kỳ (`Independent Final Audit Reviewer`)
- **Ngày kiểm toán:** `2026-11-18` (`UTC+7` / `2026-11-18T02:34Z`)
- **Nhánh / Commit gốc:** `feat/v2-integration` @ `HEAD 79ebb678b87de19cc6b664b587726983fecaf98f` (kèm `192` đường dẫn đang chỉnh sửa/chưa theo dõi hậu remediation trên working tree tại thời điểm mở kiểm toán)
- **Phiên bản phần mềm:** Desktop Tauri/Svelte `2.0.0` · Python/FastAPI Contract `0.1.0`
- **Phương pháp:** Chỉ đọc và chạy lệnh xác minh trực tiếp trên đĩa bằng `.venv\Scripts\python.exe`, `npm`, `cargo`, `git`, `gh`; không chỉnh sửa mã nguồn, test, script, artifact ML, dataset, docs hay GitHub Issues.

---

## 1. Tóm tắt Điều hành & Ranh giới Phạm vi Kiểm toán

### 1.1. Phán quyết Sẵn sàng Tổng thể

> **Phán quyết:** **`Functional Prototype / Academic & Controlled Lab Pilot`**
>
> **KHÔNG tuyên bố `Production-Ready` · KHÔNG tuyên bố `Public-Release-Ready`**

Trên working tree hiện tại của nhánh `feat/v2-integration`, toàn bộ các sửa lỗi kỹ thuật trọng yếu ở pha hậu remediation (`CI-F01..F12`, `DATA-A01..A08`, `ML-01..05`, `PROD-01..05`) đã được xác minh trực tiếp là hoạt động và vượt qua toàn bộ bộ kiểm tra cục bộ (`ruff`, `black`, `589/589` Python unit/contract/integration tests, `svelte-check`, `vitest 33/33`, `cargo fmt/clippy/test 9/9`, `verify_companion_artifacts --verify-e2e`).

Tuy nhiên, hệ thống **chưa đủ điều kiện** phát hành công khai hoặc tuyên bố sẵn sàng vận hành sản xuất vì các giới hạn cấu trúc và cổng kiểm chứng còn lại:
1. Các thay đổi hậu remediation và 4 mô hình tái huấn luyện mới hiện tồn tại trên working tree chưa commit (`git_dirty: true`, `worktree_provenance: "DIRTY_DISCLOSED"`), nên chưa có CI run trên GitHub Actions (`.github/workflows/ci.yml`) xác minh một commit sạch mới.
2. Nghiệm thu trên mạng lab thiết bị vật lý (`#137`), `UGR'16` (`HTTP 403`), liên kết trực tiếp UID `AIT-NDS-v2 ↔ AIT-LDS-v2.1` (`#85`), Clean Windows 10/11 VM NSIS installer E2E (`#73`/`#148`), phê duyệt phân phối công khai `DISTRIBUTION_AUTHORIZATION.json` (`approved: false`), website `site-source` (`#152`), và slide/PDF bảo vệ (`#153`) vẫn đang `BLOCKED` hoặc `NOT VERIFIED`.

---

## 2. Tổng hợp Kết quả Các Cổng Kiểm chứng Độc lập

Mọi kết quả dưới đây được chạy và quan sát trực tiếp tại thời điểm kiểm toán, phân loại theo quy chuẩn `PASS` / `FAIL` / `SKIPPED` / `NOT VERIFIED` (kèm ghi chú `BLOCKED` cho phần ngoại vi).

| STT | Cổng Kiểm chứng | Lệnh Thực thi Trực tiếp | Trạng thái | Kết quả & Bằng chứng Thực đo | Phạm vi & Giới hạn |
|---:|---|---|---|---|---|
| 1 | Git Tree & Whitespace | `git rev-parse HEAD; git branch --show-current; git status --short; git diff --check` | **`PASS`** | `HEAD 79ebb678b87de19cc6b664b587726983fecaf98f`, nhánh `feat/v2-integration`, `192` mục modified/untracked, `git diff --check` exit `0`. | Working tree đang chứa thay đổi hậu remediation chưa commit (`git_dirty: true`). |
| 2 | Môi trường Python | `.\.venv\Scripts\python.exe scripts/check_environment.py` | **`PASS`** | `python 3.12.10`; 10 package (`pandas`, `numpy`, `sklearn`, `xgboost`, `joblib`, `matplotlib`, `seaborn`, `cryptography`, `pydantic`, `network_anomaly`) OK. | Xác minh interpreter cục bộ `.venv`. |
| 3 | Kiểm tra Raw Datasets (Read-Only) | `.\.venv\Scripts\python.exe scripts/fetch_multi_source_dataset.py --verify-only` | **`PASS`** *(cục bộ)* / **`BLOCKED`** *(UGR'16)* | Xác nhận `10 AIT-NDS-v2`, `2 AIT-LDS-v2.1`, `2 AIT-ADS`, `4 CTU-SME-11` file(s) và `UGR16=BLOCKED`; `git status --short data/` không bị ghi đè (`chỉ M data/V2_SPLIT_MANIFEST.json`). | `UGR'16` bị chặn `HTTP 403` từ máy chủ ngoài; raw data bị `.gitignore`. |
| 4 | Companion & Model Artifacts | `.\.venv\Scripts\python.exe scripts/verify_companion_artifacts.py` | **`PASS`** | `overall_status: READY`, `ready_models: ["random_forest", "xgboost", "isolation_forest", "autoencoder"]`, `demo_ready: true`, `18` companion files, preprocessor SHA `0866dec7...`. | Kiểm tra trên bộ artifact `.gitignored` cục bộ. |
| 5 | Backend 4-Model API E2E | `.\.venv\Scripts\python.exe scripts/verify_companion_artifacts.py --verify-e2e` | **`PASS`** *(API cục bộ)* | `e2e_status: PASS`, `e2e_backend_origin: api_only_run_api`, `127.0.0.1:63294`, `source_commit: 79ebb67...`, `desktop_version: 2.0.0`, `4/4` `verified_model`: RF `MODEL_VALIDATED` (`F1=1.0, FPR=0.0`), XGB `RESEARCH_ONLY` (`F1=1.0, FPR=0.0`), IF/AE `RESEARCH_ONLY` (`F1=0.944724, FPR=0.05`); `client_spoof_fail_closed: HOLD_UNVERIFIED_PROVENANCE`. | Chế độ `api_only_run_api`: `session_auth_fail_closed: false`, `standalone_verified: false`, `clean_machine_status: "NOT VERIFIED"`, `source_tree_clean: false`. |
| 6 | Governance Quyền Phân phối | `.\.venv\Scripts\python.exe scripts/verify_companion_artifacts.py --verify-distribution-permission research-only --target-channel local_offline` | **`PASS`** | `status: APPROVED` cho kênh `local_offline` / `research-only`; `public_release_allowed: false`; xác nhận `NOTICE`, `THIRD_PARTY_NOTICES.md`, `LICENSE`. | Chỉ duyệt mức `research-only`; public release vẫn `HOLD_FOR_MAINTAINER_SIGNOFF`. |
| 7 | Đồng bộ Phiên bản Desktop | `.\.venv\Scripts\python.exe scripts/check_desktop_version.py --check` | **`PASS`** | Desktop version `2.0.0` nhất quán trên 5 file cấu hình/lockfile; Python/FastAPI contract version `0.1.0`. | Khớp `desktop/src-tauri/tauri.conf.json`. |
| 8 | Đồng bộ OpenAPI Contract | `.\.venv\Scripts\python.exe scripts/export_openapi_spec.py --check` | **`PASS`** | `reports/api/openapi.json` (`openapi 3.1.0`, `info.version: 0.1.0`) và `reports/api/API_CONTRACT.md` khớp hoàn toàn. | Không phát sinh drift schema API. |
| 9 | Dependency DAG v2 | `.\.venv\Scripts\python.exe scripts/parse_dag.py` | **`PASS`** | `Total nodes in DAG: 80`, `Topological sort visited: 80`, `0 cycles`, `Longest Critical Path length: 23 steps` (`#76 -> ... -> #154`). | Toàn bộ 80 issues `#76–#155` có lịch trình không chu trình. |
| 10 | Ruff & Black Quality Gates | `.\.venv\Scripts\python.exe -m ruff check src scripts tests`; `.\.venv\Scripts\python.exe -m black --check src scripts tests` | **`PASS`** | Ruff: `All checks passed!`; Black: `244 files would be left unchanged`. | Đã quét toàn bộ active & historical Python files trong `src`, `scripts`, `tests`. |
| 11 | Python Test Suite (Active) | `.\.venv\Scripts\python.exe -m pytest tests/unit tests/contract tests/integration -q -rs` | **`PASS`** | **`589 passed, 38 warnings in 106.36s`**, `0 failed`, `0 skipped`. | Thư mục `tests/historical` được loại trừ theo `pyproject.toml` (`norecursedirs`). |
| 12 | Targeted Hardening & Quality Tests | `.\.venv\Scripts\python.exe -m pytest tests/unit/test_v2_prod_hardening.py tests/unit/test_code_quality_gates.py tests/unit/test_desktop_version_sync.py -q -rs` | **`PASS`** | **`15 passed in 3.50s`**, `0 skipped` (xác nhận `ruff` và `black` trong `test_code_quality_gates.py` đều chạy thực sự). | Phủ `PROD-01..04`, `v2.0.0` sync và quality gates. |
| 13 | ModelRegistry & OOD Gate Runtime | Kiểm tra trực tiếp `ModelRegistry().summary()` + `OODRejectionGate` | **`PASS`** | `ready_count: 4, validated_count: 4, ai_ready: True, demo_heuristics_enabled: False`, `0` UserWarnings; `artifacts/ml/ood_reference_gate.json` (`2,658 B`, 18 features) hợp lệ. | Khác biệt nhỏ: `ModelRegistry` gán `xgboost` là `PRODUCTION_ELIGIBLE`, còn `compatibility.py` giữ `RESEARCH_ONLY`. |
| 14 | Desktop Frontend (Svelte / Vitest) | `npm --prefix desktop run check`; `npm --prefix desktop test` | **`PASS`** | `svelte-check`: `0 errors and 0 warnings`; Vitest: `5` test files, `33 passed (33)` trong `1.51s`. | Test trên jsdom/component fixtures, không phải WebView2 GUI tương tác trên VM sạch. |
| 15 | Desktop Rust Shell (Tauri 2) | `cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check`; `cargo clippy -- -D warnings`; `cargo test --lib` | **`PASS`** | `cargo fmt --check` exit `0`; `cargo clippy -- -D warnings` exit `0`; `cargo test --lib`: `9 passed; 0 failed; 0 ignored` trong `8.58s`. | Kiểm thử Rust unit/IPC cục bộ; chưa build NSIS `.exe` trên máy sạch. |
| 16 | Kiểm tra Điều kiện Build Installer | `.\.venv\Scripts\python.exe scripts/build_installer_v2.py --check-only` | **`PASS`** *(check-only)* | `status: "FRONTEND_READY"`, `frontend_build_ready: true`, `sidecar_build_ready: false`, `full_nsis_installer_ready: false` (`pyinstaller: false`, `makensis: false`, `staged_bundle_manifest: false`). | Chỉ kiểm tra tiền điều kiện; không đủ toolchain NSIS trên `.venv` này. |
| 17 | Vệ sinh Tệp (LF / 0-byte / Path / AI ID) | Quét Python trực tiếp trên 192 đường dẫn `git status` & active files | **`PASS`** | `0` file 0-byte bị cắt cụt; `0` file non-binary chứa CRLF (`\r\n`) trong 192 mục `git status`; `0` đường dẫn cá nhân trong active generated JSONs & docs mới; `0` tên công cụ/model/vendor AI hay git trailer mới. | Các file audit Phase 0 (`reports/audits/V2_*.md`) và tệp lịch sử (`tests/historical/...`, `PROJECT.md`) giữ nguyên vết tham chiếu cũ trước remediation. |
| 18 | GitHub Actions CI Từ xa | `.github/workflows/ci.yml` đối chiếu working tree | **`NOT VERIFIED`** | CI Run `#44171616420` trước đó chạy trên `79ebb67` (chưa có các sửa lỗi hậu remediation); chưa có commit/push mới để chạy lại CI từ xa. | Cần commit sạch & push lên `PR #156` để xác minh CI Ubuntu/Windows `3.11`/`3.12`. |
| 19 | Clean Windows VM E2E & Lab Vật lý | `#73`, `#137`, `#148`, `DISTRIBUTION_AUTHORIZATION.json` | **`NOT VERIFIED` / `BLOCKED`** | `clean_machine_status: "NOT VERIFIED"`; `real_device_tested: false`; `public_release_authorization.approved: false`. | Phụ thuộc VM Windows 10/11 sạch, thiết bị switch/router lab và chữ ký maintainer. |

---

## 3. Truy vết Khoa học & Dữ liệu (`DATA → PREPROCESSING → MODELS → RQ1–RQ6`)

### 3.1. Split `v2-scenario-group-purged-v1` & Tính toàn vẹn Dữ liệu

- **Tệp manifest:** [`data/V2_SPLIT_MANIFEST.json`](../../data/V2_SPLIT_MANIFEST.json) và [`reports/splits/v2_split_manifest.json`](../../reports/splits/v2_split_manifest.json) đồng nhất tuyệt đối theo byte (`4,716` bytes, `0` CRLF).
- **SHA-256 LF chuẩn:** `ed542ee80babca26f6e8ad977168b061e18e99a24be1cbe1ec8767b66d6339e8` (trùng khớp trên cả preprocessor, 4 model manifests, `model_comparison_report.json`, `rq2_imbalance_report.json`, `rq4_unknown_attack_report.json`, `demo_manifest.json`, và `desktop_csv.py`).
- **Bảo toàn dữ liệu (`DATA-A01` đã sửa):** Tổng dòng `AIT-NDS-v2` được bảo toàn trọn vẹn **`3,464,400` labeled + `942` unmapped = `3,465,342` raw flows** (`0` dòng rơi ở ranh giới chunk):
  - `train` (`fox`, `harrison`, `santos`, `wardbeck`, `wilson`): `2,097,891` dòng (`1,825,866` Benign / `272,025` Attack, attack rate `12.97%`).
  - `validation` (`russellmitchell`): `377,704` dòng (`206,676` Benign / `171,028` Attack, attack rate `45.28%`).
  - `test` (`shaw`, `wheeler`): `988,805` dòng (`812,980` Benign / `175,825` Attack, attack rate `17.78%`).
  - **Leakage Audit (`PASS`):** `scenario_overlap_count: 0`, `scenario_5tuple_ts_overlap_count: 0`.
- **Dữ liệu ngoài `CTU-SME-11` (`ctu_cross_source_eval.json`):** `ctu_echo` (`76,073` dòng: `39,497` Benign / `36,576` Attack), `ctu_windows7ad` (`175,146` labeled + `9,394` unmapped; sau khi khử trùng `45` nhóm LAN `(5-tuple, 300s)` còn `175,101` dòng cho Exps C/D).

### 3.2. Preprocessor `asinh_robust` & `OODRejectionGate`

- **Preprocessor (`reports/preprocessing/v2_flow_preprocessing_manifest.json`):** `2,668` bytes, `0` CRLF, `split_manifest_sha256` khớp `ed542ee8...`, `artifact_sha256` khớp [`artifacts/preprocessing/v2_flow_preprocessor.joblib`](../../artifacts/preprocessing/v2_flow_preprocessor.joblib) (`0866dec7252d36d3f2bb2becddf266787cc49ddf19306a8e003ba1e951cf51a7`). Fit thuần túy trên `2,097,891` dòng `train` cho `18` đặc trưng (`canonical-flow-v2-18`), cấu hình `asinh_robust` (`MIN_BOUNDED_SCALE_FLOOR = 0.25` chống suy biến IQR `pkts_in_ratio`).
- **`OODRejectionGate` (`artifacts/ml/ood_reference_gate.json`):** `2,658` bytes, `0` CRLF, SHA-256 `8a52bfe5ad156560a3949afd5d4860c175ce5d158c38eb47aae07342102e9825`, fit trên `2,097,891` dòng raw `AIT-NDS-v2` `train` (18 features, `std_margin=4.0`, `statistical_threshold=5.0`). Được xác minh runtime `ood_gate=FITTED` trong `synthetic_udp_loopback_report.json`.

### 3.3. Bốn Mô hình Tái huấn luyện (`AI Ready: 4/4`, Empirical Val FPR & Provenance)

Kiểm tra trực tiếp xác nhận 3 bản sao JSON của từng mô hình (`reports/models/*_manifest.json`, `artifacts/models/*/*_manifest.json`, `reports/evaluation/*_v2_eval.json`) khớp 100% theo byte, không có CRLF, khớp `split_manifest_sha256` LF (`ed542ee8...`), khớp `preprocessor_artifact_sha256` (`0866dec7...`), và khớp SHA-256 của tệp `.joblib` tương ứng. Tất cả 4 mô hình mang dấu vết `git_commit: "79ebb678b87de19cc6b664b587726983fecaf98f"`, `git_dirty: true` (`DIRTY_DISCLOSED`).

| Mô hình (`Run ID`) | SHA-256 `.joblib` (`Size`) | `AIT-Val` (`N=377,704`) `F1` / `FPR` (`empirical_val_fpr`) | `AIT-Test` (`N=988,805`) `P` / `R` / `F1` / `FPR` / `ROC-AUC` | `CTU-Echo` (`N=76,073`) `F1` / `R` / `FPR` / `ROC-AUC` | `CTU-Win7AD` (`N=175,146`) `F1` / `R` / `FPR` / `ROC-AUC` | Tầng Triển khai (`Registry` / `Compatibility`) |
|---|---|---|---|---|---|---|
| **Random Forest** (`v2-rf-20261117T231214Z`, `th=0.5`, `balanced_subsample`, `leaf=5`) | `b2e42f85...` (`12,445,660 B`) | `0.999658` / **`0.000198`** | `0.998854` / `0.991110` / **`0.994967`** / `0.000246` / `0.999372` | `0.047418` / `0.026411` / `0.081069` / `0.613739` | `0.071233` / `0.541217` / `0.160755` / `0.839246` | `PRODUCTION_ELIGIBLE` / `MODEL_VALIDATED` |
| **XGBoost** (`v2-xgb-20261117T231609Z`, `th=0.5`) | `33d201f8...` (`249,182 B`) | `0.999556` / **`0.000160`** | `0.998886` / `0.821066` / **`0.901289`** / `0.000198` / `0.988440` | `0.143595` / `0.083197` / `0.069980` / `0.701663` | `0.073752` / `0.562316` / `0.161131` / `0.697827` | `PRODUCTION_ELIGIBLE` / `RESEARCH_ONLY` *(chênh giữa 2 tầng)* |
| **Isolation Forest** (`v2-if-20261118T020525Z`, `th=0.031268`, Benign-only) | `11b16900...` (`925,957 B`) | `0.921308` / **`0.049991`** (`<= 0.05` khớp cal.) | `0.777525` / `0.467846` / **`0.584182`** / `0.028952` / `0.833013` | `0.885328` / `0.990814` / `0.229182` / `0.957148` | `0.046382` / `0.975957` / `0.472185` / `0.764901` | `RESEARCH_ONLY` / `RESEARCH_ONLY` |
| **Autoencoder** (`v2-ae-20261118T020635Z`, `th=0.000467`, Benign-only `(16,8,16)`) | `e6afecef...` (`25,581 B`) | `0.921513` / **`0.049996`** (`<= 0.05` khớp cal.) | `0.785970` / `0.469262` / **`0.587662`** / `0.027637` / `0.554383` | `0.732531` / `0.998988` / `0.674634` / `0.780993` | `0.032628` / `0.992149` / `0.692521` / `0.728011` | `RESEARCH_ONLY` / `RESEARCH_ONLY` |

### 3.4. Phân định Nghiêm ngặt Trạng thái Khoa học (`RQ1–RQ6`, `CTU Cross-Source`, `Traceability`)

| Hạng mục | Bằng chứng JSON Thực tế | Phân loại Trạng thái Nghiêm ngặt | Kết quả & Giới hạn Khoa học Bắt buộc Nêu rõ |
|---|---|---|---|
| **RQ1** (So sánh 4 mô hình) | `reports/experiments/ml/model_comparison_report.json` | **`EXPERIMENTALLY VALIDATED`** | Đánh giá trên đủ `988,805` dòng `AIT-Test`; có `top_features` cho cả 4 model (`validation_permutation_importance` cho IF/AE). Supervised `RF` (`F1=0.9950`) vượt xa unsupervised (`AE 0.5877`, `IF 0.5842`) trên in-domain. |
| **RQ2** (Mất cân bằng & Lớp hiếm) | `reports/experiments/imbalance/rq2_imbalance_report.json` | **`EXPERIMENTALLY VALIDATED`** | **`h2_full_confirmed = false`:** `RF_CostSensitive` đạt overall `F1=0.9947` (`macro_f1=0.9968`), `Post_Exploitation_Discovery` (`39` flows) đạt Recall `0.8974`, `Exploitation_And_C2` (`5` flows) `1.0000`, nhưng `Credential_Attack` (`78` flows) vẫn dừng ở `0.1410` (RF/XGB/IF) và `0.0641` (AE) do trùng lắp phân phối đơn-flow 18-D. |
| **RQ3** (Tương quan phiên độc lập IP) | `reports/experiments/behavioral/rq3_session_correlation_experiment.json` | **`SIMULATION`** *(Empirical AIT **`BLOCKED`**)* | Chạy mô phỏng `20` phiên / `190` cặp (`simulation_hypothesis_met = false`): Strategy B `cos >= 0.85` đạt `F1=0.3191` (`FalseLink=0.80`); `cos >= 0.95` đạt `F1=0.5556` (`FalseLink=0.30`). Tuyên bố kiểm chứng thực nghiệm trên `AIT` là `BLOCKED` do thiếu khóa UID trực tiếp. |
| **RQ4** (Unknown attack holdout) | `reports/experiments/ml/rq4_unknown_attack_report.json` | **`EXPERIMENTALLY VALIDATED`** | Loại 100% `Exploitation_And_C2` + `Post_Exploitation_Discovery` khỏi Train (`216` flows) và Val (`58` flows). Trên `44` test holdout flows: `IF Recall=0.9091` (`FPR=0.0290`), `RF=0.9091` (`FPR=0.0004`), `XGB=0.7500` (`FPR=0.0003`), `AE=0.2045` (`FPR=0.0276`). **`unsupervised_ge_0_75_both = false`**. Chỉ phản ánh holdout testbed, không bảo đảm phát hiện zero-day ngoài thực tế. |
| **RQ5** (Adaptive vs Fixed Key Rotation) | `reports/experiments/crypto/rq5_rotation_experiment.json` | **`SIMULATION`** | `execution_mode = "SIMULATION"`, `hypothesis_confirmed = true`: mô phỏng 60 phút (`120` events) dùng `KeyManager`/`KeyRotationPolicy` thật giảm `87.5%` max exposure (`20.0m -> 2.5002m`) và `85.0%` blast radius (`40 -> 6` attack records/key). |
| **RQ6** (Crypto & E2E Benchmark) | `reports/benchmarks/{crypto_benchmark_report,system_performance_benchmark}.json` | **`IMPLEMENTED / TESTED / BENCHMARKED`** | `AES-256-GCM`: 256B P95=`13.3 us` (`75,851.2 ops/s`), 1024B P95=`17.3 us` (`59,259.3 ops/s`), 4096B P95=`29.6 us` (`38,617.1 ops/s`). Full system CPU (`REAL_MODELS 4/4`): `16.38 events/s` (median `61.75 ms`), replay `19.43 events/s`, `0` dropped. Không phải chứng nhận NIC 1–10 Gbps. |
| **CTU Cross-Source** (Exps A–E) | `reports/experiments/ml/ctu_cross_source_eval.json` *(trùng byte với `cross_dataset_evaluation.json`)* | **`EXPERIMENTALLY VALIDATED`** *(Exps A–D)* / **`BLOCKED`** *(Exp E)* | Khắc phục inverted AUC của XGB (`0.0373 -> 0.7017` trên `CTU-Echo`). Tuy nhiên zero-shot supervised tại `th=0.5` trên CTU vẫn thấp (`RF/XGB Echo F1=0.0474/0.1436`), trong khi `IF Echo F1=0.8853`. Device-disjoint (`AIT+Echo -> unseen Win7AD`): `RF F1=0.0928` (`AUC=0.8280`), `XGB F1=0.0923` (`AUC=0.8465`), `AE AUC=0.9520` (`FPR=0.4688`). CTU temporal late `Echo F1=0.9634` (RF) / `0.9589` (XGB). Exp E `UGR'16` **`BLOCKED`**. |
| **Synthetic UDP Loopback** (`#137`) | `reports/acceptance/synthetic_udp_loopback_report.json` | **`IMPLEMENTED / TESTED`** *(Synthetic Loopback)* | `synthetic: true`, `6/6` events qua UDP `127.0.0.1:62982`, `ood_gate=FITTED`, `4/4 VALIDATED`, `6/6` vector mã hóa ciphertext; `alerts: NOT_TRIGGERED` (`0` alerts >= `70.0`), `real_device_tested: false`. |
| **Traceability Evaluation** (`#114`) | `reports/experiments/trace/traceability_evaluation.json` | **`IMPLEMENTED / TESTED`** *(Synthetic 8-Event Benchmark)* | `TraceEngine` + `AttackTimelineReconstructor` đạt `1.0` / `1.0` so với dynamic grep `0.375` / `0.50` (`+62.5%` / `+50.0%`) trên kịch bản synthetic `8` events (`TRACEABILITY_EVALUATION.md` ghi nhãn `EXPERIMENTALLY VALIDATED`, nhưng kiểm toán độc lập xác định đây là synthetic ground-truth benchmark, chưa phải dữ liệu thực AIT-LDS/NDS). |

---

## 4. Đối chiếu 31 Findings & Đồng bộ 88 Open GitHub Issues

### 4.1. Đối chiếu `31` Findings trong `reports/audits/V2_FINDING_REGISTER.md`

Kiểm tra độc lập xác nhận trạng thái hậu remediation (Mục 5 của [`V2_FINDING_REGISTER.md`](V2_FINDING_REGISTER.md)) phản ánh đúng hiện trạng đĩa, kèm các lưu ý tinh chỉnh sau:

1. **Nhóm `PASS` trên working tree (`27` findings):**
   - `CI-F01` (`V2_SPLIT_MANIFEST.json` chuẩn LF `ed542ee8...`), `CI-F02` (`test_f01_provenance_anti_spoofing_matrix` pass), `CI-F03` (`verify_companion_artifacts --verify-e2e` pass), `CI-F04` (tests E2E/companion pass trong `589/589`), `CI-F05` (`ruff` 0 lỗi, `black` 244 files unchanged), `CI-F08` (`0` skipped trong `589/589`), `CI-F09` (`demo_flows.csv` SHA `90b02893...` verified), `CI-F10` (Desktop `2.0.0` sync), `CI-F11` (`THIRD_PARTY_NOTICES.md` bổ sung `cryptography`, active docs & generated JSONs sạch đường dẫn cá nhân), `CI-F12` (`ruff==0.17.5` & `black==26.10.1` đồng bộ giữa `pyproject.toml`, `ci.yml`, `lint-audit.yml`).
   - `DATA-A01` (`3,464,400 + 942 = 3,465,342`), `DATA-A02` (UDP `* 1000.0`), `DATA-A03` (Zeek `orig_bytes`/`resp_bytes`), `DATA-A04` (`MIN_BOUNDED_SCALE_FLOOR = 0.25` + Benign std AE), `DATA-A05` (audit & công bố Bayes error 18-D), `DATA-A06` (`45` LAN overlap deduplicated), `DATA-A08` (`asinh_robust` docstring/audit sync).
   - `ML-01` (LF provenance + `SplitReference` + AE split check), `ML-02` (RF/XGB retrain + CTU Exps A–E), `ML-03` (`RF_CostSensitive` + báo cáo trung thực `Credential_Attack`), `ML-04` (IF/AE `empirical_val_fpr <= 0.05` & RQ4 0 holdout leak), `ML-05` (sạch metadata + `top_features` IF/AE + `0` ModelRegistry warnings).
   - `PROD-01` (`v2_adapter.py` fail-closed + query redaction + 5 adapters trong `SourceRegistry`), `PROD-02` (`ood_reference_gate.json` fitted & scoped), `PROD-03` (`missing_feature_count`/`names` + `EntityBaselineProfiler`), `PROD-04` (`V2_SCHEMA_SQL` trong `db.py`, `clock_fn` + SQLite cooldown/rate-limit persistence trong `rotation.py`, `evaluate_traceability.py` dynamic baseline, `cryptography` notice), `PROD-05` (mở track `docs/audits/` khỏi `.gitignore`, sửa tên test & API routes).
2. **Nhóm `PARTIAL` (`2` findings đã xử lý phần nội bộ, giữ phần ngoài `BLOCKED`):**
   - `CI-F06`: `fetch_multi_source_dataset.py --verify-only` đã chuyển sang read-only thuần túy (`PASS`), còn `UGR'16` giữ `BLOCKED` (`HTTP 403`).
   - `CI-F07`: `run_live_lab_acceptance.py` sửa docstring 18 features & pass synthetic UDP loopback (`ood_gate=FITTED`, 4/4 `VALIDATED`), còn thiết bị lab vật lý giữ `BLOCKED`.
3. **Nhóm `BLOCKED` (`2` findings):**
   - `DATA-A07`: `UGR'16` (`HTTP 403`) & `AIT-NDS-v2 ↔ AIT-LDS-v2.1` direct UID join (`NOT VERIFIED`).
   - `PROD-06`: `DISTRIBUTION_AUTHORIZATION.json` (`approved: false`), Clean Windows 10/11 VM installer E2E (`#73`/`#148`), và website `site-source` (`#152`).
4. **Phát hiện tinh chỉnh nhỏ của Kiểm toán viên Độc lập (không làm thất bại cổng kiểm chứng hiện tại, cần minh bạch):**
   - `CI-F11`/`PROD-05`: [`docs/audits/THREAT_MODEL_V2.md`](../../docs/audits/THREAT_MODEL_V2.md) dòng 34 vẫn ghi *"trong Rust Collector (#131)"* dù `ARCHITECTURE_V2.md:14` đã chốt Python UDP Collector; `rq2_imbalance_report.{json,md}` còn chuỗi ví dụ cũ `(e.g., Worms)` ở mục Limitations.
   - `ML-01`: cả 4 model manifests đều mang `git_dirty: true` (`DIRTY_DISCLOSED`) do huấn luyện trước khi commit thay đổi working tree.
   - `PROD-06` / `Compatibility`: `ModelRegistry` gán `xgboost` là `PRODUCTION_ELIGIBLE`, trong khi `compatibility.py:124` mặc định `is_research_only=True` (`RESEARCH_ONLY`) cho `xgboost`.

### 4.2. Đối chiếu Đồng bộ `88` Open GitHub Issues (`V2_ISSUE_AC_AUDIT.md`)

Kiểm tra read-only trực tiếp qua GitHub CLI (`gh pr view 156` và `gh issue list --state open --limit 100`) khớp **100%** với thống kê tại Mục 9 của [`V2_ISSUE_AC_AUDIT.md`](V2_ISSUE_AC_AUDIT.md):

- **Pull Request `#156`:** `OPEN`, `isDraft: true`, `mergeStateStatus: BLOCKED` (`feat/v2-integration -> main`).
- **Tổng số Open Issues:** **`88`** (`0` issue bị đóng trước khi merge `main`); tổng AC checkboxes đã tick: **`282 / 372`**.
- **`80` Issues v2 (`#76–#155`):**
  - **`54` issues đạt `100%` AC checkboxes** (giữ `OPEN` chờ merge PR `#156` & CI xanh trên `main`): `#77, #78, #79, #81, #84, #86, #87, #88, #89, #90, #91, #92, #93, #94, #95, #96, #98, #99, #100, #101, #102, #104, #105, #107, #110, #111, #112, #113, #114, #115, #116, #117, #118, #120, #121, #122, #124, #125, #126, #127, #129, #130, #131, #132, #133, #134, #136, #138, #139, #143, #144, #145, #146, #155`. *(Lưu ý: `#104` và `#125` ghi rõ phạm vi `SIMULATION`; `#114` dùng synthetic 8-event benchmark).*
  - **`22` issues đạt một phần (`partial AC`):** `#76 (3/4), #80 (3/4), #82 (4/5), #83 (3/4), #85 (2/3), #97 (3/4), #103 (3/4), #106 (3/4), #108 (3/4), #109 (2/4), #119 (3/4), #123 (3/4), #135 (3/4), #137 (3/5), #140 (3/4), #141 (3/4), #142 (3/4), #147 (3/4), #149 (3/4), #150 (2/4), #151 (3/4), #152 (1/4)`.
  - **`4` issues giữ `0` checkboxes:** `#128 (0/4, Rust collector hoãn sau v2.0)`, `#148 (0/4, Clean VM NSIS installer)`, `#153 (0/4, slide/PDF bảo vệ)`, `#154 (0/4, cổng release cuối)`.
- **`8` Legacy Issues (`M7` + `None`):** `#18 (1/8), #19 (0/4), #20 (1/6), #25 (0/3), #48 (0/3), #60 (3/11), #71 (6/15)` thuộc `M7`, và `#73 (0/8)` chưa gắn milestone — đều giữ `OPEN` và đã dọn checkbox lỗi thời.

---

## 5. Danh sách Đầy đủ Blockers Còn lại & Giới hạn

1. **`UGR'16` External ISP Validation (`#82`, `#83`, `#97`):** Máy chủ `nesg.ugr.es` trả `HTTP 403` (*Portal en Mantenimiento*); không dùng dữ liệu giả thay thế.
2. **Liên kết Trực tiếp `AIT-NDS-v2 ↔ AIT-LDS-v2.1` (`#85`, `#104`):** `direct_uid_join_possible: false` (`NOT VERIFIED`) do chênh lệch phiên bản nguồn `v2.0` vs `v2.1` và thiếu khóa UID chung; RQ3 chỉ dừng ở `SIMULATION`.
3. **Thiết bị Mạng Lab Vật lý & Live GUI Alert (`#137`):** Mới nghiệm thu bằng synthetic UDP loopback trên `127.0.0.1` (`real_device_tested: false`, `alerts: NOT_TRIGGERED`).
4. **Clean Windows 10/11 x64 VM NSIS Installer E2E (`#73`, `#148`):** `clean_machine_status: "NOT VERIFIED"`, `standalone_verified: false`, `session_auth_fail_closed: false` trong chế độ `api_only_run_api`; `.venv` cục bộ chỉ đạt `FRONTEND_READY` (thiếu `pyinstaller`, `makensis`, `staged_bundle_manifest`).
5. **Phê duyệt Phân phối Công khai (`DISTRIBUTION_AUTHORIZATION.json`):** `public_release_authorization.approved: false` (`status: HOLD_FOR_MAINTAINER_SIGNOFF`); mới chỉ `APPROVED` ở mức `research-only` / `local_offline`.
6. **Website `site-source` (`#152`):** Nhánh `site-source` nằm ngoài nhánh `feat/v2-integration` hiện tại, chưa cập nhật giao diện/tài liệu v2.0.
7. **Báo cáo PDF & Slide Bảo vệ Đề tài (`#153`):** Hiện mới có tài liệu khung dàn ý (`docs/REPORT_OUTLINE.md`, `docs/PRESENTATION_OUTLINE.md`), chưa có bộ slide 10–12 trang và PDF hoàn chỉnh.
8. **Cổng Release Cuối & CI Commit Sạch (`#154`, `PR #156`):** Các thay đổi hậu remediation đang nằm trên working tree (`192` mục, `git_dirty: true` trong 4 model manifests); `PR #156` giữ `Draft / BLOCKED` và cần commit sạch + kích hoạt lại GitHub Actions CI từ xa trước khi xem xét merge hoặc đóng issue.
