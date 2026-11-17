# Yêu cầu hệ thống — NetFlow Sentinel v2

## Yêu cầu chức năng (Functional Requirements)

| ID | Yêu cầu | Checkpoint | Trạng thái |
|---|---|---|---|
| F01 | Acquisition, provenance SHA-256, streaming profiling & quality gates cho `AIT-NDS-v2`, `AIT-LDS-v2.1`, `AIT-ADS`, `CTU-SME-11`; đánh dấu trung thực `UGR'16 BLOCKED` | C1 | **COMPLETED** (`VERIFIED` CC BY 4.0; `UGR'16 BLOCKED`) |
| F02 | Canonical contract `canonical-flow-v2-18` (18 ML features), `taxonomy-v2` (không ép `background`/`unknown` thành `Benign`), `v2-scenario-group-purged-v1`, `TrainOnlyPreprocessor(asinh_robust)` | C2 | **COMPLETED** (`d33dfe09...`, `1,930,219` rows) |
| F03 | Random Forest & XGBoost huấn luyện mới trên `AIT-Train`, audit feature shortcut | C3 | **EXPERIMENTALLY VALIDATED** (`AIT-Test` RF `F1=0.8997`, XGB `F1=0.8910`) |
| F04 | Isolation Forest & Autoencoder benign-only trên `AIT-Train`, calibration trên `AIT-Val` (`target_fpr=0.05`), `AI Ready 4/4` | C4 | **EXPERIMENTALLY VALIDATED** (`IF F1=0.5766`, `AE F1=0.5788`, `CTU-Echo IF F1=0.8527`) |
| F05 | Behavioral Vector 16-D & Session Correlation | C5 | **IMPLEMENTED / TESTED** (`RQ3` simulation; empirical AIT linkage `BLOCKED`) |
| F06 | Risk Scoring `[0..100]` & Trace Engine / Attack Timeline | C6 | **IMPLEMENTED / TESTED** |
| F07 | Bảo mật AES-256-GCM, DPAPI/POSIX key wrapping & Adaptive Key Rotation | C7 | **IMPLEMENTED / TESTED / BENCHMARKED** (`RQ5`, `RQ6`) |
| F08 | Adaptive Security Response Dry-Run (`executed=false`) | C8 | **IMPLEMENTED / TESTED (Dry-Run)** |
| F09 | Python FastAPI + SQLite + PyInstaller Sidecar + Desktop UI Rust/Tauri 2 + Svelte 5 (18-feature v2) | C9 | **IMPLEMENTED / TESTED** (`576` pytest pass, `33` vitest pass, Cargo clippy/test pass) |
| F10 | Cross-source evaluation trên `CTU-SME-11` (`CTU-Echo`, `CTU-Windows7AD`) & RQ1–RQ6 | C10 | **EXPERIMENTALLY VALIDATED** (`CTU-SME-11` hoàn thành; `UGR'16 BLOCKED`) |
| F11 | Tài liệu v2, CI workflows v2, lưu trữ historical `NF-UNSW-NB15-v3` | C11 | **COMPLETED** trên `feat/v2-integration` |

## Yêu cầu phi chức năng (Non-Functional Requirements)

| ID | Yêu cầu | Kiểm chứng |
|---|---|---|
| N01 | Python `>=3.11` (`src/network_anomaly/`), Svelte 5 + Rust/Tauri 2 (`desktop/`) | `check_environment.py`, `ci.yml`, Vitest, Cargo clippy/test |
| N02 | Không commit raw datasets, `.joblib` model binaries, hoặc secrets vào Git | `.gitignore`, `fetch_multi_source_dataset.py --verify-only` |
| N03 | Fail-closed SHA-256 & `canonical-flow-v2-18` contract; không fallback sang v1 `NF-UNSW-NB15-v3` | `test_v2_migration_guards.py`, `test_inference_pipeline.py`, `test_api_service.py` |
| N04 | Mã nguồn `Apache-2.0`; ghi nhận nguồn CC BY 4.0 cho AIT & CTU-SME-11 | `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` |
