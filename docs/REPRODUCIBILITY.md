# Reproducibility Guide (NetFlow Sentinel v2)

## 1. Environment & Static Checks

- Python: `>=3.11` (CI chạy `3.11` & `3.12` trên Ubuntu và Windows; cục bộ khuyến nghị `.venv` Python `3.12`).
- Desktop: Node.js `22+`, Rust stable (`cargo`, `rustfmt`, `clippy`).
- Raw dataset và binary `.joblib` nằm ngoài Git (`.gitignore`); các kiểm tra CI chạy đầy đủ không cần tải 3+ GB raw dataset.

```powershell
.venv\Scripts\python.exe scripts/check_environment.py
.venv\Scripts\python.exe scripts/fetch_multi_source_dataset.py --verify-only
.venv\Scripts\python.exe scripts/export_openapi_spec.py --check
.venv\Scripts\python.exe scripts/check_desktop_version.py --check
.venv\Scripts\python.exe -m compileall -q src scripts tests
.venv\Scripts\python.exe -m pytest tests -q --tb=short
.venv\Scripts\python.exe -m ruff check src scripts tests
.venv\Scripts\python.exe -m black --check src scripts tests
git diff --check
```

Hướng dẫn kiểm thử chi tiết xem tại [TESTING.md](TESTING.md).

---

## 2. Reproduce Dataset Acquisition, Profiling & Splitting

```powershell
# Tải / xác minh checksum HTTPS cho AIT-NDS-v2, AIT-LDS-v2.1, AIT-ADS, CTU-SME-11
.venv\Scripts\python.exe scripts/fetch_multi_source_dataset.py

# Streaming profiling & kiểm toán chất lượng
.venv\Scripts\python.exe scripts/profile_multi_source.py

# Chuẩn hóa canonical-flow-v2-18 & chia tập scenario-disjoint
.venv\Scripts\python.exe scripts/build_v2_dataset_and_split.py

# Tạo 200 dòng demo Validation-only
.venv\Scripts\python.exe scripts/prepare_demo_dataset.py
```

Ghi chú trạng thái `UGR'16`: cổng chính thức `https://nesg.ugr.es/nesg-ugr16/` hiện trả `HTTP 403` / *"Portal en Mantenimiento"*, được ghi nhận là `BLOCKED` trong `data/EXTERNAL_DATASETS_PROVENANCE.json` và không thay thế bằng dữ liệu giả.

---

## 3. Reproduce Training, Threshold Calibration & Evaluation (4 Models v2)

Mỗi mô hình huấn luyện độc lập, fit preprocessing **chỉ trên `ait_train`** (`asinh_robust`, SHA-256 `d33dfe09630687f825d7e4cfa604001c3e091560538059da2eb397b49f44bc32`) và ghi manifest kèm `model_artifact_sha256`, `dataset_sha256`, `split_manifest_sha256`, `preprocessor_artifact_sha256`:

```powershell
.venv\Scripts\python.exe scripts/train_random_forest.py
.venv\Scripts\python.exe scripts/train_xgboost.py
.venv\Scripts\python.exe scripts/train_isolation_forest.py
.venv\Scripts\python.exe scripts/train_autoencoder.py

# Kiểm thực toàn bộ 4 artifact, 4 manifest, preprocessor và 200 demo rows
.venv\Scripts\python.exe scripts/verify_companion_artifacts.py
```

---

## 4. Reproduce Research Experiments & Cross-Source Benchmarks

```powershell
# RQ1: So sánh 4 mô hình trên AIT-Test (923,292 dòng)
.venv\Scripts\python.exe scripts/generate_model_comparison_report.py

# RQ2: Mất cân bằng lớp & tấn công hiếm trên AIT-NDS-v2
.venv\Scripts\python.exe scripts/run_rq2_rare_attack_experiment.py

# RQ3: Tương quan phiên độc lập IP (Simulation; Empirical AIT linkage BLOCKED/NOT VERIFIED)
.venv\Scripts\python.exe scripts/run_rq3_session_correlation_experiment.py

# RQ4: Unknown Attack Holdout (loại Exploitation_And_C2, Post_Exploitation_Discovery khỏi Train/Val)
.venv\Scripts\python.exe scripts/run_rq4_unknown_attack_experiment.py

# RQ5 & RQ6: Adaptive Key Rotation & AES-256-GCM overhead benchmark
.venv\Scripts\python.exe scripts/run_rq5_rotation_experiment.py
.venv\Scripts\python.exe scripts/benchmark_crypto_overhead.py

# Cross-Source Real-Capture Evaluation trên CTU-SME-11 (zero-shot, device-disjoint, temporal)
.venv\Scripts\python.exe scripts/run_ctu_cross_source_eval.py

# Live Lab UDP Loopback Acceptance & System Performance Benchmark
.venv\Scripts\python.exe scripts/run_live_lab_acceptance.py
.venv\Scripts\python.exe scripts/benchmark_full_system.py
.venv\Scripts\python.exe scripts/evaluate_traceability.py
```

---

## 5. Desktop Frontend, Rust Sidecar & Schema Export

```powershell
.venv\Scripts\python.exe scripts/export_academic_schema_summary.py --format json --output reports/schema/v2_schema_summary.json
.venv\Scripts\python.exe scripts/export_openapi_spec.py

npm --prefix desktop ci
npm --prefix desktop run check
npm --prefix desktop run test
npm --prefix desktop run build

cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check
cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path desktop/src-tauri/Cargo.toml --lib
```
