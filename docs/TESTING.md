# Hướng dẫn Kiểm thử Hệ thống & ML Pipeline (`TESTING.md`)

Tài liệu này hướng dẫn kiến trúc kiểm thử đa tầng (Python ML/API, Frontend Svelte 5, Desktop Rust/Tauri 2 và Release E2E) trong repository `AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN` (CI thực tế tại [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) và [`.github/workflows/release.yml`](../.github/workflows/release.yml)).

---

## 1. Kiến trúc Kiểm thử Đa tầng

```text
tests/
├── unit/                        # Unit Tests: module/hàm độc lập, schema, split, preprocessing, models, API, OOD
├── contract/                    # Contract Tests: schema event & tích hợp M6 API contracts
└── integration/                 # Integration Tests: E2E inference, 4-model integrity, desktop E2E, dry-run, VM controller

desktop/
├── src/lib/**/*.test.ts         # Frontend Unit Tests (Vitest 23 tests) & svelte-check TypeScript
└── src-tauri/src/*.rs           # Rust Backend Sidecar & IPC Unit Tests (cargo test / clippy / fmt)
```

---

## 2. Phân loại kiểm thử và phạm vi chứng minh

| Tầng kiểm thử | Công cụ | Mục tiêu & Dữ liệu | Điều **chứng minh được** | Điều **không chứng minh được** |
|---|---|---|---|---|
| **Python Unit & Contract** | `pytest` (`tests/unit`, `tests/contract`) | Minimal fixtures & synthetic arrays | Logic hàm, 47-feature contract, fit boundary, OOD guards, API auth/validation | Không chứng minh accuracy/F1 trên `NF-UNSW-NB15-v3` |
| **Python Integration** | `pytest` (`tests/integration`) | Synthetic CSV & fixture artifacts | Luồng end-to-end CSV → Preprocessing → 4 Models → SQLite → Dry-Run → Export | Các test phụ thuộc `.joblib`/raw CSV thật sẽ `SKIPPED` nếu thiếu file |
| **Frontend Svelte 5** | `npm --prefix desktop run check` & `test` | Vitest mocks (`23` tests) | State comparison 4 model, hiển thị `MODEL_VALIDATED`/`RESEARCH_ONLY`, `ABSTAINED_OOD` | Không thay thế tương tác WebView2 GUI trên Windows thật |
| **Rust / Tauri 2** | `cargo fmt/clippy/test` | Sidecar launcher & IPC (`9` lib tests) | Spawning sidecar loopback, token auth, shutdown sạch không orphan | Clean Windows 10/11 VM GUI E2E theo dõi riêng tại Issue `#73` |
| **Release & Artifact E2E** | `verify_companion_artifacts.py --verify-e2e` | Bộ cài NSIS + 4 model `.joblib` thật | SHA-256, 4 model `READY`, 200 dòng demo (`198` + `2` OOD), fail-closed auth, uninstall | Smoke trên máy build giữ `clean_machine_status="NOT VERIFIED"` |

---

## 3. Lệnh Chạy Kiểm Thử trên Windows PowerShell

Chạy từ thư mục gốc repository:

### A. Kiểm tra Python & OpenAPI/Governance (theo `ci.yml`)
```powershell
python scripts/check_environment.py
python scripts/export_openapi_spec.py --check
python scripts/check_desktop_version.py --check
python scripts/verify_companion_artifacts.py --verify-distribution-permission research-only --target-channel local_offline
python -m compileall -q src scripts tests
python -m pytest tests -q --tb=short
```

### B. Chạy tách từng nhóm Python tests
```powershell
python -m pytest tests/unit/test_basic.py tests/integration/test_pipeline.py -q
python -m pytest tests/unit -q
python -m pytest tests/contract tests/integration -q
```

### C. Kiểm tra Frontend Svelte 5 & Rust Desktop
```powershell
npm --prefix desktop ci
npm --prefix desktop run check
npm --prefix desktop test
npm --prefix desktop run build

cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check
cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
$env:NETWORK_ANOMALY_REQUIRE_PYTHON_TEST = "1"
cargo test --manifest-path desktop/src-tauri/Cargo.toml --lib
```

### D. Lint, Format & Diff Cleanliness
```powershell
python -m ruff check src scripts tests
python -m black --check src scripts tests
git diff --check
```

### E. Kiểm tra Real-Data Audit (chỉ chạy khi có raw CSV / `.joblib` cục bộ)
```powershell
python scripts/validate_data.py
python scripts/eda_nf_unsw_nb15_v3.py
python scripts/verify_eda_reproducibility.py
python scripts/preprocess_nf_unsw_nb15_v3.py --verify-only
python scripts/export_academic_schema_summary.py
```

---

## 4. Cách Diễn Giải Trạng Thái Kiểm Thử

1. **`PASS`**: Toàn bộ assertions đều đạt.
2. **`FAIL`**: Vi phạm contract, lỗi runtime, sai hash hoặc regression — bắt buộc sửa trước khi merge.
3. **`SKIPPED`**: Môi trường thiếu raw dataset (577 MB) hoặc `.joblib` ngoài Git (`.gitignore`). **Lưu ý:** `SKIPPED` với exit code `0` tuyệt đối **không** được báo cáo là `PASS` trên dữ liệu thật.
4. **`NOT VERIFIED`**: Hạng mục chưa được kiểm chứng trong môi trường mục tiêu (ví dụ `clean_machine_status="NOT VERIFIED"` khi chạy E2E trên máy build có toolchain thay vì VM Windows 10/11 sạch tại `#73`).
