# Hướng dẫn Kiểm thử Hệ thống & ML Pipeline (`TESTING.md`)

Tài liệu này mô tả kiến trúc kiểm thử đa tầng cho **NetFlow Sentinel v2** theo CI thực tế tại [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) và [`.github/workflows/release.yml`](../.github/workflows/release.yml). Các test cũ dành riêng cho `NF-UNSW-NB15-v3` được lưu trữ tại `tests/historical/nf_unsw_nb15_v3/` và không chạy trong active suite.

---

## 1. Kiến trúc Kiểm thử Đa tầng

```text
tests/
├── unit/                        # Schema v2 (18 features), taxonomy-v2, split, asinh_robust preprocessing, 4 models, API, OOD, crypto, v2 guards
├── contract/                    # CanonicalSecurityEvent v2 & M6 API contracts
├── integration/                 # Multi-source pipeline, 4-model integrity E2E, desktop CSV/E2E, live telemetry, VM controller
└── historical/nf_unsw_nb15_v3/  # Lưu trữ lịch sử v1 (không thuộc active CI test suite)

desktop/
├── src/**/*.test.ts             # Frontend Unit Tests (Vitest 39+ tests) & svelte-check
└── src-tauri/src/*.rs           # Rust Backend Sidecar & IPC Unit Tests (11 Cargo tests / clippy / fmt)
```

---

## 2. Phân loại kiểm thử và phạm vi chứng minh

| Tầng kiểm thử | Công cụ | Mục tiêu & Dữ liệu | Điều **chứng minh được** | Điều **không chứng minh được** |
|---|---|---|---|---|
| **Python Unit & Contract** | `pytest` (`tests/unit`, `tests/contract`, `665+` total pytest suite) | Minimal fixtures & synthetic arrays v2 | Logic hàm, `canonical-flow-v2-18`, chặn fallback v1, train-only fit boundary, OOD & API auth | Không thay thế kết quả F1/FPR trên `AIT-NDS-v2` / `CTU-SME-11` |
| **Python Integration** | `pytest` (`tests/integration`) | Synthetic CSV & fixture/local v2 artifacts | Luồng E2E CSV/Live → Preprocessing → 4 Models → SQLite → Dry-Run → Export | Các case kiểm tra binary `.joblib` thật phụ thuộc môi trường có artifact cục bộ |
| **Frontend Svelte 5** | `npm --prefix desktop run check` & `test` | Vitest (`39+` tests) | State 4 model v2, 18-feature CSV upload/validation, `ABSTAINED_OOD` | Không thay thế WebView2 GUI tương tác trên Windows thật |
| **Rust / Tauri 2** | `cargo fmt/clippy/test` | Sidecar launcher & IPC (`11` lib tests) | Spawning sidecar loopback, token auth, shutdown sạch | Clean Windows VM GUI E2E |
| **Artifact & Data Verification** | `fetch_multi_source_dataset.py --verify-only`, `verify_companion_artifacts.py` | Manifests, 4 v2 `.joblib`, `demo_flows.csv` (`200` dòng) | SHA-256 chain, `READY 4/4`, OpenAPI sync, CC BY 4.0 governance | Không chứng minh khả năng phát hiện zero-day ngoài thực tế |

---

## 3. Lệnh Chạy Kiểm Thử trên Windows PowerShell

```powershell
# A. Kiểm tra nền tảng, dữ liệu v2, OpenAPI & unit/integration tests
.venv\Scripts\python.exe scripts/check_environment.py
.venv\Scripts\python.exe scripts/fetch_multi_source_dataset.py --verify-only
.venv\Scripts\python.exe scripts/verify_companion_artifacts.py
.venv\Scripts\python.exe scripts/export_openapi_spec.py --check
.venv\Scripts\python.exe scripts/check_desktop_version.py --check
.venv\Scripts\python.exe -m compileall -q src scripts tests
.venv\Scripts\python.exe -m pytest tests -q --tb=short

# B. Lint, Format & Diff Cleanliness
.venv\Scripts\python.exe -m ruff check src scripts tests
.venv\Scripts\python.exe -m black --check src scripts tests
git diff --check

# C. Frontend Svelte 5 & Rust Desktop
npm --prefix desktop run check
npm --prefix desktop test
npm --prefix desktop run build
cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check
cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
$env:NETWORK_ANOMALY_REQUIRE_PYTHON_TEST = "1"
cargo test --manifest-path desktop/src-tauri/Cargo.toml --lib
```

---

## 4. Cách Diễn Giải Trạng Thái Kiểm Thử

1. **`PASS`**: Toàn bộ assertions đạt sau chỉnh sửa cuối cùng.
2. **`FAIL`**: Vi phạm contract, lỗi runtime, sai SHA-256 hoặc regression — bắt buộc sửa.
3. **`SKIPPED`**: Bỏ qua có điều kiện khi thiếu raw file/artifact cục bộ; `SKIPPED` với exit code `0` không được báo là bằng chứng trên dữ liệu thật.
4. **`BLOCKED`**: Nguồn bên ngoài không truy cập được hoặc thiếu điều kiện hợp lệ (ví dụ `UGR'16` trả HTTP 403 / Portal en Mantenimiento).
5. **`NOT VERIFIED`**: Hạng mục chưa được kiểm chứng trong môi trường mục tiêu.
