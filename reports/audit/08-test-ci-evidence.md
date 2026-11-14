# Report 08 — Test & CI Evidence

## 1. Kết quả chạy test tại HEAD

### 1.1. Trong git clone sạch (có `.git`)

```text
python -m pytest tests -q -rs
```

```text
739 passed, 10 skipped, 13 warnings in 100.12s (0:01:40)
```

- Exit code: `0`.
- Snapshot: clone tại `b14dfeed9e7cbb07201cfb0ac8ce69c951434be1`.
- Đây là kết quả **PASS** cho test suite hiện tại.

### 1.2. Trong `git archive` export (không có `.git`)

```text
2 failed, 737 passed, 10 skipped in 99.82s
```

Hai failure:

- `test_execute_training_full_pipeline_mock_integration` (RF)
- `test_execute_training_full_pipeline_mock_integration` (XGB)

Nguyên nhân: `_get_git_commit()` trả `UNKNOWN` khi không có `.git`; manifest sinh ra có `provenance_complete` không đạt; `load_verified()` từ chối reload. Đây **không phải** lỗi logic ML trên HEAD, nhưng là **lỗi reproducibility từ source archive**: trainer tạo artifact nhưng không reload được nếu chạy ngoài Git checkout.

**Kết luận**: test suite PASS trong môi trường chuẩn; có coupling với `.git` cần ghi nhận.

## 2. Mười test bị skip

| # | Test | Lý do |
|---|---|---|
| 1 | `tests/integration/test_inference_e2e.py:379` | Thiếu real preprocessor artifact |
| 2 | `tests/integration/test_pipeline.py:618` | Thiếu real preprocessor artifact (`artifact=False, manifest=True`) |
| 3 | `tests/integration/test_pipeline.py:648` | Thiếu RF `.joblib` (bị `.gitignore`) |
| 4 | `tests/unit/test_preprocessing_pipeline.py:2430` | Thiếu raw dataset |
| 5 | `tests/unit/test_rf_training.py:721` | Thiếu dataset CSV hoặc preprocessor artifact |
| 6 | `tests/unit/test_split_protocol.py:306` | Thiếu split manifest trong workspace |
| 7 | `tests/unit/test_validate_data.py:1106` | Symlink không khả dụng |
| 8 | `tests/unit/test_validate_data.py:1123` | Symlink không khả dụng |
| 9 | `tests/unit/test_xgb_training.py:583` | Thiếu dataset/preprocessor |
| 10 | `tests/unit/test_xgboost.py:220` | Training bị BLOCKED do thiếu dữ liệu/điều kiện |

**Không có skip nào là PASS.** Sáu skip trực tiếp liên quan dataset/artifact thật; hai skip symlink là giới hạn môi trường Windows; một skip split manifest; một skip XGB training.

## 3. Bản chất test suite

- **26 file test**, 739 test.
- Phần lớn dùng fixture nhỏ 15–50 dòng hoặc constructor/validation test.
- Có integration test cho:
  - inference CSV → transform → predict → export (synthetic);
  - RF/XGB training với mock split environment;
  - IF threshold/score/E2E (synthetic);
  - split leakage guards.
- **Không có** test nào chạy full dataset 2.365.424 dòng trong CI.
- **Không có** test nào đánh giá RF/XGB trên test partition thật.
- **Không có** benchmark/threshold performance gate.

Vì vậy: **739 PASS chứng minh code không crash trên fixture**, không chứng minh ML pipeline thật hoạt động.

## 4. CI workflow

### 4.1. `ci.yml`

Trigger:

- `push` → `main`
- `pull_request` → `main`

Matrix:

- OS: `ubuntu-latest`, `windows-latest`
- Python: `3.11`, `3.12`

Các bước:

1. `pip install -e .`
2. `python scripts/check_environment.py`
3. `python -m compileall -q src scripts tests`
4. import check các module lõi (bao gồm `xgboost_model`, `inference.pipeline`)
5. `python -m pytest tests -q --tb=short`
6. `validate_data.py` — SKIPPED nếu thiếu raw package
7. `eda_nf_unsw_nb15_v3.py` — SKIPPED nếu thiếu raw package
8. `verify_eda_reproducibility.py` — SKIPPED nếu thiếu raw package
9. `preprocess_nf_unsw_nb15_v3.py` — SKIPPED nếu thiếu raw package

**Điểm yếu**:

- `check_environment.py` tại HEAD chỉ kiểm tra `pandas`, `numpy`, `sklearn`; **không kiểm tra `xgboost`** dù `pyproject.toml` khai báo dependency.
- Các bước dữ liệu thật đều skip trong CI mặc định; CI xanh không chứng minh data pipeline chạy.
- Không có bước verify artifact/model thật.

### 4.2. `lint-audit.yml`

Trigger:

- `workflow_dispatch`
- `pull_request` với path `**/*.py` hoặc chính workflow.

**Không có `push`**. Vì vậy:

- code merge vào `main` không được lint lại trên push;
- repo-wide Ruff/Black là `continue-on-error: true` → không gating;
- scoped list bao gồm nhiều file XGB nhưng **không bao gồm** `scripts/predict.py`, `src/network_anomaly/inference/*`, `models/random_forest.py`, `models/isolation_forest.py`, `preprocessing/*` — trừ khi các file đó nằm trong diff PR.

**Hệ quả**: không thể tuyên bố “main sạch lint” chỉ vì CI xanh. PR #37 vẫn open.

## 5. CI của các commit/PR quan trọng

| Ref | Kết quả | Ghi chú |
|---|---|---|
| `b14dfee` (push main) | CI success | 4 matrix job + lint? Lint không chạy push |
| `72e74b2` (merge #38) | test success | Không chứng minh IF artifact |
| `905da0d` (merge #45) | test success | Test synthetic |
| `c286149` (merge #44) | test success | Không chứng minh inference thật |
| PR #51 head `8a75e375…` | 5/5 success | Branch-only; test + lint audit |
| PR #50 | CHANGES_REQUESTED | Không merge |
| PR #47/#52 | CONFLICTING | Không merge |

**Không được dùng CI xanh của #51 để credit `main`.**

## 6. Kết luận

- **PASS**: test suite 739/739 (có `.git`), exit 0.
- **PASS có điều kiện**: CI matrix chạy đúng trên synthetic tests.
- **FAIL**: không có real-data/artifact gate; lint không chạy trên push; `check_environment` thiếu xgboost.
- **SKIPPED**: 10 test, trong đó 6 do thiếu dữ liệu/artifact thật.
- **NOT VERIFIED**: bất kỳ claim nào dựa trên “CI xanh” để nói ML pipeline đã chạy thật.
