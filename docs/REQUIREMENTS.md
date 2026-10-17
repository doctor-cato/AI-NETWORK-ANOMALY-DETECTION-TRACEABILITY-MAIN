# Requirements — Functional and Non-Functional

Ma trận đầy đủ Requirement → Issue → Deliverable → Acceptance Criteria → Verification nằm ở
[`TRACEABILITY_MATRIX.md`](TRACEABILITY_MATRIX.md). File này giữ danh sách yêu cầu gốc.

## Functional requirements (core, must work)

| ID | Requirement | Verification |
|---|---|---|
| F01 | Load UNSW-NB15 data (after download) and verify schema | `scripts/validate_data.py` passes on fixture; instructions exist |
| F02 | Inspect labels, class distribution, duplicates, missing values | Notebook / script produces summary |
| F03 | Preprocess without leakage: split first, then fit scaler/encoder | Pipeline object; test set untouched during fit |
| F04 | Build Random Forest classifier with documented hyperparameters | `src/network_anomaly/models/random_forest.py` (constructor only so far); train script runs |
| F05 | Evaluate with Precision, Recall, F1, Macro-F1, confusion matrix, FPR | `src/network_anomaly/evaluation/metrics.py` returns P/R/F1/Macro-F1/confusion matrix; **FPR chưa có trong module — thuộc issue #12** |
| F06 | Document Isolation Forest evaluation protocol separately (unsupervised score → threshold) | `docs/METHODOLOGY.md`; evaluation notes |
| F07 | Provide inference pipeline for new input data | `src/network_anomaly/inference/` module; demo script |
| F08 | Cung cấp hướng dẫn chạy thực nghiệm có thể tái lập | `docs/REPRODUCIBILITY.md`; `python scripts/run_experiments.py` (hoặc tương đương) |

## Optional requirements (NOT blocking core acceptance)

| ID | Requirement | Verification |
|---|---|---|
| O01 | Triển khai Isolation Forest không giám sát (ngoài phần tài liệu protocol F06) | Issue #11. Không có kết quả IF vẫn không chặn chấp nhận core; issue có thể giữ mở |
| O02 | Chạy nhiều seed và báo mean/std | Issue #12 — chỉ khi còn thời gian |
| O03 | Demo giao diện web (đề xuất Streamlit) | Issue #16 — cần issue riêng để thêm dependency; `streamlit` chưa khai trong `requirements.txt` |

## Non-functional requirements

| ID | Requirement | Verification |
|---|---|---|
| N01 | Code organized under `src/network_anomaly/`; logic callable from notebooks/scripts | Directory structure verified |
| N02 | Python 3.11+; giới hạn dependency tối thiểu, lưu phiên bản môi trường thực tế khi tái lập | `pyproject.toml`; `requirements.txt`; `docs/REPRODUCIBILITY.md`; CI matrix 3.11/3.12 |
| N03 | Không dùng đường dẫn tuyệt đối cố định; dùng đường dẫn tương đối hoặc config | `config.py`; tài liệu cấu hình môi trường |
| N04 | No secrets, API keys, or personal data in repo | `.gitignore`; kiểm tra diff và file trước commit |
| N05 | CI checks basic import and light tests without dataset | `.github/workflows/ci.yml` |
| N06 | Repository dùng Apache-2.0; xác minh nghĩa vụ riêng của dependency/assets | `LICENSE`; `README.md` |
| N07 | Documentation distinguishes planned / implemented / tested / experimentally validated | `README.md`; `docs/TRACEABILITY_MATRIX.md`; milestone descriptions |

## Acceptance criteria (per milestone)

Mỗi yêu cầu ở trên chỉ đóng được khi có lệnh kiểm chứng chạy được và bằng chứng gắn với commit; xem cột
Verification trong `docs/TRACEABILITY_MATRIX.md`.

- M0: Structure + docs + CI pass.
- M1: Dataset validated; leakage audit documented; EDA produced.
- M2: Preprocessing pipeline reproducible; Random Forest trained; metrics recorded.
- M3: Isolation Forest documented / implemented if feasible; comparison protocol written; error analysis done.
  Không có kết quả Isolation Forest vẫn không chặn chấp nhận core.
- M4: Inference pipeline + demo run; integration test passes.
- M5: Report outline + presentation outline complete; final verification passes.

Updated: 2026-10-17
