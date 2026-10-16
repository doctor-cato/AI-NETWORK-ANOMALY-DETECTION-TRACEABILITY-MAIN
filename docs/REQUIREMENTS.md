# Requirements — Functional and Non-Functional

## Functional requirements (must work)

| ID | Requirement | Verification |
|---|---|---|
| F01 | Load UNSW-NB15 data (after download) and verify schema | `scripts/validate_data.py` passes on fixture; instructions exist |
| F02 | Inspect labels, class distribution, duplicates, missing values | Notebook / script produces summary |
| F03 | Preprocess without leakage: split first, then fit scaler/encoder | Pipeline object; test set untouched during fit |
| F04 | Build Random Forest classifier with documented hyperparameters | `src/network_anomaly/models/random_forest.py` exists; train script runs |
| F05 | Evaluate with Precision, Recall, F1, Macro-F1, confusion matrix, FPR | Evaluation module outputs metrics |
| F06 | Document Isolation Forest evaluation protocol separately (unsupervised score → threshold) | `docs/METHODOLOGY.md`; evaluation notes |
| F07 | Provide inference pipeline for new input data | `src/network_anomaly/inference/` module; demo script |
| F08 | Cung cấp hướng dẫn chạy thực nghiệm có thể tái lập | `REPRODUCIBILITY.md`; `python scripts/run_experiments.py` (hoặc tương đương) |

## Non-functional requirements

| ID | Requirement | Verification |
|---|---|---|
| N01 | Code organized under `src/network_anomaly/`; logic callable from notebooks/scripts | Directory structure verified |
| N02 | Python 3.11+; giới hạn dependency tối thiểu, lưu phiên bản môi trường thực tế khi tái lập | `pyproject.toml`; `requirements.txt`; `docs/REPRODUCIBILITY.md` |
| N03 | Không dùng đường dẫn tuyệt đối cố định; dùng đường dẫn tương đối hoặc config | `config.py`; tài liệu cấu hình môi trường |
| N04 | No secrets, API keys, or personal data in repo | `.gitignore`; kiểm tra diff và file trước commit |
| N05 | CI checks basic import and light tests without dataset | `.github/workflows/ci.yml` |
| N06 | Repository dùng Apache-2.0; xác minh nghĩa vụ riêng của dependency/assets | `LICENSE`; `README.md` |
| N07 | Documentation distinguishes planned / implemented / verified | `README.md`; milestone descriptions |

## Acceptance criteria (per milestone)

- M0: Structure + docs + CI pass.
- M1: Dataset validated; leakage audit documented; EDA produced.
- M2: Preprocessing pipeline reproducible; Random Forest trained; metrics recorded.
- M3: Isolation Forest documented / implemented if feasible; comparison protocol written; error analysis done.
- M4: Inference pipeline + demo run; integration test passes.
- M5: Report outline + presentation outline complete; final verification passes.

Updated: 2026-10-16
