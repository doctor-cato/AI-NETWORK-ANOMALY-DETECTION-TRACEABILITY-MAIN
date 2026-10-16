# Reproducibility

## Environment

- Python 3.11+ (recommended 3.12)
- Core: pandas, NumPy, scikit-learn, matplotlib, seaborn, pytest, jupyter
- Versions pinned in `pyproject.toml` and `requirements.txt`
- Installation: `pip install -e .` or `pip install -r requirements.txt`

## Random seeds

- Default seed: 42 (configurable via `config.py`; không có `.env.example` — cấu hình qua biến môi trường hoặc `pyproject.toml`)
- Set for: NumPy (`np.random.seed`), Python (`random.seed`), scikit-learn (`random_state`)

## Running experiments

- `pip install -e .` — cài đặt phụ thuộc từ `pyproject.toml`
- `python -m pytest` — chạy kiểm thử đơn vị và tích hợp
- Kiểm tra dữ liệu: `python scripts/check_data.py` (hoặc `python -c "import checks"`) khi có script
- Huấn luyện baseline (tương lai): `python scripts/train_rf.py` (chưa triển khai)
- Đánh giá (tương lai): `python scripts/evaluate.py` (chưa triển khai)
- Suy luận (tương lai): `python scripts/inference.py --input data/new.csv` (chưa triển khai)

## Config and artifacts

- `config.py` defines paths, seeds, hyperparameters.
- Each experiment run should save: config snapshot, model file (`artifacts/model_*.joblib`), metrics CSV, confusion matrix image.
- Do not overwrite artifacts silently; use versioned filenames.

## Dataset version recording

- Once UNSW-NB15 is downloaded, record version, file names, checksum (if available), and download date in `REPRODUCIBILITY.md`.
- Until verified, state is: planned, not verified.

Updated: 2026-10-16
