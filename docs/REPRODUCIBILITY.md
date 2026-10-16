# Reproducibility

## Environment

- Python 3.11+ (recommended 3.12)
- Core: pandas, NumPy, scikit-learn, matplotlib, seaborn, pytest, jupyter
- Versions pinned in `pyproject.toml` and `requirements.txt`
- Installation: `pip install -e .` or `pip install -r requirements.txt`

## Random seeds

- Default seed: 42 (configurable via `config.py` / `.env`)
- Set for: NumPy (`np.random.seed`), Python (`random.seed`), scikit-learn (`random_state`)

## Running experiments

- `make install` — install dependencies
- `make check-data` — run validation script on `data/raw/`
- `make run-baseline` — train Random Forest
- `make run-evaluate` — evaluate saved model
- `make run-inference` — inference on new input
- `make test` — run unit and integration tests

## Config and artifacts

- `config.py` defines paths, seeds, hyperparameters.
- Each experiment run should save: config snapshot, model file (`artifacts/model_*.joblib`), metrics CSV, confusion matrix image.
- Do not overwrite artifacts silently; use versioned filenames.

## Dataset version recording

- Once UNSW-NB15 is downloaded, record version, file names, checksum (if available), and download date in `REPRODUCIBILITY.md`.
- Until verified, state is: planned, not verified.

Updated: 2026-10-16
