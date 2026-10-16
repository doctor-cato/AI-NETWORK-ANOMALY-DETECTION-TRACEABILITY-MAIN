# AI-Based Network Anomaly Detection Using Machine Learning and Network Traffic Behavior Analysis

**Language:** English (primary documentation) | **Vietnamese title:** Xây dựng hệ thống AI phát hiện kết nối mạng bất thường bằng học máy và phân tích hành vi lưu lượng mạng

**Status:** Repository initialized; core structure, documentation, and CI established. Dataset not yet downloaded; experiments planned for M1–M3; results not fabricated.

- **License:** Apache License 2.0 (not MIT)
- **Repository:** https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN
- **Branch:** `main`
- **Project type:** Course assignment (AI / Machine Learning) — 5–6 weeks

---

## Project title

- **English:** AI-Based Network Anomaly Detection Using Machine Learning and Network Traffic Behavior Analysis
- **Vietnamese:** Xây dựng hệ thống AI phát hiện kết nối mạng bất thường bằng học máy và phân tích hành vi lưu lượng mạng

## Short description

Build a reproducible machine-learning pipeline that uses UNSW-NB15 network-traffic data to detect anomalous connections. The project provides a supervised Random Forest baseline, documents an Isolation Forest unsupervised evaluation protocol (separate from supervised evaluation), records metrics transparently, and includes inference and demo components — without claiming unverified zero-day detection, production deployment, or fabricated benchmark results.

---

## Problem statement and motivation

Network traffic contains both normal and abnormal connection patterns. Detecting anomalies supports security awareness, but evaluation must be transparent, reproducible, and limited to verified evidence. This assignment demonstrates a structured ML pipeline for a 5–6 week course project.

## Objectives (mandatory — see `docs/PROJECT_CHARTER.md`)

1. Analyze anomaly detection in network traffic and define the target.
2. Use UNSW-NB15 as primary dataset; verify schema and labels.
3. Check data quality; handle missing values; avoid target leakage.
4. Design reproducible train/val/test split.
5. Build Random Forest baseline with documented pipeline.
6. Build Isolation Forest as unsupervised method if feasible; document separate evaluation protocol.
7. Compare using Precision, Recall, F1, Macro-F1, confusion matrix, FPR — with protocols clearly described per model.
8. Analyze false positives / false negatives; document limitations.
9. Provide inference pipeline and minimal demo.
10. Deliver reproducible scripts/notebooks, architecture, documentation, and presentation outline.

## Scope and non-goals

### In scope
- Problem analysis; dataset sourcing; EDA; preprocessing; split; RF; IF (if time); evaluation; error analysis; inference; documentation.

### Explicitly out of scope (documented in `docs/FUTURE_WORK.md`; do NOT implement now)
- Autoencoder, LSTM, Transformer, GNN.
- Zero-day detection claims without experimental proof.
- Device identity / attacker tracing from behavior vectors.
- Vector behavior encoding / adaptive key rotation.
- Automatic blocking / isolation / counter-attack.
- Production deployment / distributed processing.

---

## Dataset

- **Name:** UNSW-NB15 (University of New South Wales — Network Based Data Set 15)
- **Source reference:** Official UNSW dataset portal (link to be confirmed when downloading; see `docs/DATASET.md`)
- **Status:** Not downloaded / not committed (planned)
- **Download instructions:** See `docs/DATASET.md`; place files in `data/raw/`; run `python scripts/validate_data.py`
- **Checksum / version:** Not yet verified; to be recorded after download in `docs/REPRODUCIBILITY.md`
- **Usage conditions:** For academic/research use; do not redistribute original data without confirming terms
- **Fixture data:** `tests/` uses synthetic fixtures clearly marked as test-only, not UNSW-NB15

---

## Methodology (high-level — see `docs/METHODOLOGY.md`)

1. Load and verify dataset.
2. EDA + leakage audit (identity columns, duplicates, missing values, class distribution).
3. Train/val/test split (before any fit).
4. Preprocessing pipeline (fit on train only; save artifacts).
5. Random Forest (supervised) — train, predict, compute Precision/Recall/F1/Macro-F1/confusion matrix/FPR.
6. Isolation Forest (unsupervised) — score production; threshold selection on validation set; then evaluate on test with documented protocol.
7. Note: Isolation Forest uses a different evaluation setup from supervised RF. Metrics are comparable numerically only after both protocols are clearly described.

---

## System architecture (see `docs/ARCHITECTURE.md`)

Data flow: Raw → Validate → EDA/Leakage Audit → Split → Preprocessing Pipeline → Model (RF / IF) → Evaluation → Error Analysis → Inference → Demo/Report.

Modules under `src/network_anomaly/`: config, data, preprocessing, features, models (random_forest, isolation_forest), evaluation, inference, visualization.

---

## Models (planned / partially implemented)

- **Random Forest** (`src/network_anomaly/models/random_forest.py`) — supervised; implemented as module; training requires dataset.
- **Isolation Forest** (`src/network_anomaly/models/isolation_forest.py`) — unsupervised; module implemented; evaluation protocol documented separately.

---

## Metrics and evaluation protocol (see `docs/EVALUATION.md`)

- Precision, Recall, F1-score (binary / per-class), Macro-F1, confusion matrix (labeled axes), False Positive Rate.
- Confusion matrix interpreted clearly (normal / anomaly axes).
- Isolation Forest evaluation uses score-to-label conversion with documented threshold selection.
- No fabricated accuracy or F1 claims.

---

## Repository structure (see full tree in repo; key directories)

```
.
├── README.md
├── LICENSE (Apache 2.0 — full text; not MIT)
├── CITATION.cff
├── pyproject.toml
├── requirements.txt
├── Makefile
├── .gitignore
├── docs/
│   ├── PROJECT_CHARTER.md
│   ├── PROBLEM_STATEMENT.md
│   ├── REQUIREMENTS.md
│   ├── DATASET.md
│   ├── METHODOLOGY.md
│   ├── ARCHITECTURE.md
│   ├── EXPERIMENT_PLAN.md
│   ├── EVALUATION.md
│   ├── REPRODUCIBILITY.md
│   ├── ETHICS_AND_PRIVACY.md
│   ├── REPORT_OUTLINE.md
│   ├── PRESENTATION_OUTLINE.md
│   ├── TEAM_TASKS.md
│   ├── DEVELOPMENT_PLAN.md
│   └── FUTURE_WORK.md
├── src/network_anomaly/
│   ├── config.py
│   ├── data/, preprocessing/, features/, models/, evaluation/, inference/, visualization/
├── notebooks/README.md (planned notebooks listed)
├── scripts/
│   ├── check_environment.py
│   ├── validate_data.py
│   └── run_experiments.py
├── tests/unit/ + integration/
├── reports/figures/ + artifacts/ (not committed when large)
├── data/raw/, interim/, processed/ (dataset not committed)
└── .github/ (issue templates, PR template, CI, dependabot)
```

---

## Environment setup

- Python 3.11+ (recommended 3.12)
- Dependencies pinned in `pyproject.toml` and `requirements.txt`
- Install: `make install` or `pip install -e .`
- Check environment: `python scripts/check_environment.py`
- Check syntax / imports: `python -m py_compile src/network_anomaly/config.py ...`

---

## Installation

```bash
# Clone or use existing repo
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
```

---

## How to prepare data

```bash
# Download UNSW-NB15 from official source (see docs/DATASET.md)
# Place CSV(s) in data/raw/
python scripts/validate_data.py
```

Dataset not committed; see `docs/DATASET.md` for source details and usage conditions.

---

## How to run checks

```bash
make check-env
make check-data      # planned; expects dataset download
python -m pytest tests/unit/test_basic.py -q
```

---

## How to train / evaluate (planned — requires dataset)

```bash
# Planned commands (not fully verified until dataset available):
make run-baseline    # Random Forest
make run-evaluate    # Metrics + confusion matrix
make run-inference   # New data prediction
```

Actual execution depends on dataset download and experiment tracking (see `docs/REPRODUCIBILITY.md`).

---

## Tests

- Unit: `tests/unit/test_basic.py`
- Integration: `tests/integration/test_pipeline.py`
- CI runs light tests without dataset (`.github/workflows/ci.yml`)
- Fixture data in tests clearly marked synthetic, not UNSW-NB15

---

## Expected outputs (planned / verified status marked)

- [Planned] EDA notebook / figures (class distribution, missing values, duplicates)
- [Planned] Preprocessing pipeline artifacts (fit objects, encoded data)
- [Implemented / Not Verified] Random Forest model code; training not verified (depends on dataset)
- [Implemented / Not Verified] Isolation Forest module; evaluation protocol documented separately
- [Planned] Metrics files (Precision, Recall, F1, Macro-F1, confusion matrix, FPR)
- [Planned] Error analysis write-up (false positives / false negatives)
- [Planned] Inference script and demo output
- [Implemented] Documentation (all planned docs exist; some content planned until experiments complete)
- [Implemented] Milestones M0–M5 (created via GitHub CLI / API where possible)

---

## Reproducibility (see `docs/REPRODUCIBILITY.md`)

- Random seed: 42 (configurable)
- Environment versions pinned
- Split before fit; pipeline saved
- Each experiment should save: seed, config, metrics, confusion matrix, version info
- Dataset version and checksum to be recorded after download

---

## Limitations and honest statements

- Dataset download and full verification not yet completed (planned, not verified).
- Random Forest results depend on actual data quality; metrics not fabricated.
- Isolation Forest evaluation uses a different protocol than supervised evaluation; direct comparison requires explicit explanation.
- No claim of zero-day detection; no claim of production deployment; no claim of attacker identification.
- No MIT license used (Apache 2.0 applied).
- This is an educational project; results should not be treated as production security guarantees.

---

## Ethical and safe-use statement (see `docs/ETHICS_AND_PRIVACY.md`)

- UNSW-NB15 intended for academic/research use; users must confirm terms.
- No personal/network-identifying data committed.
- No inference about specific individuals or devices claimed.
- Do not use this system as an unverified security control.

---

## Team / task allocation (see `docs/TEAM_TASKS.md`)

Roles defined for up to 3 members; names to be filled when team forms. Key roles: Data/EDA, ML/Model, Docs/Integration.

---

## Roadmap and milestones (see `docs/DEVELOPMENT_PLAN.md`)

- **M0 — Repository Foundation and Project Design:** Structure, docs, CI, environment, labels.
- **M1 — Dataset Acquisition and Exploratory Data Analysis:** Download, validation, EDA, leakage audit.
- **M2 — Preprocessing and Baseline Models:** Pipeline, Random Forest, documented results.
- **M3 — Anomaly Detection and Model Evaluation:** Isolation Forest (if feasible), comparison protocol, error analysis.
- **M4 — Inference, Demo and Integration:** Inference pipeline, demo, tests.
- **M5 — Final Report, Presentation and Release:** Report outline, presentation outline, final verification.

Milestone links and deadlines: planned based on 5–6 week schedule; exact dates depend on course calendar.

---

## GitHub Issues and Milestones

Issues are planned / created for key tasks; see `.github/ISSUE_TEMPLATE/` for formats. Milestones M0–M5 are defined. Issues include dataset validation, leakage audit, baseline, evaluation, inference, documentation, report, presentation, and verification — with labels and milestone links.

---

## Citation

```bibtex
@software{network_anomaly_2026,
  author = {{Project Team}},
  title = {AI-Based Network Anomaly Detection Using ML and Network Traffic Behavior Analysis},
  url = {https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN},
  version = {0.1.0},
  date = {2026-10-16},
  license = {Apache-2.0}
}
```

Also see `CITATION.cff`.

---

## License

Apache License 2.0 — full text in `LICENSE`. Copyright placeholder included; replace with actual owner when known. Dataset UNSW-NB15 retains its own license/conditions; this repository does not change dataset licensing.

---

## Acknowledgements

- UNSW for UNSW-NB15 dataset (academic use).
- scikit-learn, pandas, NumPy, matplotlib, pytest, Jupyter communities.
- Course assignment requirements.

---

## Contact / contribution

- Issues: https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/issues
- PR template: `.github/pull_request_template.md`
- Contributing guidelines: `CONTRIBUTING.md`
