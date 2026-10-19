# Phát hiện kết nối mạng bất thường bằng học máy và phân tích hành vi lưu lượng

**Ngôn ngữ tài liệu:** Tiếng Việt | **Tên dự án:** Xây dựng hệ thống AI phát hiện kết nối mạng bất thường bằng học máy và phân tích hành vi lưu lượng mạng

**Trạng thái:** C0 của roadmap Phương án B đang triển khai trên nền M0 lịch sử. C1–C11
chưa được coi là hoàn thành nếu thiếu code/test/evidence. PR #22 chứa workstream #4/#5
(tải UNSW-NB15 tái lập, manifest provenance, validation) với bằng chứng local riêng, vẫn
mở và không được suy thành trạng thái `main` cho đến khi được review/merge hợp lệ. Xem
`docs/ROADMAP_FULL_SYSTEM.md`, `docs/IMPLEMENTATION_CHECKPOINTS.md` và
`docs/TRACEABILITY_MATRIX.md`.

- **License:** Apache License 2.0 (not MIT)
- **Repository:** https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN
- **Branch:** `main`
- **Project type:** Course project — roadmap prototype C0–C11

---

## Project title

- **English:** AI-Based Network Anomaly Detection Using Machine Learning and Network Traffic Behavior Analysis
- **Vietnamese:** Xây dựng hệ thống AI phát hiện kết nối mạng bất thường bằng học máy và phân tích hành vi lưu lượng mạng

## Tóm tắt ngắn

Xây dựng hệ thống lab tái lập được cho UNSW-NB15 và network/API/session events: phát hiện
và phân loại bất thường, Behavioral Vector, Risk/Trace Engine, AES-GCM/key rotation,
FastAPI/SQLite và Streamlit. Hệ thống không tuyên bố zero-day, attacker identity hoặc
production readiness khi chưa có bằng chứng.

---

## Phát biểu vấn đề và động lực

Lưu lượng mạng chứa cả mẫu kết nối bình thường và bất thường. Việc phát hiện bất thường hỗ trợ nhận thức bảo mật, nhưng đánh giá phải minh bạch, tái lập và giới hạn ở bằng chứng đã xác minh. Bài tập này minh họa một pipeline ML có cấu trúc cho dự án 5–6 tuần.

## Mục tiêu (bắt buộc — xem `docs/PROJECT_CHARTER.md`)

Phạm vi bắt buộc được chia thành C0–C11: governance; Data/EDA; preprocessing; RF và
XGBoost; Isolation Forest và Autoencoder; Behavioral Vector; Risk/Trace; AES-GCM và
key lifecycle; adaptive dry-run response; FastAPI/SQLite/Streamlit; 7 experiments; và
bàn giao report/slides/demo cho 5 vai trò.

Ma trận yêu cầu → issue → deliverable → acceptance criteria → cách kiểm chứng nằm ở
`docs/TRACEABILITY_MATRIX.md`.

## Scope and non-goals

### Trong phạm vi
- Toàn bộ module và checkpoint trong `docs/ROADMAP_FULL_SYSTEM.md`, với security response
  chỉ ở chế độ lab/dry-run.

### Rõ ràng ngoài phạm vi
- LSTM, Transformer, GNN và post-quantum cryptography.
- Tuyên bố phát hiện zero-day không có chứng cứ thực nghiệm.
- Truy vết danh tính thật của attacker.
- Response trên hệ thống thật, phản công, production deployment hoặc xử lý phân tán.

---

## Bộ dữ liệu

- **Tên:** UNSW-NB15 (University of New South Wales — Network Based Data Set 15)
- **Tham chiếu nguồn:** [trang UNSW-NB15 chính thức](https://research.unsw.edu.au/projects/unsw-nb15-dataset); xem `docs/DATASET.md`
- **Trạng thái:** Raw CSV không nằm trong Git. PR #22 có manifest/validator và bằng chứng
  local riêng; `main` chưa chứa workstream đó cho đến khi được review/merge hợp lệ.
- **Hướng dẫn tải:** `python scripts/fetch_unsw_nb15.py`; xem `docs/DATASET.md`
- **Checksum / phiên bản:** SHA-256 trên PR #22 là project-computed local hash, không phải
  checksum do UNSW công bố; manifest ở `data/UNSW_NB15_MANIFEST.json`, báo cáo thật ở
  `reports/data_quality/unsw_nb15_validation.json`
- **Điều kiện sử dụng:** Học thuật / nghiên cứu; không phân phối lại dữ liệu gốc mà không xác nhận điều khoản
- **Dữ liệu fixture:** `tests/` dùng fixture tổng hợp rõ ràng là test-only, không phải UNSW-NB15

---

## Phương pháp (tổng quan — xem `docs/METHODOLOGY.md`)

1. Đọc và kiểm tra dữ liệu.
2. EDA + kiểm tra rò rỉ dữ liệu (cột định danh, bản ghi trùng, giá trị thiếu, phân bố lớp).
3. Chia train/val/test (trước mọi fitting).
4. Pipeline tiền xử lý (fit trên train; lưu artifact).
5. Random Forest (giám sát) — huấn luyện, dự đoán, tính Precision/Recall/F1/Macro-F1/confusion matrix/FPR.
6. Isolation Forest (không giám sát) — sản xuất điểm bất thường; chọn ngưỡng trên validation; đánh giá với protocol riêng.
7. Lưu ý: Isolation Forest có setup đánh giá khác với RF giám sát. Các metric chỉ so sánh được khi cả hai protocol được mô tả rõ ràng.

---

## System architecture (see `docs/ARCHITECTURE.md`)

Data flow: Raw → Validate → EDA/Leakage Audit → Split → Preprocessing Pipeline → Model (RF / IF) → Evaluation → Error Analysis → Inference → Demo/Report.

Modules under `src/network_anomaly/`: config, data, preprocessing, features, models (random_forest, isolation_forest), evaluation, inference, visualization.

---

## Models (planned / partially implemented)

- **Random Forest** (`src/network_anomaly/models/random_forest.py`) — supervised, **baseline bắt buộc**; hiện chỉ có constructor `build_model()`, chưa fit/predict (M2, #10).
- **Isolation Forest** (`src/network_anomaly/models/isolation_forest.py`) — bắt buộc ở C4;
  hiện chỉ có constructor `build_model()`, chưa fit/threshold/evaluate (#11).

Constructor test không chứng minh huấn luyện hay đánh giá đã chạy. Xem `docs/ARCHITECTURE.md` cho trạng thái từng mô-đun.

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
├── pyproject.toml
├── requirements.txt
├── .gitignore
├── docs/
│   ├── PROJECT_CHARTER.md
│   ├── PROBLEM_STATEMENT.md
│   ├── REQUIREMENTS.md
│   ├── TRACEABILITY_MATRIX.md
│   ├── ISSUE_SUPPLEMENTS.md
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
├── reports/figures/ + artifacts/ (chỉ giữ .gitkeep; nội dung không commit)
├── data/raw/, interim/, processed/ (chỉ giữ .gitkeep; dataset không commit)
├── AGENTS.md + .agents/ (workflow cho AI agent: PLAN → IMPLEMENT → VERIFY → REVIEW)
└── .github/ (issue templates, PR template, CI)
```

---

## Environment setup

- Python 3.11+ (CI kiểm tra 3.11 và 3.12 trên Ubuntu và Windows; xem `.github/workflows/ci.yml`)
- Dependencies dùng giới hạn phiên bản tối thiểu (`>=`) trong `pyproject.toml` và `requirements.txt`; chưa có lockfile. Ghi phiên bản thực tế bằng `python -m pip freeze` khi tái lập.
- Cài: `python -m pip install -e .` (hoặc `python -m venv .venv` rồi `python -m pip install -e .`)
- Check environment: `python scripts/check_environment.py` (kiểm tra phiên bản Python, dependency và chính package `network_anomaly`)
- Check syntax: `python -m compileall -q src scripts tests`; kiểm tra import riêng bằng `python -c "import network_anomaly"`.

---

## Cài đặt

```bash
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Trên macOS/Linux, thay dòng kích hoạt bằng `source .venv/bin/activate`.

---

## Cách chuẩn bị dữ liệu

```bash
# Tải mirror revision-pinned sau khi đọc giới hạn provenance trong docs/DATASET.md
python scripts/fetch_unsw_nb15.py
python scripts/dataset_manifest.py verify
python scripts/validate_data.py --manifest data/UNSW_NB15_MANIFEST.json --report reports/data_quality/unsw_nb15_validation.json
```

Dataset không được commit; xem `docs/DATASET.md` để biết chi tiết nguồn và điều kiện sử dụng.

---

## Cách chạy kiểm tra

```bash
python scripts/check_environment.py
python scripts/validate_data.py        # SKIPPED (exit 0) nếu chưa tải dataset; không phải validation PASS
python -m pytest tests -q              # unit + integration, không cần dataset
python scripts/run_experiments.py --step check-data   # gọi validate_data
```

---

## Cách huấn luyện / đánh giá (đã dự kiến — cần dataset)

```bash
# Kiểm tra constructor (không phải huấn luyện):
python -c "from network_anomaly.models.random_forest import build_model; print('RF OK')"
# Entrypoint huấn luyện/đánh giá/suy luận chưa tồn tại ở M0 — script báo rõ và trả exit khác 0:
python scripts/run_experiments.py --step baseline    # exit 3 = NOT IMPLEMENTED (M2, #10)
python scripts/run_experiments.py --step evaluate   # exit 3 = NOT IMPLEMENTED (M3, #12)
python scripts/run_experiments.py --step inference  # exit 3 = NOT IMPLEMENTED (M4, #15)
```

Không có lệnh inference dạng `python src/network_anomaly/inference/pipeline.py <input>` ở M0; entrypoint
CSV cho inference thuộc issue #15. Chạy file đó hiện không in gì và thoát với code 0 — đừng dùng như bằng chứng
đã dự đoán.

Thực thi thực tế phụ thuộc vào tải dataset và theo dõi thực nghiệm (xem `docs/REPRODUCIBILITY.md`).

---

## Tests

- Unit config/model: `tests/unit/test_basic.py`
- Unit validator/manifest (fixture tổng hợp + exit code): `tests/unit/test_validate_data.py`
- Unit exit-code contract của experiment runner: `tests/unit/test_run_experiments.py`
- Integration (smoke): `tests/integration/test_pipeline.py`
- CI chạy toàn bộ `tests/` trên Ubuntu và Windows, Python 3.11 và 3.12, không cần dataset (`.github/workflows/ci.yml`)
- Fixture data in tests clearly marked synthetic, not UNSW-NB15

---

## Expected outputs (planned / verified status marked)

- [Planned] EDA notebook / figures (class distribution, missing values, duplicates)
- [Planned] Preprocessing pipeline artifacts (fit objects, encoded data)
- [Implemented (constructor only) / Not Verified] Random Forest model code; training not verified (depends on dataset)
- [Implemented (constructor only) / Optional] Isolation Forest module; evaluation protocol documented separately
- [Implemented (no FPR) / Not Verified] `evaluation/metrics.py` returns Precision, Recall, F1, Macro-F1, confusion matrix; FPR thuộc #12
- [Planned] Metrics files on real data (Precision, Recall, F1, Macro-F1, confusion matrix, FPR)
- [Planned] Error analysis write-up (false positives / false negatives)
- [Planned] Inference script and demo output
- [Implemented] Documentation (all planned docs exist; some content planned until experiments complete)
- [Implemented at C0] GitHub giữ M0–M5 và bổ sung M6/M7; C1–C11 vẫn cần evidence riêng

---

## Khả năng tái lập (xem `docs/REPRODUCIBILITY.md`)

- Random seed: 42 (configurable)
- Dependencies hiện chưa khóa phiên bản; lưu phiên bản môi trường thực tế cho từng lần chạy
- Split before fit; pipeline saved
- Each experiment should save: seed, config, metrics, confusion matrix, version info
- Dataset version and checksum are recorded in `data/UNSW_NB15_MANIFEST.json`

---

## Hạn chế và tuyên bố trung thực

- Provenance đạt mức đối chiếu nhiều mirror; UNSW không công bố SHA-256 và endpoint chính thức yêu cầu đăng nhập khi kiểm tra.
- Kết quả Random Forest phụ thuộc vào chất lượng dữ liệu thực tế; metric không bị giả mạo.
- Đánh giá Isolation Forest dùng protocol khác đánh giá giám sát; so sánh trực tiếp cần giải thích rõ.
- Không tuyên bố phát hiện zero-day; không tuyên bố triển khai production; không tuyên bố truy vết danh tính kẻ tấn công.
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

Năm vai trò được định nghĩa; tên để trống cho đến khi nhóm xác nhận.

---

## Roadmap and milestones (see `docs/DEVELOPMENT_PLAN.md`)

- **M0 — Repository Foundation and Project Design:** Structure, docs, CI, environment, labels.
- **M1 — Dataset Acquisition and Exploratory Data Analysis:** Download, validation, EDA, leakage audit.
- **M2 — Preprocessing and Baseline Models:** Pipeline, Random Forest, documented results.
- **M3 — Anomaly Detection and Model Evaluation:** Isolation Forest (if feasible), comparison protocol, error analysis.
- **M4 — Inference, Demo and Integration:** Inference pipeline, demo, tests.
- **M5 — Final Report, Presentation and Release:** Report outline, presentation outline, final verification.
- **M6 — Backend, Dashboard & Integration:** Behavioral/Risk/Trace/Security services, API, persistence và dashboard.
- **M7 — Experiments, Documentation & Delivery:** bảy experiments, report, slides, demo và handoff.

Milestone links and deadlines: planned based on 5–6 week schedule; exact dates depend on course calendar.

---

## GitHub Issues and Milestones

Issues #23–#32 bổ sung governance, XGBoost, Autoencoder, Behavioral Vector, Risk/Trace,
AES-GCM/key lifecycle, adaptive response, FastAPI và bảy experiments. Issue #11, #16 và
#18–#20 đã được cập nhật dependency/milestone theo Phương án B.

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

Thông tin trích dẫn hiện nằm trong khối BibTeX ở trên.

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
- Khi đóng góp: mô tả phạm vi, lệnh kiểm chứng và giới hạn trong PR theo template hiện có.
