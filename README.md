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

## Tóm tắt ngắn

Xây dựng một pipeline học máy tái lập được sử dụng dữ liệu lưu lượng mạng UNSW-NB15 để phát hiện các kết nối bất thường. Dự án cung cấp baseline Random Forest giám sát, ghi rõ protocol đánh giá riêng cho Isolation Forest không giám sát (nếu khả thi), ghi metric một cách minh bạch, và bao gồm thành phần suy luận và demo — không tuyên bố phát hiện zero-day chưa kiểm chứng, triển khai production, hoặc kết quả benchmark giả mạo.

---

## Phát biểu vấn đề và động lực

Lưu lượng mạng chứa cả mẫu kết nối bình thường và bất thường. Việc phát hiện bất thường hỗ trợ nhận thức bảo mật, nhưng đánh giá phải minh bạch, tái lập và giới hạn ở bằng chứng đã xác minh. Bài tập này minh họa một pipeline ML có cấu trúc cho dự án 5–6 tuần.

## Mục tiêu (bắt buộc — xem `docs/PROJECT_CHARTER.md`)

1. Phân tích phát hiện bất thường trong lưu lượng mạng và xác định mục tiêu.
2. Sử dụng UNSW-NB15 làm bộ dữ liệu chính; kiểm tra schema và nhãn.
3. Kiểm tra chất lượng dữ liệu; xử lý giá trị thiếu; tránh rò rỉ dữ liệu (target leakage).
4. Thiết kế chia train/val/test tái lập.
5. Xây dựng baseline Random Forest với pipeline đã ghi.
6. Xây dựng Isolation Forest theo phương pháp không giám sát nếu khả thi; ghi protocol đánh giá riêng.
7. So sánh bằng Precision, Recall, F1, Macro-F1, confusion matrix, FPR — với protocol rõ ràng cho từng mô hình.
8. Phân tích dương tính giả / âm tính giả; ghi rõ hạn chế.
9. Cung cấp pipeline suy luận và demo tối thiểu.
10. Đưa ra script/notebook tái lập, kiến trúc, tài liệu và dàn ý trình bày.

## Scope and non-goals

### Trong phạm vi
- Phân tích vấn đề; nguồn dữ liệu; EDA; tiền xử lý; chia dữ liệu; RF; IF (nếu có thời gian); đánh giá; phân tích lỗi; suy luận; tài liệu.

### Rõ ràng ngoài phạm vi (đã ghi trong `docs/FUTURE_WORK.md`; KHÔNG triển khai ngay)
- Autoencoder, LSTM, Transformer, GNN.
- Tuyên bố phát hiện zero-day không có chứng cứ thực nghiệm.
- Truy vết danh tính thiết bị / hành vi từ vector đặc trưng.
- Mã hóa hành vi vector / xoay khóa thích ứng.
- Chặn tự động / cô lập / phản công tự động.
- Triển khai production / xử lý phân tán.

---

## Bộ dữ liệu

- **Tên:** UNSW-NB15 (University of New South Wales — Network Based Data Set 15)
- **Tham chiếu nguồn:** Cổng dữ liệu chính thức UNSW (liên kết sẽ xác nhận khi tải; xem `docs/DATASET.md`)
- **Trạng thái:** Chưa tải / chưa commit (đã dự kiến)
- **Hướng dẫn tải:** Xem `docs/DATASET.md`; đặt file vào `data/raw/`; chạy `python scripts/validate_data.py`
- **Checksum / phiên bản:** Chưa xác minh; sẽ ghi sau khi tải trong `docs/REPRODUCIBILITY.md`
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
- Cài: `pip install -e .` (hoặc `python -m venv .venv` rồi `pip install -e .`)
- Check environment: `python scripts/check_environment.py`
- Check syntax / imports: `python -m py_compile src/network_anomaly/config.py ...`

---

## Cài đặt

```bash
# Clone hoặc dùng repo hiện có
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
```

---

## Cách chuẩn bị dữ liệu

```bash
# Tải UNSW-NB15 từ nguồn chính thức (xem docs/DATASET.md)
# Đặt CSV vào data/raw/
python scripts/validate_data.py
```

Dataset không được commit; xem `docs/DATASET.md` để biết chi tiết nguồn và điều kiện sử dụng.

---

## Cách chạy kiểm tra

```bash
python scripts/check_environment.py
python scripts/validate_data.py        # dự kiến; cần tải dataset trước
python -m pytest tests/unit/test_basic.py -q
```

---

## Cách huấn luyện / đánh giá (đã dự kiến — cần dataset)

```bash
# Lệnh dự kiến (chưa kiểm chứng đầy đủ cho đến khi có dataset):
python -c "from network_anomaly.models.random_forest import build_model; print('RF OK')"
python -m pytest tests/integration/test_pipeline.py -q
# Sau khi huấn luyện: python src/network_anomaly/inference/pipeline.py <input>
```

Thực thi thực tế phụ thuộc vào tải dataset và theo dõi thực nghiệm (xem `docs/REPRODUCIBILITY.md`).

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

## Khả năng tái lập (xem `docs/REPRODUCIBILITY.md`)

- Random seed: 42 (configurable)
- Environment versions pinned
- Split before fit; pipeline saved
- Each experiment should save: seed, config, metrics, confusion matrix, version info
- Dataset version and checksum to be recorded after download

---

## Hạn chế và tuyên bố trung thực

- Tải dataset và xác minh đầy đủ chưa hoàn thành (đã dự kiến, chưa xác minh).
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
