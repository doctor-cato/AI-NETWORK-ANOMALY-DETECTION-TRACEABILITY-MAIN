# Project Charter — AI-Based Network Anomaly Detection

## Project identification

- **Vi ngữ (Vietnamese):** Xây dựng hệ thống AI phát hiện kết nối mạng bất thường bằng học máy và phân tích hành vi lưu lượng mạng
- **English title:** AI-Based Network Anomaly Detection Using Machine Learning and Network Traffic Behavior Analysis
- **Repository:** https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN
- **License:** Apache License 2.0 (NOT MIT)
- **Runtime target:** Python 3.11+ (CI kiểm tra 3.11 và 3.12); scikit-learn 1.5+; pandas 2.2+; NumPy 1.26+ (xem `requirements.txt`)

## Objectives

Mục tiêu 1–5 và 7–10 là **bắt buộc** (core). Mục tiêu 6 (Isolation Forest) là **tùy chọn**: thiếu kết quả IF
không chặn chấp nhận core, và chỉ thực hiện sau khi baseline Random Forest đã có kết quả thật.

1. Analyze the anomaly-detection problem in network traffic and define the detection target. (bắt buộc)
2. Use UNSW-NB15 as the primary dataset; verify schema, labels, and class distribution. (bắt buộc)
3. Check data quality, handle missing values, encode features appropriately, and avoid target leakage. (bắt buộc)
4. Design a reproducible train/validation/test split without data leakage. (bắt buộc)
5. Build a Random Forest baseline with documented pipeline and configuration. (bắt buộc — baseline chính)
6. Build Isolation Forest as an unsupervised anomaly-detection method if feasible with data and time. (TÙY CHỌN)
7. Compare models using Precision, Recall, F1-score, Macro-F1, confusion matrix, and False Positive Rate, describing the evaluation protocol clearly for each model because their label setups and thresholds differ. (bắt buộc cho RF; IF nếu có)
8. Analyze false positives/negatives, data limitations, and model constraints. (bắt buộc)
9. Provide an inference pipeline and a minimal demo. (bắt buộc)
10. Deliver reproducible experiment scripts/notebooks, documentation, architecture diagram, and presentation outline. (bắt buộc)

Ma trận yêu cầu → issue → deliverable → cách kiểm chứng: `docs/TRACEABILITY_MATRIX.md`.

## Scope and non-goals

### In scope (mandatory)
- Problem analysis; UNSW-NB15 sourcing; EDA; preprocessing; train/val/test split; Random Forest; evaluation; error analysis; inference; demo; documentation; report outline; presentation outline.
- Isolation Forest **chỉ khi khả thi** và **không chặn** chấp nhận core.

### Explicitly out of scope (do NOT implement now; document only in docs/FUTURE_WORK.md or an enhancement issue)
- Autoencoder, LSTM, Transformer, GNN.
- Zero-day detection claims without experimental proof.
- Device identity / attacker tracing from behavior vectors.
- Vector behavior encoding and adaptive key-rotation mechanism.
- Post-quantum cryptography of any traffic or feature representation.
- Automatic blocking, isolation, or counter-attack of devices.
- Production deployment, distributed processing, or enterprise network monitoring.

## Success criteria (verifiable)

- [ ] Repository structure matches design; all mandatory docs exist.
- [ ] README distinguishes planned / implemented / verified; no fabricated metrics.
- [ ] Data validation script passes on fixture data; UNSW-NB15 load instructions documented.
- [ ] Preprocessing pipeline can be reconstructed from `docs/REPRODUCIBILITY.md` and `config.py`.
- [ ] Random Forest model trains and evaluates with recorded seed, metrics, confusion matrix.
- [ ] Isolation Forest evaluation protocol is documented separately from supervised evaluation.
- [ ] No MIT content in LICENSE or README; Apache 2.0 full text present.
- [ ] Milestones M0–M5 exist; 15–22 issues exist with labels and milestone links.
- [ ] CI runs basic import/test checks without requiring large dataset or GPU.
- [ ] No hardcoded absolute paths, no secrets, no unverified benchmark claims.

## Risk and limitation notes

- Dataset size/availability: UNSW-NB15 is ~2.5 GB compressed; not committed to Git.
- Isolation Forest requires different evaluation (unsupervised score → threshold → pseudo-label); direct comparison with supervised F1 requires explicit threshold selection and label agreement explanation.
- Time budget: 5–6 weeks; complex deep-learning extensions deferred.
- Data quality risks: missing values, duplicate rows, leakage-prone identity columns.

## Time plan (5–6 weeks)

- Week 1 (M0): Repository, docs, environment, CI.
- Week 2 (M1): Dataset sourcing, validation, EDA, leakage audit.
- Week 3 (M2): Preprocessing pipeline, baseline, Random Forest.
- Week 4 (M3): Isolation Forest (if time), evaluation, comparison, error analysis.
- Week 5 (M4): Inference, demo, visualization, integration tests.
- Week 6 (M5): Final report, presentation, release verification.

## Key design decisions (recorded)

- Source code organized under `src/network_anomaly/`; logic callable from notebooks/scripts.
- Pipeline objects (scikit-learn Pipeline / custom) to prevent test-set leakage.
- Random seeds fixed; results logged with version info.
- No dataset committed; download instructions and checksum references documented (not verified yet;
  marked as planned).

Updated: 2026-10-17 (M0)
