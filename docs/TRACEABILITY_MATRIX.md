# Ma trận truy vết Phương án B

Trạng thái vòng đời: `PLANNED`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED`.
Trạng thái kiểm chứng: `PASS`, `FAIL`, `SKIPPED`, `NOT VERIFIED`.

C0 chỉ xác nhận governance/backlog. Mọi checkpoint C1–C11 vẫn `PLANNED` cho đến khi có
code, test và evidence tương ứng. PR #22 là workstream #4/#5 riêng, không tự merge.

| C | Requirement | Issue | Deliverable/evidence bắt buộc | Trạng thái C0 |
|---|---|---|---|---|
| C0 | Governance, scope, architecture, backlog | #23 | docs, GitHub readback, branch/commit/PR | IMPLEMENTED; VERIFY chờ CI/PR |
| C1 | Data quality, EDA, leakage | #4–#7, PR #22 | manifest/report/EDA/leakage decision | #4/#5 TESTED trên PR #22; #6/#7 PLANNED |
| C2 | Preprocessing không leakage | #8 | pipeline artifact, fit-boundary tests | PLANNED |
| C3 | RF và XGBoost supervised | #9, #10, #12, #31 | model artifacts, metrics, reproduction | PLANNED |
| C4 | IF, Autoencoder, unknown holdout | #11, #29 | thresholds, holdout protocol, results | Pipeline IF `IMPLEMENTED`/`TESTED` (synthetic fixtures); real-data experiment `BLOCKED` (thiếu dataset file local) |
| C5 | Behavioral Vector | #28 | versioned schemas, fixtures, correlation tests | PLANNED |
| C6 | Risk và Trace | #32, #24 | explanation, calibration, evidence/timeline tests | PLANNED |
| C7 | AES-GCM và key lifecycle | #26 | integrity/recovery/rotation tests | PLANNED |
| C8 | Adaptive response | #27 | cooldown/rate/idempotency/concurrency audit | PLANNED |
| C9 | API, persistence, dashboard | #30, #16, #17 | OpenAPI, DB recovery, E2E | PLANNED |
| C10 | 7 experiments | #25 | protocol, artifact, results, limitations | PLANNED |
| C11 | Delivery | #18–#20 | PDF, slides, demo, guides, 5-role handoff | PLANNED |

Chuỗi bắt buộc cho từng claim:
`Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results`.
Synthetic fixture/CI không thay thế real-data experiment. Mỗi result phải gắn commit,
dataset/split identifier, dependency versions, seed/config, artifact và reproduction command.

## Review PR #22 và Issue #4/#5 tại C0

- Remote: PR #22 `OPEN`, `MERGEABLE`, chưa có `reviewDecision`; 4/4 CI jobs thành công.
- Local review worktree: 105 tests PASS; manifest verify PASS; real split validation PASS
  với duplicate warning; `git diff --check` PASS.
- Giới hạn: SHA-256 là project-computed, UNSW không công bố checksum; duplicate/overlap
  leakage thuộc #7. Không merge hoặc đóng #4/#5 trong C0.

Cập nhật: 2026-10-19 (self-review; không phải reviewer độc lập khác)

## Model component Isolation Forest tại Issue #11

- Issue: #11 (C4). Chỉ phần model component; protocol đánh giá chưa làm.
- Implementation: `src/network_anomaly/models/isolation_forest.py` (factory có validate,
  `random_state` tường minh, hợp đồng score direction và feature matrix số hữu hạn) và
  `ISOLATION_FOREST_DEFAULTS` trong `src/network_anomaly/config.py`.
- Tests: `tests/unit/test_isolation_forest.py` — khởi tạo, mặc định, cấu hình tùy chỉnh,
  tham số không hợp lệ, và hành vi fit/score trên fixture synthetic.
- Evidence: `python -m pytest tests -q` PASS (189 passed, 2 skipped — 2 skip là symlink
  trên Windows, có sẵn từ trước). Fixture synthetic chỉ chứng minh contract của model.
- `NOT VERIFIED`: EDA (#6), split/leakage audit (#7), fitted preprocessing artifact (#8),
  threshold calibration trên validation, unknown-attack holdout, detection rate, FPR và
  so sánh với Autoencoder. Không có kết quả trên UNSW-NB15, không tuyên bố zero-day.

Cập nhật: 2026-10-22 (model component Isolation Forest cho Issue #11)

## Pipeline huấn luyện & Đánh giá Isolation Forest (Issue #11 — C4)

- Issue: #11 (C4).
- Implementation:
  - `src/network_anomaly/data/nf_unsw_nb15_v3.py`: Hợp đồng 47 baseline features, loại trừ targets (`Label`, `Attack`) và trace/grouping metadata (`FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`, `IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, `L4_SRC_PORT`, `L4_DST_PORT`).
  - `scripts/train_isolation_forest.py`: Pipeline fail-closed toàn diện:
    1. Kiểm tra điều kiện tiên quyết (SHA-256 dữ liệu, split manifest, companion preprocessor manifest, 47 feature schema, kiểm tra không rò rỉ metadata/target, kiểm tra giá trị hữu hạn).
    2. Huấn luyện Isolation Forest chỉ trên mẫu lành tính (`Label == 0`) từ tập Train (1.655.797 dòng train).
    3. Hiệu chuẩn ngưỡng (Threshold Calibration) trên Validation: loại trừ các nhóm tấn công chưa biết đã đăng ký trước (`UNKNOWN_ATTACK_CATEGORIES` = `{"Worms", "Backdoor"}`); hỗ trợ chính sách tối đa hóa F1 hoặc đáp ứng mục tiêu FPR.
    4. Đóng băng ngưỡng trước khi đánh giá tập Test (345.953 dòng).
    5. Đánh giá Test độc lập: TP, TN, FP, FN, Accuracy, Precision, Recall, F1, FPR, ROC-AUC, PR-AUC, tỷ lệ phát hiện theo từng nhóm tấn công và tỷ lệ phát hiện tấn công đã biết so với chưa biết.
    6. Lưu trữ artifact (`isolation_forest.joblib`, `model_config.json`, `threshold.json`, `training_metadata.json`) và kiểm tra reload consistency.
    7. Xuất báo cáo máy đọc được (`metrics.json`, `threshold_calibration.json`, `per_attack_metrics.json`, `run_metadata.json`, `evaluation_report.md`).
- Tests:
  - `tests/unit/test_train_isolation_forest.py`: 63 unit/integration tests bao phủ toàn bộ 12 nhóm kiểm thử: huấn luyện benign-only, loại trừ target, kiểm thực 47 feature schema, hiệu chuẩn ngưỡng, chiều score (cao hơn = bất thường hơn), cô lập holdout unknown attack, bảo vệ tập Test, lưu/nạp artifact, tái lập thực nghiệm, tính toán metrics, xử lý lỗi fail-closed, và tính toàn vẹn của hợp đồng đặc trưng.
  - Tổng số test trong repository: 263 passed, 2 skipped (Windows symlink).
- Evidence:
  - `python -m pytest tests/unit/test_train_isolation_forest.py -v`: 63 passed (18s).
  - `python -m pytest tests/ -q`: 263 passed, 2 skipped.
  - `python scripts/train_isolation_forest.py --check-prereqs-only`: PASS kiểm tra cấu trúc pipeline; phát hiện dataset absent và ghi nhận trạng thái BLOCKED tại `reports/experiments/isolation_forest/blocked_status.json`.
  - `python scripts/train_isolation_forest.py`: exit 1 (fail-closed khi thiếu dataset `NF-UNSW-NB15-v3.csv`).
  - `python -m ruff check scripts/train_isolation_forest.py tests/unit/test_train_isolation_forest.py`: All checks passed.
  - `git diff --check`: PASS.
- Trạng thái vòng đời & kiểm chứng:
  - Pipeline & synthetic tests: `IMPLEMENTED` / `TESTED` (PASS).
  - Thực nghiệm trên dữ liệu thật NF-UNSW-NB15-v3: `BLOCKED` / `NOT VERIFIED` do file dataset `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv` không có sẵn trong môi trường máy cục bộ. Không thay thế bằng mock data; không đóng Issue #11 cho đến khi đủ dữ liệu thật và chạy thực nghiệm ra kết quả hoàn chỉnh.

Cập nhật: 2026-11-03 (Pipeline huấn luyện & đánh giá Isolation Forest cho Issue #11)
