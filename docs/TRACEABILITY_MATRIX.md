# Ma trận truy vết Phương án B

Trạng thái vòng đời: `PLANNED`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED`.
Trạng thái kiểm chứng: `PASS`, `FAIL`, `SKIPPED`, `NOT VERIFIED`.

| C | Requirement | Issue | Deliverable/evidence | Trạng thái hiện tại (Cập nhật Consolidation MVP) |
|---|---|---|---|---|
| C0 | Governance, scope, architecture, backlog | #23 | docs, backlog, PR evidence | **COMPLETED** (#23 CLOSED; backlog/milestones đã đồng bộ theo phạm vi Demo Cuối kỳ) |
| C1 | NF-UNSW-NB15-v3 provenance, quality, EDA, leakage | #4–#7 | v3 manifest, schema, real numeric/duplicate audit, EDA report, leakage decision | **COMPLETED** (`#4–#7` CLOSED; `SOURCE_INTEGRITY: PASS`, split `bb84c1e...` đã kiểm toán) |
| C2 | Preprocessing không leakage | #8 | train-only pipeline artifact, fit-boundary tests, single-load verified loader, execution evidence | **COMPLETED** (`#8` CLOSED; `12d4360a...` REAL-DATA VERIFIED trên 1.655.797 dòng Train) |
| C3 | RF và XGBoost supervised | #9, #10, #12, #13, #31 | RF baseline (#9,#10), Held-out Test (`rf-heldout-ea330b9` #12,#13), XGBoost (#31) | **RF:** **EXPERIMENTALLY VALIDATED** cả Validation (`345.371` dòng) và Held-out Test (`rf-heldout-ea330b9`: `345.953` dòng, `Accuracy=0.999974`, `Precision=0.999771`, `Recall=0.999935`, `F1=0.999853`, `Macro-F1=0.999919`, `FPR=0.0000222`, `TN=315350, FP=7, FN=2, TP=30594`). **XGBoost (#31 CLOSED):** **EXPERIMENTALLY VALIDATED trên Validation** (`F1=0.999984`, `CM=[[314870, 1], [0, 30500]]`), Held-out Test `NOT VERIFIED` |
| C4 | IF, Autoencoder, unknown holdout | #11, #29 | thresholds, holdout protocol, results | **IMPLEMENTED / TESTED** — IF (`#11` OPEN) & Autoencoder (`#29` CLOSED via PR #51) có unit/integration tests + `AutoencoderModel`/verified loading trong `InferencePipeline` & `ApiService`; real-data run `NOT VERIFIED` (`BLOCKED / NOT READY` nếu thiếu `.joblib`/`.pt` cục bộ) |
| C5 | Behavioral Vector (NetFlow-only) | #28 | NetFlow metadata stats | **REDUCED / DEFERRED** — loại Auth/API log không tồn tại; chỉ giữ thống kê NetFlow metadata nếu UI cần |
| C6 | Risk & Trace (Simplified) | #32, #24 | deterministic ranking & timeline | **REDUCED** — `/api/v1/timeline` + deterministic scoring minh bạch qua FastAPI; bỏ graph engine & FFI/PyO3 phức tạp |
| C7 | Bảo mật cục bộ & key audit | #26 | localhost bind, SHA-256 gate, SQLite audit | **DEFERRED / REDUCED** — hoãn full AES-256-GCM keyring & 30-min rotation |
| C8 | Adaptive response | #27 | deferred outside MVP | **DEFERRED** — không chặn Demo MVP M6 |
| C9 | FastAPI, SQLite, 4-Model Inference, Demo CSV & Desktop UI | #30, #15, #17, #16 | `src/network_anomaly/api/`, `scripts/prepare_demo_dataset.py`, OpenAPI, Desktop UI | **Backend/Inference (#15,#17,#30 CLOSED + Consolidation):** **IMPLEMENTED / TESTED** + Demo Validation run (`200` rows, `0` Train/Test overlap, RF `TN=100, FP=0, FN=0, TP=100`); **Desktop UI Rust/Tauri 2 + Svelte 5 (#16 OPEN):** **PLANNED** (thay Streamlit) |
| C9/M6 | Ingestion NetFlow & Eligibility Gate | #46, #58 | `src/network_anomaly/ingestion/`, `InferenceEligibilityGate`, `fetch_external_dataset.py` | **PR #47 (`f999930`):** Ready for Review, **6/6 CI PASS**, chờ maintainer review (`REVIEW_REQUIRED`); `#58` CLOSED theo bản vá `f999930`; **REDUCE** scope adapter phụ |
| C10 | Thực nghiệm trọng tâm & Cross-Dataset M7 | #25, #48, #57 | Exp 1–3/4 & cross-dataset research | **REDUCED / DEFERRED sang M7** — `#25` thu gọn từ 7 xuống core ML experiments; **PR #49 (`7344994`)** Ready for Review (stacked PR #47), `#57` CLOSED theo bản vá `7344994` |
| C11 | Delivery & Audit QA | #18–#20, #60 | Docs sync, PDF/10–12 slides, QA gates | **IN PROGRESS** — `#53–#59` audit findings đã vá (`#52` PR CLOSED superseded) |

## Dataset migration A–H

| Gate | Implementation | Tests/evidence | Status |
|---|---|---|---|
| A — Research/source | decision, provenance, schema, impact records | official UQ/RDM bytes and metadata compared | VERIFIED |
| B — Architecture | component inventory, default/historical paths, rollback boundary | `git diff --check` | PASS |
| C — Acquisition/manifest | bounded fetch, safe ZIP, lock, transaction, checksums | synthetic safety tests + official download/cache verification | PASS |
| D — Quality audit | streaming validator, disk-backed numeric/duplicate/label-conflict audit | real report on 2.365.424 rows | SOURCE_INTEGRITY PASS; RAW_QUALITY FINDINGS_RECORDED; ML_READY BLOCKED |
| E — Split contract | 47-feature exclusion, versioned fingerprints, group/temporal guards | synthetic + real split tests (PR #41) | TESTED / EXPERIMENTALLY VALIDATED; real split/leakage audit PASS |
| F — Architecture/docs | v3 default throughout current docs | link/text/status checks | IMPLEMENTED / VERIFIED |
| G — Tests/CI | Windows/Linux matrix, migration regression tests, lint audit workflow | 219 pytest PASS (211 previous + 8 reproducibility tests); PR-scoped Ruff and Black PASS; repository-wide Ruff (5 findings) and Black (11 files) still FAIL on pre-existing files, tracked in #37; CI matrix PASS 4/4; lint audit workflow PASS on Linux | PARTIAL — remote CI PASS, repository-wide lint debt remains in #37 |
| H — Issues/PR | #6–#15, #17, #18, #20, #25, #29, #31; historical notes #4/#5; M1–M5/M7 | #6/#7/#8/#17/#20 hardening contracts read back OPEN; PR #36 OPEN into `main` | VERIFIED; not merged |
| I — EDA (Issue #6) | `scripts/eda_nf_unsw_nb15_v3.py`, `src/network_anomaly/eda/`, generated report + summary | 15 EDA unit tests + 8 reproducibility tests on synthetic fixtures PASS; real run on 2.365.424 rows; inherited findings reproduced (rows, labels, exact duplicates, repeated rows all MATCH) | IMPLEMENTED / TESTED; no split, no fitted artifact, `ML_READY: BLOCKED` |
| J — EDA reproducibility evidence | `scripts/verify_eda_reproducibility.py`, `reports/eda/evidence/` | two independent real-data runs with captured stdout/stderr, git state, environment, dataset identity, manifest/schema verification and key aggregates; deterministic content comparison PASS per metric | VERIFIED — evidence retrievable per run |

UNSW-NB15 (2015) evidence is preserved under `historical/`; its old validation cannot satisfy a v3
gate. PR #22 and #35 are merged historical workstreams, not pending proof for this migration.

Chuỗi bắt buộc cho mọi claim:
`Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results`.
Synthetic fixture/CI không thay thế real-data experiment. Mỗi result phải gắn commit,
dataset/split identifier, dependency versions, seed/config, artifact và reproduction command.

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
  - `tests/unit/test_train_isolation_forest.py`: 78 unit/integration tests bao phủ toàn bộ các nhóm kiểm thử: huấn luyện benign-only, loại trừ target, kiểm thực 47 feature schema, hiệu chuẩn ngưỡng (O(N) vectorized), chiều score, cô lập holdout unknown attack, bảo vệ tập Test, lưu/nạp artifact, tái lập thực nghiệm, tính toán metrics, xử lý lỗi fail-closed, tính toàn vẹn hợp đồng đặc trưng, kiểm thực split/preprocessor manifest, streaming chunked loading và end-to-end integration trên partition indices.
  - Tổng số test trong repository: 550+ passed.
- Evidence:
  - `python -m pytest tests/unit/test_isolation_forest.py tests/unit/test_train_isolation_forest.py -v`: 136 passed.
  - `python scripts/train_isolation_forest.py --check-prereqs-only`: PASS kiểm tra cấu trúc pipeline; phát hiện dataset absent và ghi nhận trạng thái BLOCKED tại `reports/experiments/isolation_forest/blocked_status.json`.
  - `python scripts/train_isolation_forest.py`: exit 1 (fail-closed khi thiếu dataset `NF-UNSW-NB15-v3.csv`).
  - `python -m ruff check scripts/train_isolation_forest.py tests/unit/test_train_isolation_forest.py`: All checks passed.
  - `git diff --check`: PASS.
- Trạng thái vòng đời & kiểm chứng:
  - Pipeline, synthetic tests & integration: `IMPLEMENTED` / `TESTED` / `INTEGRATION VERIFIED` (PASS).
  - Thực nghiệm trên dữ liệu thật NF-UNSW-NB15-v3: `BLOCKED` / `NOT EXPERIMENTALLY VALIDATED` do file dataset `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv` không có sẵn trong môi trường máy cục bộ. Không thay thế bằng mock data; không đóng Issue #11 cho đến khi đủ dữ liệu thật và chạy thực nghiệm ra kết quả hoàn chỉnh.

Cập nhật: 2026-11-07 (PR #43 hoàn thành huấn luyện thực nghiệm Random Forest baseline Issue #10 trên dữ liệu thật NF-UNSW-NB15-v3, xác minh toàn bộ AC1–AC7 và giữ khóa tập Test cho Issue #12)
Cập nhật: 2026-11-08 (Pipeline huấn luyện & đánh giá Isolation Forest cho Issue #11)
Cập nhật Consolidation MVP (hậu PR #50 / PR #51 / PR #61): Đã bổ sung Held-out Test RF (`reports/evaluation/rf-heldout-ea330b9/`), Autoencoder (#29 merged + `AutoencoderModel`), FastAPI + SQLite (`#30` + `#53–#59` qua PR #61), đóng PR #52 superseded, chuẩn bị demo Validation-only (`scripts/prepare_demo_dataset.py`) và chốt Desktop UI **Rust/Tauri 2 + Svelte 5** tại #16 (trạng thái `PLANNED`).
