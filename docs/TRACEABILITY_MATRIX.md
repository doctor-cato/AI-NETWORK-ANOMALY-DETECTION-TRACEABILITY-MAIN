# Ma trận truy vết Phương án B

Trạng thái vòng đời: `PLANNED`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED`.
Trạng thái kiểm chứng: `PASS`, `FAIL`, `SKIPPED`, `NOT VERIFIED`.

| C | Requirement | Issue | Deliverable/evidence | Trạng thái hiện tại (Cập nhật Consolidation MVP) |
|---|---|---|---|---|
| C0 | Governance, scope, architecture, backlog | #23 | docs, backlog, PR evidence | **COMPLETED** (#23 CLOSED; backlog/milestones đã đồng bộ theo phạm vi Demo Cuối kỳ) |
| C1 | NF-UNSW-NB15-v3 provenance, quality, EDA, leakage | #4–#7 | v3 manifest, schema, real numeric/duplicate audit, EDA report, leakage decision | **COMPLETED** (`#4–#7` CLOSED; `SOURCE_INTEGRITY: PASS`, split `bb84c1e...` đã kiểm toán) |
| C2 | Preprocessing không leakage | #8 | train-only pipeline artifact, fit-boundary tests, single-load verified loader, execution evidence | **COMPLETED** (`#8` CLOSED; `12d4360a...` REAL-DATA VERIFIED trên 1.655.797 dòng Train) |
| C3 | RF và XGBoost supervised | #9, #10, #12, #13, #31 | RF baseline (#9,#10), Held-out Test (`rf-heldout-ea330b9` #12,#13), XGBoost (#31) | **RF:** **EXPERIMENTALLY VALIDATED** cả Validation (`345.371` dòng) và Held-out Test (`rf-heldout-ea330b9`: `345.953` dòng, `Accuracy=0.999974`, `Precision=0.999771`, `Recall=0.999935`, `F1=0.999853`, `Macro-F1=0.999919`, `FPR=0.0000222`, `TN=315350, FP=7, FN=2, TP=30594`). **XGBoost (#31):** **EXPERIMENTALLY VALIDATED** cả Validation (`345.371` dòng, `F1=0.999984`, `CM=[[314870, 1], [0, 30500]]`) và Held-out Test (`xgb-baseline-1794755807`: `345.953` dòng, `Accuracy=0.999997`, `Precision=0.999967`, `Recall=1.000000`, `F1=0.999984`, `Macro-F1=0.999991`, `FPR=0.00000317`, `ROC-AUC=1.000000`, `TN=315356, FP=1, FN=0, TP=30596`); đạt `READY` trên `demo_flows.csv` |
| C4 | IF, Autoencoder, unknown holdout | #11, #29 | thresholds, holdout protocol, results | **Isolation Forest (#11):** **EXPERIMENTALLY VALIDATED** & **REPRODUCED** trên `NF-UNSW-NB15-v3` (`if-c4-20261115T055359Z`, clean commit `bf0f3ec`, `git_dirty=false`: benign-only Train `1.590.608`, Validation threshold `-0.033527` quét `74.421` candidates loại trừ `{Backdoor, Worms}`, Test `TP=27528, TN=264755, FP=50602, FN=3068`, `F1=0.5064`, `Recall=0.8997`, `ROC-AUC=0.893730`, Unknown `1122/1296=0.8657`); đạt `READY` trong `InferencePipeline`/`ApiService`. **Autoencoder (#29 via PR #51):** **EXPERIMENTALLY VALIDATED** trên `NF-UNSW-NB15-v3` với 2 run phân tách minh bạch: (a) run gốc `ae_benign_quantile_20261115T151859Z` (threshold `17234106.380850`, Val `FPR=0.050001429 > 0.05`, Test `TP=3343, FP=15189, TN=300168, FN=27253`, `F1=0.1361`, `Recall=0.1093`, `FPR=0.0482`, `ROC-AUC=0.6303`, Unknown `81/1296=0.0625`); (b) run active hiệu chỉnh hard-constraint `ae_fpr_constrained_20261115T163000Z` (`fpr_constrained`, threshold `17234985.792476`, `threshold_sha256: d8718af9...`, Val `FPR=0.049998253 <= 0.05`, Held-out Test `345.953` dòng `TP=3343, FP=15188, TN=300169, FN=27253`, `Accuracy=0.8773`, `Precision=0.1804`, `Recall=0.1093`, `F1=0.1361`, `FPR=0.0482`, `ROC-AUC=0.6303`, `PR-AUC=0.1615`, Unknown `81/1296=0.0625`); đạt `READY` trên `demo_flows.csv` |
| C5 | Behavioral Vector (NetFlow-only) | #28 | NetFlow metadata stats (`compute_netflow_behavioral_summary` + Desktop UI) | **REDUCED / IMPLEMENTED & TESTED** — loại Auth/API log không tồn tại; thống kê NetFlow metadata (`IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, `L4_*_PORT`, `FLOW_*`) tách biệt hoàn toàn khỏi 47 ML features kèm non-attribution notice |
| C6 | Risk & Trace (Simplified) | #32, #24 | `compute_deterministic_risk_score`, `build_deterministic_evidence_timeline`, `/api/v1/csv/analyze` | **REDUCED / IMPLEMENTED & TESTED** — deterministic risk priority [0..100] (`ABSTAINED_OOD` từ chối cả suy luận `predicted_label=null` lẫn risk scoring và loại khỏi Confusion Matrix qua `abstained_rows`, không FFI/PyO3) + timeline deterministic sắp theo `(FLOW_START_MILLISECONDS asc, row_id asc)` |
| C7 | Bảo mật cục bộ & key audit | #26 | localhost `127.0.0.1` bind guard, SHA-256 gate, CSV path safety, Tauri minimal capabilities, SQLite audit | **REDUCED / IMPLEMENTED & TESTED** (phần cốt lõi cục bộ) — **DEFERRED** phần full AES-256-GCM keyring & 30-min rotation ngoài phạm vi demo |
| C8 | Adaptive Security Response Simulation / Dry-run | #27 | `src/network_anomaly/api/response_policy.py`, `POST /api/v1/security/simulate-response`, `GET /api/v1/security/simulations`, `POST /api/v1/security/simulations/export`, `SecurityDryRunPanel.svelte` (Tab 4), `ResponseSimulationRepository` | **IMPLEMENTED / TESTED (Dry-Run)** (`SIMULATED` / `RECOMMENDED`, `executed=false`, chỉ cấp `ISOLATE_RECOMMENDED` & rotation escalation từ `server_verified_analysis`, chặn spoof `compatibility_gate`/`inference_mode`, cấm containment cho `ABSTAINED_OOD`, AST isolation check) — live firewall/PowerShell execution, AES-256-GCM keyring & live key rotation **DEFERRED** |
| C9 | FastAPI, SQLite, 4-Model Inference, Demo CSV & Desktop UI (`v0.6.0` Stable) | #30, #15, #17, #16 | `src/network_anomaly/api/`, `desktop/` (`v0.6.0` Rust Tauri 2 + Svelte 5 + NSIS installer), `scripts/prepare_demo_dataset.py`, `scripts/verify_companion_artifacts.py`, `scripts/check_desktop_version.py`, `.github/workflows/release.yml`, `docs/WINDOWS_INSTALLATION.md`, `docs/RELEASE_PROCESS.md`, `docs/releases/v0.6.0.md` | **IMPLEMENTED / TESTED / REAL-DATA DEMO VERIFIED** — Desktop Windows Tauri 2 + Svelte 5 `v0.6.0` Stable: cả **4 model (`Random Forest`, `XGBoost`, `Isolation Forest`, `Autoencoder`)** đạt `READY` và đối chiếu 100% trên `demo_flows.csv` (198 non-OOD Validation rows + 2 OOD rows `ABSTAINED_OOD`) kèm so sánh batch 4 model, Tab 4 Issue #27 dry-run (`executed=false`), Ground Truth confusion matrix loại trừ OOD, Export CSV + provenance; fail-closed `HTTP 503` không fallback khi thiếu/hỏng binary; yêu cầu Python + companion artifacts bên ngoài |
| C9/M6 | Ingestion NetFlow & Eligibility Gate | #46, #58 | `src/network_anomaly/ingestion/`, `resolve_csv_source_provenance`, `docs/MULTI_SOURCE_INGESTION.md`, `docs/FEATURE_COMPATIBILITY_MATRIX.md`, `InferenceEligibilityGate`, `scripts/fetch_external_dataset.py`, `scripts/evaluate_cross_dataset.py`, `reports/evaluation/cross_dataset_generalization_report.md` | **COMPLETED (PR #47 merged vào `main` tại `e02548b` + M6 provenance hardening):** Xác minh provenance SHA-256/`demo_manifest.json` trước khi gán `source:nf-v3-canonical` (`MODEL_VALIDATED`); CSV bên ngoài chưa kiểm chứng nhận `source:nf-v3-unverified` (`VALIDATION_NOT_VERIFIED`) |
| C10 | Thực nghiệm trọng tâm & Cross-Dataset M7 | #25, #48, #57 | Exp 1–3/4 & cross-dataset research | **REDUCED / DEFERRED sang M7** — `#25` thu gọn từ 7 xuống core ML experiments; **PR #49 (`7344994`)** Ready for Review, `#57` CLOSED theo bản vá `7344994` |
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
- Trạng thái vòng đời & kiểm chứng (Cập nhật M3 — 2026-11-15):
  - Pipeline, synthetic tests & integration: `IMPLEMENTED` / `TESTED` / `INTEGRATION VERIFIED` (PASS).
  - Thực nghiệm trên dữ liệu thật `NF-UNSW-NB15-v3`: **EXPERIMENTALLY VALIDATED** & **REPRODUCED** (run `if-c4-20261115T055359Z`, clean commit `bf0f3ec`, `git_dirty=false`, `script_sha256=bdd98556...`, `model_module_sha256=73547fb5...`, `artifacts/models/isolation_forest/isolation_forest.joblib` SHA-256 `15a69cc4...`, `reports/models/isolation_forest_manifest.json`, `reports/experiments/isolation_forest/{metrics.json,threshold_calibration.json,per_attack_metrics.json,run_metadata.json,confusion_matrix.csv,confusion_matrix.png,evaluation_report.md}`). Lưu ý: `blocked_status.json` trong cùng thư mục là snapshot lịch sử trước khi có dữ liệu thật cục bộ (`rf-heldout-ea330b9` cũng giữ snapshot riêng tại `reports/evaluation/rf-heldout-ea330b9/verified_summary.json`).
  - Clean Reproduction (#14): Đã chạy lại sạch trong môi trường Python `3.12.10` độc lập (`pip install -e .`) cho Random Forest (Validation `0` sai khác CM/metrics), XGBoost (Validation `0` sai khác CM/metrics; Test `NOT VERIFIED`), và Isolation Forest (Validation + Held-out Test `0.0` sai khác score/metrics).

Cập nhật: 2026-11-07 (PR #43 hoàn thành huấn luyện thực nghiệm Random Forest baseline Issue #10 trên dữ liệu thật NF-UNSW-NB15-v3, xác minh toàn bộ AC1–AC7 và giữ khóa tập Test cho Issue #12)
Cập nhật: 2026-11-08 (Pipeline huấn luyện & đánh giá Isolation Forest cho Issue #11)
Cập nhật Consolidation MVP (hậu PR #50 / PR #51 / PR #61): Đã bổ sung Held-out Test RF (`reports/evaluation/rf-heldout-ea330b9/`), Autoencoder (#29 merged + `AutoencoderModel`), FastAPI + SQLite (`#30` + `#53–#59` qua PR #61), đóng PR #52 superseded, chuẩn bị demo Validation-only (`scripts/prepare_demo_dataset.py`) và chốt Desktop UI **Rust/Tauri 2 + Svelte 5** tại #16 (trạng thái `PLANNED`).
Cập nhật M3 Completion (2026-11-15 — #11, #14): Hoàn thành real-data training/calibration/held-out/unknown-attack evaluation cho Isolation Forest (`if-c4-20261115T055359Z`, clean commit `bf0f3ec`, `git_dirty=false`), tích hợp `READY` trong CLI/API/demo, và clean reproduction M3 trên Python `3.12.10` kèm tách ranh giới M3/M7 khỏi #20/#60.
Cập nhật M6 Beta -> M7 / `v0.6.0` Stable Release Readiness (2026-11-15 — #16, #24, #26, #27, #28, #29, #31, #32, #46, `v0.6.0`): Hoàn thiện PR #69 (**Issue #27 Adaptive Security Response Dry-Run**, deterministic policy engine + adaptive key-rotation simulation `executed=false` + Tab 4 `SecurityDryRunPanel.svelte` + SQLite + JSON export, OOD non-containment; giữ nguyên AES-256-GCM keyring & OS firewall `DEFERRED`), hoàn tất thực nghiệm real-data Validation & Held-out Test cho **XGBoost (#31)** và **Autoencoder (#29)**, nâng cấp ứng dụng desktop **NetFlow Sentinel `v0.6.0` Stable** hỗ trợ chọn/chạy/so sánh đủ **4 model** (`ModelComparisonPanel.svelte`, `normalized_anomaly_score` cho unsupervised mà không biến thành probability) trên `demo_flows.csv`, bổ sung `scripts/verify_companion_artifacts.py` và bộ kiểm thử `tests/integration/test_four_model_integrity_e2e.py`. Giữ nguyên fail-closed SHA-256 (`HTTP 503` nếu thiếu binary), provenance gate (`source:nf-v3-canonical` vs `source:nf-v3-unverified`), OOD abstention (`ABSTAINED_OOD`) và cảnh báo bộ cài NSIS không phải standalone.
