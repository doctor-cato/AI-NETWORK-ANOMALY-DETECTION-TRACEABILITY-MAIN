# NetFlow Sentinel v2 Migration — Session Checkpoint

**Thời điểm cập nhật:** 2026-11-18T03:35:00+07:00 (Checkpoint 5 — Kiểm chứng & Khắc phục Sót v1, Đồng bộ Docs/Tests/Issues & Full QA Desktop/Rust)
**Nhánh:** `feat/v2-integration`
**Tracking:** `origin/feat/v2-integration`
**Base:** `main` (commit `42a656a`)
**Pull Request:** #156 (`feat(v2): NetFlow Sentinel v2.0.0 integration`) — Duy trì **DRAFT**, đã cập nhật mô tả theo hard cutover v2, không merge, không sửa `main`.
**Nguyên tắc tuân thủ:**
- Không sử dụng model weights, preprocessor, split, threshold hay 47 đặc trưng cũ của `NF-UNSW-NB15-v3`.
- Không tạo fallback ngầm sang v1; fail-closed `canonical-flow-v2-18` trên toàn bộ pipeline.
- Đánh dấu trung thực `UGR'16` là `BLOCKED` (HTTP 403 / Portal en Mantenimiento), và `AIT-NDS-v2 ↔ AIT-LDS-v2.1` cross-source linkage là `NOT VERIFIED / BLOCKED`, tuyệt đối không tạo dữ liệu hay liên kết giả.
- Đánh giá trung thực chênh lệch phân phối synthetic-to-real trên `CTU-SME-11` và ghi nhận đầy đủ kết quả âm (negative results).
- Tuyệt đối không thêm trailer hay dấu ấn AI (`Co-Authored-By`, `Generated with`, bot emojis, model names) vào commit message, PR description, issue hay code/doc comments.

---

## 1. Kết quả Kiểm chứng Checkpoint 4 & Các Khắc phục Trong Checkpoint 5

### 1.1. Phần đã xác minh ĐÚNG ở Checkpoint 4
- Số liệu split `v2-scenario-group-purged-v1` (`1,930,219` / `377,704` / `923,292`, `942` unmapped excluded), preprocessor `asinh_robust` (`d33dfe09...`), SHA-256 của 4 model (`0dd7aaaf...`, `6bb5a6f2...`, `aca66915...`, `2032f8ca...`), và toàn bộ metric trong bảng đối chiếu (`AIT-Test`, `CTU-Echo`, `CTU-Win7AD`) khớp với `reports/models/*_manifest.json`, `model_comparison_report.json` và `ctu_cross_source_eval.json`.
- Toàn bộ kết quả RQ1–RQ6 và benchmark AES-256-GCM / E2E CPU (`10.78 events/s`, 0 dropped) khớp các file JSON báo cáo trong `reports/`.

### 1.2. Các điểm chưa chính xác / còn sót ở Checkpoint 4 đã được phát hiện và sửa ở Checkpoint 5
1. **Active Code, Scripts & Tests còn sót tham chiếu v1/47-feature:**
   - `src/network_anomaly/ingestion/contracts.py`: cập nhật thông báo UI summary từ `47-feature` sang `18-feature canonical-flow-v2-18`.
   - `src/network_anomaly/streaming/realtime_inference.py`: sửa `_demo_decision` từ khóa v1 `OUT_BYTES`/`TCP_FLAGS` sang khóa v2 `bytes_out`/`bytes_in`/`is_tcp`.
   - `scripts/verify_companion_artifacts.py`, `scripts/vm_target_e2e.ps1`, `scripts/_rq_common.py`: gỡ chuỗi help/đường dẫn/alias `NF-UNSW-NB15-v3` và `nf_unsw_nb15_v3_preprocessor.joblib`.
   - `data/demo/demo_manifest.json`: chạy lại `scripts/prepare_demo_dataset.py` để đồng bộ SHA-256 & `training_run_id` của Isolation Forest (`aca66915...`) và Autoencoder (`2032f8ca...`) mới nhất (`AI Ready 4/4`).
   - `tests/integration/test_security_dry_run_integration.py`: chuyển từ `nf_unsw_nb15_v3_preprocessor.joblib` sang `v2_flow_preprocessor.joblib`, bỏ trạng thái `SKIPPED` để 2 real-artifact E2E test chạy và PASS.
   - `tests/unit/test_xgboost.py`, `tests/integration/test_inference_e2e.py`, `tests/unit/test_isolation_forest.py`, `tests/integration/test_full_system_e2e.py`: dọn bỏ placeholder `UNSW-NB15` bị skip và tham số `OUT_BYTES`; xóa fixture mồ côi `tests/fixtures/ait_synthetic/synthetic_netflow_fixture.csv`.
2. **Active Documentation còn mâu thuẫn hard cutover hoặc sai tên cột v2:**
   - Sửa lỗi sai 3 tên feature (`bytes_ratio`, `pkts_ratio`, `tcp_flags_int` -> `has_response`, `is_tcp`, `is_udp`) và tên 5 cột provenance trong `README.md`, `docs/DATASET.md`, `docs/INFERENCE_PIPELINE.md` khớp `src/network_anomaly/data/v2_schema.py`.
   - Viết lại toàn bộ các tài liệu active còn sót hướng dẫn v1/47-feature: `docs/MIGRATION_V1_TO_V2.md`, `docs/TRACEABILITY_MATRIX.md`, `docs/FEATURE_COMPATIBILITY_MATRIX.md`, `docs/CANONICAL_SECURITY_EVENT_V2.md`, `docs/MULTI_SOURCE_INGESTION.md`, `docs/MULTI_SOURCE_PIPELINE.md`, `docs/ARCHITECTURE_V2.md`, `docs/PRESENTATION_OUTLINE.md`, `docs/REPORT_OUTLINE.md`, `docs/V2_DEPENDENCY_GRAPH.md`, `docs/DEVELOPMENT_PLAN.md`, `docs/ROADMAP_FULL_SYSTEM.md`, `desktop/README.md`, `desktop/src-tauri/Cargo.toml`.
   - Đánh dấu `SUPERSEDED` trên `docs/decisions/MODEL_FEATURE_SPACE_COMPATIBILITY.md` (`ADR-ML-002`) và gắn banner lịch sử cho `docs/IMPLEMENTATION_CHECKPOINTS.md`, `docs/ISSUE_SUPPLEMENTS.md`.
3. **GitHub Issues & Draft PR #156:**
   - Cập nhật 20 issue còn mâu thuẫn (`#79`, `#82`–`#95`, `#101`, `#102`, `#106`, `#132`, `#155`) sang tiêu chí hard cutover `canonical-flow-v2-18` (giữ trạng thái OPEN, ghi rõ `BLOCKED`/`NOT VERIFIED` cho `UGR'16` và `AIT` linkage).
   - Cập nhật mô tả Draft PR #156 đồng bộ số liệu v2, `CTU-SME-11`, `UGR'16 BLOCKED` và `Refs #76–#155`.

---

## 2. Tổng hợp Bảng Kiểm chứng & Bằng chứng Hiện hành

| Hạng mục | Status | Evidence / Lệnh kiểm tra | Ghi chú & Giới hạn |
|---|---|---|---|
| **Dataset provenance** | **PASS** (`UGR'16 BLOCKED`) | `fetch_multi_source_dataset.py --verify-only`, `data/EXTERNAL_DATASETS_PROVENANCE.json` | `AIT-NDS-v2`, `AIT-LDS-v2.1`, `AIT-ADS`, `CTU-SME-11` verified CC BY 4.0; `UGR'16` HTTP 403 `BLOCKED` |
| **Profiling** | **PASS** | `reports/datasets/v2_multi_source_profile.json`, `docs/dataset/{AIT_PROFILE,CTU_SME_11_PROFILE}.md` | AIT cross-source log↔flow linkage `NOT VERIFIED` (`AIT_LINKAGE_FEASIBILITY.md`) |
| **Feature contract** | **PASS** | `src/network_anomaly/data/{v2_schema,taxonomy}.py`, `test_v2_migration_guards.py` | `canonical-flow-v2-18` (18 ML features) + `taxonomy-v2` (unmapped tách riêng) |
| **Preprocessing** | **PASS** | `reports/preprocessing/v2_flow_preprocessing_manifest.json` (`d33dfe09...`) | `asinh_robust` fit chỉ trên `ait_train` (`1,930,219` rows) |
| **RF / XGBoost / IF / AE** | **PASS** (`AI Ready 4/4`) | `verify_companion_artifacts.py` (`overall_status: READY`), `reports/models/*_manifest.json` | Train từ đầu trên `AIT-Train`, calibrated trên `AIT-Val` (`FPR <= 0.05`) |
| **Cross-dataset evaluation** | **PASS** (`CTU-SME-11`) / **BLOCKED** (`UGR'16`) | `reports/experiments/ml/ctu_cross_source_eval.json` | RF/XGB sụp đổ zero-shot trên `CTU`; IF đạt `F1=0.8527` trên `CTU-Echo` |
| **Python Tests** | **PASS** | `.venv\Scripts\python.exe -m pytest tests -q --tb=short -rs` | **578 passed, 3 skipped, 0 failed** (3 skip là negative non-existent file & `ruff`/`black` chưa cài trong `.venv`) |
| **Ruff / Black (local)** | **SKIPPED / NOT VERIFIED** | `.venv\Scripts\python.exe -m ruff check ...` | Không có `ruff`/`black` trong `.venv` cục bộ; kiểm tra qua CI job `lint` |
| **Frontend Svelte / Vite** | **PASS** | `npm --prefix desktop run check && npm --prefix desktop test && npm --prefix desktop run build` | `svelte-check` 0 errors, `vitest` **33 passed (5 files)**, `vite build` OK |
| **Rust / Tauri 2** | **PASS** | `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --lib` | `cargo fmt` OK, `clippy` 0 warnings, `cargo test` **9 passed, 0 failed** |
| **Contracts & Diff** | **PASS** | `check_environment.py`, `export_openapi_spec.py --check`, `check_desktop_version.py --check`, `git diff --check` | Tất cả exit code 0, không lỗi whitespace |
| **Issues / Draft PR #156** | **PASS** (Updated, Draft) | `gh pr view 156`, `gh issue edit` (`#79`, `#82`–`#95`, `#101`, `#102`, `#106`, `#132`, `#155`) | Giữ PR ở trạng thái Draft, không merge |

---

## 3. Công việc Còn lại (Ngoài phạm vi Session hoặc Chờ Môi trường Ngoài)

1. **Commit & Push lên nhánh `feat/v2-integration`:** Chỉ thực hiện khi người dùng yêu cầu hoặc xác nhận commit/push các thay đổi đã rà soát trong working tree.
2. **CI Workflow Verification sau Push:** Xác nhận job `lint` (`ruff` + `black`), `test` (Linux/Windows matrix) và `desktop-tauri-windows` chạy xanh trên remote CI.
3. **Các Hạng mục Ngoài / Blocker Khách quan:**
   - `UGR'16`: Chờ cổng NESG mở lại (`HTTP 403` / Maintenance).
   - Empirical `AIT-NDS-v2 ↔ AIT-LDS-v2.1` cross-session linkage (`RQ3`): Chờ xác minh đồng bộ timestamp/timezone/entity giữa PCAP v2.0 và Log v2.1.
   - Clean Windows VM NSIS installer E2E (`#148`, `#71`/`#73`): Thực hiện khi build release bundle trên runner/VM sạch.
