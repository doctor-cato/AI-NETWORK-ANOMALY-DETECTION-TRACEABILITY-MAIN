# Yêu cầu hệ thống — NetFlow Sentinel v1.0.0 (Consolidated M7)

## Yêu cầu chức năng (Functional Requirements)

| ID | Yêu cầu (Sau rà soát củng cố) | Checkpoint | Issue | Trạng thái / Ghi chú phạm vi |
|---|---|---|---|---|
| F01 | Provenance, schema (55 cột), quality, EDA và leakage audit `NF-UNSW-NB15-v3` | C1 | #4–#7 | **COMPLETED** |
| F02 | Chronological 5m-purged split trước fit; preprocessing artifact (`TrainOnlyPreprocessor`, `scaler=none`, no OHE) và leakage tests | C2 | #8 | **COMPLETED** |
| F03 | Random Forest và XGBoost theo cùng supervised binary protocol | C3 | #9, #10, #12, #13, #31 | **EXPERIMENTALLY VALIDATED** cả Validation và Held-out Test (`rf-heldout-ea330b9`, `xgb-baseline-1794755807`) |
| F04 | Isolation Forest và Autoencoder (`MLPRegressor`); validation-only threshold (`FPR <= 0.05`); unknown holdout `{Backdoor, Worms}` | C4 | #11, #29 | **EXPERIMENTALLY VALIDATED** (`if-c4-20261115T055359Z`, `ae_fpr_constrained_20261115T163000Z` với `Val FPR=0,049998 <= 0,05`); tách biệt `raw_anomaly_score` với `attack_probability=null`; báo `BLOCKED / NOT READY` nếu thiếu binary |
| F05 | Thống kê/tổng hợp hành vi chỉ từ NetFlow metadata có thật (loại Auth/API log) | C5 | #28 | **REDUCED / IMPLEMENTED & TESTED** |
| F06 | Deterministic Risk Ranking (`0–100`, từ chối `ABSTAINED_OOD`) & Evidence Timeline từ NetFlow metadata qua FastAPI | C6 | #32, #24 | **REDUCED / IMPLEMENTED & TESTED** |
| F07 | An toàn cục bộ (loopback `127.0.0.1`, 256-bit `X-Sentinel-Session-Token`, SHA-256 fail-closed, path validation, SQLite key metadata audit) | C7 | #26 | **IMPLEMENTED / TESTED (Scoped)** — full AES-256-GCM keyring & auto-rotation **DEFERRED** |
| F08 | Adaptive Security Response Simulation / Dry-run (`NO_ACTION`, `MONITOR`, `INVESTIGATE`, `ISOLATE_RECOMMENDED`; chỉ cấp `ISOLATE_RECOMMENDED` khi `server_verified_analysis` + `MODEL_VALIDATED` + `PREDICTION_AVAILABLE`; chặn `RESEARCH_ONLY` & `ABSTAINED_OOD`; Tab 4 + SQLite + JSON export) | C8 | #27 | **IMPLEMENTED / TESTED (Dry-Run)** (`executed=false`) — live OS firewall, PowerShell/system execution & AES-256-GCM keyring **DEFERRED** |
| F09 | Python FastAPI (`18` endpoints) + SQLite (single writer), Validation Demo CSV (`prepare_demo_dataset.py`), Eligibility Gate, PyInstaller Sidecar và **Desktop UI Rust / Tauri 2 + Svelte 5** (`v1.0.0`) | C9 | #30, #15, #16, #46, #71 | **IMPLEMENTED / TESTED (`v1.0.0` Source Release)** — PR #72 merged; người dùng cuối cài qua NSIS không cần Python/Companion Bundle; Clean Windows VM & Public Binary Release **DEFERRED / BLOCKED → #73** |
| F10 | Thực nghiệm trọng tâm (Exp 1–3/4) có protocol/artifact/reproduction & Cross-dataset M7 | C10 | #25, #48 | **IN PROGRESS (M7)** — RF cross-dataset trên `NF-CSE-CIC-IDS2018-v3` đã có bằng chứng; PR #49 nghiên cứu tiếp |
| F11 | Tài liệu End User / Developer / Academic Defense (`docs/academic-defense/`), website `site-source`, slide/PDF, kiểm tra giấy phép & bàn giao 5 vai trò | C11 | #18–#20 | **IN PROGRESS** |

## Yêu cầu phi chức năng (Non-Functional Requirements)

| ID | Yêu cầu | Kiểm chứng |
|---|---|---|
| N01 | Python `>=3.11` (`src/network_anomaly/`) cho ML & FastAPI; Rust/Tauri 2 + Svelte 5 + PyInstaller Sidecar cho Windows Desktop UI `v1.0.0` | `check_environment.py`, CI matrix, Svelte check/Vitest, Cargo clippy/test |
| N02 | Không đưa secret, key, raw CSV lớn, `.joblib` nặng, installer `.exe` hoặc `data/demo/*.csv` vào Git | `.gitignore`, `ci.yml`, `release.yml` source-only guard, `git status` |
| N03 | Kiểm tra 47 ML features & SHA-256 fail-closed; từ chối `ABSTAINED_OOD` khi `MIN_TTL==0` hoặc lỗi vật lý; báo `BLOCKED / NOT READY` (`HTTP 503`) nếu thiếu binary | `test_inference_pipeline.py`, `test_api_service.py`, `test_four_model_integrity_e2e.py`, `test_ood_gate.py` |
| N04 | Truy vết mọi kết quả/dự đoán demo tới `dataset_sha256`, `split_manifest_sha256`, `preprocessor_sha256`, `model_sha256`, `demo_manifest.json` | `rf-heldout-ea330b9`, `prepare_demo_dataset.py`, `predict.py`, `/api/v1/csv/export` |
| N05 | Tách biệt rõ `PLANNED` / `IMPLEMENTED` / `TESTED` / `EXPERIMENTALLY VALIDATED` / `DEFERRED` và `MODEL_VALIDATED` vs `RESEARCH_ONLY` | `docs/TRACEABILITY_MATRIX.md`, `docs/academic-defense/EVIDENCE_INDEX.md` |
| N06 | Mã nguồn `Apache-2.0`; giữ điều khoản phi thương mại `Permitted Re-Use with Commercial Use Restriction` của `NF-UNSW-NB15-v3` (DOI `10.48610/6E0EDA1`, UQ `454104`) | `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `DISTRIBUTION_AUTHORIZATION.json` |
| N07 | FastAPI chỉ bind `127.0.0.1` với `X-Sentinel-Session-Token`; hoạt động offline hoàn toàn sau khi cài đặt | `desktop/src-tauri/src/backend.rs`, `src/network_anomaly/api/main.py`, `test_api_security.py` |

## Điều kiện trung thực

- Unit/integration tests với fixture synthetic chỉ chứng minh hành vi mã nguồn; **không** thay thế `EXPERIMENTALLY VALIDATED` trên `NF-UNSW-NB15-v3`.
- Mọi tính năng `REDUCED` hoặc `DEFERRED` so với `docs/Ke_hoach_de_tai_22_AI_Anomaly_Detection.docx` được công bố minh bạch trong [docs/academic-defense/07_MODEL_RESULTS_AND_LIMITATIONS.md](academic-defense/07_MODEL_RESULTS_AND_LIMITATIONS.md) và các tài liệu dự án (#18, #19).
