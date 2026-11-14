# Yêu cầu hệ thống — Phạm vi Củng cố Demo Cuối kỳ

## Yêu cầu chức năng (Functional Requirements)

| ID | Yêu cầu (Sau rà soát củng cố) | Checkpoint | Issue | Trạng thái / Ghi chú phạm vi |
|---|---|---|---|---|
| F01 | Provenance, schema, quality, EDA và leakage audit `NF-UNSW-NB15-v3` | C1 | #4–#7 | **COMPLETED** |
| F02 | Split trước fit; preprocessing artifact (`TrainOnlyPreprocessor`) và leakage tests | C2 | #8 | **COMPLETED** |
| F03 | Random Forest và XGBoost theo cùng supervised binary protocol | C3 | #9, #10, #12, #13, #31 | **RF Held-out Test VERIFIED**; XGBoost Validation VERIFIED |
| F04 | Isolation Forest và Autoencoder; validation-only threshold; unknown holdout protocol | C4 | #11, #29 | **IMPLEMENTED / TESTED** (code + tests + 4-model inference loading); real-data experiment `NOT VERIFIED` |
| F05 | Thống kê/tổng hợp hành vi chỉ từ NetFlow metadata có thật (loại Auth/API log) | C5 | #28 | **REDUCED / DEFERRED** (không chặn MVP) |
| F06 | Deterministic Risk Ranking & Evidence Timeline từ NetFlow metadata qua FastAPI | C6 | #32, #24 | **REDUCED** (thay thế graph engine & Rust FFI phức tạp) |
| F07 | An toàn cục bộ (localhost bind, SHA-256 fail-closed, SQLite key metadata audit) | C7 | #26 | **DEFERRED / REDUCED** (hoãn full AES-256-GCM keyring & auto-rotation) |
| F08 | Khuyến nghị/phản ứng bảo mật | C8 | #27 | **DEFERRED** (ngoài phạm vi Demo MVP) |
| F09 | Python FastAPI + SQLite (single writer), Validation Demo CSV (`prepare_demo_dataset.py`), Eligibility Gate và **Desktop UI Rust / Tauri 2 + Svelte 5** (thay Streamlit) | C9 | #30, #15, #17, #46, #16 | Backend/Inference/Demo Prep **IMPLEMENTED / TESTED**; PR #47 chờ review; **Rust/Tauri 2 UI (#16) PLANNED** |
| F10 | Thực nghiệm trọng tâm (Exp 1–3/4) có protocol/artifact/reproduction & Cross-dataset M7 | C10 | #25, #48 | **REDUCED** (Exp 5–7 thu gọn/hoãn theo C5–C8; #48 PR #49 không chặn M6) |
| F11 | Tài liệu đồng bộ, báo cáo PDF, 10–12 slides, demo offline Windows và handoff 5 vai trò | C11 | #18–#20 | **IN PROGRESS** |

## Yêu cầu phi chức năng (Non-Functional Requirements)

| ID | Yêu cầu | Kiểm chứng |
|---|---|---|
| N01 | Python `>=3.11` (`src/network_anomaly/`) cho ML & FastAPI; Rust/Tauri 2 + Svelte 5 cho Windows Desktop UI | `check_environment.py`, CI matrix, Tauri build check (khi triển khai #16) |
| N02 | Không đưa secret, key, raw CSV lớn, `.joblib`/`.pt` nặng hoặc `data/demo/*.csv` vào Git | `.gitignore`, `ci.yml` raw-data guard, `git status` |
| N03 | Kiểm tra 47 ML features & SHA-256 fail-closed; báo `BLOCKED / NOT READY` nếu thiếu binary; không dùng model giả | `test_inference_pipeline.py`, `test_api_service.py`, `test_prepare_demo_dataset.py` |
| N04 | Truy vết mọi kết quả/dự đoán demo tới `dataset_sha256`, `split_manifest_sha256`, `preprocessor_sha256`, `model_sha256`, `demo_manifest.json` | `rf-heldout-ea330b9`, `prepare_demo_dataset.py`, `predict.py` |
| N05 | Tách biệt rõ `PLANNED` / `IMPLEMENTED` / `TESTED` / `EXPERIMENTALLY VALIDATED` / `DEFERRED` và `READY` / `BLOCKED` | Traceability & Audit review (#60) |
| N06 | Mã nguồn `Apache-2.0`; giữ điều khoản phi thương mại `Permitted Re-Use with Commercial Use Restriction` của `NF-UNSW-NB15-v3` (DOI `10.48610/6E0EDA1`) | `LICENSE`, license inventory (#18) |
| N07 | FastAPI chỉ bind `127.0.0.1` cục bộ; hoạt động offline sau khi chuẩn bị dependencies, artifact và `data/demo/` | `run_api.py` default `--host 127.0.0.1`, tests |

## Điều kiện trung thực

- Unit/integration tests với fixture synthetic chỉ chứng minh hành vi mã nguồn; **không** thay thế `EXPERIMENTALLY VALIDATED` trên `NF-UNSW-NB15-v3`.
- Mọi tính năng `REDUCED` hoặc `DEFERRED` so với `docs/Ke_hoach_de_tai_22_AI_Anomaly_Detection.docx` phải được công bố minh bạch trong tài liệu và báo cáo bảo vệ (#18, #19).
