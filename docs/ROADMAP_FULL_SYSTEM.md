# Roadmap triển khai hệ thống — Phạm vi Củng cố Demo Cuối kỳ (Consolidated MVP)

## Mục đích và nguyên tắc

Tài liệu này đồng bộ lộ trình từ đề cương gốc `docs/Ke_hoach_de_tai_22_AI_Anomaly_Detection.docx` thành **kiến trúc và phạm vi sản phẩm AI cuối kỳ có thể chạy, demo offline trên Windows và bàn giao được**. Đây là tài liệu phạm vi/kế hoạch thực tế gắn trực tiếp với GitHub issues và milestones (`M0–M7`), không tự thay thế bằng chứng kiểm chứng. Mọi claim phải truy vết theo `Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results` với các trạng thái trung thực (`PLANNED`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED`, `DEFERRED`, `REDUCED`, `BLOCKED / NOT READY`, `PASS`, `FAIL`, `SKIPPED`, `NOT VERIFIED`).

Raw dataset lớn, secret và model binaries không được commit vào Git. Hệ thống hoạt động cục bộ (`offline` sau khi chuẩn bị dependencies, artifacts và mẫu demo), tuyệt đối không tự động block mạng thật hoặc quy kết danh tính cá nhân.

## Kiến trúc đã chốt (MVP Củng cố)

- **Desktop UI (`CORE-DEMO`, #16, `v0.6.0`):** **Rust / Tauri 2 + Svelte 5** (ứng dụng desktop cục bộ trên Windows, đóng gói NSIS installer `NetFlow Sentinel M6_0.6.0_x64-setup.exe`). Rust đảm nhận native file dialogs, quản lý lifecycle (khởi chạy/giám sát health/tắt gọn) của Python backend process và typed HTTP client tới localhost; **không** dùng Streamlit, không thêm frontend thứ hai và không nhân bản ML inference trong Rust. *(Trạng thái hiện tại: `IMPLEMENTED / TESTED` trong `desktop/` tại PR #67; yêu cầu môi trường Python, repo root, `.joblib` artifacts và WebView2 Runtime bên ngoài — xem [WINDOWS_INSTALLATION.md](WINDOWS_INSTALLATION.md)).*
- **Backend & Storage (`IMPLEMENTED`, #30):** **Python FastAPI** chạy local-only trên `127.0.0.1:8000` (`scripts/run_api.py`), **SQLite** là cơ sở dữ liệu duy nhất do Python FastAPI làm chủ ghi (single writer, tránh Rust và Python ghi tranh chấp file DB). Contract chuẩn nằm tại `reports/api/openapi.json` và `reports/api/API_CONTRACT.md`.
- **AI / ML Pipeline (`CORE-ML`):**
  - 4 mô hình được giữ và hỗ trợ đồng nhất trong `InferencePipeline` / `ApiService` / `scripts/predict.py`: **Random Forest**, **XGBoost**, **Isolation Forest** và **Autoencoder**.
  - `TrainOnlyPreprocessor` + kiểm thực SHA-256 fail-closed cho mọi `.joblib`/`.pt` + `manifest`; thiếu artifact nhị phân phải báo `BLOCKED / NOT READY`, **không** tự tạo model giả hoặc fallback heuristic ẩn.
- **Demo CSV Contract (Validation-Only):** `scripts/prepare_demo_dataset.py` tái sử dụng hàm lấy mẫu `partition_indices` (`scripts/fetch_external_dataset.py` từ PR #47) để tạo 100–300 dòng cân bằng (mặc định 200 dòng: 100 Benign / 100 Attack) từ **Validation partition** (`validation_indices.csv.gz`), tách biệt `demo_flows.csv` (không chứa `Label`/`Attack`), `demo_labels.csv` và `demo_manifest.json`.
- **Thành phần rút gọn / hoãn để bảo vệ khả năng bàn giao MVP:**
  - `C5` (#28 Behavioral): **REDUCE / DEFER** — chỉ giữ thống kê trên NetFlow metadata có thật, loại bỏ Auth/API log giả lập.
  - `C6` (#32 Risk & #24 Trace): **REDUCE** — giảm xuống deterministic scoring/ranking từ output model + evidence timeline từ NetFlow metadata (`/api/v1/timeline`); không cần FFI/PyO3 hay graph engine lớn.
  - `C7` (#26 Encryption/Key Lifecycle): **DEFER** — chỉ giữ localhost-only safety, SHA-256 artifact gate và SQLite key metadata audit (`algorithm` chỉ là policy metadata, không phải AES-256-GCM đang mã hóa payload).
  - `C8` (#27 Adaptive Security Response Simulation / Dry-run): **IMPLEMENTED / TESTED (Dry-Run)** cho Stable/M7 — deterministic policy engine (`NO_ACTION`, `MONITOR`, `INVESTIGATE`, `ISOLATE_RECOMMENDED`), chỉ cấp `ISOLATE_RECOMMENDED` và mô phỏng rotation escalation từ `server_verified_analysis` (xác minh `analysis_id` qua in-memory CSV analysis registry có giới hạn dung lượng/retention, mất khi restart -> fail-closed 400; chặn spoof gate/mode và chặn model `RESEARCH_ONLY`/chưa `MODEL_VALIDATED` + `PREDICTION_AVAILABLE`), từ chối containment với `ABSTAINED_OOD`, lưu lịch sử simulation vào SQLite (`executed=false`, bounded recommendations) và xuất bằng chứng JSON từ Tab 4; **DEFERRED** đối với live firewall/OS commands và sinh/xoay khóa mật mã thật.

## GitHub, milestone và nhánh

- **Milestones lịch sử `M0–M5` được giữ nguyên.** Các milestone mục tiêu đang hoạt động:
  - **M3 (`#4`):** Đánh giá mô hình, provenance, leakage và reproducibility (#11, #14, #54, #55, #56).
  - **M6 (`#7`):** Rust/Tauri 2 + Svelte 5 Desktop UI (#16), Python FastAPI/SQLite (#30 CLOSED, #59 CLOSED), Canonical Ingestion & Demo Gate (#46 / PR #47, #58 CLOSED), và các module reduced/deferred (#24, #28, #32, #26, #27).
  - **M7 (`#8`):** Thực nghiệm trọng tâm (#25), Cross-Dataset robustness research (#48 / PR #49, #57 CLOSED), Audit tổng hợp (#60) và Tài liệu/Slide/QA bàn giao (#18–#20).
- **Trạng thái PR chính:** PR #52 đã đóng (`SUPERSEDED`); PR #47 (`f999930`, 6/6 CI PASS) và PR #49 (`7344994`, stacked trên PR #47) đang ở trạng thái **Ready for Review** chờ maintainer duyệt merge (`REVIEW_REQUIRED`).

## Checkpoint C0–C11 (Sau điều chỉnh phạm vi)

| Checkpoint | Phạm vi củng cố & Trạng thái hiện tại |
| --- | --- |
| C0 — Governance & Consolidation | #23 COMPLETED; rà soát backlog, đóng PR #52 superseded, hợp nhất contract 4 model + Validation demo CSV. |
| C1 — Data quality & EDA | #4–#7 COMPLETED; `NF-UNSW-NB15-v3.csv` (2.365.424 dòng), SHA-256 và EDA reproducibility đã xác minh. |
| C2 — Preprocessing | #8 COMPLETED; `TrainOnlyPreprocessor` fit chỉ trên Train (1.655.797 dòng) + verify hash-chain fail-closed. |
| C3 — Supervised ML | **Random Forest** (#9, #10, #12, #13): **EXPERIMENTALLY VALIDATED** cả Validation và Held-out Test (`rf-heldout-ea330b9`: `345.953` dòng, `F1=0.999853`, `TN=315350, FP=7, FN=2, TP=30594`). **XGBoost** (#31): **EXPERIMENTALLY VALIDATED trên Validation** (`345.371` dòng, `F1=0.999984`); Test `NOT VERIFIED`. |
| C4 — Unsupervised & Unknown Attacks | **Isolation Forest** (#11) **EXPERIMENTALLY VALIDATED** trên `NF-UNSW-NB15-v3` (`if-c4-20261115T055359Z`, clean commit `bf0f3ec`: benign-only Train, Validation threshold `-0.033527`, Held-out Test `F1=0.5064`, `Recall=0.8997`, Unknown `{Backdoor, Worms}` `Recall=0.8657`) và đạt `READY` trong `InferencePipeline`/`ApiService`. **Autoencoder** (#29 CLOSED, PR #51) **IMPLEMENTED / TESTED** với synthetic fixtures; real-data benchmark `NOT VERIFIED` (`BLOCKED / NOT READY` nếu thiếu binary). |
| C5 — Behavioral Vector (REDUCED) | #28 **REDUCE / DEFER**: chỉ thống kê theo NetFlow metadata thật nếu UI cần; không dùng Auth/API log không tồn tại. |
| C6 — Risk & Trace (REDUCED) | #32 Risk & #24 Trace **REDUCE**: deterministic priority ranking + timeline NetFlow metadata (`/api/v1/timeline`); không FFI phức tạp, không quy kết danh tính. |
| C7 — Encryption & Key Lifecycle (DEFERRED) | #26 **DEFER**: giữ SQLite key metadata audit + SHA-256 verification + localhost-only; hoãn full AES-256-GCM & 30-min rotation. |
| C8 — Adaptive Security Response Simulation / Dry-run | #27 **IMPLEMENTED / TESTED (Dry-Run)** trong M7/Stable: response policy tất định, mô phỏng adaptive key rotation không sinh/xoay khóa thật, Tab 4 + SQLite + JSON export, OOD non-containment; live OS firewall & AES-256-GCM auto-rotation **DEFERRED**. |
| C9 — Desktop App, FastAPI, SQLite & Demo Ingestion | **Python FastAPI + SQLite** (#30 CLOSED), `/api/v1/csv/*`, provenance verification (`source:nf-v3-canonical` vs `source:nf-v3-unverified`), OOD inference/risk abstention (`ABSTAINED_OOD`), `prepare_demo_dataset.py` và `API_CONTRACT.md` **IMPLEMENTED / TESTED**. **Desktop UI Rust/Tauri 2 + Svelte 5** (#16, `v0.6.0`) đã **IMPLEMENTED / TESTED** kèm bộ cài NSIS và release workflow `.github/workflows/release.yml`. |
| C10 — Focused Experiments & Cross-Dataset M7 | #25 **REDUCE** từ 7 xuống các thí nghiệm ML trọng tâm (Exp 1–3/4); Exp 5–7 thu gọn/hoãn theo C5–C8. #48 Cross-dataset research (PR #49 `7344994`) nằm ở M7, không chặn Demo MVP. |
| C11 — Delivery & QA | #18–#20, #60: đồng bộ docs, kịch bản demo offline trên Windows, báo cáo PDF, 10–12 slide và kiểm tra cổng bàn giao cuối kỳ. |

## Kiểm chứng chung

Mọi thay đổi chạy kiểm tra môi trường (`PYTHONPATH=src python scripts/check_environment.py`), `export_openapi_spec.py --check`, `compileall`, `ruff check`, `black --check`, `pytest tests -q` và `git diff --check`. Test bằng fixture synthetic chứng minh tính đúng đắn của phần mềm, **không** thay thế real-data experiment hay che lấp trạng thái `BLOCKED / NOT READY` khi thiếu file `.joblib`/`.pt` cục bộ.
