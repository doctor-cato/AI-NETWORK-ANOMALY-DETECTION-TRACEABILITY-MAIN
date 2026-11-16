# Roadmap triển khai hệ thống — NetFlow Sentinel v1.0.0 (Consolidated M7)

## Mục đích và nguyên tắc

Tài liệu này đồng bộ lộ trình từ đề cương gốc `docs/Ke_hoach_de_tai_22_AI_Anomaly_Detection.docx` thành **kiến trúc và phạm vi sản phẩm đồ án AI cuối kỳ (`NetFlow Sentinel v1.0.0`)**. Đây là tài liệu kế hoạch/phạm vi đối chiếu trực tiếp với GitHub issues và milestones (`M0–M7`), không tự thay thế bằng chứng kiểm chứng. Mọi claim truy vết theo `Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results` với các trạng thái trung thực (`PLANNED`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED`, `DEFERRED`, `REDUCED`, `BLOCKED / NOT READY`, `PASS`, `FAIL`, `SKIPPED`, `NOT VERIFIED`).

Raw dataset lớn, secret và model binaries không được commit vào Git. Hệ thống vận hành hoàn toàn offline trên Windows (`127.0.0.1`), tuyệt đối không tự động block mạng thật hoặc quy kết danh tính cá nhân.

## Kiến trúc đã chốt (`v1.0.0` Standalone — PR #72 đã hợp nhất)

- **Desktop UI & Sidecar Packaging (`#16`, `#71`, PR #72 merged):** **Rust / Tauri 2 + Svelte 5** quản lý **Python FastAPI PyInstaller Sidecar** (`netflow-sentinel-backend.exe`), đóng gói thành bộ cài NSIS x64 (`NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe`) tích hợp WebView2 Offline Installer, 4 model `.joblib`, preprocessor, manifests và `data/demo/`. Người dùng cuối **không cần cài Python, `.venv` hay Companion Bundle**. *(Phát hành `v1.0.0` hiện là Source Release trên GitHub; nghiệm thu Windows 10/11 VM sạch và cấp phép phân phối binary UQ `454104` chuyển theo dõi sang Issue #73).*
- **Backend & Storage (`#30` CLOSED):** **Python FastAPI** chạy loopback `127.0.0.1` với xác thực `X-Sentinel-Session-Token` (CSPRNG 256-bit theo phiên), **SQLite** là cơ sở dữ liệu single-writer đặt tại `%LOCALAPPDATA%\NetFlowSentinel\` (hoặc `data/` khi dev). Contract tại `reports/api/openapi.json` và `reports/api/API_CONTRACT.md`.
- **AI / ML Pipeline (`CORE-ML`):**
  - 4 mô hình được hỗ trợ đồng nhất: **Random Forest** (`MODEL_VALIDATED`), **XGBoost**, **Isolation Forest** và **Autoencoder (`MLPRegressor`)** (`RESEARCH_ONLY` trên UI/Gate).
  - `TrainOnlyPreprocessor` + kiểm thực SHA-256 fail-closed cho mọi `.joblib` + manifest; thiếu binary báo `BLOCKED / NOT READY` (`HTTP 503`), không tạo model giả.
- **Demo CSV Contract (Validation-Only):** `scripts/prepare_demo_dataset.py` tách 200 dòng cân bằng (100 Benign / 100 Attack) từ **Validation partition** (`0` overlap Train/Test): `demo_flows.csv` (không nhãn), `demo_labels.csv` và `demo_manifest.json`.
- **Thành phần rút gọn / hoãn để bảo vệ chất lượng bàn giao:**
  - `C5` (#28 Behavioral): **REDUCED / IMPLEMENTED** — chỉ thống kê metadata NetFlow, không giả lập Auth/API log.
  - `C6` (#32 Risk & #24 Trace): **REDUCED / IMPLEMENTED** — chấm điểm rủi ro tất định 0–100 (từ chối `ABSTAINED_OOD`) và timeline theo thời gian.
  - `C7` (#26 Local Security): **REDUCED / IMPLEMENTED** — localhost bind, session token, path validation, SHA-256 gate, SQLite key audit; full AES-256-GCM keyring & auto-rotation **DEFERRED**.
  - `C8` (#27 Adaptive Security Response Dry-Run): **IMPLEMENTED / TESTED (Dry-Run)** — policy engine tất định (`executed=false`), kiểm tra `server_verified_analysis` + chỉ cho phép `ISOLATE_RECOMMENDED` với `MODEL_VALIDATED`, lưu SQLite và xuất JSON; live firewall/OS commands **DEFERRED**.

## GitHub, milestone và trạng thái phát hành

- **Milestones lịch sử `M0–M5` được giữ nguyên.** Các milestone hoạt động: **M3 (`#4`)**, **M6 (`#7`)** và **M7 (`#8` — Experiments, Documentation & Delivery)**.
- **PR đã hợp nhất quan trọng:** PR #47 (`e02548b`, Ingestion Gate), PR #50 (RF Held-out Test), PR #51 (Autoencoder), PR #61 (FastAPI/SQLite + Audit), PR #66 (M3 Reproduction), PR #67/#68 (`v0.6.0-beta.1`), PR #69 (Security Dry-Run #27), PR #70 (`v0.6.0` 4-model E2E), và **PR #72 (`e5a1f89`, NetFlow Sentinel `v1.0.0` Standalone Installer & Source Release)**.
- **Open issues theo dõi tiếp:** `#18` (Tài liệu, Academic Defense, Website & Giấy phép), `#19` (Slide & Báo cáo), `#20` (Nghiệm thu bàn giao), `#25` & `#48` (Cross-dataset M7 — PR #49), `#60` (Audit tổng hợp), `#73` (Clean Windows 10/11 VM acceptance & quyền phân phối binary UQ `454104`).

## Checkpoint C0–C11 (Trạng thái hiện tại trên `main`)

| Checkpoint | Phạm vi & Trạng thái hiện tại |
| --- | --- |
| C0 — Governance & Consolidation | #23 **COMPLETED**; chốt phạm vi MVP và phân tầng `MODEL_VALIDATED` vs `RESEARCH_ONLY`. |
| C1 — Data quality & EDA | #4–#7 **COMPLETED**; `NF-UNSW-NB15-v3.csv` (`2.365.424` dòng), EDA reproducibility và chronological 5m-purged split đã xác minh. |
| C2 — Preprocessing | #8 **COMPLETED**; `TrainOnlyPreprocessor` (`scaler=none`, no OHE) fit chỉ trên Train (`1.655.797` dòng), SHA-256 `12d4360a...`. |
| C3 — Supervised ML | **Random Forest** (`rf-heldout-ea330b9`: `F1=0,999853`) và **XGBoost** (`xgb-baseline-1794755807`: `F1=0,999984`) đều **EXPERIMENTALLY VALIDATED** trên Validation & Held-out Test (`345.953` dòng). |
| C4 — Unsupervised & Unknown Attacks | **Isolation Forest** (`if-c4-20261115T055359Z`: Test `F1=0,5064`, `Recall=0,8997`, Unknown `0,8657`) và **Autoencoder `MLPRegressor`** (`ae_fpr_constrained_20261115T163000Z`: `Val FPR=0,049998 <= 0,05`, Test `F1=0,1361`, `Recall=0,1093`, Unknown `0,0625`) đều **EXPERIMENTALLY VALIDATED**. |
| C5 — Behavioral Vector (REDUCED) | #28 **IMPLEMENTED / TESTED** — thống kê NetFlow metadata kèm non-attribution notice. |
| C6 — Risk & Trace (REDUCED) | #32 & #24 **IMPLEMENTED / TESTED** — deterministic risk priority + evidence timeline. |
| C7 — Security & Key Audit (REDUCED) | #26 **IMPLEMENTED / TESTED** (localhost, CSPRNG token, path guard, SHA-256); AES-256-GCM keyring **DEFERRED**. |
| C8 — Adaptive Security Response Dry-Run | #27 **IMPLEMENTED / TESTED (Dry-Run)** (`executed=false`, Tab 4 + SQLite + export); live firewall **DEFERRED**. |
| C9 — Desktop App, FastAPI, Sidecar & `v1.0.0` | #30, #15, #16, #46, #71 (**PR #72 merged**): `v1.0.0` Source Release đã phát hành; binary installer & Clean VM E2E chuyển sang **#73 (`DEFERRED / BLOCKED`)**. |
| C10 — Focused Experiments & Cross-Dataset | #25, #48: Đánh giá cross-dataset RF trên `NF-CSE-CIC-IDS2018-v3` (`Recall=0,0`, `FPR=0,3802`) đã có bằng chứng; PR #49 tiếp tục ở M7. |
| C11 — Delivery & Academic Defense | #18–#20, #60 (**IN PROGRESS**): đồng bộ tài liệu end-user/developer, bộ hồ sơ [docs/academic-defense/](academic-defense/README.md), website `site-source`, slide và kiểm tra cổng bàn giao. |

## Kiểm chứng chung

Mọi thay đổi tuân thủ kiểm tra theo `AGENTS.md` và `.github/workflows/ci.yml`: `python scripts/check_environment.py`, `python scripts/export_openapi_spec.py --check`, `python scripts/check_desktop_version.py --check`, `python -m pytest tests -q`, `ruff`, `black --check`, `npm --prefix desktop run check/test/build`, `cargo clippy/test` và `git diff --check`.
