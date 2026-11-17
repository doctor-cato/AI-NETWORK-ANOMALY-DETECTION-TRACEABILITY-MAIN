# Roadmap triển khai hệ thống — NetFlow Sentinel v2

> Tài liệu mô tả kiến trúc và lộ trình hiện hành của **NetFlow Sentinel v2** trên nhánh `feat/v2-integration` (Draft PR #156). Các ghi nhận lịch sử `v1.0.0` (`NF-UNSW-NB15-v3`) nằm tại [`docs/historical/nf_unsw_nb15_v3/`](historical/nf_unsw_nb15_v3/).

## Kiến trúc Tổng thể v2

- **Desktop UI & Sidecar (`desktop/`):** Rust / Tauri 2 + Svelte 5 quản lý Python FastAPI PyInstaller Sidecar (`127.0.0.1`, token `X-Sentinel-Session-Token`), SQLite (`%LOCALAPPDATA%\NetFlowSentinel\`). Toàn bộ upload CSV, demo workflow và 4-model compare dùng hợp đồng v2 `canonical-flow-v2-18` (18 ML features).
- **AI / ML Pipeline (`src/network_anomaly/`):**
  - 4 mô hình v2 huấn luyện từ đầu trên `AIT-NDS-v2`: **Random Forest**, **XGBoost**, **Isolation Forest**, **Autoencoder**, với kiểm thực SHA-256 fail-closed (`AI Ready 4/4`, zero fallback sang v1).
  - Tiền xử lý `TrainOnlyPreprocessor(scaler_type="asinh_robust")` fit duy nhất trên `ait_train` (`1,930,219` flows).
  - Đánh giá domain shift trên dữ liệu thực tế `CTU-SME-11` (`CTU-Echo` và `CTU-Windows7AD`); nguồn `UGR'16` giữ trạng thái `BLOCKED`.
- **Behavioral, Risk, Trace & Crypto Engines:** Behavioral Vector 16-D, Sessionizer, Risk Scoring `[0..100]`, Trace Engine / Attack Timeline, AES-256-GCM với Adaptive Key Rotation và Security Dry-Run (`executed=false`).
- **Demo CSV Contract (`data/demo/`):** `scripts/prepare_demo_dataset.py` tách 200 dòng cân bằng (100 Benign / 100 Attack) từ Validation partition (`russellmitchell`) của `AIT-NDS-v2`.

## Trạng thái Checkpoint C0–C11 & Thứ tự Milestone v2

Thứ tự 7 giai đoạn chuẩn hóa của NetFlow Sentinel v2:
1. Dataset governance và acquisition (`ADR-dataset-hard-cutover-v2.md`, `V2_SOURCE_AUDIT.md`).
2. Profiling, quality, labeling và feature engineering (`canonical-flow-v2-18`, `taxonomy-v2`).
3. Preprocessing và split (`v2-scenario-group-purged-v1`, `TrainOnlyPreprocessor(asinh_robust)`).
4. Retraining 4 model (Random Forest, XGBoost, Isolation Forest, Autoencoder — `AI Ready 4/4`).
5. Cross-dataset evaluation (`AIT-Test` + `CTU-SME-11`; `UGR'16 BLOCKED`).
6. Multi-source behavioral, risk và trace integration (Behavioral Vector 16-D, Risk Engine, Trace Engine, AES-256-GCM Adaptive Key Rotation).
7. Product integration, QA và release (FastAPI + Desktop Tauri 2/Svelte 5, active docs, CI/CD, Issues & Draft PR #156).

Xem bảng cập nhật chi tiết tại [`docs/DEVELOPMENT_PLAN.md`](DEVELOPMENT_PLAN.md) và [`docs/TRACEABILITY_MATRIX.md`](TRACEABILITY_MATRIX.md).
