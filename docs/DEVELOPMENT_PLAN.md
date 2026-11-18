# Kế hoạch triển khai — NetFlow Sentinel v2 (C0–C11 & Lộ trình Milestone)

> Bảng lịch sử `v1.0.0` (`NF-UNSW-NB15-v3`) đã được lưu trữ chỉ đọc tại [`docs/historical/nf_unsw_nb15_v3/`](historical/nf_unsw_nb15_v3/). Bảng dưới đây phản ánh trạng thái **NetFlow Sentinel v2** trên nhánh `feat/v2-integration`.

## Thứ tự Milestone Roadmap v2 (7 Giai đoạn Chuẩn hóa)

1. **Dataset governance và acquisition:** Hard cutover ADR, lưu trữ v1 vào `historical/`, audit nguồn (`AIT-NDS-v2`, `AIT-LDS-v2.1`, `AIT-ADS`, `CTU-SME-11`; `UGR'16 BLOCKED` HTTP 403), verified manifests & checksums.
2. **Profiling, quality, labeling và feature engineering:** Chunk-based profiling, quality gate, duplicate audit, phân tích khả năng liên kết AIT (`NOT VERIFIED`), hợp đồng `canonical-flow-v2-18` và `taxonomy-v2` (chống ép `background`→`Benign`).
3. **Preprocessing và split:** Scenario-disjoint split `v2-scenario-group-purged-v1` (0 overlap), `TrainOnlyPreprocessor(asinh_robust)` fit chỉ trên `ait_train`.
4. **Retraining 4 model:** Huấn luyện mới từ đầu Random Forest, XGBoost, Isolation Forest, Autoencoder với manifest/threshold/SHA-256 riêng (`AI Ready 4/4`).
5. **Cross-dataset evaluation:** Đánh giá `AIT-Test` (`988,805` flows) và traffic thực tế `CTU-SME-11` (`CTU-Echo`, `CTU-Windows7AD`), báo cáo trung thực domain-shift collapse & `UGR'16 BLOCKED`.
6. **Multi-source behavioral, risk và trace integration:** Behavioral Vector 16-D, Sessionizer, Risk Engine `[0..100]`, Trace Engine & Attack Timeline, AES-256-GCM Adaptive Key Rotation (`RQ3`, `RQ5`, `RQ6`).
7. **Product integration, QA và release:** `ModelRegistry` v2 fail-closed, FastAPI + Desktop Rust/Tauri 2 + Svelte 5, viết lại active docs, tối ưu CI/CD, đồng bộ Issues & Draft PR #156.

---

## Trạng thái Checkpoint C0–C11 (`feat/v2-integration`)

| Thứ tự | Checkpoint | Trạng thái thực tế v2 (`feat/v2-integration`) |
|---|---|---|
| 1 | C0 Governance & V2 Migration Map | **COMPLETED** — Khóa hard cutover, tách historical `nf_unsw_nb15_v3/` (`ADR-dataset-hard-cutover-v2.md`, `MIGRATION_V1_TO_V2.md`, `V2_DEPENDENCY_GRAPH.md`) |
| 2 | C1 Data Acquisition & Quality | **COMPLETED** — Xác minh SHA-256 `AIT-NDS-v2`, `AIT-LDS-v2.1`, `AIT-ADS`, `CTU-SME-11` (CC BY 4.0); `UGR'16` ghi nhận `BLOCKED`; AIT linkage `NOT VERIFIED` |
| 3 | C2 Contract, Split & Preprocessing | **COMPLETED** — `canonical-flow-v2-18`, `taxonomy-v2`, `v2-scenario-group-purged-v1` (0 overlap), `TrainOnlyPreprocessor(asinh_robust)` (`0866dec7...`) |
| 4 | C3 Supervised ML v2 | **COMPLETED — EXPERIMENTALLY VALIDATED**: RF (`F1=0.9950`), XGBoost (`F1=0.9013`) trên `AIT-Test` (`988,805` flows) |
| 5 | C4 Unsupervised ML v2 | **COMPLETED — EXPERIMENTALLY VALIDATED**: IF (`F1=0.5842`), AE (`F1=0.5877`) trên `AIT-Test`; IF đạt `F1=0.8853` trên `CTU-Echo` |
| 6 | C5 Behavioral Vector | **IMPLEMENTED / TESTED** — 16-D Behavioral Vector + Sessionizer (`RQ3` simulation; empirical AIT linkage `BLOCKED`) |
| 7 | C6 Risk & Trace | **IMPLEMENTED / TESTED** — Risk Engine `[0..100]` + Entity Graph + Attack Timeline |
| 8 | C7 AES-256-GCM & Key Rotation | **IMPLEMENTED / TESTED / BENCHMARKED** — DPAPI/POSIX key wrapping, Adaptive Key Rotation (`RQ5`, `RQ6`) |
| 9 | C8 Security Dry-Run | **IMPLEMENTED / TESTED (Dry-Run)** — `executed=false` |
| 10 | C9 FastAPI, Desktop UI & Sidecar | **IMPLEMENTED / TESTED** — 18-feature `canonical-flow-v2-18`, `AI Ready 4/4`, `verify_companion_artifacts.py` `READY`, `vitest` & `cargo test` PASS |
| 11 | C10 RQ1–RQ6 & Cross-Source Real Capture | **COMPLETED** — Chạy đầy đủ RQ1–RQ6 + `run_ctu_cross_source_eval.py` (`CTU-Echo` & `CTU-Windows7AD`) |
| 12 | C11 Docs, CI & Final Verification | **IN PROGRESS (Finalizing on Draft PR #156)** — Hoàn thiện đồng bộ active docs v2, test remediation, GitHub Issues & Draft PR #156 |
