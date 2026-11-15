# Kế hoạch triển khai — Lộ trình Củng cố Demo Cuối kỳ (C0–C11)

| Thứ tự | Checkpoint | Milestone | Phạm vi sau rà soát & Trạng thái |
|---|---|---|---|
| 1 | C0 Governance & consolidation | M7 (#23) | **COMPLETED** (công tác C0 cơ bản đóng; tiếp tục cập nhật backlog/docs đồng bộ demo MVP) |
| 2 | C1 Data quality & EDA | M1 (#4–#7) | **COMPLETED** (`NF-UNSW-NB15-v3.csv` verified, EDA reproducible, split/leakage audit) |
| 3 | C2 Preprocessing | M2 (#8) | **COMPLETED** (`TrainOnlyPreprocessor` fit chỉ trên Train 1.655.797 dòng) |
| 4 | C3 Supervised ML | M2–M3 (#9, #10, #12, #13, #31) | **COMPLETED** với Random Forest (`rf-heldout-ea330b9` Test verified); **XGBoost (#31 CLOSED)** verified trên Validation, Test `NOT VERIFIED` |
| 5 | C4 Unsupervised & unknown | M3 (#11, #29) | **Isolation Forest (#11)** **EXPERIMENTALLY VALIDATED** & **REPRODUCED** trên `NF-UNSW-NB15-v3` (`if-c4-20261115T053123Z`: Test `Recall=0.8997`, `FPR=0.1605`, Unknown `Backdoor`/`Worms` `Recall=0.8657`); **Autoencoder (#29 CLOSED)** `IMPLEMENTED / TESTED` (synthetic) |
| 6 | C5 Behavioral Vector | M6 (#28) | **REDUCED / DEFERRED** — chỉ giữ thống kê NetFlow metadata thật nếu cần |
| 7 | C6 Risk & Trace | M6 (#32, #24) | **REDUCED** — deterministic risk ranking & NetFlow evidence timeline qua FastAPI |
| 8 | C7 Encryption & key lifecycle | M6 (#26) | **DEFERRED** — chỉ giữ SHA-256 verification, localhost-only & SQLite key metadata audit |
| 9 | C8 Adaptive response | M6 (#27) | **DEFERRED** — ngoài phạm vi Demo MVP M6 |
| 10 | C9 Backend, Ingestion & Desktop UI | M6 (#30, #15, #17, #46, #16) | **Python FastAPI + SQLite (#30 CLOSED)**, 4-model API/CLI & Validation Demo CSV (`prepare_demo_dataset.py`) **IMPLEMENTED / TESTED**. **PR #47 (#46/#58)** chờ duyệt merge. **Desktop UI Rust/Tauri 2 + Svelte 5 (#16 OPEN)** là hạng mục `CORE-DEMO` đang chờ triển khai |
| 11 | C10 Focused Experiments & Cross-Dataset | M7 (#25, #48) | **REDUCED / DEFERRED sang M7** — tập trung Exp 1–3/4; Cross-dataset research PR #49 (`7344994`) không chặn MVP |
| 12 | C11 Delivery & QA | M7 (#18–#20, #60) | **IN PROGRESS** — đồng bộ docs, kiểm chứng CI/QA, slide/PDF & đóng gói bàn giao offline |

**Lưu ý quy trình:** Các milestone lịch sử `M0–M5` được giữ nguyên. Mọi PR đều chịu bảo vệ nhánh (`REVIEW_REQUIRED`) của GitHub trước khi hợp nhất vào `main`.
