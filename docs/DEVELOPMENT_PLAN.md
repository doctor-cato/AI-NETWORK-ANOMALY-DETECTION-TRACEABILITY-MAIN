# Kế hoạch triển khai — Lộ trình Củng cố & Hoàn thiện v1.0.0 (C0–C11)

| Thứ tự | Checkpoint | Milestone | Phạm vi & Trạng thái thực tế trên `main` (`e5a1f89`) |
|---|---|---|---|
| 1 | C0 Governance & consolidation | M7 (#23) | **COMPLETED** (#23 CLOSED; chốt kiến trúc Tauri 2 + Svelte 5 + FastAPI + 4 ML models) |
| 2 | C1 Data quality & EDA | M1 (#4–#7) | **COMPLETED** (`NF-UNSW-NB15-v3.csv` verified `2.365.424` dòng, EDA reproducibility PASS, chronological split + 5m purge gap PASS) |
| 3 | C2 Preprocessing | M2 (#8) | **COMPLETED** (`TrainOnlyPreprocessor` fit chỉ trên Train `1.655.797` dòng, SHA-256 `12d4360a...`) |
| 4 | C3 Supervised ML | M2–M3 (#9, #10, #12, #13, #31) | **COMPLETED — EXPERIMENTALLY VALIDATED**: Random Forest (`rf-heldout-ea330b9`, Test `F1=0,999853`) và XGBoost (`xgb-baseline-1794755807`, Test `F1=0,999984`) đều đã có Held-out Test (`345.953` dòng) |
| 5 | C4 Unsupervised & unknown | M3 (#11, #29) | **COMPLETED — EXPERIMENTALLY VALIDATED**: Isolation Forest (`if-c4-20261115T055359Z`, Test `F1=0,5064`, Unknown `0,8657`) và Autoencoder `MLPRegressor` (`ae_fpr_constrained_20261115T163000Z`, `Val FPR=0,049998 <= 0,05`, Test `F1=0,1361`, Unknown `0,0625`) |
| 6 | C5 Behavioral Vector | M6 (#28) | **REDUCED / IMPLEMENTED & TESTED** — thống kê NetFlow metadata thật + non-attribution notice |
| 7 | C6 Risk & Trace | M6 (#32, #24) | **REDUCED / IMPLEMENTED & TESTED** — deterministic risk priority 0–100 + NetFlow evidence timeline |
| 8 | C7 Local Security & Key Audit | M6 (#26) | **REDUCED / IMPLEMENTED & TESTED** — loopback `127.0.0.1`, 256-bit `X-Sentinel-Session-Token`, SHA-256 gate, path guard, SQLite key audit; full AES-256-GCM keyring **DEFERRED** |
| 9 | C8 Adaptive Security Response Dry-Run | M6/M7 (#27) | **IMPLEMENTED / TESTED (Dry-Run)** — PR #69 merged (`executed=false`, Tab 4 + SQLite + JSON export, OOD guard); live firewall/OS commands **DEFERRED** |
| 10 | C9 Backend, Ingestion, Desktop UI & Packaging | M6/M7 (#30, #15, #16, #46, #71) | **IMPLEMENTED / TESTED (`v1.0.0` Source Release)** — PR #47, #67, #70, #72 merged: 18 FastAPI endpoints, SQLite, 4-model PyInstaller sidecar, NSIS packaging scripts, 4-step UI. Clean Windows VM & Public Binary Release **DEFERRED / BLOCKED → #73** |
| 11 | C10 Focused Experiments & Cross-Dataset | M7 (#25, #48) | **IN PROGRESS (M7)** — Cross-dataset RF trên `NF-CSE-CIC-IDS2018-v3` ghi nhận `Recall=0,0`, `FPR=0,3802`; PR #49 tiếp tục mở rộng nghiên cứu M7 |
| 12 | C11 Delivery, Academic Defense & QA | M7 (#18–#20, #60) | **IN PROGRESS** — đồng bộ docs (`README`, `docs/`, `docs/academic-defense/`), cập nhật website `site-source`, slide/PDF và nghiệm thu bàn giao |

**Lưu ý quy trình:** Các milestone lịch sử `M0–M5` được giữ nguyên. Phát hành `v1.0.0` hiện tại là **Source Release**; phát hành bộ cài Windows `.exe` công khai chỉ thực hiện khi các tiêu chí tại Issue #73 (`AC-03, 07, 08, 10, 12, 13, 14, 15`) đạt nghiệm thu và quyền phân phối được phê duyệt hợp lệ.
