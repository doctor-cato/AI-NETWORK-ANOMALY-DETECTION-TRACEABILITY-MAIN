# Phạm vi dự án — NetFlow Sentinel v2.0

Nguồn yêu cầu: [docs/ROADMAP_FULL_SYSTEM.md](../../docs/ROADMAP_FULL_SYSTEM.md), [docs/TRACEABILITY_MATRIX.md](../../docs/TRACEABILITY_MATRIX.md) và đề cương [docs/Ke_hoach_de_tai_22_AI_Anomaly_Detection.docx](../../docs/Ke_hoach_de_tai_22_AI_Anomaly_Detection.docx). Phạm vi v2.0 hiện hành gồm Milestones **`M6.1–M6.7` (`#76–#155`)** sau **Hard Cutover v1 → v2** ([docs/MIGRATION_V1_TO_V2.md](../../docs/MIGRATION_V1_TO_V2.md)).

## Phạm vi bắt buộc (v2.0)

- **Active Datasets (`canonical-flow-v2-18`, 18 ML features):**
  - Chính thức: **`AIT-NDS-v2`** (`10.5281/zenodo.13168643`, `CC BY 4.0`, split theo scenario/host tại `data/V2_SPLIT_MANIFEST.json`: Train `2,097,891`, Val `377,704`, Test `988,805`).
  - Cross-source zero-shot: **`CTU-SME-11`** (`10.5281/zenodo.7958258`, `CC BY 4.0`: `ctu_echo`, `ctu_windows7ad`) và bổ sung **`UWF-ZeekData24`** (`CC BY 4.0`, `evaluation_only = true`).
  - Cách ly bản quyền & rào cản nguồn: **`AIT-LDS-v2.1`** (`CC BY-NC-SA 4.0`) tách khỏi ML weights và `data/demo/`; **`UGR'16`** giữ `BLOCKED` (`HTTP 403`). **`NF-UNSW-NB15-v3`** đã chuyển sang `historical/` archive (không fallback v1).
- **Preprocessing & OOD Gate:** `TrainOnlyPreprocessor` (`asinh_robust`, `MIN_BOUNDED_SCALE_FLOOR = 0.25`) fit thuần túy trên `ait_train`; `OODRejectionGate` (`artifacts/ml/ood_reference_gate.json`) + `deployment` mode fail-closed yêu cầu trusted `NETFLOW_OOD_GATE_SHA256` ngoài trust boundary.
- **4 Mô hình AI (`E0` baseline, tier `RESEARCH_ONLY`):**
  - Supervised: `Random Forest` và `XGBoost` (binary anomaly detection; phân loại đa lớp tách ở thí nghiệm riêng không ghi đè `E0`).
  - Unsupervised: `Isolation Forest` và `Autoencoder` (reconstruction error + percentile calibration/threshold chọn thuần trên `ait_val`). Unknown-attack evaluation dùng holdout (`RQ4`) không tham gia fit/tuning.
- **Behavioral, Risk & Trace:** 16-D versioned Behavioral Vector (`EventSessionizer`, `BehavioralVectorBuilder`, `EntityBaselineProfiler`, `BehavioralSimilarityCalculator`, `IPSpoofingSessionCorrelator`); `RiskScorer` `0–100` + 4 `AggregationPolicy` (`WEIGHTED_ENSEMBLE` mặc định); `EntityRelationshipGraph` & `AttackTimelineReconstructor` (phân biệt `observed` vs `inferred`, non-attribution).
- **Security & Crypto Layer:** `AES-256-GCM`, `KeyManager` (`DPAPI` / POSIX perms, không hardcode secret), `EncryptedStorageVault` (ciphertext at-rest), fixed `30`-minute & adaptive rotation (`Risk >= 85` non-OOD), cooldown/rate-limit, `KEYSTORE_RUNBOOK.md`.
- **Containment, Collector & Stack:** Security response mặc định dry-run (`executed = false`; không auto-block/cô lập hệ thống thật). Python `UDPFlowCollector` (`#131`, NetFlow v9/IPFIX) + `StreamingEventPipeline` (`capacity = 10_000`; Rust collector `#128` giữ `DEFERRED`). Stack: **FastAPI + SQLite + Svelte 5 + Rust/Tauri 2** (chưa phát hành công khai, `DISTRIBUTION_AUTHORIZATION.json` giữ `approved: false`).

## Ranh giới khoa học và an toàn

- Không gọi unknown-attack holdout hoặc cross-source `RESEARCH_ONLY` model là sẵn sàng production hoặc phát hiện zero-day tổng quát.
- Không dùng `ait_test` hay target dataset để chọn feature, hyperparameter, threshold hoặc calibration (nếu tham chiếu hậu nghiệm phải khai báo `holdout_independent_selection = false`).
- Không gọi fixture synthetic hay localhost UDP loopback/replay là nghiệm thu thiết bị switch/router vật lý (`#137`).
- Không tự tải/commit raw/processed dataset lớn, model `.joblib` lớn, key material hay ghi đè `E0` baseline khi chưa được giao.
- Không tự thiết kế cryptography; `LSTM/Transformer/GNN`, `post-quantum`, `SOAR` thật và auto-containment ngoài phạm vi.

## Trạng thái và bằng chứng

Dùng `PLANNED`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED` cho vòng đời và `PASS`, `FAIL`, `SKIPPED`, `NOT VERIFIED` cho kiểm chứng. Chuỗi bắt buộc:
`Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results`.
