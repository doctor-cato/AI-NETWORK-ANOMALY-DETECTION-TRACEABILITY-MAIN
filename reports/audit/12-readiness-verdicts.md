# Report 12 — Readiness Verdicts

## 1. Định nghĩa mức sẵn sàng

| Mức | Ý nghĩa |
|---|---|
| **PLANNED** | Chỉ có thiết kế/tài liệu, chưa có code chạy được |
| **IMPLEMENTED** | Code tồn tại, chưa chứng minh chạy đúng |
| **TESTED** | Có test tự động, chủ yếu synthetic/fixture |
| **EXPERIMENTALLY VALIDATED** | Có artifact + dữ liệu thật + kết quả tái lập được |
| **BLOCKED** | Không thể chạy do thiếu dữ liệu/artifact |
| **NOT VERIFIED** | Không đủ bằng chứng để kết luận |

## 2. Bảng readiness theo năng lực

| Năng lực | Mức cao nhất đạt được | Bằng chứng | Thiếu gì |
|---|---|---|---|
| Data acquisition | **EXPERIMENTALLY VALIDATED** | raw 577.360.958 byte; SHA-256 khớp BagIt; fetch/manifest | CI chưa chạy real-data gate |
| Data validation | **EXPERIMENTALLY VALIDATED** | 2.365.424 dòng, hash khớp | Chưa có policy dedup |
| EDA | **EXPERIMENTALLY VALIDATED** | report + figures + summary | — |
| Split | **PARTIAL** | manifest + guards | Index thật không có trong Git; hash index `main` ≠ external |
| Preprocessing | **PARTIAL** | code + train-only tests | Artifact/hash chain không tái lập; Test partition bị materialize |
| RF training | **EXPERIMENTALLY VALIDATED (historical)** | artifact `801afcbb…`, metric validation | Không tái lập từ `main` |
| RF evaluation | **BLOCKED** | chưa có test metric | Test evaluation + prediction |
| RF inference | **PARTIAL (external)** | 1.000 dòng E2E | Main split fail; loader fail-open |
| XGBoost | **IMPLEMENTED** | code + manifest | Artifact, CLI, test eval |
| Isolation Forest | **IMPLEMENTED** | code + training script | Artifact, inference threshold |
| Autoencoder | **IMPLEMENTED (branch-only)** | PR #51 | Merge, artifact, real eval |
| Inference verification | **FAIL** | F-01/F-02 | Manifest bắt buộc, fail-closed |
| API | **IMPLEMENTED (branch-only)** | PR #52 | Merge + security audit |
| SQLite | **IMPLEMENTED (branch-only)** | PR #52 | Merge |
| Dashboard | **PLANNED** | #16 | Code |
| AES-GCM/key lifecycle | **PLANNED** | #26/#27 | Code |
| Behavioral Vector | **PLANNED** | #28 | Code |
| Risk/Trace Engine | **PLANNED** | #24/#32 | Code |
| CI | **TESTED (synthetic)** | matrix xanh | Real-data/artifact gate |
| Security | **FAIL** | CWE-502/integrity | Fail-closed + supply chain |
| Delivery | **PLANNED** | #19/#25 | PDF/slides/demo/handoff |

## 3. Readiness theo môi trường

### 3.1. Local research

**PARTIAL**: có thể chạy data/EDA/RF validation nếu có external artifact; không chạy được XGB/IF/AE.

### 3.2. CI

**PARTIAL**: 739 test pass; real-data steps SKIPPED; không có artifact/model thật.

### 3.3. Production

**NOT READY**:

- không có API/DB/dashboard;
- không có auth/security;
- model chưa test;
- provenance fail-open;
- không có monitoring/rollback.

### 3.4. Bàn giao nghiên cứu

**NOT READY**:

- không có PDF/slides/demo;
- không có experiment matrix #25;
- không có handoff package #19;
- issue/milestone không phản ánh thực tế.

## 4. Ma trận failure modes

| # | Tình huống | Hành vi quan sát | Đạt? |
|---|---|---|---|
| 1 | Thiếu raw dataset | CI skip, exit 0 | **SKIPPED**, không PASS |
| 2 | Thiếu preprocessor artifact | skip test, inference fail | **BLOCKED** |
| 3 | Thiếu RF `.joblib` | skip test | **SKIPPED** |
| 4 | Hash split mismatch | `verify_preprocessing_artifact` fail | **FAIL (đúng)** |
| 5 | Manifest rỗng | inference vẫn load | **FAIL (sai)** |
| 6 | Manifest `UNVERIFIED` | RF vẫn load | **FAIL (sai)** |
| 7 | XGB không artifact | CLI `Model artifact not found` | **FAIL** |
| 8 | IF artifact | raw `-1/1` | **FAIL semantics** |
| 9 | Input schema sai | `validate_inference_input` reject | **PASS** |
| 10 | Output trùng input | reject | **PASS** |
| 11 | Test partition bị chạm | không có audit toàn cục | **FAIL** |
| 12 | CI xanh | không chứng minh real-data | **False confidence** |

## 5. Điều kiện để nâng mức

| Từ | Lên | Điều kiện |
|---|---|---|
| IMPLEMENTED | TESTED | Có unit/integration test cho happy path + error path |
| TESTED | EXPERIMENTALLY VALIDATED | Artifact thật + dữ liệu thật + metric tái lập + manifest |
| EXPERIMENTALLY VALIDATED (validation) | EXPERIMENTALLY VALIDATED (test) | Chạy test đúng một lần, lưu prediction/metric/manifest |
| PARTIAL | READY | Fail-closed loader + canonical provenance + test metric + CI gate |

## 6. Verdict cuối

> **Repository READINESS: NOT READY.**
>
> - **Research data/EDA**: sẵn sàng.
> - **RF validation**: có bằng chứng lịch sử, không tái lập từ `main`.
> - **RF test**: chưa có.
> - **XGB/IF/AE**: chưa đủ.
> - **Inference**: fail-open.
> - **API/DB/dashboard/security**: chưa có trong `main`.
> - **Delivery**: chưa có.

Không được dùng bất kỳ mức nào cao hơn để trả lời “đã xong”.
