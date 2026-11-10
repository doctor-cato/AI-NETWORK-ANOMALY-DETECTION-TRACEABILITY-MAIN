# Report 03 — PR Matrix

## 1. Tổng quan

Có **19 PR** trong phạm vi quan sát:

- **13 merged**: #21, #22, #33, #34, #35, #36, #38, #40, #41, #42, #43, #44, #45.
- **1 closed không merge**: #39 (bị #43 thay thế).
- **5 open**: #47, #49, #50, #51, #52; trong đó #47, #49, #52 là draft.

Chỉ 4 PR merge nằm trong commit range `b212377..b14dfee` (#44, #45, #38, #40). Các PR còn lại thuộc lịch sử trước baseline hoặc chưa merge.

## 2. Ma trận PR

| PR | Trạng thái | Issue đích | Vấn đề đặt ra | Kết quả thực tế | Verdict |
|---|---|---|---|---|---|
| #21 | MERGED | — | Hoàn thiện skills/audit workflow | Docs/agent skills | **PASS (docs)** |
| #22 | MERGED | #4, #5 | Thu thập và kiểm định UNSW-NB15 | Data acquisition/validation ban đầu (2015), sau đó migrate v3 | **PASS trong phạm vi lịch sử** |
| #33 | MERGED | — | Revert direct push, khôi phục main | Governance recovery | **PASS (process)** |
| #34 | MERGED | #23 | Căn chỉnh roadmap Phương án B | Docs governance | **PARTIAL**: #23 vẫn open |
| #35 | MERGED | — | Refactor README | Docs | **PASS (docs)** |
| #36 | MERGED | #6 | Migrate NF-UNSW-NB15-v3 + EDA | Real source/schema/EDA | **PASS**; EDA không thay thế ML readiness |
| #38 | MERGED | #11 | IF model + training/eval pipeline | Code + training script; không có artifact thật; inference sai semantics | **PARTIAL/FAIL DoD** |
| #39 | CLOSED | #9, #10 | RF baseline protocol | Bị #43 thay thế | **SUPERSEDED** |
| #40 | MERGED | #31 | XGBoost supervised | Code + manifest; **không có artifact**; issue #31 đóng khi 0/4 AC | **FAIL DoD** |
| #41 | MERGED | #7 | Chronological split + leakage audit | Manifest + audit report; index thật không có trong Git | **PARTIAL / NOT VERIFIED** |
| #42 | MERGED | #8 | Train-only preprocessing | Code + policy + tests; artifact external; hash chain lệch | **PARTIAL** |
| #43 | MERGED | #9, #10 | RF protocol review fixes + training | RF artifact lịch sử; validation metric tái lập ngoài main | **PARTIAL** |
| #44 | MERGED | #15 | Inference CSV từ artifact | Code + CLI + tests; loader fail-open | **PARTIAL** |
| #45 | MERGED | #17 | Unit/integration tests | +806 dòng test; 2/4 AC | **PARTIAL** |
| #47 | OPEN draft, CONFLICTING | #46 | Multi-source ingestion + cross-dataset | 7 commit, +6.059/−2, 39 file; chưa rebase | **NOT MERGED** |
| #49 | OPEN draft, MERGEABLE | #48 | Robust cross-dataset training | 2 commit, +1.712/−45, 9 file; stacked trên #47 | **NOT MERGED** |
| #50 | OPEN, CHANGES_REQUESTED | #12, #13 | RF test evaluation + error analysis | 1 commit, +3.754/−58, 7 file; test index checksum chưa đạt | **NOT MERGED** |
| #51 | OPEN, REVIEW_REQUIRED | #29 | Autoencoder + unknown attack protocol | 3 commit, +3.390/−5, 13 file; CI 5/5; chưa merge | **BRANCH-ONLY** |
| #52 | OPEN draft, CONFLICTING | #30 | FastAPI + SQLite persistence | 1 commit, +4.815/−2, 22 file; chưa rebase | **NOT MERGED** |

## 3. Đánh giá từng PR merged quan trọng

### PR #36 — migrate NF-UNSW-NB15-v3 + EDA

- **Đúng vấn đề**: thay thế UNSW-NB15 2015 bằng NF-UNSW-NB15-v3, xác minh nguồn/byte/schema.
- **Bằng chứng**: raw dataset 2.365.424 dòng, SHA-256 khớp manifest; EDA report 3/3 AC của #6.
- **Giới hạn**: `ML_READY: BLOCKED`; EDA không tạo split/fit transformer.
- **Kết luận**: **PASS** cho phạm vi migration/EDA.

### PR #41 — split và leakage audit

- **Đúng vấn đề**: tạo split protocol và audit leakage.
- **Bằng chứng**: `reports/splits/nf_unsw_nb15_v3_split_manifest.json`, audit report, test guards.
- **Thiếu**: file index `.csv.gz` không được commit; hash index trong manifest `main` không thể kiểm chứng; external index hash khác.
- **Kết luận**: **PARTIAL / NOT VERIFIED** ở mức byte-level reproducibility.

### PR #42 — train-only preprocessing

- **Đúng vấn đề**: fit chỉ trên train, transform validation/test, lưu artifact + manifest.
- **Bằng chứng**: code `preprocessing/pipeline.py`, test no-fit-on-validation/test, `execution_evidence.json`.
- **Thiếu**: artifact `.joblib` ngoài Git; hash split trong preprocessor manifest (`845d…`) không khớp split manifest `main` (`1ba6…`); evidence bị ghi đè bởi run XGB.
- **Kết luận**: **PARTIAL**.

### PR #43 — RF baseline protocol + training

- **Đúng vấn đề**: khóa protocol, train RF, lưu manifest.
- **Bằng chứng**: `reports/models/random_forest_manifest.json`; artifact hash `801afcbb…`; validation metric tái lập.
- **Thiếu**: run commit `6f506335…` không nằm trên `main`; split pin `bb84…` không khớp `main`; artifact không có trong Git; test chưa evaluate.
- **Kết luận**: **PARTIAL**: code + historical artifact có thật, nhưng không tái lập từ `main`.

### PR #44 — inference CSV

- **Đúng vấn đề**: entrypoint CSV, schema validation, output row identity.
- **Bằng chứng**: `scripts/predict.py`, `inference/predict.py`, E2E test; RF inference 1.000 dòng chạy với artifact lịch sử.
- **Lỗi**: `load_verified_model()` không bắt buộc manifest; manifest `{}` được chấp nhận; `except Exception: pass`.
- **Kết luận**: **PARTIAL**, có **P0 fail-open**.

### PR #45 — test coverage

- **Đúng vấn đề**: tăng unit/integration coverage.
- **Bằng chứng**: 739 test pass (có `.git`), 10 skip.
- **Thiếu**: 2/4 AC; không có real split/model evaluation.
- **Kết luận**: **PARTIAL**.

### PR #38 — Isolation Forest

- **Đúng vấn đề**: IF model, threshold calibration trên validation, test frozen.
- **Bằng chứng**: `scripts/train_isolation_forest.py` có `calibrate_threshold`, `anomaly_scores`, test E2E.
- **Lỗi**:
  - Không có artifact thật trên `main`;
  - Inference chung trả raw `-1/1`, không áp threshold;
  - `decision_score` dùng `decision_function` (score cao = bình thường), dễ đọc ngược;
  - PR bị `CHANGES_REQUESTED` nhưng vẫn merge.
- **Kết luận**: **PARTIAL/FAIL DoD**.

### PR #40 — XGBoost

- **Đúng vấn đề**: XGBoost theo protocol supervised.
- **Bằng chứng**: code, protocol, manifest khai báo artifact `c70ec52f…`, validation metric trong manifest.
- **Lỗi**:
  - Không có artifact `.joblib`;
  - `scripts/predict.py` không nhận `--model xgboost`;
  - CLI trả `Model artifact not found at 'xgboost'`;
  - issue #31 đóng khi 0/4 AC;
  - PR bị `CHANGES_REQUESTED` nhưng vẫn merge.
- **Kết luận**: **FAIL DoD**.

## 4. PR #51 — Autoencoder (branch-only)

| Thuộc tính | Giá trị |
|---|---|
| State | OPEN, không draft |
| Mergeable | MERGEABLE |
| Review decision | `REVIEW_REQUIRED` (review CHANGES_REQUESTED trước đó đã bị dismiss) |
| Base | `b14dfee` |
| Head | `8a75e37507bc1d2e63865e7f73af35db3a928056` |
| Commits | `adfb2784…`, `0721002c…`, `8a75e375…` |
| Diff | +3.390/−5, 13 file |
| CI | 5/5 check SUCCESS (test 4 matrix + lint audit) |
| Artifact | Không có |

**Đánh giá**:

- Đây là **năng lực branch-only**, không phải năng lực của `main`.
- CI xanh chỉ chứng minh code chạy với fixture; không chứng minh autoencoder đã train/evaluate trên dữ liệu thật.
- Issue #29 yêu cầu threshold chỉ chọn trên validation, holdout class không tham gia fit, báo detection rate/FPR/limitations. Chưa có bằng chứng real-data trong PR.
- Không được dùng PR #51 để trả lời “Autoencoder đã hoàn thành”.

## 5. PR open còn lại — rủi ro đã biết

| PR | Rủi ro chính | Remediation issue |
|---|---|---|
| #47 | Ingestion chưa tích hợp `InferenceEligibilityGate`; UUID trong hash; conflicting | #58 |
| #49 | E0 evaluation contamination; sample config; stacked trên #47 | #57 |
| #50 | Test index checksum; fail-closed disjointness; evidence động | #56 |
| #52 | API dùng loader chưa verified; artifact filename; security claim | #59 |

Các issue #56–#59 là **audit remediation issues đã tồn tại**; nội dung của chúng chưa được xác minh lại trong phiên này vì các PR chưa rebase/merge. Khi rebase, phải kiểm tra lại trên diff mới, không copy kết luận cũ.

## 6. Kết luận

- **13 PR merged** nhưng chỉ một phần đạt definition of done.
- **3 PR merged khi review `CHANGES_REQUESTED`** (#38, #40 trong range; #41 trước baseline) là điểm yếu quản trị.
- **5 PR open** không tạo thành năng lực của `main`; đặc biệt #51 không được tính.
- PR description và CI xanh **không thay thế** kiểm chứng artifact/real-data.
