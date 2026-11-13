# Report 04 — Issue Acceptance Audit

## 1. Tổng quan

- **41 issue thực** (không phải 60; 60 là số object gồm 19 PR).
- **13 closed**: #1–#10, #15, #17, #31.
- **28 open**: #11–#14, #16, #18–#20, #23–#30, #32, #37, #46, #48, #53–#60.
- Checkbox trong issue body **không đáng tin**:
  - #2–#5 đóng với 0/N checkbox;
  - #8, #9, #10 đóng với đủ checkbox;
  - #15 đóng với 0/3;
  - #17 đóng với 2/4;
  - #31 đóng với 0/4.

Vì vậy đánh giá dưới đây dựa trên **code/artifact/test**, không dựa trên checkbox.

## 2. Issue đã đóng

| Issue | AC (checkbox) | Bằng chứng thực tế | Verdict | Đóng sớm? |
|---|---|---|---|---|
| #1 | 0/0 | Milestone link test | **N/A** | Không |
| #2 | 0/2 | Scope/requirements docs tồn tại | **PASS (docs)**; checkbox stale | Không |
| #3 | 0/3 | `check_environment.py`, CI, package import | **PASS** | Không |
| #4 | 0/2 | Dataset manifest, SHA-256, raw data ngoài Git | **PASS** | Không |
| #5 | 0/3 | Validation report 2.365.424 dòng, schema/nhãn/quality | **PASS**; `ML_READY: BLOCKED` là finding, không phải lỗi issue | Không |
| #6 | 3/3 | EDA report + summary + figures | **PASS** | Không |
| #7 | 1/3 | Split manifest + leakage audit report; index thật không có trong Git | **PARTIAL / NOT VERIFIED** | Chưa đủ bằng chứng byte-level |
| #8 | 4/4 | Code/test preprocessing; artifact ngoài Git; evidence `git_commit=89c32fa` | **PARTIAL** | AC4 evidence hiện tại được tạo/cập nhật **sau** khi issue đóng |
| #9 | 8/8 | Protocol, config, metrics, tests | **PASS** | Không |
| #10 | 7/7 | RF manifest + historical artifact; metric validation tái lập ngoài main | **PARTIAL** | Đóng khi artifact/run commit không nằm trên `main` |
| #15 | 0/3 | Code inference + test; smoke real artifact `SKIPPED`; loader fail-open | **FAIL/PARTIAL** | **CÓ** |
| #17 | 2/4 | 739 test pass; không có real split/model evaluation | **PARTIAL** | **CÓ** (2 AC còn lại chưa đạt) |
| #31 | 0/4 | XGB code + manifest; **không có artifact**; CLI không hỗ trợ | **FAIL** | **CÓ** |

### 2.1. Các issue đóng sớm rõ ràng

#### #15 — Inference từ artifact

- AC1: artifact load/predict nhất quán — chưa chứng minh với artifact trên `main`.
- AC2: CSV giữ row identity + artifact ID — code có, test synthetic có.
- AC3: artifact thiếu/sai/schema lỗi phải fail-closed — **không đạt**: model không manifest vẫn được nạp.
- Smoke report real model: `SKIPPED` vì thiếu artifact.
- Đóng lúc `2026-11-08T08:56:10Z`, cùng thời điểm merge PR #44 (auto-close theo PR).
- **Kết luận**: đóng khi acceptance quan trọng nhất (fail-closed) chưa đạt.

#### #17 — Unit/integration tests

- AC1, AC2 đạt (migration tests + CI skip đúng).
- AC3: preprocessing/model/artifact/inference integration coverage “hoàn chỉnh” — chưa.
- AC4: real split + model evaluation — chưa.
- Đóng lúc `2026-11-08T09:50:44Z`, cùng thời điểm merge PR #45 (auto-close theo PR).
- **Kết luận**: đóng khi 2/4 AC còn unchecked.

#### #31 — XGBoost

- AC1: split trước fit — code có, nhưng không có real run trên `main`.
- AC2: binary/multiclass semantics — code có.
- AC3: metric cùng protocol — chỉ có validation trong manifest, không có test.
- AC4: artifact chứa commit/dataset/split/seed/feature/deps — manifest có, **artifact `.joblib` không tồn tại**.
- Đóng lúc `2026-11-09T16:33:04Z`, cùng thời điểm merge PR #40 (auto-close theo PR).
- **Kết luận**: 0/4 checkbox, không artifact, không reproduce command; đóng hoàn toàn trái Definition of Done.

### 2.2. Các issue đóng “đúng phạm vi” nhưng thiếu tái lập

- **#10**: RF đã train thật (bằng chứng lịch sử), nhưng run commit `6f506335…` không nằm trên `main`; `main` không thể tái lập. Đây là **PARTIAL do reproducibility**, không phải “chưa từng train”.
- **#8**: code và real-data smoke có thật, nhưng evidence hiện tại mang `git_commit=89c32fa` (commit XGB) và split `845d…`, không phải trạng thái lúc đóng 2026-10-29. Không thể chứng minh AC4 đã đạt tại thời điểm đóng.
- **#7**: split protocol/audit có thật; nhưng index thật không có trong Git nên AC “real split audit xác minh overlap” chỉ được chứng minh bằng report, không bằng byte-level artifact.

## 3. Issue còn mở

| Issue | Milestone | Trạng thái thực tế | Verdict |
|---|---|---|---|
| #11 | M3 | IF code + training script + threshold protocol; chưa có artifact; inference trả raw `-1/1` | **PARTIAL** |
| #12 | M3 | Chưa có evaluation test; không có metric trên test | **NOT STARTED / BLOCKED** |
| #13 | M3 | Chưa có predictions/confusion matrix trên test | **NOT STARTED** |
| #14 | M3 | Manifest có nhưng chuỗi hash đứt | **PARTIAL** |
| #16 | M6 | Không có Streamlit dashboard trong `src/` | **NOT STARTED** |
| #18 | M7 | Docs/license/provenance một phần | **PARTIAL** |
| #19 | M7 | PDF/slides/demo/handoff chưa có | **NOT STARTED** |
| #20 | M7 | Audit verification; 1/5 AC | **PARTIAL** |
| #23 | M7 | Governance docs; 0/3 | **PARTIAL** |
| #24 | M6 | Trace Engine không có code | **NOT STARTED** |
| #25 | M7 | 7 experiments chưa có | **NOT STARTED** |
| #26 | M6 | AES-GCM/key lifecycle không có code | **NOT STARTED** |
| #27 | M6 | Adaptive rotation không có code | **NOT STARTED** |
| #28 | M6 | Behavioral Vector không có code | **NOT STARTED** |
| #29 | M3 | Autoencoder chỉ trên PR #51 branch-only | **NOT MERGED / PARTIAL** |
| #30 | M6 | FastAPI/SQLite chỉ trên PR #52 branch-only | **NOT MERGED** |
| #32 | M6 | Risk Engine không có code | **NOT STARTED** |
| #37 | — | Lint debt; một phần đã xử lý, repo-wide vẫn chưa sạch | **PARTIAL** |
| #46 | M6 | Ingestion chỉ trên PR #47 draft/conflicting | **NOT MERGED** |
| #48 | — | Cross-dataset chỉ trên PR #49 draft/stacked | **NOT MERGED** |
| #53 | — | Audit P0: unverified deserialization vẫn tồn tại trên HEAD | **OPEN — confirmed** |
| #54 | — | Audit P0: IF packaging/threshold mismatch vẫn tồn tại | **OPEN — confirmed** |
| #55 | — | Audit P1: provenance hash-chain vẫn đứt | **OPEN — confirmed** |
| #56 | — | Audit P0: PR #50 blockers | **OPEN — PR chưa merge** |
| #57 | — | Audit P0: PR #49 E0 contamination | **OPEN — PR chưa merge** |
| #58 | — | Audit P1: PR #47 eligibility gate | **OPEN — PR chưa merge** |
| #59 | — | Audit P1: PR #52 API verification | **OPEN — PR chưa merge** |
| #60 | — | Consolidated remediation | **OPEN** |

## 4. Issue “chỉ trên giấy” hoặc chỉ có synthetic test

- **#12/#13**: module metric có, nhưng chưa có kết quả test thật.
- **#16, #24, #26, #27, #28, #32**: không có code trong `src/`; chỉ là target architecture.
- **#19, #25**: không có PDF/slides/demo/experiment results.
- **#29, #30, #46, #48**: chỉ tồn tại trên PR branch, không phải `main`.
- **#31**: code + manifest nhưng artifact không tồn tại → không thể chạy.
- **#17**: “integration test” chủ yếu là synthetic fixture; không thay thế real-data evaluation.

## 5. Kết luận

- **3 issue đóng sớm rõ ràng**: #15, #17, #31.
- **3 issue đóng đúng phạm vi nhưng không tái lập được từ `main`**: #7, #8, #10.
- **28 issue còn open**, trong đó nhiều issue là “paper architecture” chưa có code.
- **Milestone M5 hiện không còn issue nào được gán**; #18/#19/#20 đã chuyển sang M7. GitHub vẫn hiển thị counter M5 = 3 open, M7 = 2 open (xem Report 05, phần đính chính cách đếm).
- Việc đóng issue phải dựa trên **artifact + test + reproduction command**, không dựa trên merge PR hoặc checkbox.
