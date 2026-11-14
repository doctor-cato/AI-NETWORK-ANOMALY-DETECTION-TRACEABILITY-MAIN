# Report 05 — Milestone Audit

## 1. Bảng milestone

| # | Milestone | State | Open | Closed | Due | Closed at | Đánh giá |
|---|---|---|---|---|---|---|---|
| 1 | M0 — Nền tảng kho lưu trữ và thiết kế dự án | closed | 0 | 3 | 2026-10-23 | 2026-10-17 | **PASS** |
| 2 | M1 — Chuẩn bị dữ liệu, EDA và kiểm toán leakage | closed | 0 | 5* | 2026-10-30 | 2026-11-08 | **PARTIAL** |
| 3 | M2 — Tiền xử lý và baseline Random Forest | closed | 0 | 4 | 2026-11-06 | 2026-11-09 | **FAIL (đóng sớm)** |
| 4 | M3 — Đánh giá mô hình và phân tích kết quả | open | 5 | 0 | 2026-11-13 | — | **NOT DONE** |
| 5 | M4 — Inference, demo và kiểm thử tích hợp | open | 0 | 2 | 2026-11-20 | — | **NOT ACCEPTED** |
| 6 | M5 — Tài liệu, trình bày và xác minh bàn giao | open | 0* | 0 | 2026-11-27 | — | **NOT DONE** |
| 7 | M6 — Backend, Dashboard & Integration | open | 8 | 0 | — | — | **NOT STARTED** |
| 8 | M7 — Experiments, Documentation & Delivery | open | 5* | 0 | — | — | **NOT DONE** |

\* **Đính chính cách đếm**: GitHub API trả `closed_issues = 5` cho M1 vì milestone này chứa cả **PR #22**; membership thực tế là 4 issue (#4–#7) + PR #22. Với M5/M7, counter của GitHub đang không nhất quán với membership: API trả M5 = 3 open, M7 = 2 open, nhưng truy vấn issue theo `milestone` cho thấy **M5 = 0 issue**, **M7 = 5 issue** (#18, #19, #20, #23, #25). Bảng trên dùng membership thực tế; counter M5/M7 là dữ liệu GitHub stale, không dùng để kết luận.

## 2. M0 — PASS

- 3 issue (#1, #2, #3) đóng.
- Repo structure, environment check, CI cơ bản hoạt động.
- Không có claim ML trong milestone này.

## 3. M1 — PARTIAL

M1 gồm **4 issue** (#4, #5, #6, #7) và **PR #22**; GitHub đếm 5 closed vì tính cả PR #22. Theo bằng chứng:

- #4 nguồn/byte dữ liệu: **PASS**.
- #5 schema/quality: **PASS**, nhưng `ML_READY: BLOCKED`.
- #6 EDA: **PASS**.
- #7 split/leakage: **PARTIAL / NOT VERIFIED**: manifest và audit report có, nhưng index thật không có trong Git; hash index `main` khác external.

Vì vậy M1 đóng ngày 2026-11-08 trong khi “real split audit” chưa thể kiểm chứng byte-level. Đây là **đóng đúng phạm vi tài liệu, chưa đủ phạm vi reproducibility**.

## 4. M2 — FAIL (đóng sớm)

M2 gồm #8, #9, #10, #31.

| Issue | Điều kiện | Thực tế |
|---|---|---|
| #8 preprocessing | Preprocessing + real-data smoke | Code/test có; artifact ngoài Git; hash chain lệch; Test partition vẫn bị materialize trong evidence (F-05) |
| #9 RF protocol | Protocol khóa | **PASS** |
| #10 RF training | Train thật + manifest | Artifact lịch sử có; không tái lập từ `main` |
| #31 XGBoost | Train thật + artifact | **Không có artifact**; 0/4 AC; CLI không hỗ trợ |

Ngoài ra, evidence của #8 hiện mang `git_commit=89c32fa` (commit XGB) và split `845d…`, được tạo/cập nhật **sau** khi issue đóng; không thể chứng minh AC4 đã đạt tại thời điểm đóng.

M2 được đóng ngày 2026-11-09, ngay sau khi PR #40 merge. Nhưng:

- #31 được đóng cùng ngày dù **không có file `artifacts/models/xgboost/xgboost_baseline.joblib`**;
- manifest XGB tham chiếu split `845d…`, không khớp split manifest `main` `1ba6…`;
- CLI `--model xgboost` fail;
- không có test evaluation.

**Kết luận**: M2 **không đạt** định nghĩa “baseline Random Forest + so sánh XGBoost có artifact”. Việc đóng M2 là **false completion**.

## 5. M3 — NOT DONE

- #11 IF: code + training script, chưa có artifact; inference threshold mismatch.
- #12 RF evaluation: chưa có metric trên test.
- #13 error analysis: chưa có prediction/confusion matrix test.
- #14 traceability: manifest có nhưng chuỗi hash đứt.
- #29 Autoencoder: branch-only PR #51.

Không có “kết quả thực nghiệm M3” nào được chứng minh trên test set. Các metric 0,9999 chỉ là **validation**.

## 6. M4 — NOT ACCEPTED

M4 có **0 open / 2 closed** (#15, #17) nhưng milestone vẫn **open**. Đây là trạng thái không nhất quán:

- Nếu tiêu chí là “tất cả issue closed”, M4 có thể đóng — nhưng không nên, vì #15/#17 đóng sớm và end-to-end chưa chạy.
- Nếu tiêu chí là “demo/integration thật”, M4 chưa đạt.

Kết luận: **không được đóng M4** chỉ vì 0 open issue. Cần một acceptance gate riêng: inference thật + artifact thật + demo.

## 7. M5, M6, M7 — NOT DONE

- **M5**: không còn issue nào được gán; các issue tài liệu/bàn giao hiện nằm trong M7 (#18, #19, #20). Chưa có gói bàn giao.
- **M6**: 8 issue backend/dashboard/security (#16, #24, #26, #27, #28, #30, #32, #46). Không có code trong `src/` cho FastAPI/Streamlit/SQLite/AES/Behavioral/Risk/Trace.
- **M7**: 5 issue (#18 tài liệu/giấy phép/nghĩa vụ nguồn; #19 PDF/slides/demo/handoff; #20 xác minh tổng thể; #23 governance; #25 bảy experiments). Chưa có gói bàn giao/experiment evidence.

## 8. Kết luận

- **M0 đóng đúng.**
- **M1 đóng đúng phạm vi tài liệu nhưng chưa đủ reproducibility.**
- **M2 đóng sai** vì #31 không đạt và XGBoost không có artifact.
- **M3/M5/M6/M7 chưa đạt.**
- **M4 không nên đóng** dù 0 open issue; cần acceptance gate end-to-end.
- Không được dùng “0 open issue” làm tiêu chí duy nhất cho milestone completion.
