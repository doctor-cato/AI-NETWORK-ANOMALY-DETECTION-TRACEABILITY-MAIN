# Forensic Audit — Reports 01–14

- **Repository**: `doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN`
- **Baseline**: `b212377a614aadbfb27eccff8d808c5b7dda551f` (merge PR #43)
- **HEAD được kiểm toán**: `b14dfeed9e7cbb07201cfb0ac8ce69c951434be1` (`origin/main`, merge PR #40)
- **Snapshot nguồn để đối chiếu**: `C:\Users\ASUS\AppData\Local\Temp\opencode\head_b14dfee` (`git archive HEAD`); full test suite được chạy trong một **git clone sạch** riêng vì `git archive` không có `.git` (xem Report 08)
- **Phạm vi**: 38 commits, 49 file thay đổi, +13.469/−158; 19 PR; 41 issue thực; 8 milestone.
- **Chế độ**: STRICT READ-ONLY. Không sửa tracked source, không commit/push/merge, không đổi issue hay GitHub settings.
- **Ngày hoàn tất**: 2026-11-10.

## Trạng thái bằng chứng

| Nhãn | Ý nghĩa |
|---|---|
| **PASS** | Đã chạy/tái lập được trong phiên audit, kết quả khớp claim. |
| **FAIL** | Đã tái lập lỗi hoặc claim trái với bằng chứng. |
| **PARTIAL** | Một phần chức năng có thật, nhưng không đạt đầy đủ acceptance/definition of done. |
| **SKIPPED** | Kiểm tra hợp lệ nhưng bỏ qua vì thiếu dữ liệu/artifact; không phải PASS. |
| **NOT VERIFIED** | Không thể chứng minh từ repository/snapshot; không được tính là hoàn thành. |
| **BLOCKED** | Thiếu artifact/dữ liệu/điều kiện bắt buộc để chạy. |

## Danh mục báo cáo

| # | File | Nội dung |
|---|---|---|
| 01 | [`01-executive-summary.md`](01-executive-summary.md) | Kết luận điều hành, score card, top findings |
| 02 | [`02-commit-audit.md`](02-commit-audit.md) | 38 commit và thay đổi hành vi thực tế |
| 03 | [`03-pr-matrix.md`](03-pr-matrix.md) | 19 PR: mục tiêu, kết quả, rủi ro, PR #51 |
| 04 | [`04-issue-acceptance.md`](04-issue-acceptance.md) | 41 issue, đóng sớm, acceptance thực tế |
| 05 | [`05-milestone-audit.md`](05-milestone-audit.md) | 8 milestone và mức hoàn thành thật |
| 06 | [`06-architecture.md`](06-architecture.md) | Kiến trúc đã triển khai vs tài liệu |
| 07 | [`07-data-ml-scientific-audit.md`](07-data-ml-scientific-audit.md) | Dữ liệu, split, leakage, RF/XGB/IF/AE, TTL shortcut |
| 08 | [`08-test-ci-evidence.md`](08-test-ci-evidence.md) | 739 test, 10 skip, CI/lint gate |
| 09 | [`09-security.md`](09-security.md) | CWE-502, integrity, supply chain |
| 10 | [`10-findings-register.md`](10-findings-register.md) | Findings P0–P3 kèm file:line và reproducer |
| 11 | [`11-reality-check.md`](11-reality-check.md) | Trả lời 17 câu hỏi của ULTIMATE OBJECTIVE |
| 12 | [`12-readiness-verdicts.md`](12-readiness-verdicts.md) | Readiness theo năng lực và môi trường |
| 13 | [`13-remediation-roadmap.md`](13-remediation-roadmap.md) | Thứ tự sửa, điều kiện nghiệm thu, cách chứng minh |
| 14 | [`14-github-summary.md`](14-github-summary.md) | Nội dung sẵn sàng đăng GitHub |

## Lưu ý về dữ liệu nền

1. **Working tree tại thời điểm audit không phải HEAD**: có 11 file tracked bị sửa và nhiều module untracked (API, ingestion, evaluation, tests). Đây là thay đổi của một tiến trình khác, không được dùng làm bằng chứng cho `main` và không được credit trong báo cáo này.
2. **Artifact và dữ liệu thật nằm ngoài Git**. Các kết luận real-data dùng external clone `C:\Users\ASUS\Documents\GitHub\AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN` và raw dataset `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv`.
3. **Các issue #53–#60 đã tồn tại từ trước phiên audit này**. Báo cáo chỉ dùng chúng làm nơi ánh xạ remediation; không coi nội dung issue là bằng chứng độc lập.
4. **Checkpoint cũ có bốn điểm cần đính chính**:
   - Không phải “60 issue”. Có **41 issue thực**; 60 là số object gồm cả 19 PR.
   - PR #41 là **split/leakage audit**, không phải Isolation Forest.
   - PR #51 **chưa merge**; mọi capability Autoencoder chỉ là branch-only.
   - `audit_checkpoint.md` trong thư mục này là snapshot trung gian trước khi hoàn tất; vẫn chứa số liệu cũ (“60 issues”, trạng thái PR, mô tả Autoencoder) và **chỉ dùng làm provenance**, không dùng làm kết luận. Reports 01–14 là bản cuối.

## Tóm tắt một dòng

> Repository có code ML thật và một artifact Random Forest lịch sử đạt metric rất cao trên validation, nhưng **không thể tái lập end-to-end từ `main`** vì chuỗi hash split → preprocessing → model bị đứt, loader inference fail-open, XGBoost không có artifact, test partition chưa được đánh giá, và nhiều issue/milestone đã đóng vượt quá bằng chứng.
