# Sổ checkpoint triển khai

## Quy ước

Mỗi checkpoint C0–C11 trong `docs/ROADMAP_FULL_SYSTEM.md` có đúng một mục được bổ sung
khi đến điểm bàn giao. Không thay `PLANNED` thành `IMPLEMENTED`, `TESTED` hoặc
`EXPERIMENTALLY VALIDATED` nếu thiếu code, kết quả test, hoặc evidence phù hợp. PR #22
được review như workstream riêng và không là dependency của checkpoint tài liệu.

Mẫu bắt buộc:

```text
Checkpoint:
Branch:
HEAD:
Completed:
Tests:
Issues:
PR:
Remaining:
Blockers:
Next Action:
```

## C0 — Governance & documentation

```text
Checkpoint: C0
Branch: codex/c0-governance-after-revert (base khôi phục dce80bf)
HEAD: xác minh bằng git/PR readback tại bàn giao; không nhúng self-hash vào commit
Completed: IMPLEMENTED — scope, charter, requirements, architecture, traceability,
  5-role mapping, M6/M7 và backlog #23–#32 đã đồng bộ.
Tests: PASS — workflow validator; environment check; targeted 4 passed; full 36 passed;
  git diff --check. PR #22 worktree: 105 passed; manifest/real validation/diff-check PASS.
  Remote CI cho C0: NOT VERIFIED cho đến khi PR chạy.
Issues: #23 (C0); #24–#32; cập nhật #11, #16, #18–#20; #4/#5 hiện CLOSED
  sau workstream dữ liệu 2015 và được giữ làm bằng chứng lịch sử.
PR: chờ PR khôi phục #33 được maintainer merge; không merge tự động.
Remaining: Sau #33, mở PR C0 từ branch này vào main và đọc lại CI.
Blockers: DOCX layout NOT VERIFIED vì runtime không có LibreOffice bundled; không chặn
  mapping nội dung. C1 real-data workstream vẫn phụ thuộc quyết định PR #22/#7.
Next Action: Maintainer review/merge #33; sau đó tạo PR C0 và chỉ tiếp tục C1 khi CI C0 đạt.
```

## C1–C11

C1 đã có provenance/schema, real-data quality/duplicate audit và EDA tái lập được cho
NF-UNSW-NB15-v3: SOURCE_INTEGRITY: PASS, RAW_QUALITY: FINDINGS_RECORDED; EDA chạy trên
2.365.424 dòng và tái lập khớp các finding đã xác minh. Real split và leakage audit hoàn thành
qua PR #41. C2 đã có train-only preprocessing artifact được fit trên 1.655.797 dòng train
và kiểm chứng qua PR #42.
C3: Protocol baseline Random Forest (Issue #9) đạt IMPLEMENTED / TESTED, huấn luyện trên dữ liệu
thực (Issue #10) đạt IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED, trong khi đánh giá trên tập
held-out Test (Issue #12) vẫn PLANNED. XGBoost (Issue #31) đạt IMPLEMENTED / TESTED (cấu trúc mô hình và giao thức dùng chung), huấn luyện thực tế BLOCKED (chờ dataset raw tại môi trường cục bộ). C4–C11 vẫn PLANNED.
```
