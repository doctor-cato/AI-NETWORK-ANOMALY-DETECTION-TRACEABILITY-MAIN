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
Branch: codex/c0-governance (base origin/main a707038)
HEAD: xác minh bằng git/PR readback tại bàn giao; không nhúng self-hash vào commit
Completed: IMPLEMENTED — scope, charter, requirements, architecture, traceability,
  5-role mapping, M6/M7 và backlog #23–#32 đã đồng bộ.
Tests: PASS — workflow validator; environment check; targeted 4 passed; full 36 passed;
  git diff --check. PR #22 worktree: 105 passed; manifest/real validation/diff-check PASS.
  Remote CI cho C0: NOT VERIFIED cho đến khi PR chạy.
Issues: #23 (C0); #24–#32; cập nhật #11, #16, #18–#20; #4/#5 giữ OPEN.
PR: sẽ ghi URL sau khi push/tạo PR; không merge tự động.
Remaining: VERIFY/REVIEW diff C0, commit, push, PR và CI readback.
Blockers: DOCX layout NOT VERIFIED vì runtime không có LibreOffice bundled; không chặn
  mapping nội dung. C1 real-data workstream vẫn phụ thuộc quyết định PR #22/#7.
Next Action: Chạy check C0, self-review, tạo commit/PR riêng rồi tiếp tục C1 nếu không blocker.
```

## C1–C11

Các checkpoint C1 đến C11 hiện là `PLANNED`. Khi hoàn thành từng checkpoint, thêm một
mục theo mẫu trên; nêu rõ lệnh đã chạy, exit code, evidence path/URL, Issue/PR liên
quan, phần `SKIPPED` hoặc `NOT VERIFIED`, và điều kiện chuyển tiếp còn lại.
