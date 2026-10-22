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
Issues: #23 (C0); #24–#32; cập nhật #11, #16, #18–#20; #4/#5 giữ OPEN.
PR: chờ PR khôi phục #33 được maintainer merge; không merge tự động.
Remaining: Sau #33, mở PR C0 từ branch này vào main và đọc lại CI.
Blockers: DOCX layout NOT VERIFIED vì runtime không có LibreOffice bundled; không chặn
  mapping nội dung. C1 real-data workstream vẫn phụ thuộc quyết định PR #22/#7.
Next Action: Maintainer review/merge #33; sau đó tạo PR C0 và chỉ tiếp tục C1 khi CI C0 đạt.
```

## C1–C11

Các checkpoint C1 đến C11 hiện là `PLANNED`. Khi hoàn thành từng checkpoint, thêm một
mục theo mẫu trên; nêu rõ lệnh đã chạy, exit code, evidence path/URL, Issue/PR liên
quan, phần `SKIPPED` hoặc `NOT VERIFIED`, và điều kiện chuyển tiếp còn lại.

## C3 — Supervised ML (Issue #31 — XGBoost)

```text
Checkpoint: C3 (partial — XGBoost constructor)
Branch: main (working tree)
HEAD: xác minh bằng git log HEAD
Completed: IMPLEMENTED — xgboost_model.py, XGBOOST_DEFAULTS trong config.py,
  dependency khai báo trong requirements.txt và pyproject.toml,
  tests/unit/test_xgboost.py (14 data-free tests; 1 training test SKIPPED/BLOCKED).
  Random Forest constructor đã có trước; supervised protocol dùng chung được ghi
  trong docstring và test schema contract.
Tests: TESTED — python -m pytest tests/unit/test_xgboost.py -v
  (data-free tests: PASS; training test: SKIPPED/BLOCKED — xem lý do trong test).
  Các test hiện có (test_basic.py, test_pipeline.py) không bị ảnh hưởng.
Issues: #31 (C3 XGBoost)
PR: chưa tạo — chờ review và merge từ maintainer.
Remaining:
  - C1 leakage audit (#7) cần hoàn thành trước khi split.
  - C2 preprocessing pipeline cần triển khai và xác minh fit boundary.
  - Sau C1/C2: un-skip test training, chạy trên UNSW-NB15 thật, ghi
    run_id / dataset sha256 / split seed / feature schema / metrics thật.
Blockers:
  - UNSW-NB15 CSV không có trong data/raw/ trên môi trường CI.
  - C1 leakage audit (group/near-duplicate overlap) chưa hoàn tất (#7).
  - C2 preprocessing pipeline chưa triển khai.
  - Training và evaluation: BLOCKED (không có dữ liệu thật đã xác minh).
  - Benchmark và metrics: NOT VERIFIED (chưa chạy thực nghiệm trên dữ liệu thật).
Next Action: Maintainer review C3 PR; sau đó tiếp tục C1 (#7) và C2 trước khi
  un-block training. Không tuyên bố EXPERIMENTALLY VALIDATED cho đến khi
  có run thật trên UNSW-NB15 với provenance, split và metrics được ghi đầy đủ.
```
