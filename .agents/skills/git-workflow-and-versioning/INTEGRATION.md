name: git-workflow-and-versioning
source_global: C:\Users\Admin\.agents\skills\git-workflow-and-versioning
date_checked: 2026-10-16

trigger: mọi thay đổi code; commit, branch, review PR; giải quyết dirty working tree; cắt release / tag nếu cần.

repo_notes:
- Trunk-based cho bài tập: `main` luôn sạch; làm việc ngắn, atomic commit.
- Không force-push, không reset hard, không xóa branch/tag.
- Commit message rõ: `chore: ...`, `feat: ...` theo convention; không dùng message AI-slop.
- Đã sửa `46cfe2e` (strip phá hủy) bằng restore + fix; từ đó giữ `main` ổn định.
- Trước push: `git diff --check`, `python scripts/check_environment.py`, test liên quan.
- PR template (`.github/pull_request_template.md`) phải giữ nguyên khi mở PR.

activation: tham chiếu SKILL.md toàn cục khi cần chi tiết (atomic commits, trunk-based, changelog, tag). Luôn kết hợp `.agents/rules/coding-standards.md` (không `|| true`, không hardcode).
