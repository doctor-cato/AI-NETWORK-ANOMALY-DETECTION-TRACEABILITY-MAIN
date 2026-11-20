name: git-workflow-and-versioning
source_local: .agents/skills/git-workflow-and-versioning/INTEGRATION.md
date_updated: 2026-11-19

trigger: kiểm tra Git status, tạo commit/push khi được yêu cầu, cập nhật PR description/comment trên `feat/v2-integration` / PR `#156`.

repo_notes:
- Nhánh tích hợp hiện hành: `feat/v2-integration` -> `main` (PR `#156` giữ `OPEN / DRAFT` trừ khi maintainer/user yêu cầu đổi).
- Không tự stage/commit/push, không force-push, không reset hard, không sửa Issue/Milestone khi user chưa yêu cầu rõ.
- Commit message dùng Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`), nêu rõ thay đổi + bằng chứng kiểm chứng + giới hạn; tuyệt đối không thêm trailer AI (`Co-Authored-By`, `Generated with`) hay tên công cụ/vendor/model AI.
- Trước khi commit/push: chạy `git diff --check`, `ruff check`, `black --check`, `scripts/export_openapi_spec.py --check`, và bộ test liên quan.
- Giữ nguyên `.github/pull_request_template.md` và lịch sử commit cũ.

activation: kết hợp `.agents/rules/coding-standards.md` và `AGENTS.md`.
