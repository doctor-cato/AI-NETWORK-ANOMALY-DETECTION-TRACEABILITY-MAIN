name: pytest-skill
source_global: C:\Users\Admin\.agents\skills\pytest-skill
license: MIT (SKILL.md line 9; source_repo: LambdaTest/agent-skills)
date_checked: 2026-10-16

trigger: viết/chạy test cho `tests/unit/test_basic.py`, `tests/integration/test_pipeline.py`; thêm fixture cho synthetic data; kiểm tra import và pipeline load.

repo_notes:
- Hiện có `test_basic.py` (config, build RF) và `test_pipeline.py` (IF build). Đã chạy 3 passed.
- Khi thêm test cho preprocessing hoặc evaluation: dùng fixture nhỏ (numpy synthetic), không cần dataset lớn.
- Phân biệt rõ `test synthetic` vs `test on UNSW-NB15` trong tên/test case hoặc comment.
- Không tạo test chỉ để tăng coverage qua import kiểm tra; phải kiểm tra hành vi thực tế (fit, predict, metrics tính đúng).
- Nếu thiếu dataset thật, không bắt buộc toàn bộ pipeline test chạy; nhưng phải ghi `SKIP` / giới hạn.

activation: tham chiếu SKILL.md toàn cục khi cần mẫu `parametrize`, `fixture`, `conftest`. Kiểm tra `.agents/workflows/verify.md` trước khi thêm test mới.
