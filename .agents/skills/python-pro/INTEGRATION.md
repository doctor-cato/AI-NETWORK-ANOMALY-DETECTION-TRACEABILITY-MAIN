name: python-pro
source_global: C:\Users\Admin\.agents\skills\python-pro
license: unknown (community; SKILL.md checked, no suspicious commands)
date_checked: 2026-10-16

trigger: viết/review Python cho `src/network_anomaly/`, `scripts/`, `tests/`; cấu hình `pyproject.toml`; xử lý đường dẫn, seed, test.

repo_notes:
- Python 3.11+ theo `pyproject.toml`; CI bao phủ 3.11 và 3.12.
- Ưu tiên `pathlib` (`config.DATA_RAW`, `DATA_PROCESSED`).
- Seed tập trung (`RANDOM_SEED = 42`).
- Không hardcode đường dẫn máy cá nhân.
- Không `except: pass`; không `|| true` che lỗi (đã sửa CI).
- Test synthetic (fixture nhỏ) rõ ràng; không giả lập benchmark UNSW-NB15.
- Không thêm dependency không cần; cập nhật `requirements.txt`/`pyproject.toml` nhất quán.

activation: tham chiếu SKILL.md toàn cục khi cần chi tiết (async, typing, ruff, uv). Trước khi sửa, đọc `.agents/rules/coding-standards.md` và file liên quan.
