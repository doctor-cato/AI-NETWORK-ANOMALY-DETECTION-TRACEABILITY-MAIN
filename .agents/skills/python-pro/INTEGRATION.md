name: python-pro
source_local: .agents/skills/python-pro/INTEGRATION.md
date_updated: 2026-11-19

trigger: viết/review Python cho `src/network_anomaly/`, `scripts/`, `tests/`; cấu hình `pyproject.toml`; xử lý đường dẫn, seed, API/FastAPI, typing.

repo_notes:
- Python >= 3.11 theo `pyproject.toml`; CI chạy matrix `3.11` & `3.12` trên Ubuntu & Windows.
- Định dạng bằng `black` và lint bằng `ruff check src scripts tests`; ghi file với `newline="\n"`.
- Ưu tiên `pathlib` (`PROJECT_ROOT`, `DATA_RAW`, `DATA_PROCESSED`); không hardcode đường dẫn máy cá nhân.
- Seed tập trung (`config.RANDOM_SEED = 42`); không `except: pass` hay `|| true`.
- Sau khi sửa FastAPI/Pydantic schema (`src/network_anomaly/api/`), đồng bộ bằng `python scripts/export_openapi_spec.py`.
- Test synthetic (fixture nhỏ) rõ ràng, CI-safe khi vắng `artifacts/`; không gán nhãn synthetic là benchmark thực nghiệm (`AIT-NDS-v2`, `CTU-SME-11`, `UWF-ZeekData24`).
- Chỉ thêm dependency khi thật sự cần; cập nhật `pyproject.toml` và `requirements*.txt` nhất quán.

activation: đọc `.agents/rules/coding-standards.md` và file nguồn liên quan trước khi sửa.
