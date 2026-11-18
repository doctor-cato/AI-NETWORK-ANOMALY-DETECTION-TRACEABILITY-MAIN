name: pytest-skill
source_local: .agents/skills/pytest-skill/INTEGRATION.md
license: MIT
date_updated: 2026-11-19

trigger: viết/chạy test trong `tests/unit/` và `tests/integration/`; viết test CI-safe cho FastAPI, streaming, migration, adapters và OOD gate.

repo_notes:
- Suite v2 chạy toàn phần bằng `python -m pytest tests -q -rs --tb=short` (trên CI Ubuntu/Windows các binary `.joblib`/OOD/demo bị `.gitignore` và test Windows DPAPI/PowerShell được skip có kiểm soát qua `-rs`).
- Khi viết test mới cho API/CSV/streaming/scripts: dùng fixture nhỏ trong `tmp_path` hoặc mock pipeline/gate để pass 100% cả trên GitHub Actions CI khi thiếu `artifacts/` và raw datasets.
- Kiểm tra hành vi thực tế (fail-closed `"deployment"` OOD gate, SHA-256 tamper rejection, DB rollback, 10k `tracemalloc` bounds, migration errors), không tạo test chỉ để tăng coverage.
- Phân biệt rõ `synthetic` / `localhost UDP replay` với dữ liệu benchmark v2 thật hoặc thiết bị router/switch vật lý.

activation: đọc `.agents/workflows/verify.md` và `.github/workflows/ci.yml` trước khi thêm test mới.
