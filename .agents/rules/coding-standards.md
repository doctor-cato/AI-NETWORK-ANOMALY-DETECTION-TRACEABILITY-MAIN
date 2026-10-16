# Quy chuẩn code — rules/coding-standards.md

- Python theo `pyproject.toml`; seed tập trung (`config.RANDOM_SEED = 42`).
- Ưu tiên code dễ đọc, ít abstraction, dễ kiểm thử. Không tạo module/class không cần.
- Dùng `pathlib` cho đường dẫn khi phù hợp (`config.DATA_RAW`, `DATA_PROCESSED`).
- Không hardcode đường dẫn tuyệt đối máy cá nhân.
- Không `except: pass`; không `|| true` để che lỗi (đã sửa `.github/workflows/ci.yml`).
- Xử lý lỗi rõ ràng; nếu thiếu dataset, ghi rõ `SKIP (intentional)` thay vì lỗi.
- Dependency: chỉ thêm khi thực sự cần; cập nhật `requirements.txt`/`pyproject.toml` nhất quán.
- Test: viết cho hành vi quan trọng (import, model build, pipeline load, metric tính đúng). Không tạo test giả chỉ để tăng coverage.
- Thay đổi nhỏ, có mục tiêu, dễ review; không sửa file ngoài phạm vi nếu không có lý do rõ ràng.
- Không đưa thông tin nhạy cảm vào Git; không commit dataset hoặc model artifact lớn.
