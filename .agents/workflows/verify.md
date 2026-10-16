# Kiểm thử — workflows/verify.md

Sau implement:

1. Chọn kiểm tra phù hợp: unit (`tests/unit/`), integration (`tests/integration/`), env (`scripts/check_environment.py`), import (`py_compile`), CI (`.github/workflows/ci.yml`).
2. Chạy test liên quan; nếu thiếu dataset thật, phân biệt synthetic với dữ liệu thật.
3. `git diff --check`; kiểm tra import/đường dẫn/config/dependency nếu có thay đổi.
4. Với ML: xác minh preprocessing không fit trên val/test; kiểm tra leakage rõ ràng (cột nhãn, cột dẫn xuất, identity).
5. Với thí nghiệm: không tuyên bố end-to-end nếu chưa thử UNSW-NB15 thật.
6. Báo từng kiểm tra: `PASS`, `FAIL`, `SKIP` (intentional, ví dụ thiếu dataset), `NOT RUN`.
7. Nếu không có dataset thật: không bắt buộc toàn bộ test dữ liệu phải chạy; nhưng phải ghi rõ giới hạn.
8. Không tuyên bố thành công nếu chưa chạy lệnh tương ứng.
