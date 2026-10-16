# Kiểm thử — workflows/verify.md

Sau implement:

1. Chọn kiểm tra phù hợp: unit (`tests/unit/`), integration (`tests/integration/`), env (`scripts/check_environment.py`), cú pháp (`py_compile`), CI (`.github/workflows/ci.yml`). `py_compile` không chứng minh import hoặc hành vi runtime; kiểm tra import riêng nếu cần.
2. Chạy test liên quan; nếu thiếu dataset thật, phân biệt synthetic với dữ liệu thật.
3. `git diff --check`; kiểm tra import/đường dẫn/config/dependency nếu có thay đổi.
4. Với ML: xác minh preprocessing không fit trên val/test; kiểm tra leakage rõ ràng (cột nhãn, cột dẫn xuất, identity).
5. Với thí nghiệm: không tuyên bố end-to-end nếu chưa thử UNSW-NB15 thật.
6. Báo từng kiểm tra: `PASS` (đã chạy và đạt), `FAIL` (đã chạy và lỗi), `SKIPPED` (chủ đích bỏ qua, nêu lý do), `NOT VERIFIED` (chưa chạy/không đủ bằng chứng). Không đổi FAIL thành SKIPPED để che lỗi; exit 0 khi thiếu dataset vẫn là SKIPPED.
7. Nếu không có dataset thật: không bắt buộc toàn bộ test dữ liệu phải chạy; nhưng phải ghi rõ giới hạn.
8. Không tuyên bố thành công nếu chưa chạy lệnh tương ứng.

Input: diff thực tế, yêu cầu và danh sách check bắt buộc. Output: lệnh, exit code, trạng thái, kết quả và giới hạn cho từng check. Xem cả staged/unstaged diff và nội dung file mới chưa tracked. VERIFY-only không sửa lỗi; test có thể tạo cache tạm nhưng không được sửa code sản phẩm. Khi FAIL và nhiệm vụ cho phép sửa, quay IMPLEMENT; sau đó chỉ chạy lại check bị ảnh hưởng. Chỉ kết luận đủ điều kiện khi check bắt buộc đạt; không gọi local check là remote CI PASS.
