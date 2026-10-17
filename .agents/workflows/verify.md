# Kiểm thử — workflows/verify.md

Sau implement:

1. Chọn kiểm tra phù hợp: unit (`tests/unit/`), integration (`tests/integration/`), env (`scripts/check_environment.py`), cú pháp (`py_compile`), CI (`.github/workflows/ci.yml`). `py_compile` không chứng minh import hoặc hành vi runtime; kiểm tra import riêng nếu cần.
2. Chạy test liên quan; nếu thiếu dataset thật, phân biệt synthetic với dữ liệu thật.
3. `git diff --check`; kiểm tra import/đường dẫn/config/dependency nếu có thay đổi.
4. Với dữ liệu: xác minh provenance/checksum, biến thể/schema, type/missing/duplicate, label/category và split protocol. Dữ liệu vắng mặt hoặc synthetic không phải validation dữ liệu thật.
5. Với ML: audit target/train-test/preprocessing/feature-selection/tuning/duplicate-group/threshold leakage; xác minh encoder/imputer/scaler/selector chỉ fit trong training boundary. Kiểm tra binary/multiclass semantics, label order, per-class/Macro-F1 và FPR.
6. Với thí nghiệm: kiểm tra seed, dataset version, dependency, config, split, feature/target mapping, artifact metadata và lệnh tái lập; không tuyên bố end-to-end nếu chưa thử UNSW-NB15 thật.
7. Với runtime/integration: kiểm tra hành vi và đường lỗi, không chỉ import/constructor. Kết thúc bằng `git diff --check`, staged/unstaged/untracked, và scan không có secret/dataset/model artifact ngoài phạm vi.
8. Báo từng kiểm tra: `PASS` (đã chạy và đạt), `FAIL` (đã chạy và lỗi), `SKIPPED` (chủ đích bỏ qua, nêu lý do), `NOT VERIFIED` (chưa chạy/không đủ bằng chứng). Mỗi dòng có lệnh, exit code, evidence và giới hạn. Không đổi FAIL thành SKIPPED để che lỗi; exit 0 khi thiếu dataset vẫn là SKIPPED.
9. Nếu không có dataset thật: không bắt buộc toàn bộ test dữ liệu phải chạy; nhưng phải ghi rõ giới hạn.
10. Không tuyên bố thành công nếu chưa chạy lệnh tương ứng; Markdown/frontmatter PASS không chứng minh runtime discovery hoặc skill đã được kích hoạt.

Input: diff thực tế, yêu cầu và danh sách check bắt buộc. Output: lệnh, exit code, trạng thái, kết quả và giới hạn cho từng check. Xem cả staged/unstaged diff và nội dung file mới chưa tracked. VERIFY-only không sửa lỗi; test có thể tạo cache tạm nhưng không được sửa code sản phẩm. Khi FAIL và nhiệm vụ cho phép sửa, quay IMPLEMENT; sau đó chỉ chạy lại check bị ảnh hưởng. Chỉ kết luận đủ điều kiện khi check bắt buộc đạt; không gọi local check là remote CI PASS.
