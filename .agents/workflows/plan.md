# Kế hoạch — workflows/plan.md

Khi nhận task:

1. Đọc yêu cầu; xác định kết quả cần đạt.
2. Kiểm tra repo: `README.md`, `docs/` liên quan (`METHODOLOGY.md`, `EVALUATION.md`), code `src/`, `tests/`, `scripts/`, CI `.github/workflows/ci.yml`.
3. Xác định phần đã có / chưa có / có nguy cơ bị ảnh hưởng:
   - Dataset: `planned` (chưa tải).
   - Preprocessing: `implemented` (placeholder, cần triển khai).
   - RF: `implemented`; IF: `implemented` (build model) nhưng `planned` cho protocol đánh giá.
4. Đưa ra kế hoạch theo thứ tự, chỉ ra file cần sửa và cách xác minh (test nào, lệnh nào).
5. Ưu tiên giải pháp nhỏ nhất đáp ứng yêu cầu; không mở rộng scope.
6. Không sửa code trước khi hiểu phạm vi.
7. Chỉ hỏi khi thiếu dữ kiện có ảnh hưởng đáng kể đến tính đúng đắn; không hỏi lại nếu đã có trong repo.
