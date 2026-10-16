# Kế hoạch — workflows/plan.md

Khi nhận task:

1. Đọc yêu cầu; xác định kết quả cần đạt.
2. Kiểm tra `git status --short`, branch, HEAD, remote; đọc `README.md` và chỉ các docs/code/test/CI liên quan. Đọc file thực tế, không suy luận chức năng từ tên.
3. Xác định phần đã có / chưa có / có nguy cơ bị ảnh hưởng bằng bằng chứng hiện tại. Constructor, placeholder và test import không chứng minh pipeline hoạt động. Phân tích dependencies, rủi ro, dữ liệu và quyền cần thiết; không dùng snapshot tài liệu như trạng thái live.
4. Đưa ra kế hoạch theo thứ tự, chỉ ra file cần sửa và cách xác minh (test nào, lệnh nào).
5. Ưu tiên giải pháp nhỏ nhất đáp ứng yêu cầu; không mở rộng scope.
6. PLAN-only không sửa file hoặc chuyển sang triển khai. Với nhiệm vụ đã cho phép thực hiện, kế hoạch rõ là đủ để tiếp tục, không hỏi lại chỉ để chuyển bước.
7. Chỉ hỏi khi thiếu dữ kiện có ảnh hưởng đáng kể đến tính đúng đắn; không hỏi lại nếu đã có trong repo.

Input: yêu cầu, ràng buộc, trạng thái Git và tài liệu liên quan. Output: phạm vi/ngoài phạm vi, dependency/rủi ro, các bước + file dự kiến + điều kiện kiểm chứng. Chỉ chuyển IMPLEMENT khi nhiệm vụ cho phép thực hiện.
