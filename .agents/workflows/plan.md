# Kế hoạch — workflows/plan.md

Khi nhận task:

1. Đọc yêu cầu; xác định kết quả cần đạt.
2. Kiểm tra `git status --short`, branch, HEAD, remote; đọc `README.md` và chỉ các docs/code/test/CI liên quan. Đọc file thực tế, không suy luận chức năng từ tên.
3. Xác định phần đã có / chưa có / có nguy cơ bị ảnh hưởng bằng bằng chứng hiện tại. Constructor, placeholder và test import không chứng minh pipeline hoạt động. Phân tích dependencies, rủi ro, dữ liệu và quyền cần thiết; không dùng snapshot tài liệu như trạng thái live.
4. Xác định issue/acceptance criteria và chọn đúng domain skill trong `.agents/skills/`: NIDS, UNSW-NB15, leakage/evaluation hoặc model experiment. Chỉ đọc skill thực sự cần; một task thuần tài liệu/workflow không mặc định cần cả bốn.
5. Nếu liên quan ML/dữ liệu, xác định trạng thái dữ liệu (absent/synthetic/real), split/fit boundary, mục tiêu binary/multiclass/unsupervised và evidence cần để nâng PLANNED → IMPLEMENTED → TESTED → EXPERIMENTALLY VALIDATED.
6. Đưa ra kế hoạch theo thứ tự, chỉ ra file cần sửa, mắt xích traceability bị ảnh hưởng và cách xác minh (test nào, lệnh nào).
7. Ưu tiên giải pháp nhỏ nhất đáp ứng yêu cầu; không mở rộng scope.
8. PLAN-only không sửa file hoặc chuyển sang triển khai. Với nhiệm vụ đã cho phép thực hiện, kế hoạch rõ là đủ để tiếp tục, không hỏi lại chỉ để chuyển bước.
9. Chỉ hỏi khi thiếu dữ kiện có ảnh hưởng đáng kể đến tính đúng đắn; không hỏi lại nếu đã có trong repo.

Input: yêu cầu, ràng buộc, trạng thái Git và tài liệu liên quan. Output: phạm vi/ngoài phạm vi, dependency/rủi ro, các bước + file dự kiến + điều kiện kiểm chứng. Chỉ chuyển IMPLEMENT khi nhiệm vụ cho phép thực hiện.
