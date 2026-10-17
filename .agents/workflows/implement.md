# Triển khai — workflows/implement.md

Khi thực hiện:

1. Làm theo kế hoạch đã xác định.
2. Đọc nội dung file trước khi sửa (`git show`, `cat`, `python` kiểm tra import nếu cần).
3. Không ghi đè thay đổi có sẵn của người dùng; kiểm tra `git status` trước khi sửa.
4. Không tạo placeholder nhưng báo cáo như đã xong.
5. Không thay đổi file ngoài phạm vi nếu không có lý do rõ ràng (ghi lại lý do nếu cần).
6. Không tự tải dataset hoặc thực hiện tác vụ tốn tài nguyên khi chưa cần.
7. Với task domain, tuân thủ đúng skill đã chọn ở PLAN; không tự chuyển từ data validation sang training, từ binary sang multiclass, hoặc từ RF sang IF.
8. Giữ traceability tối thiểu trong file hiện có: issue/requirement, code, test, evidence và result/giới hạn; không tạo tracking framework mới nếu ma trận/manifest hiện có đủ.
9. Cập nhật tài liệu liên quan nếu hành vi thực tế thay đổi (`docs/REPRODUCIBILITY.md`, `README.md` trạng thái).
10. Nếu phần chưa hoàn thành: ghi rõ trong commit message / báo cáo, không che giấu.

Input: yêu cầu được phép thực hiện và kế hoạch rõ ràng. Output: diff tối thiểu, file/lý do thay đổi, test bổ sung nếu cần và phần còn lại. Nếu kế hoạch không còn đúng, điều chỉnh trong phạm vi đã cho phép; hỏi khi thiếu quyết định bắt buộc. Không tự stage/commit/push. Chuyển VERIFY khi diff có thể kiểm tra; không ghi đè file mới chưa tracked của người dùng.
