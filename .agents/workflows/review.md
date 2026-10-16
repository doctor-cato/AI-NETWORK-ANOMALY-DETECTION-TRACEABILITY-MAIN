# Review — workflows/review.md

Review sau triển khai:

- So sánh diff với yêu cầu ban đầu.
- Tìm lỗi logic, regression, leakage, xử lý nhãn sai, sai lệch metric, vấn đề tái lập.
- Kiểm tra ranh giới dữ liệu và trường hợp lỗi.
- Phát hiện code thừa, abstraction quá mức, dependency không cần, tài liệu mâu thuẫn.
- Kiểm tra test có xác minh hành vi thực tế hay chỉ import.
- Phân loại: `BLOCKER`, `HIGH`, `MEDIUM`, `LOW`; cung cấp đường dẫn file + dòng nếu có.
- Chỉ kết luận dựa trên bằng chứng; không sửa thêm ngoài phạm vi review nếu chưa được yêu cầu.
- Nếu không phát hiện lỗi: nêu rõ các phần đã kiểm tra và giới hạn còn lại (ví dụ: chưa có dataset thật, chưa kiểm thử IF protocol đầy đủ).

Input: yêu cầu, base/phạm vi diff, file mới và bằng chứng VERIFY. Tự đọc yêu cầu, diff, code và test trước khi đối chiếu báo cáo implementer; tìm phản ví dụ và đường lỗi. Ưu tiên security, compatibility, regression và thiếu test hành vi. Output: findings có mức độ, file:dòng, điều kiện tái hiện, tác động và gợi ý; không bịa finding. Review-only không sửa file hoặc cập nhật GitHub. Nếu không có reviewer riêng, ghi rõ review cùng agent, không tuyên bố độc lập. Lỗi cần sửa chuyển IMPLEMENT chỉ khi nhiệm vụ cho phép; giữ giới hạn số lượt sửa theo bộ điều phối đang dùng.
