# Phát biểu vấn đề — phát hiện bất thường trong lưu lượng mạng

## Vấn đề

Lưu lượng mạng có cả mẫu kết nối bình thường và bất thường. Kết nối bất thường, như quét mạng, truy cập trái phép, sử dụng protocol không thường gặp, kích thước packet hoặc thời điểm bất thường, có thể chỉ ra sự cố bảo mật. Nhiệm vụ là xây dựng hệ thống dùng đặc trưng lưu lượng để phát hiện kết nối bất thường, so sánh mô hình học máy, đánh giá hiệu quả và cung cấp kết quả có thể giải thích.

## Đối tượng mục tiêu

- Kết nối/flow mạng được mô tả bằng protocol, service, duration, số packet, byte, TCP flag và thống kê dẫn xuất.
- Không nhận diện thiết bị, không fingerprint kẻ tấn công và không tuyên bố zero-day khi chưa có bằng chứng.

## Đầu vào

- Bản ghi có cấu trúc từ UNSW-NB15 (CSV / parquet tùy phiên bản): IP/port nguồn-đích, protocol, service, duration, state, số packet, byte, metric flow và thống kê dẫn xuất.
- Nhãn mục tiêu nhị phân hoặc đa lớp, biểu thị normal và các nhóm anomaly.

## Đầu ra

- Classification / anomaly score cho từng kết nối.
- Metric: Precision, Recall, F1-score, Macro-F1, confusion matrix, False Positive Rate.
- Đầu ra có thể giải thích: feature importance, error analysis (false positive / false negative) và giới hạn đã ghi.

## Câu hỏi nghiên cứu / thiết kế

1. Đặc trưng nào của UNSW-NB15 dự đoán anomaly mà không gây target leakage, chẳng hạn cột định danh mã hóa thời gian hoặc session?
2. Random Forest hoạt động thế nào với vai trò baseline giám sát trên dataset này?
3. Isolation Forest có phát hiện không giám sát hữu ích không, và đánh giá khác gì về threshold và diễn giải score?
4. Đánh đổi false positive là gì, và mất cân bằng lớp hoặc missing value ảnh hưởng độ tin cậy ra sao?
5. Pipeline preprocessing có tái lập được và không rò rỉ dữ liệu không?

## Bối cảnh và động lực

Phát hiện bất thường mạng hỗ trợ vận hành bảo mật nhưng phải được kiểm chứng bằng dữ liệu thật và đánh giá minh bạch. Dự án nhằm minh họa pipeline ML tái lập được cho bài tập, không tuyên bố bảo đảm an ninh cấp production.

## Ngoài mục tiêu và ranh giới

- Không tuyên bố phát hiện zero-day khi chưa có thực nghiệm có kiểm soát.
- Không xác định kẻ tấn công hoặc thiết bị cụ thể từ behavior vector.
- Không chặn hoặc phản công tự động.
- Không triển khai giám sát mạng doanh nghiệp.

Cập nhật: 2026-10-17
