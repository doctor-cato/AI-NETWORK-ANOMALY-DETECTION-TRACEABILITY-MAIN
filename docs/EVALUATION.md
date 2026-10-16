# Đánh giá — Metric, Giải thích, Phân tích lỗi

## Protocol đánh giá theo mô hình

### Random Forest (giám sát)

- Huấn luyện trên tập train có nhãn.
- Dự đoán trên validation và test bằng pipeline đã fit.
- Tính: Precision, Recall, F1 (nhị phân hoặc theo lớp), Macro-F1, confusion matrix, FPR.
- Confusion matrix phải có nhãn trục rõ ràng.

### Isolation Forest (không giám sát — nếu triển khai)

- Huấn luyện trên tập train không nhãn (hoặc bỏ qua nhãn).
- Tạo điểm bất thường trên tập validation.
- Chọn ngưỡng (ghi rõ phương pháp: ví dụ ước lượng contamination = tỷ lệ bất thường dự kiến, hoặc chứng lượng điểm).
- Dự đoán trên test với ngưỡng đã chọn.
- Tính các metric giống trên; ghi rõ quá trình chọn ngưỡng.
- Lưu ý: các metric chỉ so sánh được khi cả hai protocol đã được ghi rõ.

## Định nghĩa metric (lặp lại từ METHODOLOGY cho rõ ràng)

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * P * R / (P + R)
- Macro-F1 = trung bình F1 theo từng lớp
- Confusion matrix: trục phải ghi rõ nhãn
- FPR = FP / (FP + TN) — báo cáo khi có ý nghĩa

## Phân tích lỗi

- Dương tính giả: kết nối bình thường bị đánh dấu bất thường; mô tả nguyên nhân có thể (đặc trưng tương tự bất thường; vấn đề mã hóa đặc trưng; chồng chéo lớp).
- Âm tính giả: bất thường bị bỏ sót; mô tả nguyên nhân có thể (loại bất thường thiếu dữ liệu; chưa bắt được đặc trưng; ngưỡng quá bảo thủ).
- Hạn chế dữ liệu: mất cân bằng, giá trị thiếu, bản ghi trùng, rò rỉ định danh.
- Hạn chế mô hình: Random Forest có thể overfit nếu độ sâu không giới hạn; Isolation Forest giả định dữ liệu bình thường phân cụm khác với bất thường; không tuyên bố phát hiện zero-day không có chứng cứ.

## Không tuyên bố benchmark chưa kiểm chứng

- Repo này không tuyên bố độ chính xác, F1 cụ thể, hoặc kết quả benchmark cho đến khi thực nghiệm thật hoàn thành và kết quả được ghi cùng seed/phiên bản.
- Mọi kết quả phải ghi rõ: planned / implemented / verified.

Cập nhật: 2026-10-16
