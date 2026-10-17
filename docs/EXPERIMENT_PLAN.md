# Kế hoạch thực nghiệm

## Giả thuyết

- H1: Random Forest cho kết quả phát hiện giám sát có thể sử dụng trên UNSW-NB15 sau khi preprocessing và chia tập đúng cách.
- H2: Isolation Forest có thể phát hiện bất thường không cần nhãn, nhưng đánh giá cần chọn threshold và cho profile metric khác đánh giá giám sát.

## Biến số

- Độc lập: loại mô hình (RF hoặc IF), lựa chọn preprocessing (encoding, đặc trưng được chọn), chiến lược split, random seed.
- Phụ thuộc: Precision, Recall, F1, Macro-F1, confusion matrix, FPR.

## Baseline

- Dùng Random Forest với hyperparameter mặc định/giới hạn làm baseline.
- Mốc so sánh là metric đã ghi cùng seed và phiên bản.

## Ghi nhận metric

- Mỗi lượt chạy lưu seed, phiên bản dataset, danh sách feature, cấu hình model, metric theo lớp và macro, confusion matrix dạng CSV/PNG, thời gian và thông tin môi trường.
- Kết quả đặt tại `reports/figures/` và `artifacts/` (không commit nếu lớn; vẫn lưu config).

## Protocol

- Split trước rồi mới preprocessing; lưu pipeline.
- Cố định random seed (ví dụ 42) để split và khởi tạo model tái lập được.
- Chạy nhiều seed nếu thời gian cho phép; chỉ báo mean/std khi thực sự đã chạy.
- Ghi mọi sai khác, ví dụ Isolation Forest chưa triển khai do thiếu thời gian.

Cập nhật: 2026-10-17
