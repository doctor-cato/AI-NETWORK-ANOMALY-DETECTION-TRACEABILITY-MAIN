# Phương pháp — Random Forest (baseline bắt buộc), Isolation Forest (tùy chọn)

## Luồng tổng thể

1. Đọc dữ liệu (sau khi tải về `data/raw/`)
2. Kiểm tra schema / nhãn (`scripts/validate_data.py`)
3. Khám phá (notebook EDA) — phân bố lớp, giá trị thiếu, bản ghi trùng, kiểm tra rò rỉ dữ liệu
4. Chia train/val/test (mặc định giữ official test partition; tạo validation chỉ từ official training partition;
   nếu chọn stratified/group/time-aware khác thì ghi lý do và ảnh hưởng trong `REPRODUCIBILITY.md`)
5. Tiền xử lý (fit chỉ trên train): mã hóa, chuẩn hóa, chọn đặc trưng; lưu pipeline
6. Huấn luyện mô hình: Random Forest là baseline bắt buộc (config đã ghi); thêm Isolation Forest nếu còn thời gian (không giám sát, protocol riêng bên dưới)
7. Đánh giá (protocol khác nhau theo mô hình; xem bên dưới)
8. Phân tích lỗi (dương tính giả / âm tính giả; ghi rõ hạn chế)
9. Suy luận (tải pipeline + mô hình; áp dụng cho dữ liệu mới)

## Random Forest (baseline bắt buộc)

- Loại: phân loại giám sát (nhị phân hoặc đa lớp tùy mục tiêu)
- Huấn luyện: tập huấn luyện có nhãn; siêu tham số đã ghi (`n_estimators`, `max_depth`, `random_state`)
- Đánh giá: các metric giám sát chuẩn — Precision, Recall, F1 per class, Macro-F1, confusion matrix, False Positive Rate (FPR) khi có ý nghĩa
- Giải thích confusion matrix: âm tính đúng / dương tính giả (bình thường bị phân loại nhầm là bất thường) / âm tính giả (bất thường bị bỏ sót) / dương tính đúng
- Ngăn rò rỉ dữ liệu: không tạo đặc trưng từ nhãn; chia trước mọi fitting; kiểm tra cột định danh và xử lý cẩn thận

## Isolation Forest (phát hiện bất thường không giám sát — TÙY CHỌN, không chặn core)

- Loại: không giám sát; học phân phối dữ liệu bình thường; chấm điểm độ lệch
- Dữ liệu fit phải được chọn và ghi trước: normal-only cho novelty detection, hoặc mixed/unlabeled training population
  cho outlier detection. Nếu dùng nhãn để lọc normal-only thì phải công khai bước lọc; target không được truyền như
  feature hay đối số fit của mô hình.
- Protocol đánh giá (phải ghi riêng biệt với đánh giá giám sát):
  - Tạo điểm bất thường cho tập validation/test
  - Chọn ngưỡng trên tập validation (ví dụ: contamination/quantile đã định trước, hoặc tối ưu bằng validation labels
    và ghi rõ đây là supervised calibration)
  - Áp dụng ngưỡng cho tập test để có nhãn dự đoán
  - So sánh dự đoán với nhãn thực tế bằng Precision, Recall, F1, Macro-F1, FPR
  - Ghi rõ phương pháp chọn ngưỡng và tác động đến metric
- Quan trọng: so sánh trực tiếp với Random Forest cần giải thích rõ vì RF dùng nhãn khi huấn luyện và đánh giá theo protocol giám sát, trong khi IF dùng chấm điểm và chọn ngưỡng rồi đánh giá. Các metric chỉ so sánh được khi cả hai protocol được mô tả rõ ràng.

## Quy tắc tiền xử lý (tránh rò rỉ)

- Chia train / val / test trước mọi fitting tiền xử lý.
- Fit imputer/encoder/scaler/selector chỉ trên train.
- Transform val/test bằng đối tượng đã fit.
- Lưu đối tượng đã fit cùng artifact mô hình.
- Ghi rõ cột nào được bao gồm / loại bỏ và lý do (kết quả kiểm tra rò rỉ).

## Định nghĩa metric

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * Precision * Recall / (Precision + Recall)
- Macro-F1 = trung bình điểm F1 theo từng lớp
- Confusion matrix: hàng/cột phải ghi rõ nhãn (bình thường / bất thường)
- FPR = FP / (FP + TN) — chỉ báo cáo khi có ý nghĩa cho trường hợp sử dụng

Cập nhật: 2026-10-17 — tách rõ Random Forest (bắt buộc) và Isolation Forest (tùy chọn).
